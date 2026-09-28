# Design: Typed PKCS#12 Password Signal End-to-End (ZSN-230)

Status: final (cold review: round 1 NOT-READY → fixes → round 2
READY-WITH-FIXES; all prescribed fixes applied)
Base: main @ 899170c (ZSN-96 Apple-root anchoring, ZSN-98 key↔cert guard,
ZSN-143 profile-error unification all landed)

## 1. Problem

`p12_err` (`crates/zsign-wasm/src/lib.rs:188-199`) classifies PKCS#12
password failures by substring-matching the literals
`"invalid PKCS#12 password (MAC mismatch)"` and
`"PKCS#12 decryption failed"` against a message `zsign-core` constructs —
the exact anti-pattern the repo forbids consumers from using, done inside
the library, coupled across a crate boundary by human-readable text. Any
wording change in `pkcs12.rs` silently reclassifies wrong-password as
corrupt-certificate.

Root cause: `SigningCredentials::load_p12`
(`crates/zsign-core/src/crypto/cert.rs:708-710`) and
`from_p12_with_leaf_sha1_impl` (`cert.rs:771-772`) flatten the typed
`P12Error` into `Error::Certificate(format!("Failed to parse PKCS#12: {e}"))`.
The typed mapping already exists and is used by the encrypted-PEM path:
`pem_load_error` (`crates/zsign-core/src/crypto/pkcs12.rs:823-833`) maps
`P12Error::Mac | P12Error::Decrypt(_) → Error::InvalidPassword`.

A second sniffer consumer exists in the CLI: `resolve_p12_password`
(`crates/zsign-cli/src/main.rs:958-985`) stringifies the empty-password
trial error (`:962-964`) and substring-sniffs the same two markers
(`:966-968`) to decide whether it may prompt (TTY) or emit the
`no password supplied: pass -p/--password or set ZSIGN_PASSWORD` hint
(non-TTY).

## 2. Decision

**Chosen candidate (a): one shared `p12_load_error` used by both p12
constructors + explicit typed wasm arm + delete both sniffers.**

- **(b) stop flattening entirely** (let `Error` carry `P12Error` context) —
  rejected: changes the public `zsign-core::Error` enum shape, forcing churn
  across facade, CLI, wasm `code_for_core_error` (exhaustive match), and
  every `matches!(… Error::Certificate …)` pin, for no behavioral gain
  beyond what (a) delivers.
- **(c) typed `is_password_failure(&Error)` predicate export** — rejected:
  a predicate over the *flattened* `Error` still cannot distinguish
  wrong-password from corrupt if the flatten happens first; wired after the
  flatten it is a strictly weaker form of (a), and wasm needs a `match` arm
  anyway. YAGNI.

### Classification parity table (the contract to preserve)

`Error::InvalidPassword` already maps to `ZSIGN_INVALID_PASSWORD` on wasm
(`code_for_core_error`, `lib.rs:141`); before this ticket the sniffer
achieved the same code by text. The typed path must reproduce exactly the
sniffer's classification:

| Failure | Old class (core) | Old wasm code (via sniffer) | New class (core) | New wasm code | Move? |
|---|---|---|---|---|---|
| `P12Error::Mac` (wrong password / MAC corruption) | `Certificate("…MAC mismatch…")` | `ZSIGN_INVALID_PASSWORD` | `InvalidPassword` | `ZSIGN_INVALID_PASSWORD` | code unchanged |
| `P12Error::Decrypt(_)` (wrong password, incl. non-block-aligned/bad-padding ciphertext) | `Certificate("…decryption failed…")` | `ZSIGN_INVALID_PASSWORD` | `InvalidPassword` | `ZSIGN_INVALID_PASSWORD` | code unchanged |
| `P12Error::Der(_)` (malformed container, incl. wrong password degenerating to ASN.1 failure) | `Certificate("…malformed PKCS#12…")` | `ZSIGN_INVALID_CERTIFICATE` | `Certificate` (same message) | `ZSIGN_INVALID_CERTIFICATE` | unchanged |
| `P12Error::Unsupported(_)` | `Certificate("…unsupported PKCS#12…")` | `ZSIGN_INVALID_CERTIFICATE` | `Certificate` (same message) | `ZSIGN_INVALID_CERTIFICATE` | unchanged |
| everything after extract (policy, weak key, multi-identity, anchoring) | `Certificate(…)`, `Verification`… | unchanged | unchanged | unchanged | no code moves |

Fail-closed posture: wrong password still fails on every route; only the
*classification* changes, never whether.

### Taxonomy verification (librarian, source-verified)

- `P12Error::Mac` has exactly one construction site (`pkcs12.rs:126`,
  `verify_mac` → `Ok(false)`), reachable only via HMAC mismatch — wrong
  password or tampered container. Corruption producing `Mac` was already
  classified password-shaped by the old sniffer (the marker text matched),
  so classifying it `InvalidPassword` **preserves** current wasm/CLI
  behavior rather than changing it.
- `P12Error::Decrypt(_)` has five construction sites (`pkcs12.rs:430, 440,
  450, 460, 632-633`); non-block-aligned ciphertext, short IV and bad
  PKCS#7 padding all surface as `Decrypt` (`cbc_decrypt` `:642-644,
  :645-647, :663-665`, the padding check delegating to `unpad_pkcs7`
  whose invalid-padding returns are `:672-680` → `:488`/`:633`) —
  crypto-11's claim confirmed against source.
  These were also sniffer-matched before; parity holds.
- A wrong password can degenerate into `Der` only on no-MAC files with a
  lucky padding byte (~1/256); that case carried no password signal under
  the sniffer either (message said `malformed PKCS#12`), so it stays
  `Certificate` → `ZSIGN_INVALID_CERTIFICATE` — byte-for-byte parity with
  today. The wasm doc comment's claim that this is how wrong password
  "usually" degrades is wrong (MAC check runs first on standard files) and
  is rewritten.

### Why one helper, and why not folded into `pem_load_error`

`p12_load_error` mirrors `pem_load_error` but keeps its own body: the
non-password classes differ by design. `pem_load_error` maps
`Unsupported → "unsupported key encryption: {msg}"` and
`Der → "failed to parse encrypted private key: {msg}"` (encrypted-PEM
context), while both p12 flatten sites today produce
`"Failed to parse PKCS#12: {e}"`. Folding both into one helper would either
reword the PEM path (violating "existing substring pins must keep passing"
for no gain) or need a context parameter — complexity for two call sites.
Decision: two helpers, identical password arm, context-correct wrappers.

## 3. Helper API

`crates/zsign-core/src/crypto/pkcs12.rs`, directly after `pem_load_error`
(`:833`):

```rust
/// Translates a container failure into the credential error a caller
/// reports. MAC verification failure and password-derived decryption
/// failure are passphrase outcomes; malformed or unsupported containers
/// keep their certificate class with the same wrapper text the PKCS#12
/// loaders have always produced.
pub(crate) fn p12_load_error(e: P12Error) -> Error {
    match e {
        P12Error::Mac | P12Error::Decrypt(_) => Error::InvalidPassword,
        other => Error::Certificate(format!("Failed to parse PKCS#12: {other}")),
    }
}
```

Resulting messages:
- wrong password: `Invalid password for private key or PKCS#12`
  (the existing `Error::InvalidPassword` display, `error.rs:19`) — **text
  moves**, class pins and wasm code do not;
- corrupt/unsupported: byte-identical to today
  (`Failed to parse PKCS#12: malformed PKCS#12: …` / `… unsupported PKCS#12: …`).

## 4. Sites rewired

1. **`cert.rs:709-710` (`load_p12`)** — replace the inline `map_err` with
   `.map_err(super::pkcs12::p12_load_error)`. Feeds `from_p12` (`:702`),
   `from_p12_unanchored` (`:733`) — i.e. every native CLI/wasm/facade p12
   load.
2. **`cert.rs:771-772` (`from_p12_with_leaf_sha1_impl`)** — same
   replacement. Feeds the keychain selector path
   (`crypto/keychain.rs:228-234`, which erases any class into
   `KeychainError::Credential` — no pin depends on the inner class there,
   recorded not changed).
3. **`crates/zsign-wasm/src/lib.rs:182-199` `p12_err`** — delete the
   substring sniffer. `code_for_core_error` already maps
   `Error::InvalidPassword → WasmErrorCode::InvalidPassword` (`:141`), so
   after (1)-(2) the typed signal reaches the mapper directly, and
   `p12_err`'s doc comment (claiming `from_p12` flattens everything to
   `Certificate`) is stale. The classification is extracted into a pure
   helper so the mapping is natively unit-testable (cold-review FIX:
   `cargo test -p zsign-wasm` cannot observe a `js_err`-touching test —
   the crate's own convention is `unsupported = test` for pure tests,
   plain `#[wasm_bindgen_test]` for js-touching ones, `lib.rs:1483-1488`):

   ```rust
   /// Classifies a PKCS#12 credential-load failure. A typed password
   /// failure keeps the password code on every p12 route; malformed or
   /// unsupported containers keep the certificate code, as does a wrong
   /// password that degenerates into an ASN.1 parse failure — that
   /// outcome carries no password signal.
   fn p12_code(e: &zsign_core::Error) -> WasmErrorCode {
       match e {
           zsign_core::Error::InvalidPassword => WasmErrorCode::InvalidPassword,
           other => code_for_core_error(other),
       }
   }

   /// Wraps a credential-load failure raised while reading a PKCS#12 container.
   fn p12_err(e: zsign_core::Error) -> JsValue {
       js_err(p12_code(&e), e)
   }
   ```

   Notes: (i) the explicit `InvalidPassword` arm is the brief's mandated
   typed branch at the p12 boundary — it mirrors `code_for_core_error:141`
   by design (contract locality, not accidental duplication); (ii) matching
   on `&e`/`p12_code(&e)` is required — matching `e` by value and then
   reusing `e` in `js_err` is a compile error (E0382, cold-review
   BLOCKER); (iii) signature and the sole caller (`:286
   .map_err(p12_err)`) are unchanged.
   Both substring literals (`:190-191`) are **deleted** with the old body;
   a grep of `crates/zsign-wasm/src` for them must return nothing.
4. **`crates/zsign-cli/src/main.rs:958-985` `resolve_p12_password`**
   (scope override — see §6) — stop stringifying before classifying; keep
   the trial error, branch on the typed variant:

   ```rust
   let trial = SigningCredentials::from_p12(data, "");
   let password_shaped = matches!(&trial, Err(zsign_core::Error::InvalidPassword));
   let trial_err = match trial {
       Ok(_) => return Ok(String::new()), // empty-password containers never prompt
       Err(e) => e.to_string(),
   };
   if !password_shaped {
       return Err(trial_err.into());
   }
   // …TTY prompt / non-TTY hint unchanged, both use trial_err text…
   ```

   `crates/zsign-cli/Cargo.toml` gains `zsign-core` as a direct dependency
   (it is already a dev-dependency; the main binary needs the variant name —
   the same arrangement `zsign-wasm` uses). The sniffer comment
   (`:966`) is rewritten; the prompt text, channel-hint text, exit codes
   and JSON envelope are untouched.
5. **No changes**: `crates/zsign/src/error.rs` (facade forwards
   `InvalidPassword` transparently as `Error::Core` already),
   `code_for_core_error` (`lib.rs:135-150`, arm already present),
   the wasm doc table (`lib.rs:26` already documents
   `ZSIGN_INVALID_PASSWORD`), CLI exit codes / `--json` schema,
   `P12Error`'s `Display` (`pkcs12.rs:84-92` — its text is now consumed by
   nobody across crates, but is still the `P12Error`'s own reporting and
   the wrapper in `p12_load_error` reuses it for non-password classes),
   README (Wave 8).

## 5. Contract impact

- **wasm stable codes**: zero movement. The parity table in §2 is the
  proof; every `ZSIGN_*` code for every p12 failure class is identical
  before/after. Sniffer literals deleted — the forbidden coupling is gone.
- **CLI**: exit codes 0/1/2 and the JSON envelope unchanged (derived from
  mode, not variant). Two message-level test assertions adapt (§6).
  User-visible hint flow (prompt / `no password supplied`) preserved —
  this was the behavior at risk.
- **Native enum**: no variant added or removed; `InvalidPassword`'s
  *reach* widens (now also produced by the two p12 loaders). Pre-1.0,
  minor-bump rule: no in-repo pin asserts `Certificate` for a wrong p12
  password (verified: the only `InvalidPassword` pins are encrypted-PEM,
  `cert.rs:1906-1910` and `encrypted_pem.rs:273-277`).
- **Messages are not a contract** (README: "match on the code, never the
  message"), but existing substring pins must keep passing — see §6.

## 6. Scope override and recorded deviation

The brief defers `crates/zsign-cli/` to ZSN-138 *and* requires
`resolve_p12_password`'s prompt flow and tests to stay green. Research
proved these mutually unsatisfiable: post-change the trial error reads
`Invalid password for private key or PKCS#12`, matches neither marker, the
hint stops firing, and two tests fail on behavior, not wording. Escalated
as the brief's sanctioned "genuine unforeseen decision"; **supervisor
chose: minimal typed fix in CLI now** (candidate 1 of 3). Recorded effects:

- ZSN-138 (facade-10) inherits **only**: docs (README `:286-290` password
  flow prose, Wave 8) and residual p12 surface — *not* the CLI sniffer,
  which this ticket retires. Recorded effect of this override:
  `crates/zsign-cli/Cargo.toml` gains `zsign-core` as a direct
  `[dependencies]` entry (mirroring zsign-wasm's arrangement).
- Two CLI test assertions adapt, meaning preserved (each still asserts
  "the real cause surfaced / env password was read", with the new message
  text):
  - `argv_password_beats_env_password` (`main.rs:1577`):
    `contains("MAC mismatch")` → `contains("Invalid password for private
    key or PKCS#12")`;
  - `missing_password_on_non_tty_degrades_to_clear_error`
    (`main.rs:1628-1632`): same substitution on the real-cause assertion;
    the `--password` / `ZSIGN_PASSWORD` hint assertions are untouched and
    must still pass (they prove the flow works).
  - Negative pins (`!contains("MAC mismatch")` at `:1391, :1546, :1603,
    :1657`) keep passing as-is: after the change no CLI message contains
    `MAC mismatch` at all, so the negatives are vacuously true — recorded,
    not relied upon; their *meaning* (non-password failures don't demand a
    password) is re-pinned by `empty_password_container_is_never_treated_as_missing`
    which uses behavioral assertions (`ZSIGN_PASSWORD`, `no password
    substrings` on a policy-gate failure).
- Candidate rejected by supervisor: keeping the marker inside
  `Error::InvalidPassword`'s display (would lie on the PEM path) and
  accepting CLI flow regression (would violate the brief's must-not-move).

## 7. Invariants (must not regress)

- **Fail-closed**: a wrong password still fails through `from_p12`,
  `from_p12_unanchored`, `from_p12_with_leaf_sha1`, wasm `WasmSigner::new`,
  CLI `-k`/`--pkcs12`. Never whether — only how classified.
- **Anchor/ordering (ZSN-96)**: `load_p12` still parses → selects →
  policy-checks → anchors; the flatten swap touches only the
  `extract_p12` `map_err`. Anchoring error text pins
  (`"not anchored to a trusted root"`) unchanged.
- **Key↔cert guard (ZSN-98)**: `select_identity` paths untouched.
- **Profile-error unification (ZSN-143)**: untouched (different files).
- Zero-warning gate; no ticket IDs in code comments; no `println!`/
  `eprintln!` in `src/`; no placeholders; `TMPDIR=$PWD/target/tmp` for tests.

## 8. Test matrix (regression scope)

Native (`zsign-core`):

| # | Entry | Input | Assert |
|---|---|---|---|
| N1 | `from_p12` (anchored) | `IDENTITY_DUP`, wrong password | `Err(Error::InvalidPassword)` — **red today** (`Certificate`) |
| N2 | `from_p12_with_leaf_sha1` | `IDENTITY_DUP`, wrong password, any leaf | `Err(Error::InvalidPassword)` — **red today** |
| N3 | `from_p12` (anchored; the pre-existing test's entry — equivalent to unanchored for this input, the flatten fires before any anchoring policy) | `b"not valid p12 data"` | `Err(Error::Certificate(_))`, msg contains `Failed to parse PKCS#12` — existing `test_from_p12_invalid_data` upgraded from bare `is_err()` (corrupt keeps its class: crypto-11's concern pinned) |
| N4 | `from_p12_unanchored` | `IDENTITY_DUP`, correct password | loads (existing tests untouched) |
| R1–R6 | policy/weak-key/anchoring/identity pins | existing fixtures | byte-identical messages, existing tests pass **unmodified** |

wasm:

| # | Entry | Assert |
|---|---|---|
| W1 | `WasmSigner::new(LEAF_P12_B64, "wrong-password", …)` | `ZSIGN_INVALID_PASSWORD` (existing `errors_carry_stable_zsign_codes…` `:1703` keeps passing — it now proves the typed path through `p12_err` end-to-end, under `wasm-pack test`) |
| W2 | `p12_code(&Error::InvalidPassword)` (rewritten `p12_classifier_maps_password_layer_failures`, typed input, `unsupported = test`) | `ZSIGN_INVALID_PASSWORD` — natively runnable via `cargo test -p zsign-wasm` |
| W3 | `p12_code(&Error::Certificate("Failed to parse PKCS#12: malformed…"))` | `ZSIGN_INVALID_CERTIFICATE` (same rewritten test — corrupt stays distinguishable) |
| W4 | source grep | neither sniffer literal exists anywhere under `crates/zsign-wasm/src` — records that the textual basis of the coupling is gone; the behavioral pin is W1/W2, W4 alone proves only absence |

CLI (subprocess, existing suites):

| # | Test | Assert |
|---|---|---|
| C1 | `missing_password_on_non_tty_degrades_to_clear_error` | exit 1; stderr has `--password` **and** `ZSIGN_PASSWORD` (hint fires) **and** the real-cause substring (adapted) |
| C2 | `argv_password_beats_env_password` | env-only wrong password fails with adapted real-cause substring; flag-beats-env unchanged |
| C3 | `empty_password_container_is_never_treated_as_missing` | unmodified — policy failure never demands a password |
| C4 | `env_password_signs_p12_without_flag`, `key_route_pkcs12_content_loads_with_password` | unmodified — happy paths |

## 9. Non-goals

ZSN-99 (`cms.rs`), verify.rs (Wave 2), Mach-O (Wave 3), CLI flags
(Wave 6), README (Wave 8), `scripts/`+`.github/`, the `keychain.rs`
`Credential` erasure (no pin, different ticket's surface), `P12Error`
Display wording, `pem_load_error`'s body (owned by lane-1 crypto tickets),
lane-1's `cert.rs`/`pkcs12.rs` regions outside the three hunks named in §4.

## 10. Process note (phase-2 dispatch + independent re-verification)

Deviation, recorded as instructed: the phase-2 research dispatch failed
twice on harness tool-list format (`tools` rejected in both explicit and
empty form) before succeeding on the third attempt without that field. The
prescribed single batch did run — three read-only agents (SurfaceInventory,
TestInventory, P12ErrorTaxonomy) — and their findings are what §1, §2
("Taxonomy verification"), §6 and §8 cite.

After the ticket landed, the orchestrator independently re-verified every
load-bearing research claim by direct `read`/`grep` against the worktree —
no subagent intermediation — and all were confirmed:

- both `cert.rs` flatten sites route through `p12_load_error`
  (`cert.rs:710`, `:772`), whose arms match §3 (`pkcs12.rs:841-844`);
- wasm: zero sniffer-literal matches under `crates/zsign-wasm/src`;
  `p12_code` (`lib.rs:187-192`) and the `code_for_core_error` arm
  (`lib.rs:141`) present;
- CLI: zero sniffer-literal matches under `crates/zsign-cli/src`;
  typed branch at `main.rs:965`; both adapted assertions at
  `main.rs:1580`, `:1633`;
- taxonomy: `P12Error::Mac` constructed only at `pkcs12.rs:126`;
  `Decrypt` at `:430`, `:440`, `:450`, `:460`, `:632-633`; the two marker
  strings survive only as `P12Error`'s own `Display` (`:88-89`), the
  frozen producer §4.5 records.

Final gate exit codes were captured directly from the tools (no
pipelines): `CLIPPY_RC=0`, `WS_RC=0` (789 passed / 0 failed / 1+12
ignored), `WP_RC=0` (29 passed / 0 failed).
