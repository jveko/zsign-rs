# Split PKCS#12 Decrypt Error Classes — Design

## Problem

`P12Error::Decrypt` (`crates/zsign-core/src/crypto/pkcs12.rs:73-83`) is the catch-all for
every failure of a password-derived decryption, and both flatten sites map it — together
with `P12Error::Mac` — to `zsign_core::Error::InvalidPassword`
(`pkcs12.rs:825`, `pkcs12.rs:842`; the variant is `crates/zsign-core/src/error.rs:19-20`).

Three distinct causes collapse into that one variant because `cbc_decrypt`
(`pkcs12.rs:637-667`) returns a bare `None` for all of them:

1. ciphertext that is not a multiple of the block size (`pkcs12.rs:642-644`) — a
   password-independent fact about the container;
2. an IV shorter than the block size (`pkcs12.rs:645-647`) — also password-independent;
3. invalid PKCS#7 padding after decryption (`pkcs12.rs:664-666`) — the only
   password-dependent signal of the three.

The consequences run in both directions:

- **Corrupt containers are reported as wrong passwords.** A truncated or damaged
  container that reaches `cbc_decrypt` misaligned surfaces as `InvalidPassword` — a
  retryable credential signal for input no password can fix.
- **MAC mismatches are reported as wrong passwords even when the password is right.**
  Per RFC 7292 §4 the MAC key is derived from the password and the MAC is computed over
  the authSafe bytes, so any damage to those bytes fails the MAC check at
  `pkcs12.rs:124-128` no matter how correct the supplied password is. `extract_p12`
  returns early on MAC failure, so today no other evidence is ever consulted.

Consumers were re-verified against current source and need **no change**: the CLI decides
retryability with the typed discriminant `matches!(&trial,
Err(zsign_core::Error::InvalidPassword))` (`crates/zsign-cli/src/main.rs:1135`), and wasm
maps the typed variant to `WasmErrorCode::InvalidPassword`
(`crates/zsign-wasm/src/lib.rs:189`, exhaustive delegation at `:140-150`). Neither widens
on message text or parent variants, so any narrowing done inside `pkcs12.rs` propagates to
both front-ends automatically.

## Chosen design

Two changes, both inside `crates/zsign-core/src/crypto/pkcs12.rs`.

### 1. Structural split at the CBC layer

`cbc_decrypt` returns `Result<Vec<u8>, CbcFailure>` instead of `Option<Vec<u8>>`, where the
private `enum CbcFailure { Misaligned, ShortIv, Padding }` carries the cause. Call sites
map the classes:

- `Misaligned` / `ShortIv` → new `P12Error::Corrupt(String)` — password-independent
  structural damage (e.g. `"AES-CBC ciphertext length 14 is not a multiple of the block
  size"`);
- `Padding` → `P12Error::Decrypt(String)` — the password-shaped heuristic, unchanged.

`pbes1_decrypt` (`pkcs12.rs:474-489`) stops taking a pre-built `label: P12Error` and takes
the cipher's display name instead, so it can construct the right variant per cause
(cipher-key construction failure is also structural: the key length comes from algorithm
parameters, not from the password). `aes_decrypt` (`pkcs12.rs:627-634`) keeps its exact
signature — its `pub(crate)` consumer `encrypted_pem.rs` flattens the result with `.ok()`
and is untouched.

`P12Error::Corrupt` joins `pem_load_error`'s `Der` arm and falls through `p12_load_error`'s
existing catch-all, so both land in the established `Error::Certificate(String)` bucket —
the repository has no dedicated corrupt-container variant and does not need one.

### 2. Deferred MAC verdict in `extract_p12`

`extract_p12` (`pkcs12.rs:107-146`) computes the MAC verdict but no longer returns early on
mismatch. It parses the content walk first, then classifies from the combined evidence:

- a `MacState` — `Verified` (macData present, HMAC ok), `Mismatch` (present, bad), or
  `Absent` (macData is optional, RFC 7292 Appendix D);
- the walk's `Result`, tagged by failure class (structural / padding / parse / policy);
- a `corroborated` flag: `decrypt_content_info` (`pkcs12.rs:323`) sets it when an
  `encryptedData` ContentInfo decrypts successfully under the supplied password. In the
  success branch the walk has additionally parsed that plaintext as `SafeContents`, so
  `corroborated == true` means a password-derived key produced structurally valid content.

Classification table (the whole behavioural contract):

| walk outcome        | `Verified`            | `Mismatch`                             | `Absent`                     |
|---------------------|-----------------------|----------------------------------------|------------------------------|
| Ok, corroborated    | `Ok`                  | `Corrupt` (MAC mismatch on intact contents) | `Ok`                   |
| Ok, not corroborated| `Ok`                  | `Mac` (password-transparent container: MAC is the only password signal) | `Ok` |
| Structural (`Corrupt`) | `Corrupt`          | `Corrupt`                              | `Corrupt`                    |
| Padding (`Decrypt`) | `Corrupt` (password proven by MAC) | `Mac` (both signals failed → credential verdict) | `Decrypt` → `InvalidPassword` |
| Parse (`Der`)       | `Der` → `Certificate` | `Mac` (see decision D5)                | `Der` → `Certificate`        |
| Policy (`Unsupported`) | `Certificate`       | `Certificate`                          | `Certificate`                |

Errors raised **before** the walk — the outer authSafe decryption at `pkcs12.rs:122` —
propagate as raised, because `verify_mac` needs those very bytes and cannot pre-judge:
structural damage → `Certificate`, padding failure → `InvalidPassword` (an outer
`encryptedData` authSafe is rare and a wrong password dominates it).

The two translators keep their shape: `Mac | Decrypt(_) => Error::InvalidPassword`, with
`Corrupt` joining `Der`/`Unsupported` on the certificate side. `P12Error::Mac` keeps its
Display text; it now means "the MAC failed *and* this password could not read the
contents", which is exactly the credential verdict.

## Alternatives considered

- **A — structural-only split (rejected as insufficient).** Only split `cbc_decrypt`'s
  `None` and leave `extract_p12`'s early MAC return in place. Fixes the misalignment cell,
  but because the MAC covers the ciphertext, the most common real-world corruption
  (damaged bytes anywhere in the authSafe, or in macData itself) still fails the MAC first
  and is still reported as `InvalidPassword` — the stated problem survives.
- **B — deferred MAC verdict with evidence classification (chosen).** Described above.
  Cost: the content walk now runs even after a MAC mismatch, so a wrong password pays one
  extra PBKDF derivation before failing (the walk aborts at the first encrypted layer).
  Bounded by the file's own iteration count, human-paced in the interactive paths, and
  accepted for correctness.
- **C — new public `Error::Corrupt` variant wired through CLI/wasm (rejected).** Public
  API churn across three crates when `Error::Certificate(String)` is the established
  corruption bucket (e.g. `test_from_p12_invalid_data` already pins it) and the front-ends
  were verified to discriminate narrowly. YAGNI: no consumer needs a new discriminant.
- **Message-text differentiation (rejected).** The repository classifies by typed
  discriminant at every boundary; substring sniffing was deliberately deleted from both
  front-ends in earlier work and must not return.

## Invariants

1. A wrong password on any MAC-carrying fixture — including password-transparent
   containers whose content never exercises the password (raw `keyBag`, unencrypted cert
   bags) — still yields `Error::InvalidPassword`, so the CLI keeps prompting
   (`main.rs:1135`) and wasm keeps emitting `ZSIGN_INVALID_PASSWORD` (`lib.rs:189`).
2. Password-independent damage detected at the decrypt layer — non-block-aligned
   ciphertext, short IV, cipher-rejected key length — yields `Error::Certificate`, never
   `InvalidPassword`, regardless of MAC state. Malformed DER framing yields
   `Certificate` except in the one genuinely ambiguous cell (`Der` × `Mismatch`,
   decision D4), which preserves today's credential verdict.
3. A MAC mismatch on a container whose password-bearing layers decrypted *and parsed*
   intact yields `Error::Certificate`: the password is corroborated, so the container is
   damaged.
4. A MAC-verified container that then fails to decrypt yields `Error::Certificate`: the
   password is proven by the MAC.
5. `macData`-absent containers keep today's heuristic: padding failure is their only
   password signal, so it stays `InvalidPassword`; structural failure stays
   `Certificate`.
6. No public API change: `P12Error` stays `pub(crate)`, the top-level `Error` enum is
   untouched, and `crates/zsign-cli`, `crates/zsign-wasm`, `crates/zsign` need no edits.
7. No zeroize/secrecy/buffer-wiping work, and no message-string matching anywhere.

## Test strategy

All tests are inline `#[cfg(test)]` cases in `crates/zsign-core/src/crypto/pkcs12.rs`,
deterministic, using committed fixtures and fixed byte vectors (no new fixture files):

- **Structural cell:** `aes_decrypt::<Aes128>` with a 15-byte payload (fixed zero key/IV)
  must classify as structural and map through `p12_load_error` to
  `Error::Certificate`, with a companion assertion that a 32-byte zero payload — whose
  fixed decryption ends in byte `0x3a`, so PKCS#7 unpadding fails deterministically —
  maps to `Error::InvalidPassword`. The two assertions pin the split itself.
- **MAC-damage cell:** flip one byte of `MODERN`'s stored MAC digest (located by parsing
  with `DerReader`/`MacData::parse` and pointer offset, not a hardcoded constant) and
  extract with the *correct* password: walk OK + corroborated + `Mismatch` →
  `Error::Certificate`, explicitly not `InvalidPassword`.
- **Credential end-to-end pins:** wrong password on `MODERN` → `Error::InvalidPassword`;
  wrong password on `RAW_KEYBAG` (no password-bearing layer, walk succeeds) →
  `Error::InvalidPassword`. These pin the two `Mac` cells of the table.
- **Regression:** the whole existing suite — including
  `wrong_password_is_rejected_for_every_variant`, `truncated_input_is_rejected`,
  `p12_load_error_maps_password_classes_and_keeps_container_classes`, and the
  `cert.rs`/CLI/wasm suites — runs unmodified.

## Design decisions

- **D1 — the MAC is authoritative but not alone.** MAC pass/fail is combined with what
  the content walk could actually do with the password; neither signal is consulted in
  isolation (RFC 7292 §4 makes the MAC password-derived, so a bare mismatch is
  ambiguous by construction).
- **D2 — corroboration is scoped to ContentInfo-level decryption.** The `corroborated`
  flag is set only where an `encryptedData` layer decrypts under the supplied password;
  in the `Ok` branch that plaintext has also parsed as `SafeContents`. A mistyped
  password would need valid padding *and* a valid `SafeContents` parse on random bytes
  to fake it. Bag-level shrouded-key decryption does not set the flag, so
  password-transparent layouts keep today's credential verdict.
- **D3 — accepted ambiguity: double failure reads as a credential.** MAC mismatch
  *plus* a failed walk (e.g. damaged ciphertext with the correct password) is
  signal-identical to a mistyped password; mistypes are far more frequent, so this cell
  stays `InvalidPassword`. No oracle exists that could separate them.
- **D4 — accepted ambiguity: `Der` + `Mismatch` reads as a credential.** A wrong
  password whose garbage plaintext passes unpadding (~1/256) reaches a parse failure;
  treating that as corruption would misclassify those mistypes. Preserving today's
  behaviour here costs nothing this change demands.
- **D5 — RFC 7292 §3.1 permits differing integrity and privacy passwords; we assume
  they match** (universal in practice). Consequence: after a verified MAC, a subsequent
  decrypt failure is reported as damage (row "Padding × Verified"), not as a password
  complaint.
- **D6 — outer authSafe failures stay un-classified.** `verify_mac` needs the decrypted
  authSafe bytes, so pre-walk failures cannot consult the MAC; the padding heuristic
  (credential by default) remains correct for that rare, wrong-password-dominated path.
- **D7 — `Error::Certificate(String)` remains the corruption bucket.** It is the
  repository's existing malformed-input class, already pinned by tests and mapped by both
  front-ends; adding a variant would be churn without a consumer.

## Scope

- **In:** `crates/zsign-core/src/crypto/pkcs12.rs` — enum, CBC layer, `extract_p12`,
  `decrypt_content_info`, both translators, inline tests.
- **Out (deliberately):** `crates/zsign-cli/src/main.rs` and
  `crates/zsign-wasm/src/lib.rs` (re-verified non-widening, no edit needed);
  `encrypted_pem.rs` (flattens `aes_decrypt` with `.ok()` and documents its own uniform
  padding-or-wrong-password rule); `cert.rs` (`Error::InvalidPassword` producers at
  `:230`/`:246` are the traditional-PEM path, outside this concern); any
  zeroize/secrecy/buffer-wiping work; any new public error variant; any new fixture file.
