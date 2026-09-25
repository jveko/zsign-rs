# ZSN-38 Canonical DER Entitlements + Apple Ground Truth — Design

**Date:** 2026-09-25
**Lane:** zsn38-der (base main @ c9ff0fb)
**Scope (authoritative brief):** `crates/zsign-core/src/codesign/der.rs` + inline
tests, `scripts/verify-apple-interop.sh`, and exactly these two force-added docs.
No other file may be edited; deferred lanes are listed at the end.

## Evidence base

All claims below were verified in-worktree (file:line at c9ff0fb) or against
primary external sources during the phase-2 research wave:

- **ScoutCitations** — re-anchored every der.rs / script / .gitignore citation.
- **ScoutEmitPath** — full emit path: `plist_to_der` has exactly one production
  caller (`macho/signer.rs:88`, gated `is_executable && entitlements.is_some()`);
  slots 5+7 both written (`signer.rs:83`, `:85-92`); `codesign/verify.rs` has NO
  XML/DER equivalence check today (only `SHA256(slot-7 blob) == CD slot -7` hash
  self-consistency, `verify.rs:526-580`) — ZSN-25's equivalence consumer does not
  exist yet, so no landed verifier can flip from these changes.
- **ScoutFixtures** — golden bytes in this repo are inline `assert_eq!(…, vec![0x..])`
  in `#[cfg(test)] mod tests`; no `testdata/`/`tests/` dirs exist; binary fixtures
  are checked in only under `src/**/fixtures/` and loaded with `include_bytes!`;
  docs precedent: 12 tracked `docs/superpowers/{specs,plans}` files, all force-added
  (`.gitignore:34` `docs/`), commit style `docs(<area>): … (ZSN-nn)`.
- **LibrarianDerSchema** — external contracts: envelope `[APPLICATION 16] 0x70`
  confirmed from Apple XNU `CoreEntitlementsPriv.h` (`CCDER_ENTITLEMENTS =
  CCDER_SEQUENCE|CCDER_CONSTRUCTED|CCDER_APPLICATION`); pair structure
  `SEQUENCE { UTF8String key, value }` from Apple `Serialization.h`; nested dict
  `[16] 0xb0` corroborated by upstream zsign PR #391 canonical-format text and
  `signing.cpp` (0x31 = legacy pre-canonical); Data `0x04` corroborated by ldid
  (`der(0x04, …)`) + Apple `kCESerializedData`; **Date: UNVERIFIED in Apple
  sources** (no Date in Apple's serialization enum; upstream zsign and ldid both
  reject plist dates); Real rejected by both (stays unsupported); SET OF ordering
  rule quoted verbatim from X.690 §11.6; Apple's own generator comparator is
  UNVERIFIED from Apple source.
- **LibrarianTooling** — `codesign --generate-entitlement-der` is a signing-time
  option (macOS 10.14+, default since 12) that converts the XML passed via
  `--entitlements` and embeds XML+DER; slot-7 blob = generic
  `FADE7172 || be32(total_len) || DER`; modern display syntax is
  `codesign -d --entitlements -` with `--xml` / `--der` selectors (the colon
  prefix `:-` is deprecated legacy); extraction recipe (SuperBlob index types
  `0x0005`/`0x0007`, magics `FADE7171`/`FADE7172`); plist 1.10.1 semantics
  (registry source on disk): `Integer { value: i128 }`, `as_signed() =
  i64::try_from` → `None` for values > i64::MAX, XML parse tries i64 then u64;
  `Dictionary` is IndexMap-backed (insertion = XML document order);
  `Value::Date` wraps `SystemTime`, `Date -> SystemTime` conversion works,
  `to_xml_format()` returns RFC 3339 with trailing fraction zeros trimmed;
  GeneralizedTime rule = X.690 §11.7 (`YYYYMMDDHHMMSSZ`, seconds mandatory,
  terminal `Z`, nonzero fractions allowed with trailing zeros stripped).
- **Local observation (temporary test, run then reverted):** current encoder
  output at c9ff0fb — `-1` → `02 09 00 ff…ff` (9 content bytes; first octet
  `0x00` ⇒ decodes as a *positive* value), `-128` → `02 09 00 ff…80`,
  `-9223372036854775808` → `02 09 00 80 00…00`, `18446744073709551615` →
  `02 01 00` (silent zero), `0`/`128` correct; `Date -> SystemTime` works
  (`1981-05-16T11:32:06Z` → `tv_sec 358860726`), `to_xml_format` on fractional
  input → `1981-05-16T11:32:06.5Z`.

## Brief-claim corrections found during research

| Brief claim | Verdict at c9ff0fb |
|---|---|
| der.rs:16 promises lexicographic ordering | CONFIRMED as a doc claim (`der.rs:16-19`) but FALSE vs behavior — no sort anywhere; both loops emit document order (`der.rs:152`, `:241`) |
| V1 schema doc at der.rs:148-180 | REFUTED — that range is the live `Dictionary`/`Data`/`Date` match arms; the schema text lives at `der.rs:8-14` |
| Root dict iterates insertion order (der.rs:237-250) | PARTIAL — guard `:237-239`, loop `:240-256` |
| 11 existing der tests | REFUTED — 12 unit tests (`der.rs:291-411`) + 2 doctests |
| in-range negative integers are encoded correctly | REFUTED by direct observation (see evidence base; details + open question below) |
| `codesign -d --entitlements :-` | modern spelling is `--entitlements -` + `--xml`/`--der`; `:-` is deprecated (decision below) |

## Decisions per scope-queue item (brainstorm: candidates → choice)

### Item 1 — nested-dictionary tag

Candidates considered:
- **A (chosen):** emit `0xb0` for *every* dictionary value in `encode_value`, i.e.
  the same tag the root envelope already uses at `der.rs:264`; keep no `0x31`
  path at all. The single remaining `0x31` use is `DER_TAG_SET` (`der.rs:55-56`,
  pushed only at `:172`) — delete the constant with its doc comment.
- B: keep a V0 flag/mode that emits `0x31` when requested. Rejected: nothing in
  the workspace consumes a V0 encoding (single caller `macho/signer.rs:88`;
  the verify side never decodes slot-7 content), a mode no caller can reach is
  dead code, and repo rules prohibit dead code and second conventions.
- C: emit `0xb0` only for dictionaries directly under an entitlement key and
  `0x31` deeper down. Rejected: no source distinguishes nesting depth; both
  Apple-evidence (upstream zsign emits `0xb0` for *every* dict) and the module's
  own canonical-format claim contradict a depth rule.

**Decision:** option A. Recorded per the brief's "keep SET only for an explicitly
supported V0 path" instruction: **there is no supported V0 path, so SET is
removed entirely**; the evidence that `0x31` is the legacy pre-canonical form is
zsign PR #391 ("The canonical format … entries [CONTEXT 16] (0xb0) IMPLICIT SET
OF Entitlement").

### Item 2 — Data and Date value types

Candidates considered:
- **A (chosen):** implement both with standard universal tags — Data → `0x04`
  OCTET STRING (length + raw bytes), Date → `0x18` GeneralizedTime. Date
  conversion: `plist::Date -> SystemTime` (verified working locally), then
  civil-date arithmetic (inverse of days-from-civil on epoch-seconds computed
  with `div_euclid`), formatted `YYYYMMDDHHMMSSZ`; if nanoseconds are nonzero
  append `.` + 9 fractional digits with trailing zeros stripped (X.690 §11.7.3
  canonical form); year outside 0..=9999 → `Error::DerEncoding` carrying the
  epoch-seconds value (explicit error channel). The message must NOT format the
  `Date` with `Debug`: `Date`'s `Debug` calls `to_xml_format()`, which itself
  `expect()`s/`unwrap()`s (`plist-1.10.1/src/date.rs:39-44,89-91`), so the
  numeric epoch value is used instead — that keeps the whole path
  panic-free. Real stays rejected (unchanged).
- B: format via `Date::to_xml_format()` string surgery (strip `-`, `:`, `T`).
  Rejected: `to_xml_format` internally `expect()`s a representable
  `UtcDateTime` and `unwrap()`s the RFC 3339 format
  (`plist-1.10.1/src/date.rs:39-44`) — an out-of-range binary-plist date could
  panic inside the formatter before we can validate anything; option A derives
  the calendar fields arithmetically and returns a typed error instead.
- C: keep rejecting Data/Date. Rejected: directly contradicts the brief's item 2
  (Data evidence is strong: Apple `kCESerializedData` + ldid `0x04`).

**Decision:** option A. **Evidence caveat (recorded, not a scope change):**
Apple's public serialization enum contains no Date, and upstream zsign
(`assert(false)`) and ldid (`exit(1)`) both reject plist dates; the brief
nevertheless mandates Date support, and GeneralizedTime `0x18` is the only sane
DER mapping (X.690 §11.7). Consequence: the macOS cross-check script step covers
Data but deliberately not Date ("where possible" in the brief) because no Apple
reference output exists to compare against; local golden vectors pin Date. Real
stays rejected (Apple type set has no Real; both reference implementations
reject it).

### Item 3 — canonical SET ordering

Candidates considered:
- **A (chosen):** encode every `SEQUENCE {key,value}` member fully, then sort
  the member TLVs by raw byte comparison (plain `Ord` on byte slices) and
  concatenate. Basis verified: X.690 §11.6 — "The encodings of the component
  values of a set-of value shall appear in ascending order, the encodings being
  compared as octet strings with the shorter components being padded at their
  trailing end with 0-octets. NOTE - The padding octets are for comparison
  purposes only"; "encoding" = complete TLV octets (X.690 §3.6). For distinct
  well-formed DER encodings the virtual-zero padding is equivalent to plain
  lexicographic comparison (a byte-prefix member is always lower), which is what
  Go's `encoding/asn1` does (`slices.SortFunc(…, bytes.Compare)`) and what ldid
  does (`std::multiset<std::string>` of member encodings).
- B: sort keys as strings first (what upstream zsign does:
  `std::sort(arrKeys…)`), then encode. Rejected: demonstrably not equivalent —
  for keys `b`/`aa` with equal values, pair lengths are 6 vs 7, so DER order is
  `b, aa` (length octet compared first) while key order is `aa, b`; X.690 §11.6
  normatively requires the encoded-bytes order, so key-sort can emit
  non-canonical output.
- C: rely on `Dictionary::sort_keys()` (str order) before encoding. Rejected for
  the same reason as B — str order over keys is not member-TLV order, and the
  crate documents the backing store as changeable.

**Decision:** option A, implemented once in a shared dictionary-encoding helper
used by both `plist_to_der` (root) and `encode_value` (nested) — this also
removes the duplicated pair-building logic between `der.rs:240-256` and
`:149-171`. Module doc `der.rs:16-19` and the comment at `:235-236` are rewritten
to state the real rule (members sorted by complete encoded bytes, X.690 §11.6) —
the current text ("Keys are sorted lexicographically") is exact only for
equal-length pairs, so it is replaced rather than left.
**Known divergence recorded:** upstream zsign (the empirically Apple-validated
implementation) key-sorts, and Apple's own comparator is UNVERIFIED from Apple
source; if the macOS CI cross-check (the new entitlements round-trip step in
the script) shows Apple's
`--generate-entitlement-der` orders differently from X.690 §11.6, that is a
genuine finding for the orchestrator, and the one-line revert point is the
comparison in the shared helper.

### Item 4 — golden vectors and the integer edge

Candidates for the out-of-i64 integer edge (`as_signed().unwrap_or(0)` at
`der.rs:99` silently encodes `0`; verified: `18446744073709551615` →
`02 01 00`):
- **A (chosen):** error explicitly — `as_signed() -> None` returns
  `Error::DerEncoding` naming the value (plist `Integer` implements `Display`
  over its i128 storage). Fails loudly, matches the module's existing
  unsupported-type error style, and plist 1.10.1 really does parse u64-range
  XML integers (i64-first, then u64), so the path is reachable.
- B: document and test the truncation (sanctioned alternative). Rejected:
  enshrines silent data corruption as contract; a `u64`-range entitlement
  integer would sign as `0` with no error anywhere in the pipeline.
- C: encode u64-range values as positive 9-byte INTEGERs. Rejected: not among
  the brief's sanctioned options, and Apple's converter behavior for values
  beyond `CFNumber`'s i64 range is unverifiable (no ground truth); fail-closed
  is the honest choice.

Golden-vector coverage is distributed to the item that owns each behavior, so
every vector listed in the brief exists exactly once (mapping in the plan):
multi-key ordering vector ships with item 3, nested-dict vector with item 1,
Data/Date vectors with item 2, and item 4's own series adds the remaining
vectors (array values, >127-byte long-form lengths) plus the out-of-i64 error
test. All vectors are inline byte literals in `der.rs` tests (repo convention —
no `testdata/` exists). The macOS cross-check against
`codesign --generate-entitlement-der` is a documented script step (item 5),
never a local test.

**Open question for the supervisor (integer negatives — the one sub-thread
stopped per brief protocol):** the brief states the retracted finding about
in-range negatives was correct ("plist two's-complement + sign pad is CORRECT,
do not 'fix' that"). Direct observation at c9ff0fb refutes this: `-1` encodes
as `02 09 00 ff ff ff ff ff ff ff ff`, whose first content octet `0x00` marks
it *positive*, so any DER parser decodes `+18446744073709551615`, not `-1`
(X.690 §8.3.2 requires `02 01 ff`); `-128` → `02 09 00 ff…80` (should be
`02 01 80`); `i64::MIN` → `02 09 00 80 00…00` (should be `02 08 80 00…00`).
Options:
- **A (brief-literal default if unanswered):** leave the negative path
  untouched, add no golden vector pinning negative-integer output, record this
  finding here and in the final report. Nothing in the queue depends on it.
- **B (requires brief deviation approval):** fix negative encoding to X.690
  minimal two's complement (trim redundant leading `0xFF` octets while the
  following octet's MSB is set) and add golden vectors `-1 → 02 01 ff`,
  `-128 → 02 01 80`, `-129 → 02 02 ff 7f`, `i64::MIN → 02 08 80 00…00`.
  **Ruled option B by the supervisor and applied** (empirical bytes outrank
  the argument-only retraction): the `else if val >> 63 == 1` branch plus
  `test_encode_integer_negative_minimal` landed; the positive/zero path is
  untouched and still pinned by every pre-existing vector.

### Item 5 — interop ground truth + ZSN-23 handover

Candidates for the certificate handover:
- **A (chosen):** flip the existing single self-signed certificate to an
  end-entity constraint: `basicConstraints=critical,CA:FALSE`, keeping
  `keyUsage=digitalSignature` + `extendedKeyUsage=codeSigning` — exactly the
  post-ZSN-23 leaf shape (codeSigning EKU, digitalSignature KU, CA=false).
  Update both comment blocks (header `:11-12`, section 1 `:51-55`) that
  currently justify `CA:TRUE`.
- B: build a two-cert mini-CA (root `CA:TRUE` + leaf) and export the leaf.
  Rejected: the brief mandates flipping *the script's certificate* to an
  end-entity constraint; a chain introduces profile/trust-path variables the
  brief did not ask for, and macOS acceptance of either shape is only
  observable on the CI runner anyway.

**Decision:** option A (the brief's canonical ZSN-23 fix). **Assumption +
fallback recorded (advisor finding):** the flip contradicts the script's own
former rationale that `CA:TRUE` is what makes the certificate pass
SecTrustEvaluate's code-signing policy, so the design *assumes* a self-signed
end-entity still passes macOS `codesign --verify --deep --strict` (designated
requirement match against its own implicit anchor). `bash -n` cannot validate
trust behavior; the assumption is observable only on the macOS runner
(ZSN-31's job). **Defined fallback if CI rejects:** export the certificate
into a temporary keychain and trust it there
(`security add-trusted-cert -d -r trustRoot -k "$WORK/cs.keychain"` plus
`security set-key-partition-list`/search-list wiring) so SecTrust has an
anchor — a script-local change touching no repo code. Note the deeper
cold-review finding below: `zsign -V` cannot accept this certificate
regardless of the CA bit, which is why the agreement section changes.

Candidates for the entitlements round-trip step:
- **A (chosen):** synthesize a fixture profile in `$WORK` (XML plist with an
  `Entitlements` dict — `extract_entitlements_from_profile` at
  `provisioning.rs:12-42` only needs the `<?xml ` … `</plist>` window), sign a
  third bundle with `-m/--profile` (CLI has `-m` at `main.rs:36-37`; no `-e`
  exists — that is deferred ZSN-10), then assert:
  1. `codesign -d --entitlements - --xml` parses to a dict equal to the
     fixture's `Entitlements` dict (semantic round-trip through Apple's DER
     decoder — order-insensitive);
  2. our slot-7 payload (SuperBlob index `0x0007`, magic `FADE7172`) equals
     byte-for-byte the slot-7 payload that
     `codesign --force -s - --entitlements <same xml> --generate-entitlement-der`
     writes on an unsigned copy of the same binary (generator cross-check —
     this is the documented `codesign --generate-entitlement-der` golden-vector
     cross-check the brief asks for);
  3. `codesign -d --entitlements - --der` equals our slot-7 payload (display
     path byte agreement).
  There is deliberately **no `zsign -V` assertion** in this step: CLI
  verification (`main.rs:180-190` → `verify_code_signature`) anchors only to
  the embedded Apple Root (`cms_verify.rs:275-287,328-343`); a self-signed
  chain is accepted solely when its SPKI is in that anchor set
  (`cms_verify.rs:1113-1150`), otherwise the report carries "certificate
  chain is not anchored to a trusted root" (`cms_verify.rs:858-860`). The
  script's self-signed certificate can therefore never satisfy `zsign -V`, and
  injecting custom anchors needs an out-of-scope CLI interface. **Supervisor
  ruling from ZSN-25 (option b, applied):** the *pre-existing* section-7
  `agree_valid "cert-signed bundle"` assertion is rewritten to a DUAL-PIN
  instead of being deleted — `codesign --verify` stays green on the
  self-signed bundle (step 3 asserts it), while `zsign -V` must report (i)
  structural validity and (ii) the expected anchoring failure, never
  `verified: yes`. Grounding: a local probe of the landed CLI showed the
  bundle surface emits `verified: no`, `arm64: pages ok, CMS INVALID`,
  `code resources: ok` but NO error text (print_bundle keeps per-binary CMS
  errors internal), while `-V` on the detached main binary emits
  `error: certificate chain is not anchored to a trusted root`,
  `signer: CN=zsign interop CI`, `cms: INVALID (chain: CN=zsign interop CI,
  anchor: false)` (exit 2; bundle exits 1). Section 8a pins both surfaces and
  appends both outputs to `$DIAG`; the ad-hoc/`/bin/ls`/tamper `agree_valid`
  lines are unchanged. A *positive* `verified: yes` for self-signed bundles
  remains impossible under the default anchors and would need a
  custom-anchor CLI path (CLI/ZSN-10 territory).
  The brief's `--entitlements :-` spelling is modernized to `--entitlements -`
  + `--xml`/`--der` per the current man page (colon prefix deprecated; Quinn,
  Apple Developer Forums thread 729855) — intent unchanged, one decision
  recorded here.
- B: embed a checked-in `.mobileprovision` fixture file. Rejected: no
  mobileprovision fixture convention exists in the repo, the extractor does not
  validate CMS, and a heredoc in the script keeps the fixture next to the
  assertions that use it.

**Decision:** option A. Fixture contents: multi-key entitlements with *mixed*
key and value lengths (exercises the encoded-bytes ordering question against
Apple's generator — a mismatch is a real finding, not a script bug), a nested
dict, an array (`application-groups`), and a `<data>` value; **no `<date>`**
(no Apple ground truth, see item 2). All ZSN-31 diagnostics writes are
preserved verbatim (`:30-36`, `:43-47`, `:135` content) and the new step
appends its outputs to `$DIAG` in the same style. Insertion renumbers the
following step headers (5→6, 6→7, 7→8 with `7a-7d` → `8a-8d`; section 8a's
cert-signed `agree_valid` line is removed per the finding above, leaving the
ad-hoc bundle); no diagnostic content is removed.

## Impact analysis (verified in-worktree)

- **Callers:** one production caller (`macho/signer.rs:88`) — signature
  unchanged (`fn plist_to_der(&[u8]) -> Result<Vec<u8>>`); no caller migration
  needed. Slot 5 (XML) and slot 7 (DER) are both written for executables;
  nothing writes 7 without 5 (`signer.rs:83-92`, `superblob.rs:661-669`).
- **Landed tests that can flip:** exactly one —
  `codesign::der::tests::test_plist_to_der_unsupported_data_type`
  (`der.rs:373-384`) asserts `Err` for `<data>AQID</data>`, which item 2 makes
  valid. **Conscious adjustment:** re-point the input to `<real>1.5</real>`
  (Real stays rejected) and rename to `test_plist_to_der_unsupported_real_type`
  so rejection-path coverage is preserved; reported per the brief's exception.
  Everything else encoding-sensitive is inside `der.rs` itself (envelope pins
  `:352`, `:369`; primitive pins `:307-332`, `:386-411`) and stays green: no
  existing test uses a nested dict, more than one key, Data/Date, or a
  u64-range integer. `codesign/verify.rs`, `code_directory.rs`,
  `superblob.rs`, `macho/verify.rs`, `ipa/mod.rs` tests use opaque payloads or
  `entitlements=None` and are provably content-insensitive (ScoutEmitPath
  inventory).
- **Behavior change beyond the tests:** for any real profile whose
  `Entitlements` dict is not already in encoded-member order, slot-7 bytes
  change (today `provisioning.rs:38` re-serializes in document order). This is
  the point of item 3; determinism is preserved (sort is total), so
  `test_ipa_signing_is_deterministic` is unaffected (it never builds DER
  anyway).
- **Gate:** `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core
  der -- --skip test_ipa_signing_is_deterministic` (the brief's command; the
  loose `der` filter matches 26 unit tests — the 12 `codesign::der` tests plus
  14 incidental `der`-substring matches across `code_directory`/`superblob`/
  `verify`/`pkcs12` tests). Baseline measured at c9ff0fb: 26 passed, 0 failed.
  The filtered command reports no doctest section; doctests are verified
  separately via `cargo test -p zsign-core --doc` (26 passed at base).
  `cargo fmt`/`clippy`/`hk` are NOT run mid-flight (orchestrator gates at
  merge); the pre-commit hook runs automatically on each commit.

## Known items for the orchestrator (out of lane scope or recorded risks)

1. **Negative-integer encoding was wrong at c9ff0fb** (observation above);
   RESOLVED this lane under the supervisor's option-B ruling: minimal two's
   complement fix + four golden vectors (`test_encode_integer_negative_minimal`),
   non-negative encoding unchanged (36-test scoped gate + 26 doctests green).
2. **`codesign/superblob.rs:246-251` doctest** uses `vec![0x31, 0x00]; //
   minimal empty SET` — stale pre-canonical illustration. Doc-only (cannot
   fail), and superblob.rs is not in this lane's scope; reported, not edited.
3. **Apple's generator comparator is unverified.** The script's byte
   cross-check (section 5, assertion 2) is the empirical answer; mixed-length
   keys in the fixture are deliberate so a divergence is actually observable.
4. **Date has no Apple-side evidence** (see item 2) — implemented per brief
   directive; excluded from the script cross-check.
5. **ZSN-25's XML/DER equivalence check does not exist yet** (ScoutEmitPath):
   its future consumer should call the same shared dictionary-encoding helper
   semantics described here; nothing to migrate today.
6. **Brief line anchors superseded:** schema text is `der.rs:8-14`, root loop
   `:240-256`, 12 unit tests not 11 (see corrections table).
7. **`zsign -V` can never report `verified: yes` for self-signed certificates
   under the default anchor policy** (`verify_code_signature` → Apple Root
   only, `cms_verify.rs:275-287`; self-signed accepted only via SPKI match
   `cms_verify.rs:1113-1150`). Supervisor ruling (ZSN-25, option b) applied:
   the interop script's cert-signed `zsign -V` assertion is now a dual-pin on
   BOTH surfaces — bundle (structural: `verified: no`, `pages ok`,
   `CMS INVALID`, `code resources: ok`, no mismatch) and detached main binary
   (anchoring failure text, `signer:`, `anchor: false`) — with both outputs
   logged to `$DIAG`. Positive agreement for cert-signed bundles stays out of
   scope (custom-anchor CLI path deferred to the CLI/verify lanes).

## Supervisor scope additions (ZSN-25 rulings, recorded)

1. **Dual-pin interop assertion (applied):** see item 5's assertion list and
   known item 7 — the script's section 8a pins the bundle-structural surface
   and the detached-main-binary anchoring surface, grounded by local CLI probe
   outputs; ZSN-31 diagnostics untouched (both probe outputs are appended to
   `$DIAG`), `codesign --verify` stays green via step 3.
2. **DER doc accuracy (verified landed):** the module doc no longer claims
   key-lexicographic sorting (it states the X.690 clause 11.6 encoded-bytes
   rule, landed with the ordering task); `encode_value`'s doc list documents
   the Data/Date mappings; `plist_to_der`'s `# Errors` list names only Real
   plus the integer/date range errors; the Real-policy decision (keep
   rejecting — Apple's serialized type set has no Real and both reference
   implementations reject it) is recorded in item 2 above. A grep for
   `Keys are sorted|lexicograph` in der.rs returns no stale claims.

## Deferred lanes (untouched by this design)

`codesign/code_directory.rs` (ZSN-29), `codesign/verify.rs` +
`constants.rs` (ZSN-25), `macho/signer.rs` slot-7 wiring (ZSN-33/34 — this
design needs no signer change: `plist_to_der`'s signature and error type are
unchanged), CLI `-e` (ZSN-10/35), `crypto/**` (ZSN-3/37), `.github/**`
(ZSN-31), root `.gitignore` (lane collision — force-add only).
