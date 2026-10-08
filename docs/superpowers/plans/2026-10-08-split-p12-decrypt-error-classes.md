# Split PKCS#12 Decrypt Error Classes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop reporting damaged PKCS#12 containers as a wrong password by splitting
password-independent damage out of `P12Error::Decrypt` and letting `extract_p12` weigh the
MAC verdict against what the content walk could actually do with the supplied password.

**Architecture:** Two changes in one file (`crates/zsign-core/src/crypto/pkcs12.rs`): the
CBC layer returns a typed `CbcFailure` so structural causes become a new
`P12Error::Corrupt` (certificate class) while invalid padding stays `P12Error::Decrypt`
(password class); `extract_p12` defers the early MAC return and classifies from
`walk outcome × failure class × MacState` per the spec's rule table. The public `Error`
enum, both translators' shape, and every front-end stay untouched.

**Tech Stack:** Rust 2021 / MSRV 1.88, `thiserror`, committed `.p12` fixtures, inline
`#[cfg(test)]` modules.

**Spec:** `docs/superpowers/specs/2026-10-08-split-p12-decrypt-error-classes-design.md` —
the plan argues from the spec; executors read both.

## Global Constraints

- **Only** `crates/zsign-core/src/crypto/pkcs12.rs` may change (plus these docs). No edits
  to `encrypted_pem.rs`, `cert.rs`, `crates/zsign-cli`, `crates/zsign-wasm`,
  `crates/zsign`, or `crates/zsign-core/src/error.rs`.
- Zero-warning gate: `cargo fmt --all -- --check` AND
  `cargo clippy --workspace --all-targets -- -D warnings` — both clean.
- Keep `TMPDIR` inside the repo: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`
  (`/tmp` is a small tmpfs).
- Existing tests run **unmodified** — any edit to an existing assertion is a failure, not
  a fix. New tests: 3 in Task 1, 3 in Task 2.
- No zeroize/secrecy/buffer-wiping work; no new public API; no message-string matching;
  no new fixture files.
- No ticket identifiers in code, comments, docs, commit subjects, or commit bodies.
- Conventional commits: imperative, lowercase, no trailing period. Commit per task;
  **never push**.

## Review Focus

1. **Wrong-password cell must not move.** `wrong_password_is_rejected_for_every_variant`
   asserts `Err(P12Error::Mac)` for all 9 fixtures and must pass byte-unmodified; a wrong
   password now runs the walk before the verdict, so any fixture whose walk could succeed
   on a wrong password would flip this cell. Pinned additionally by Task 2's two
   end-to-end pins.
2. **Password-transparent containers keep the credential verdict.** `RAW_KEYBAG` +
   wrong password: walk succeeds (no encrypted layer) and the `corroborated` flag stays
   `false`, so the result must remain `Error::InvalidPassword`. Pinned by
   `wrong_password_on_a_password_transparent_container_is_invalid_password`.
3. **Structural damage never reads as a credential** — non-block-aligned ciphertext,
   short IV, cipher-rejected key length map to `P12Error::Corrupt` → `Error::Certificate`
   even when the MAC is absent or mismatched. Pinned by Task 1's misalignment test and
   the exhaustive `Match` arms (clippy catches a missed arm).
4. **`aes_decrypt` keeps its exact signature** — `encrypted_pem.rs` flattens it with
   `.ok()`; a signature change would force edits in a file this plan forbids touching.
   Its existing tests must pass unmodified.
5. **The MAC-damage cell is the whole point of Task 2**: one flipped digest byte with the
   correct password must yield `Error::Certificate`, never `InvalidPassword`. Pinned by
   `mac_damage_on_an_otherwise_intact_container_is_not_a_password_failure`.

---

### Task 1: Split structural damage out of the decrypt error

**Files:**
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs` — `P12Error` enum (`:72-83`),
  `Display` (`:85-93`), `decrypt_with_algorithm` pbes1 call sites (`:429-461`),
  `pbes1_decrypt` (`:474-489`), `aes_decrypt` (`:627-634`), `cbc_decrypt` (`:637-667`),
  `pem_load_error` (`:823-834`), `p12_load_error` docs (`:835-845`), inline tests.

**Interfaces:**
- Consumes: existing `cbc_decrypt` call sites (`pbes1_decrypt:488`, `aes_decrypt:633`);
  `pem_load_error` / `p12_load_error` translators; `Error::InvalidPassword` /
  `Error::Certificate(String)`.
- Produces (Task 2 and the translators rely on these exact shapes):
  - `enum P12Error { Der(String), Mac, Decrypt(String), Corrupt(String), Unsupported(String) }`
    (`pub(crate)`, `#[derive(Debug, Clone)]`), with
    `Corrupt` documented `/// Password-independent structural damage to the container.`
    and `Display` arm `P12Error::Corrupt(msg) => write!(f, "corrupt PKCS#12 container: {msg}")`.
  - private `enum CbcFailure { Misaligned, ShortIv, Padding }` beside `cbc_decrypt`;
    `fn cbc_decrypt<C>(cipher: &C, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CbcFailure>`.
  - `fn pbes1_decrypt<C>(password: &[u8], pbe: &PbeParameter<'_>, data: &[u8], key_len: usize, make_cipher: impl FnOnce(&[u8]) -> Option<C>, name: &'static str) -> Result<Vec<u8>>`
    — the last parameter changes from `label: P12Error` to the cipher's display name
    (`"RC2-40"`, `"RC2-128"`, `"3-key Triple-DES"`, `"2-key Triple-DES"` at the four call
    sites).
  - `aes_decrypt` keeps `pub(crate) fn aes_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>>`.

- [ ] **Step 1: Write the failing tests**

Add to `crates/zsign-core/src/crypto/pkcs12.rs` inline tests (beside
`p12_load_error_maps_password_classes_and_keeps_container_classes` `:1422`):

```rust
#[test]
fn misaligned_ciphertext_is_container_damage_not_a_password_failure() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let truncated = vec![0u8; 15];
    let res = p12_load_error(aes_decrypt::<Aes128>(&key, &iv, &truncated).unwrap_err());
    assert!(
        matches!(&res, Error::Certificate(m) if m.contains("Failed to parse PKCS#12")),
        "non-block-aligned ciphertext must keep the certificate class, got {res:?}"
    );
}

#[test]
fn invalid_padding_after_decryption_is_still_a_password_failure() {
    // Fixed vector: AES-128-CBC decrypting 32 zero bytes under a zero key/IV
    // ends in byte 0x3a, so PKCS#7 unpadding fails deterministically.
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let garbage = [0u8; 32];
    let res = p12_load_error(aes_decrypt::<Aes128>(&key, &iv, &garbage).unwrap_err());
    assert!(
        matches!(res, Error::InvalidPassword),
        "an invalid-padding verdict must stay password-shaped, got {res:?}"
    );
}

#[test]
fn structural_damage_keeps_the_certificate_class_on_the_pem_path() {
    let res = pem_load_error(P12Error::Corrupt("ciphertext is not block-aligned".into()));
    assert!(
        matches!(&res, Error::Certificate(m) if m.contains("failed to parse encrypted private key")),
        "structural damage must not become a password failure on the PEM path, got {res:?}"
    );
}
```

- [ ] **Step 2: Run the tests to confirm the state**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- misaligned_ciphertext invalid_padding structural_damage`
Expected: `misaligned_ciphertext…` FAILS (today it maps to `InvalidPassword`),
`invalid_padding…` PASSES (pins existing behaviour), `structural_damage…` FAILS to
compile until `P12Error::Corrupt` exists — both reds are the work of this task.

- [ ] **Step 3: Add `P12Error::Corrupt` and its `Display` arm**

In the enum after `Decrypt(String)` add the variant with its doc comment; in the `Display`
match add `P12Error::Corrupt(msg) => write!(f, "corrupt PKCS#12 container: {msg}")`.
`p12_load_error`'s catch-all (`:843`) picks it up automatically; update both translators'
doc comments to state the rule: password-shaped outcomes are `Mac` and `Decrypt`
(padding), while `Corrupt`, `Der` and `Unsupported` keep the certificate class.

- [ ] **Step 4: Split `cbc_decrypt`'s `None` into `CbcFailure`**

Replace the three `return None` sites with their causes:

- `:642-644` (zero/short/non-multiple length) → `Err(CbcFailure::Misaligned)`
- `:645-647` (`iv.len() < block_size`) → `Err(CbcFailure::ShortIv)`
- `:664-666` (unpad failure) → `Err(CbcFailure::Padding)`
- success path returns `Ok(out)`.

- [ ] **Step 5: Map causes at both call sites**

`aes_decrypt`:

```rust
let cipher = C::new_from_slice(key)
    .map_err(|_| P12Error::Corrupt(format!("invalid AES key length {}", key.len())))?;
cbc_decrypt(&cipher, iv, data).map_err(|failure| match failure {
    CbcFailure::Padding => P12Error::Decrypt("AES-CBC".into()),
    CbcFailure::Misaligned => P12Error::Corrupt(format!(
        "AES-CBC ciphertext length {} is not a multiple of the block size",
        data.len()
    )),
    CbcFailure::ShortIv => P12Error::Corrupt(format!(
        "AES-CBC IV of {} bytes is shorter than the block size",
        iv.len()
    )),
})
```

`pbes1_decrypt`: change the `label: P12Error` parameter to `name: &'static str`;
`make_cipher(&key)` failure becomes
`P12Error::Corrupt(format!("{name} key length {key_len} rejected by the cipher"))`;
the `cbc_decrypt` result maps exactly as `aes_decrypt` does but with `{name}` in the two
structural messages and `P12Error::Decrypt(name.to_string())` for `Padding`. Update the
four call sites (`:430`, `:440`, `:450`, `:460`) to pass the bare name string.

- [ ] **Step 6: Join `Corrupt` to `pem_load_error`'s `Der` arm**

```rust
P12Error::Der(msg) | P12Error::Corrupt(msg) => {
    Error::Certificate(format!("failed to parse encrypted private key: {msg}"))
}
```

- [ ] **Step 7: Run the new tests**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- misaligned_ciphertext invalid_padding structural_damage`
Expected: 3 passed.

- [ ] **Step 8: Run the crate's full test suite**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all pass, no existing test edited. In particular
`p12_load_error_maps_password_classes_and_keeps_container_classes`,
`wrong_password_is_rejected_for_every_variant`, and every
`encrypted_pem` test pass unmodified.

- [ ] **Step 9: Scoped gates and commit**

Run: `cargo fmt --all -- --check` (clean) and
`cargo clippy -p zsign-core --all-targets -- -D warnings` (clean).

Commit: `fix(crypto): split structural damage out of the pkcs12 decrypt error`

---

### Task 2: Weigh the MAC verdict against the content walk

**Files:**
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs` — `extract_p12` (`:107-146`),
  `decrypt_content_info` (`:323-336`), `P12Error::Mac` doc (`:76-77`), inline tests.

**Interfaces:**
- Consumes (from Task 1): `P12Error::Corrupt(String)`, the split `CbcFailure` mapping,
  unchanged translators; `MacData::parse`, `verify_mac`, `DerReader`, fixtures `MODERN`
  (`:947`) and `RAW_KEYBAG` (`:1340`).
- Produces:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] enum MacState { Verified, Mismatch, Absent }`
    (private, beside `extract_p12`);
  - `fn decrypt_content_info(ci_der: &[u8], password: &str, corroborated: &mut bool) -> Result<Vec<u8>>`
    — same body, except the `ENCRYPTED_DATA` branch sets `*corroborated = true` only
    after `decrypt_encrypted_data(...)` returns `Ok`;
  - `fn walk_authenticated_safe(auth_contents: &[u8], password: &str, corroborated: bool) -> Result<(P12Contents, bool)>`
    — the current `AuthenticatedSafe` loop (`:131-143`) moved verbatim into a helper that
    returns the collected contents plus the flag;
  - `extract_p12` keeps its signature `fn extract_p12(data: &[u8], password: &str) -> Result<P12Contents>`
    (cert.rs callers unchanged).

- [ ] **Step 1: Write the tests**

Add to `crates/zsign-core/src/crypto/pkcs12.rs` inline tests:

```rust
#[test]
fn mac_damage_on_an_otherwise_intact_container_is_not_a_password_failure() {
    // Locate the stored MAC digest by parsing, then flip one byte of it:
    // the password is right, only the integrity field is damaged.
    let mut outer = DerReader::new(MODERN);
    let pfx = outer.read_sequence().expect("fixture is a PFX SEQUENCE");
    let mut reader = DerReader::new(pfx);
    reader.read_integer_u32().expect("version");
    reader.read_sequence().expect("authSafe");
    let mac = MacData::parse(&mut reader).expect("fixture carries macData");
    let offset = mac.digest.as_ptr() as usize - MODERN.as_ptr() as usize;
    let mut damaged = MODERN.to_vec();
    damaged[offset] ^= 0xff;

    let res = p12_load_error(extract_p12(&damaged, "testpassword").unwrap_err());
    assert!(
        matches!(&res, Error::Certificate(m) if m.contains("Failed to parse PKCS#12")),
        "a damaged MAC over intact contents must keep the certificate class, got {res:?}"
    );
}

#[test]
fn wrong_password_on_an_encrypted_container_is_invalid_password() {
    let res = p12_load_error(extract_p12(MODERN, "wrong").unwrap_err());
    assert!(
        matches!(res, Error::InvalidPassword),
        "a wrong password must stay retryable, got {res:?}"
    );
}

#[test]
fn wrong_password_on_a_password_transparent_container_is_invalid_password() {
    // raw_keybag has no encrypted layer: the walk succeeds for any password,
    // so the MAC is the only password signal and must decide alone.
    let res = p12_load_error(extract_p12(RAW_KEYBAG, "wrong").unwrap_err());
    assert!(
        matches!(res, Error::InvalidPassword),
        "a password-transparent container must keep the credential verdict, got {res:?}"
    );
}
```

- [ ] **Step 2: Run the tests to confirm the state**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- mac_damage wrong_password_on`
Expected: `mac_damage…` FAILS (today the early MAC return reports
`InvalidPassword`); the two `wrong_password_on…` tests PASS today and must keep passing —
they are the regression pins for this task.

- [ ] **Step 3: Add `MacState` and thread the corroboration flag**

Add the private `MacState` enum beside `extract_p12`. Change `decrypt_content_info`'s
signature to take `corroborated: &mut bool` and set it to `true` immediately after
`decrypt_encrypted_data(ci.inner, password)?` succeeds (never in the plain `data` branch).
Both call sites live in this file.

- [ ] **Step 4: Move the walk into `walk_authenticated_safe`**

Cut the `AuthenticatedSafe` parsing loop (`:131-143`, from `let mut contents =
DerReader::new(&auth_contents);` through the `while` loop) into the helper, taking
`corroborated: bool` and returning `Result<(P12Contents, bool)>` with the flag. The
helper body is otherwise byte-identical; `collect_bags` is untouched.

- [ ] **Step 5: Replace the early MAC return with the classification**

New `extract_p12` tail after parsing `mac_data`:

```rust
let mut corroborated = false;
let auth_contents = decrypt_content_info(auth_safe, password, &mut corroborated)?;

// The MAC verdict alone cannot separate a mistyped password from a damaged
// container (RFC 7292 derives the MAC key from the password), so decide
// together with what this password could actually read: the spec's rule
// table lives above this function.
let mac_state = match &mac_data {
    Some(mac) => {
        if verify_mac(mac, &auth_contents, password)? {
            MacState::Verified
        } else {
            MacState::Mismatch
        }
    }
    None => MacState::Absent,
};

match walk_authenticated_safe(&auth_contents, password, corroborated) {
    Ok((_, true)) if mac_state == MacState::Mismatch => Err(P12Error::Corrupt(
        "MAC mismatch on contents that decrypted and parsed intact".into(),
    )),
    Ok((contents, _)) => Ok(contents),
    Err(e) => match e {
        P12Error::Decrypt(_) | P12Error::Der(_) if mac_state == MacState::Mismatch => {
            Err(P12Error::Mac)
        }
        P12Error::Decrypt(_) if mac_state == MacState::Verified => Err(P12Error::Corrupt(
            "decryption failed after the MAC verified".into(),
        )),
        other => Err(other),
    },
}
```

Update the `P12Error::Mac` doc comment to its new meaning: `/// The MAC failed and this
password could not read the contents — a passphrase outcome.` Delete the now-dead early
`return Err(P12Error::Mac)` block.

- [ ] **Step 6: Run the new tests**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- mac_damage wrong_password_on`
Expected: 3 passed.

- [ ] **Step 7: Run the crate's full test suite**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all pass with zero edits to existing tests — especially
`wrong_password_is_rejected_for_every_variant`, `wrong_password_is_rejected_for_both_schemes`,
`truncated_input_is_rejected`, `extract_p12_reads_raw_keybag_fixture`,
`p12_load_error_maps_password_classes_and_keeps_container_classes`, and the
`cert.rs` `from_p12` wrong-password tests.

- [ ] **Step 8: Scoped gates and commit**

Run: `cargo fmt --all -- --check` (clean) and
`cargo clippy -p zsign-core --all-targets -- -D warnings` (clean).

Commit: `fix(crypto): weigh the pkcs12 mac against the content walk`

---

### Task 3: Full verification pass

**Files:** none (verification only; code edits only if a gate fails, in which case fix
and re-run before committing).

- [ ] **Step 1: Formatting gate**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0.

- [ ] **Step 2: Workspace lint gate**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings, exit 0.

- [ ] **Step 3: Affected-crate tests plus front-end consumers**

Run:
`TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
`TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
`TMPDIR=$PWD/target/tmp cargo test -p zsign-cli`
Expected: all pass; no existing test edited anywhere
(`git status --short` shows only `crates/zsign-core/src/crypto/pkcs12.rs` and the two
docs under `docs/superpowers/`).

- [ ] **Step 4: The land gate**

Run: `hk check --all`
Expected: hygiene, fmt, actionlint, clippy, and `cargo test --workspace` all green.
Paste its verbatim output into the final report. If a step fails: fix, re-run from
Step 1, and only commit the fix together with a clear conventional subject.

No commit from this task unless a gate forced a fix.
