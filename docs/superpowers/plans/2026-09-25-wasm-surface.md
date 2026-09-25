# ZSN-40 WASM Signing Surface Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task = one Tester-red → implementer-green → gate → commit cycle, in order.

**Goal:** Harden `crates/zsign-wasm/src/lib.rs` (SHA-256-only default, entitlements setter, size guards, chunk state machine, stable error codes) and give the crate a real wasm-bindgen-test suite.

**Architecture:** All changes live in `crates/zsign-wasm/src/lib.rs` (single-file crate, inline `#[cfg(test)] pub mod tests`). No other source file, no Cargo.toml change, no workflow change. The design doc `docs/superpowers/specs/2026-09-25-wasm-surface-design.md` is the authoritative spec — every decision, limit, error code, and rejected alternative is there.

**Tech Stack:** Rust 2021, wasm-bindgen 0.2.128, wasm-bindgen-test 0.3.78, js-sys 0.3.105, zsign-core (path dep), sha1/sha2/plist (existing deps).

---

## Ground rules (apply to every task)

- **Scope:** edit ONLY `crates/zsign-wasm/src/lib.rs`. Never touch `.gitignore`, `.github/`, other crates, READMEs, Cargo.toml.
- **Forbidden mid-flight:** `cargo fmt`, `cargo clippy`, `hk`, workspace-wide test runs. The orchestrator gates those at merge.
- **Per-task gate (run from worktree root):**

```bash
mkdir -p .tmptmp   # once
TMPDIR=$PWD/.tmptmp cargo test -p zsign-wasm
PATH="$HOME/.local/bin:$PATH" TMPDIR=$PWD/.tmptmp wasm-pack test --node crates/zsign-wasm
```

  Both must be green before committing. `wasm-pack` is at `~/.local/bin/wasm-pack` (0.13.1, not on PATH). CI runs the same wasm-pack command (`.github/workflows/ci.yml:96`) without `--release`. Add `-- --nocapture` only while diagnosing.
- **Red first:** write the task's tests, run both gates to see them fail (compile-fail counts as red for tests that reference brand-new API), then implement, then green.
- **Commit per task**, conventional subject, ticket ID in subject only (never in code comments), imperative lowercase, no trailing period:

```
feat(zsign-wasm): default sign_macho to sha256-only and reject fat (ZSN-40)
fix(zsign-wasm): seal code-resources paths against stream interleaving (ZSN-40)
test(zsign-wasm): add wasm-bindgen-test suite for signing surface (ZSN-40)
```

(Imperative, lowercase, no trailing period; each task uses its own concrete subject of this shape.)

- **Error style per task:** tasks 1–4 keep the existing `JsError::new(&msg)` style (the file's current convention). Task 5 migrates EVERY error site — including any added by tasks 1–4 — to the coded helper. Do not introduce `js_err` early.
- **Test module:** one inline module in lib.rs, declared `#[cfg(test)] pub mod tests` (the `pub` is required by wasm-bindgen-test: tests must sit at crate root or in a `pub mod`; `#[cfg(test)]` keeps it out of production builds). Dual-target tests use `#[wasm_bindgen_test(unsupported = test)]`; wasm-only tests use `#[wasm_bindgen_test]`.

## Shared test scaffolding (created in Task 1, reused by all later tasks)

Test fixtures are embedded/`include_bytes!` in the test module — tracked files only, zero new files, zero new deps:

- `LEAF_P12_B64` + `decode_base64()` — self-issued RSA-2048 leaf p12 generated ONCE with the exact openssl commands in Task 1 Step 1 (CA:FALSE, digitalSignature, codeSigning EKU, `OU=ZSN40TEST`, password `test`; RSA because the repo's verify path cannot parse DER-encoded ECDSA — cross-lane finding in the design doc). Mirrors fixture reality (`Profile::Leaf` + codeSigning EKU) without x509-cert dev-deps and without `Validity::from_now` (panics on wasm32). Validity must cover native now AND the wasm fixed verify epoch 2027-01-15 (cms_verify.rs:1359).
- `MINIMAL_MACHO: &[u8] = include_bytes!("../../zsign/src/ipa/fixtures/minimal_macho.bin")` — tracked, thin arm64 MH_EXECUTE, 8192 B. If it turns out unsuitable for signing, build a minimal macho in the test module instead and log the deviation in the final report.
- `PROFILE_XML: &str` — minimal provisioning-profile stand-in: XML plist containing an `Entitlements` dict (`get-task-allow` true + `application-identifier` string). `extract_entitlements_from_profile` (provisioning.rs:12-42) only requires `<?xml`, `</plist`, bounds, and re-serializes the `Entitlements` value.
- `new_signer()` / `new_signer_with_profile()` helpers wrapping `WasmSigner::new` (profile fixture = `PROFILE_XML`).
- Test-module imports (beyond `use super::*; use wasm_bindgen_test::*;`): explicit `use sha1::{Digest as _, Sha1}; use sha2::{Digest as _, Sha256};` — `use super::*` does not carry the parent's anonymous `Digest as _` imports, so the trait must be re-imported locally for `Sha1::digest(...)` to resolve.
- `err_message(err: impl Into<JsValue>) -> String` — `let value: JsValue = err.into();` then `value.unchecked_into::<js_sys::Error>().message().into()`. Note: use `.into()`, NOT `JsValue::from(err)` — `From<T>` cannot be resolved from an `Into<JsValue>` bound on a generic parameter (no reverse blanket impl). `JsError` does not implement `JsCast` (wasm-bindgen lib.rs:1839-1870), so errors must go through `JsValue` first; the same helper keeps compiling after Task 5 (error type becomes `JsValue`, which also satisfies `Into<JsValue>`).
- `anchored_verify(signed, creds)` = `anchored_verify_slice(signed, 0, creds)`; `anchored_verify_slice(signed, slice_idx, creds) -> CmsVerifyReport` — parse the slice's superblob (`MachOFile::parse` → signature offset = `slice.offset + code_sig_offset` → `zsign_core::codesign::verify::parse_superblob`), then locate BOTH code directories by hash type and call `verify_code_signature_with_anchors`:
  - content = `primary.raw()` (the CMS signs the primary CD — signer.rs:515; superblob.rs:544-545);
  - `cd_sha1` = `Some(Sha1::digest(sha1_cd.raw()))` when a SHA-1 CD exists (primary or alternate), else `None`;
  - `cd_sha256` = `Sha256::digest(sha256_cd.raw())`;
  - anchors = `TrustAnchors::from_certificates(vec![creds.certificate.clone()])`.
  This mirrors the signer's CDHash v1/v2 attributes (signer.rs:508-526; cms_verify.rs:897-900) for BOTH layouts: dual = SHA-1 primary + SHA-256 alternate (superblob.rs:37-41, 546-557), sha256-only = single SHA-256 primary. Passing `None`/primary-only — as zsign's own recipe does (crates/zsign/src/verify.rs:1003-1011, correct only for sha256-only output) — fails dual output.
- `cd_layout(signed) -> (bool, bool)` = `(has_sha1_cd, has_sha256_cd)` over primary + alternates via `is_sha1()` — pins "default output carries no SHA-1 CD" and "dual output carries both" without depending on which slot each occupies.
- `entitlements_slot(signed) -> Option<Vec<u8>>` — primary CD's special slot −5 (`cd.special_slot_hash(5)`). Fallback if `special_slot_hash` is not visible cross-crate: read it from `cd.raw()` — `hash_offset` u32 at byte 16, `n_special_slots` u32 at byte 24, `hash_size` u8 at byte 36; slot −k spans `raw[hash_offset − k×hash_size ..][..hash_size]`.
- `error_code(err: &JsValue) -> Option<String>` — `js_sys::Reflect::get(err, &"code".into()).ok().and_then(|v| v.as_string())` (defined with Task 5; wasm-only use).
- `build_fat_macho()` — hand-built FAT for the reject and dual tests: magic `0xcafebabe`, `nfat_arch = 2`, two big-endian `fat_arch` entries (cputype `0x0100000c`, cpusubtype `0`, `offset0 = 4096`, `offset1 = 12288` (= 4096 + 8192, still 4096-aligned), `size = 8192` each, `align = 12`), payload = two NON-overlapping copies of `MINIMAL_MACHO`, total file size 20480. Overlapping offsets would make the second slice corrupt — `sign_macho_fat` signs both, so both must be intact. No FAT fixture exists in the repo.

---

### Task 1: SHA-256-only default for `sign_macho`

**Files:**
- Modify: `crates/zsign-wasm/src/lib.rs` (`sign_macho` at 180-200, `sign_macho_fat` at 205-213, crate doc bullet at line 6, method docs at 179 and 204)
- Test: inline `#[cfg(test)] pub mod tests` in the same file

- [ ] **Step 1: Generate the embedded leaf p12 (once, local)**

RSA-2048 (not P-256): this repo's `cms_verify.rs` parses ECDSA signatures
as fixed 64-byte raw while the CMS builder emits DER-encoded ECDSA — every
ECDSA verification fails at parse (core defect owned by ZSN-3, recorded as
a cross-lane finding in the design doc). RSA matches the in-repo
`rsa_credentials`/fixture-reality precedent and is the proven verify path.

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout .tmptmp/zsn40-key.pem -out .tmptmp/zsn40-cert.pem -days 3650 -nodes \
  -subj "/CN=zsign-wasm-test/OU=ZSN40TEST" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=critical,codeSigning"
openssl pkcs12 -export -out .tmptmp/zsn40.p12 -inkey .tmptmp/zsn40-key.pem \
  -in .tmptmp/zsn40-cert.pem -passout pass:test \
  -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg SHA256
base64 -w0 .tmptmp/zsn40.p12
openssl x509 -in .tmptmp/zsn40-cert.pem -noout -subject -dates -text | grep -E 'Subject:|notBefore|notAfter|CA:|Key Usage|Extended'
```

(Write all outputs under `.tmptmp/`, never `/tmp` — tmpfs quota flakes.)

**Scratch cleanup (mandatory):** `.tmptmp/` is NOT gitignored (`.gitignore`
covers `tmp/` only) and these files include a private key. After pasting the
base64 into the test module, run
`rm -f .tmptmp/zsn40-key.pem .tmptmp/zsn40-cert.pem .tmptmp/zsn40.p12`.
Stage only exact file paths in this lane — never a broad `git add`.

Verify the printed cert: `OU=ZSN40TEST`, `CA:FALSE`, `digitalSignature`, `codeSigning`, notAfter ≈ +10 years (must be after 2027-01-15). If `-days 3650` starts at now (2026-09-25) that satisfies the window; the design doc's exact dates are illustrative — the constraint is "covers native now and 2027-01-15". Paste `base64 -w0` output into the test module as `const LEAF_P12_B64: &str` (split into concatenated 76-char lines for reviewability).

- [ ] **Step 2: Write the failing tests (red)**

Add to lib.rs:

```rust
#[cfg(test)]
pub mod tests {
    use super::*;
    use sha1::{Digest as _, Sha1};
    use sha2::{Digest as _, Sha256};
    use wasm_bindgen_test::*;

    // The Step 1 base64 output is declared here in the real module as
    // `const LEAF_P12_B64: &str` (concatenated 76-char quoted lines);
    // the committed lib.rs carries the real fixture value.

    fn decode_base64(s: &str) -> Vec<u8> {
        const ALPHA: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::with_capacity(s.len() * 3 / 4);
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &b in s.bytes() {
            if b.is_ascii_whitespace() {
                continue;
            }
            if b == b'=' {
                break;
            }
            let val = ALPHA.iter().position(|&a| a == b).expect("valid base64 char") as u32;
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    }

    const MINIMAL_MACHO: &[u8] =
        include_bytes!("../../zsign/src/ipa/fixtures/minimal_macho.bin");

    const PROFILE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key><dict>
    <key>get-task-allow</key><true/>
    <key>application-identifier</key><string>ZSN40TEST.com.zsign.test</string>
  </dict>
</dict></plist>
"#;

    fn new_signer() -> WasmSigner {
        WasmSigner::new(&decode_base64(LEAF_P12_B64), "test", None).expect("fixture p12 loads")
    }

    fn new_signer_with_profile() -> WasmSigner {
        WasmSigner::new(&decode_base64(LEAF_P12_B64), "test", Some(PROFILE_XML.as_bytes().to_vec()))
            .expect("fixture p12 + profile load")
    }

    fn err_message(err: impl Into<JsValue>) -> String {
        let value: JsValue = err.into();
        value.unchecked_into::<js_sys::Error>().message().into()
    }

    /// (has_sha1_cd, has_sha256_cd) over primary + alternate code directories.
    fn cd_layout(signed: &[u8]) -> (bool, bool) {
        let m = zsign_core::macho::MachOFile::parse(signed.to_vec()).unwrap();
        let sl = &m.slices()[0];
        let off = sl.offset as usize + sl.code_sig_offset.unwrap() as usize;
        let sb = zsign_core::codesign::verify::parse_superblob(
            &signed[off..off + sl.code_sig_size.unwrap() as usize]).unwrap();
        let mut sha1 = sb.code_directory.as_ref().unwrap().is_sha1();
        let mut sha256 = !sha1;
        for cd in &sb.alternate_code_directories {
            sha1 |= cd.is_sha1();
            sha256 |= !cd.is_sha1();
        }
        (sha1, sha256)
    }

    /// Primary CD's entitlements special slot (−5).
    fn entitlements_slot(signed: &[u8]) -> Option<Vec<u8>> {
        let m = zsign_core::macho::MachOFile::parse(signed.to_vec()).unwrap();
        let sl = &m.slices()[0];
        let off = sl.offset as usize + sl.code_sig_offset.unwrap() as usize;
        let sb = zsign_core::codesign::verify::parse_superblob(
            &signed[off..off + sl.code_sig_size.unwrap() as usize]).unwrap();
        sb.code_directory.as_ref().unwrap()
            .special_slot_hash(5)
            .map(|h| h.to_vec())
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sign_macho_default_emits_sha256_only_for_thin_input() {
        let signed = new_signer()
            .sign_macho(MINIMAL_MACHO.to_vec(), "com.zsign.test", None, None)
            .expect("thin sign succeeds");
        let m = zsign_core::macho::MachOFile::parse(signed.clone()).unwrap();
        assert_eq!(m.slices().len(), 1);
        let (has_sha1, has_sha256) = cd_layout(&signed);
        assert!(!has_sha1, "default output must carry no SHA-1 CodeDirectory");
        assert!(has_sha256, "default output must carry the SHA-256 CodeDirectory");
        // signature still cryptographically valid under an injected anchor
        let report = anchored_verify(&signed, &new_signer().credentials);
        assert!(report.valid, "sha256-only signature must verify: {:?}", report.errors);
    }

    #[wasm_bindgen_test]
    fn sign_macho_rejects_fat_input() {
        let fat = build_fat_macho();
        let err = new_signer()
            .sign_macho(fat, "com.zsign.test", None, None)
            .expect_err("FAT rejected by default");
        let msg = err_message(err);
        assert!(msg.contains("sign_macho_fat"), "error must name the dual opt-in: {msg}");
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sign_macho_fat_keeps_dual_behavior_for_thin_and_fat() {
        let signer = new_signer();
        let thin = signer
            .sign_macho_fat(MINIMAL_MACHO.to_vec(), "com.zsign.test", None, None)
            .expect("thin dual sign");
        let (has_sha1, has_sha256) = cd_layout(&thin);
        assert!(has_sha1 && has_sha256, "dual output carries both CodeDirectories");
        assert!(anchored_verify(&thin, &signer.credentials).valid);

        let fat = signer
            .sign_macho_fat(build_fat_macho(), "com.zsign.test", None, None)
            .expect("FAT dual sign");
        let m = zsign_core::macho::MachOFile::parse(fat.clone()).unwrap();
        assert_eq!(m.slices().len(), 2);
        for idx in 0..2 {
            assert!(anchored_verify_slice(&fat, idx, &signer.credentials).valid,
                "FAT slice {idx} must verify under the injected anchor");
        }
    }

    /// Pins the executable/non-executable entitlements replication in
    /// `sign_macho`: non-executable input must ignore profile entitlements
    /// (EMPTY_ENTITLEMENTS both times), executable input must not. Passes on
    /// the pre-change delegation; goes red if the replication is dropped.
    #[wasm_bindgen_test(unsupported = test)]
    fn non_executable_input_ignores_profile_entitlements() {
        let mut dylib = MINIMAL_MACHO.to_vec();
        dylib[12..16].copy_from_slice(&6u32.to_le_bytes()); // MH_EXECUTE -> MH_DYLIB
        let with = new_signer_with_profile();
        let without = new_signer();
        let a = with.sign_macho(dylib.clone(), "com.zsign.test", None, None).expect("sign");
        let b = without.sign_macho(dylib.clone(), "com.zsign.test", None, None).expect("sign");
        assert_eq!(entitlements_slot(&a), entitlements_slot(&b),
            "non-executable input must ignore profile entitlements");
        let c = with.sign_macho(MINIMAL_MACHO.to_vec(), "com.zsign.test", None, None).expect("sign");
        let d = without.sign_macho(MINIMAL_MACHO.to_vec(), "com.zsign.test", None, None).expect("sign");
        assert_ne!(entitlements_slot(&c), entitlements_slot(&d),
            "executable input must carry the profile entitlements when loaded");
    }
}
```

`anchored_verify`, `anchored_verify_slice`, and `build_fat_macho` are implemented per the "Shared test scaffolding" section (all self-contained, wasm-only-safe to call from dual tests since they build no error values). If `special_slot_hash` is not visible cross-crate, use the byte-layout fallback documented in the scaffolding section.

- [ ] **Step 3: Run both gates, confirm red**

`TMPDIR=$PWD/.tmptmp cargo test -p zsign-wasm` → `sign_macho_default_emits_sha256_only_for_thin_input` FAILS (output is dual). `sign_macho_rejects_fat_input` does not run natively — a plain `#[wasm_bindgen_test]` is never registered under cargo test (its body compiles as dead code only). The dual and non-executable tests pass pre-change — they are regression pins for the rewrite (they go red only if the task's implementation drops dual support or the entitlements replication). `wasm-pack test --node crates/zsign-wasm` → BOTH `sign_macho_default_emits_sha256_only_for_thin_input` and `sign_macho_rejects_fat_input` FAIL under node (FAT accepted today).

- [ ] **Step 4: Implement**

Replace the `sign_macho` body (lib.rs:187-199):

```rust
        let macho =
            zsign_core::macho::MachOFile::parse(data).map_err(|e| JsError::new(&e.to_string()))?;
        if macho.slices().len() > 1 {
            return Err(JsError::new(
                "FAT/Universal input is not supported by SHA-256-only signing; call sign_macho_fat() to opt into dual SHA-1+SHA-256 signing explicitly",
            ));
        }
        let is_executable = macho.slices().first().map(|s| s.is_executable).unwrap_or(false);
        let entitlements: Option<&[u8]> = if is_executable {
            self.entitlements.as_deref()
        } else {
            Some(zsign_core::macho::EMPTY_ENTITLEMENTS)
        };
        zsign_core::macho::sign_macho_sha256_only(
            &macho,
            identifier,
            entitlements,
            &self.credentials,
            info_plist.as_deref(),
            code_resources.as_deref(),
            false,
        )
        .map_err(|e| JsError::new(&e.to_string()))
```

Replace the `sign_macho_fat` body (lib.rs:212) so it no longer delegates:

```rust
        let macho =
            zsign_core::macho::MachOFile::parse(data).map_err(|e| JsError::new(&e.to_string()))?;
        zsign_core::macho::sign_any_macho(
            &macho,
            identifier,
            self.entitlements.as_deref(),
            &self.credentials,
            info_plist.as_deref(),
            code_resources.as_deref(),
            false,
        )
        .map_err(|e| JsError::new(&e.to_string()))
```

(`sign_any_macho` performs the executable/non-executable entitlements selection itself — signer.rs:167-177 — so `sign_macho_fat` passes raw entitlements exactly as the old delegation did. The `sign_macho` path replicates that selection because `sign_macho_sha256_only` has no such logic: `SigningContext::new` builds the entitlements blob from any `Some` — signer.rs:85-97 — so a dylib must be handed `EMPTY_ENTITLEMENTS` explicitly.)

Update docs:
- `sign_macho` doc: "Sign a thin (single-arch) Mach-O binary with a SHA-256-only code directory. FAT/Universal input is rejected — call `sign_macho_fat` to opt into dual SHA-1+SHA-256 signing. Returns the signed binary bytes."
- `sign_macho_fat` doc: "Sign a Mach-O binary (thin or FAT/Universal) with dual SHA-1+SHA-256 code directories. Returns the signed binary bytes."
- Crate doc bullet line 6: "Mach-O binary signing (SHA-256-only default for thin input; dual SHA-1+SHA-256 via `sign_macho_fat`, incl. FAT/Universal)".

- [ ] **Step 5: Gates green**

Both gates pass (4 tests; the wasm-only FAT test runs in the wasm-pack gate only, the other 3 run on both targets).

- [ ] **Step 6: Commit**

`git add -f` is NOT needed here (lib.rs is tracked). Commit:
`feat(zsign-wasm): default sign_macho to sha256-only and reject fat (ZSN-40)`

---

### Task 2: validated entitlements setter

**Files:**
- Modify: `crates/zsign-wasm/src/lib.rs` (struct field 50, constructor 64-79, getter 83-85, `sign_macho`/`sign_macho_fat` bodies from Task 1)

- [ ] **Step 1: Write the failing tests (red)**

```rust
    fn parse_dict(xml: &[u8]) -> plist::Dictionary {
        let v: plist::Value = plist::from_bytes(xml).expect("fixture plist parses");
        v.as_dictionary().expect("top-level dict").clone()
    }

    const OVERRIDE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.example.override</key><true/>
</dict></plist>
"#;

    #[wasm_bindgen_test(unsupported = test)]
    fn entitlements_setter_overrides_then_reverts_to_profile() {
        let mut signer = new_signer_with_profile();
        let derived = signer.entitlements().expect("profile-derived entitlements exist");
        assert!(parse_dict(&derived).contains_key("application-identifier"));

        signer
            .set_entitlements(Some(OVERRIDE_XML.as_bytes().to_vec()))
            .expect("valid dictionary accepted");
        assert_eq!(
            parse_dict(&signer.entitlements().expect("override is effective")),
            parse_dict(OVERRIDE_XML.as_bytes())
        );

        signer.set_entitlements(None).expect("clear succeeds");
        assert_eq!(
            parse_dict(&signer.entitlements().expect("profile fallback returns")),
            parse_dict(&derived)
        );
    }

    #[wasm_bindgen_test]
    fn entitlements_setter_rejects_invalid_input() {
        let mut signer = new_signer();
        let e1 = signer
            .set_entitlements(Some(b"not a plist".to_vec()))
            .expect_err("garbage rejected");
        assert!(err_message(e1).contains("plist dictionary"));

        let arr = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array><string>x</string></array></plist>"#;
        let e2 = signer
            .set_entitlements(Some(arr.to_vec()))
            .expect_err("non-dictionary rejected");
        assert!(err_message(e2).contains("dictionary"));

        // values the signer's DER encoder refuses (Data/Date/Real, der.rs:176-188)
        // must fail at set time, not at sign time
        let with_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>k</key><data>AA==</data></dict></plist>"#;
        let e3 = signer
            .set_entitlements(Some(with_data.to_vec()))
            .expect_err("DER-unsupported value rejected");
        let m3 = err_message(e3);
        assert!(m3.contains("cannot encode"), "got: {m3}");
    }
```

Red check: `set_entitlements` does not exist → compile failure (that is the red state for new-API tasks).

- [ ] **Step 2: Implement**

Struct field change (lib.rs:50):

```rust
    profile_entitlements: Option<Vec<u8>>,
    entitlements_override: Option<Vec<u8>>,
```

Constructor (lib.rs:75-79) stores `profile_entitlements: entitlements, entitlements_override: None`.

Replace the getter (lib.rs:83-85) and add the setter + effective helper:

```rust
    /// Get the effective entitlements: the override when set, otherwise the
    /// profile-derived entitlements (if any).
    pub fn entitlements(&self) -> Option<Vec<u8>> {
        self.effective_entitlements().map(<[u8]>::to_vec)
    }

    /// Override the entitlements used for signing.
    ///
    /// `Some(bytes)` must be an XML or binary plist dictionary whose values
    /// the signer can encode to DER (strings, booleans, integers, arrays,
    /// dictionaries — Data/Date/Real are rejected here rather than at sign
    /// time) — it replaces the profile-derived entitlements until cleared.
    /// `None` clears the override, falling back to the profile-derived
    /// entitlements. To sign with no entitlements while holding a profile,
    /// construct the signer without profile bytes instead.
    pub fn set_entitlements(&mut self, data: Option<Vec<u8>>) -> Result<(), JsError> {
        match data {
            Some(bytes) => {
                let value: plist::Value = plist::from_bytes(&bytes)
                    .map_err(|e| JsError::new(&format!("entitlements must be a valid XML or binary plist dictionary: {e}")))?;
                if value.as_dictionary().is_none() {
                    return Err(JsError::new(
                        "entitlements plist must contain a top-level dictionary",
                    ));
                }
                zsign_core::codesign::der::plist_to_der(&bytes).map_err(|e| {
                    JsError::new(&format!("entitlements contain types the signer cannot encode: {e}"))
                })?;
                self.entitlements_override = Some(bytes);
            }
            None => self.entitlements_override = None,
        }
        Ok(())
    }

    fn effective_entitlements(&self) -> Option<&[u8]> {
        self.entitlements_override
            .as_deref()
            .or(self.profile_entitlements.as_deref())
    }
```

Migrate every reader of the old field: constructor argument at lib.rs:193-area (`self.entitlements.as_deref()` in `sign_macho`'s executable branch and in `sign_macho_fat`) → `self.effective_entitlements()`.

- [ ] **Step 3: Gates green, commit**

Both gates pass (setter tests ×2 targets; rejection test wasm-only).
Commit: `feat(zsign-wasm): add validated entitlements setter (ZSN-40)`

---

### Task 3: input size guards

**Files:**
- Modify: `crates/zsign-wasm/src/lib.rs` (all byte-input entry points: `new` 59-63, `hash_file` 95-98, `hash_file_chunk` 101, `extract_entitlements` 160, `parse_macho` 165, `sign_macho`/`sign_macho_fat` 180/205, `parse_info_plist` 218, `set_entitlements` from Task 2)

- [ ] **Step 1: Write the failing tests (red)**

```rust
    // ensure_size boundaries: `len` is a plain parameter, so every constant
    // is pinned without large allocations (the 513 MiB Mach-O case is never
    // allocated in CI by design — design doc § item 3).
    #[wasm_bindgen_test(unsupported = test)]
    fn ensure_size_accepts_exactly_at_limit() {
        for max in [MAX_P12_BYTES, MAX_HASH_BYTES, MAX_PLIST_BYTES, MAX_PROFILE_BYTES, MAX_MACHO_BYTES] {
            assert!(ensure_size(max, max, "surface", "remedy").is_ok(), "at limit {max}");
        }
    }

    #[wasm_bindgen_test]
    fn ensure_size_rejects_one_byte_over_every_limit() {
        for max in [MAX_P12_BYTES, MAX_HASH_BYTES, MAX_PLIST_BYTES, MAX_PROFILE_BYTES, MAX_MACHO_BYTES] {
            let e = ensure_size(max + 1, max, "surface", "remedy").expect_err("over limit");
            let msg = err_message(e);
            assert!(msg.contains("too large") && msg.contains("surface"), "{msg}");
        }
    }

    // Wiring: exactly at the limit passes the guard (and fails later at p12
    // parsing); one byte over fails with the size error. 4 MiB allocations.
    #[wasm_bindgen_test]
    fn p12_size_boundary_is_enforced() {
        let at_limit = vec![0u8; MAX_P12_BYTES];
        let e = WasmSigner::new(&at_limit, "test", None).expect_err("garbage still fails parsing");
        let m = err_message(e);
        assert!(!m.contains("too large"), "exactly-at-limit input must pass the size guard: {m}");

        let over = vec![0u8; MAX_P12_BYTES + 1];
        let e = WasmSigner::new(&over, "test", None).expect_err("oversize rejected");
        let msg = err_message(e);
        assert!(msg.contains("too large") && msg.contains("4194304"), "{msg}");
    }

    #[wasm_bindgen_test]
    fn hash_and_plist_surfaces_reject_oversize_input() {
        let mut signer = new_signer();
        // 129 MiB — the largest allocation kept in CI (one transient chunk)
        let e = signer
            .hash_file("big.bin", &vec![0u8; MAX_HASH_BYTES + 1])
            .expect_err("hash guard");
        assert!(err_message(e).contains("hash_file_chunk"),
            "remedy must name the streaming API");

        let e = signer
            .hash_file_chunk("big.bin", &vec![0u8; MAX_HASH_BYTES + 1], true)
            .expect_err("chunk guard");
        assert!(err_message(e).contains("too large"));

        let e = WasmSigner::parse_info_plist(&vec![0u8; MAX_PLIST_BYTES + 1])
            .expect_err("plist guard");
        assert!(err_message(e).contains("16777216"));

        let e = WasmSigner::extract_entitlements(&vec![0u8; MAX_PROFILE_BYTES + 1])
            .expect_err("profile guard");
        assert!(err_message(e).contains("too large"));
    }
```

(These are the red tests: the constants and `ensure_size` do not exist yet, and no entry point checks length. The Mach-O `data` surfaces get no >16 MiB integration test — their wiring is the same first-line `ensure_size` call, pinned at three other surfaces and at every constant boundary.)

- [ ] **Step 2: Implement**

Add near the top of the file (after imports):

```rust
/// Maximum size of a single Mach-O input (parse/sign): the wasm32 address
/// space is 4 GiB and signing peaks at roughly 2-3x the input.
const MAX_MACHO_BYTES: usize = 512 * 1024 * 1024;
/// Maximum size of one `hash_file` buffer or one `hash_file_chunk` chunk.
/// Larger content must be streamed chunk-wise.
const MAX_HASH_BYTES: usize = 128 * 1024 * 1024;
/// Maximum size of plist inputs (Info.plist, CodeResources, entitlements).
const MAX_PLIST_BYTES: usize = 16 * 1024 * 1024;
/// Maximum size of a provisioning profile.
const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum size of a PKCS#12 file.
const MAX_P12_BYTES: usize = 4 * 1024 * 1024;

fn ensure_size(
    len: usize,
    max: usize,
    surface: &str,
    remedy: &str,
) -> Result<(), JsError> {
    if len <= max {
        return Ok(());
    }
    Err(JsError::new(&format!(
        "{surface} input too large: {len} bytes exceeds the {max}-byte limit; {remedy}"
    )))
}
```

Insert guards as the FIRST statement of each entry point (before any parse or processing — the wasm-bindgen boundary copy precedes the body, see the design's boundary note):

| Entry point | Call |
|---|---|
| `new` | `ensure_size(p12_bytes.len(), MAX_P12_BYTES, "WasmSigner constructor (p12_bytes)", "supply a smaller PKCS#12")?;` then for `Some(profile)`: `ensure_size(profile.len(), MAX_PROFILE_BYTES, "WasmSigner constructor (profile_bytes)", "supply a smaller provisioning profile")?;` (both before `from_p12`) |
| `set_entitlements` | `ensure_size(bytes.len(), MAX_PLIST_BYTES, "set_entitlements", "entitlements must be a compact plist dictionary")?;` before parsing |
| `hash_file` | signature `-> Result<bool, JsError>`; first line `ensure_size(data.len(), MAX_HASH_BYTES, "hash_file", "stream large files with hash_file_chunk(...)")?;` |
| `hash_file_chunk` | signature `-> Result<(), JsError>` (state guards come in Task 4); first line `ensure_size(chunk.len(), MAX_HASH_BYTES, "hash_file_chunk", "send smaller chunks")?;` |
| `extract_entitlements` | `ensure_size(profile_data.len(), MAX_PROFILE_BYTES, "extract_entitlements", "supply a smaller provisioning profile")?;` |
| `parse_macho` | `ensure_size(data.len(), MAX_MACHO_BYTES, "parse_macho", "use the native zsign CLI for larger binaries")?;` |
| `sign_macho` | `ensure_size(data.len(), MAX_MACHO_BYTES, "sign_macho", "use the native zsign CLI for larger binaries")?;` first, then `if let Some(pl) = &info_plist { ensure_size(pl.len(), MAX_PLIST_BYTES, "sign_macho (info_plist)", "supply a smaller Info.plist")?; }` and `if let Some(cr) = &code_resources { ensure_size(cr.len(), MAX_PLIST_BYTES, "sign_macho (code_resources)", "supply smaller CodeResources")?; }` |
| `sign_macho_fat` | same three guards as `sign_macho`, with surface strings `sign_macho_fat`, `sign_macho_fat (info_plist)`, `sign_macho_fat (code_resources)` (design § item 3 covers the plist params) |
| `parse_info_plist` | `ensure_size(data.len(), MAX_PLIST_BYTES, "parse_info_plist", "supply a smaller Info.plist")?;` |

No size check on string inputs (`identifier`, paths, symlink targets, password) — deliberate, recorded in the design doc § item 3.

Update doc comments on `hash_file`/`hash_file_chunk` to state they now throw on oversize input (Task 4 adds the state-machine throws).

- [ ] **Step 3: Gates green**

Both gates pass. The three oversize tests run wasm-only (they build error values); native gate stays green because only Ok paths are exercised natively.

- [ ] **Step 4: Commit**

`feat(zsign-wasm): enforce per-surface input size limits (ZSN-40)`

---

### Task 4: path-sealing state machine for the CodeResources hashes

**Files:**
- Modify: `crates/zsign-wasm/src/lib.rs` (struct 47-53, constructor, `hash_file` 95-98, `hash_file_chunk` 100-126, `build_code_resources` 139-151, `reset_resources` 154-157)

- [ ] **Step 1: Write the failing tests (red)**

```rust
    /// Reads the stored digests for `rel` from built CodeResources:
    /// legacy `files` maps ordinary paths to raw SHA-1 Data; `files2` maps
    /// them to a dict with `hash` (SHA-1) and `hash2` (SHA-256) Data
    /// (code_resources.rs:412-452). Returns (sha1, sha256) bytes.
    fn resource_digests(built: &[u8], rel: &str) -> (Vec<u8>, Vec<u8>) {
        let root: plist::Value = plist::from_bytes(built).expect("CodeResources is a plist");
        let dict = root.as_dictionary().expect("root dict");
        let files = dict.get("files").and_then(|v| v.as_dictionary()).expect("files dict");
        let legacy = files.get(rel).and_then(|v| v.as_data())
            .expect("legacy files maps ordinary paths to SHA-1 Data").to_vec();
        let files2 = dict.get("files2").and_then(|v| v.as_dictionary()).expect("files2 dict");
        let entry = files2.get(rel).and_then(|v| v.as_dictionary()).expect("files2 entry dict");
        let modern = entry.get("hash2").and_then(|v| v.as_data())
            .expect("files2 entry carries hash2 Data").to_vec();
        (legacy, modern)
    }

    const CHUNK_A: &[u8] = b"first chunk of a large file ";
    const CHUNK_B: &[u8] = b"second chunk of a large file";

    #[wasm_bindgen_test(unsupported = test)]
    fn chunked_stream_hashes_full_content_once_finalized() {
        let mut signer = new_signer();
        signer.hash_file_chunk("stream.bin", CHUNK_A, false).expect("first chunk");
        signer.hash_file_chunk("stream.bin", CHUNK_B, true).expect("final chunk");
        let built = signer.build_code_resources().expect("build with no pending streams");
        let mut full = CHUNK_A.to_vec();
        full.extend_from_slice(CHUNK_B);
        let (h1, h2) = resource_digests(&built, "stream.bin");
        assert_eq!(h1, Sha1::digest(&full).to_vec());
        assert_eq!(h2, Sha256::digest(&full).to_vec());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn single_call_finalize_and_interleaved_paths_stay_correct() {
        let mut signer = new_signer();
        // single-call stream (is_final on the first call) stays legal
        signer.hash_file_chunk("one.bin", b"whole file", true).expect("single finalize");
        // two paths interleaved across their streams
        signer.hash_file_chunk("a.bin", b"A1", false).expect("a1");
        signer.hash_file_chunk("b.bin", b"B1", false).expect("b1");
        signer.hash_file_chunk("a.bin", b"A2", true).expect("a2 final");
        signer.hash_file_chunk("b.bin", b"B2", true).expect("b2 final");
        let built = signer.build_code_resources().expect("build");
        let (a1, a2) = resource_digests(&built, "a.bin");
        assert_eq!(a1, Sha1::digest(b"A1A2").to_vec());
        assert_eq!(a2, Sha256::digest(b"A1A2").to_vec());
        let (b1, b2) = resource_digests(&built, "b.bin");
        assert_eq!(b1, Sha1::digest(b"B1B2").to_vec());
        assert_eq!(b2, Sha256::digest(b"B1B2").to_vec());
    }

    #[wasm_bindgen_test]
    fn double_finalize_and_post_finalize_chunks_are_rejected() {
        let mut signer = new_signer();
        signer.hash_file_chunk("x.bin", b"data", true).expect("first finalize");

        // double finalize (previously silently re-hashed just the 2nd call)
        let e = signer.hash_file_chunk("x.bin", b"more", true).expect_err("double finalize");
        assert!(err_message(e).contains("reset_resources"));

        // post-finalize chunk (previously seeded a fresh digest = silent partial hash)
        let e = signer.hash_file_chunk("x.bin", b"more", false).expect_err("post-finalize chunk");
        let msg = err_message(e);
        assert!(msg.contains("already finalized") && msg.contains("reset_resources"), "{msg}");

        // build must not contain the corrupted partial content: only "data" was sealed
        let built = signer.build_code_resources().expect("sealed state still builds");
        let (h1, _) = resource_digests(&built, "x.bin");
        assert_eq!(h1, Sha1::digest(b"data").to_vec());
    }

    #[wasm_bindgen_test]
    fn hash_file_conflicts_with_active_or_sealed_paths() {
        let mut signer = new_signer();
        signer.hash_file_chunk("y.bin", b"part", false).expect("stream open");
        let e = signer.hash_file("y.bin", b"direct").expect_err("active stream conflict");
        assert!(err_message(e).contains("unfinished streaming hash"));

        signer.hash_file_chunk("y.bin", b" rest", true).expect("finalize");
        let e = signer.hash_file("y.bin", b"direct").expect_err("sealed conflict");
        let msg = err_message(e);
        assert!(msg.contains("already finalized") && msg.contains("reset_resources"), "{msg}");

        // unfinished-stream guard on build stays (stream z.bin never finalized)
        signer.hash_file_chunk("z.bin", b"open", false).expect("open");
        let e = signer.build_code_resources().expect_err("pending streams block build");
        assert!(err_message(e).contains("unfinished streaming hashes"));

        // reset_resources is the documented round boundary
        signer.reset_resources();
        signer.hash_file("y.bin", b"direct").expect("sealed path reusable after reset");
        let built = signer.build_code_resources().expect("clean build");
        let (h1, _) = resource_digests(&built, "y.bin");
        assert_eq!(h1, Sha1::digest(b"direct").to_vec());
    }

    /// Excluded paths (the main executable) are never stored and never
    /// sealed: repeated `hash_file` calls keep returning `false` without
    /// throwing — the pre-lane no-op behavior is preserved.
    #[wasm_bindgen_test(unsupported = test)]
    fn excluded_paths_stay_recallable_noops() {
        let mut signer = new_signer();
        signer.set_main_executable("App");
        assert!(!signer.hash_file("App", b"binary bytes").expect("first call ok"));
        assert!(!signer.hash_file("App", b"binary bytes").expect("second call ok, not sealed"));
    }
```

Red check: `hash_file_chunk`/`hash_file` currently return `()`/`bool`, so `.expect(...)`/`expect_err(...)` do not compile — that is the red state.

- [ ] **Step 2: Implement**

- Import `HashSet` next to `HashMap` (lib.rs:5).
- Struct field (lib.rs:52): add `finalized_paths: HashSet<String>,`; constructor inits it to `HashSet::new()`; `reset_resources` gains `self.finalized_paths.clear();`.
- `hash_file` (after the Task 3 size guard):

```rust
        if self.streaming_hashes.contains_key(relative_path) {
            return Err(JsError::new(&format!(
                "path \"{relative_path}\" has an unfinished streaming hash; finalize it with hash_file_chunk(..., true) before hashing it directly"
            )));
        }
        if self.finalized_paths.contains(relative_path) {
            return Err(JsError::new(&format!(
                "path \"{relative_path}\" was already finalized in this resources round; call reset_resources() before hashing it again"
            )));
        }
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(data);
        let added = self.resource_builder.add_file(relative_path, sha1, sha256);
        if added {
            self.finalized_paths.insert(relative_path.to_string());
        }
        Ok(added)
```

- `hash_file_chunk` (after the Task 3 size guard): prepend the seal guard

```rust
        if self.finalized_paths.contains(relative_path) {
            return Err(JsError::new(&format!(
                "path \"{relative_path}\" was already finalized in this resources round; call reset_resources() before hashing it again"
            )));
        }
```

  keep the existing `entry/or_insert → update → if is_final { remove, finalize }` flow, and on finalize seal the path **only when `add_file` stored it**:
  `if self.resource_builder.add_file(relative_path, sha1, sha256) { self.finalized_paths.insert(relative_path.to_string()); }` — excluded paths are never stored, so they are never sealed (same rule as `hash_file`).
- `build_code_resources`: no logic change (pending-stream guard and message stay verbatim).
- Doc comments: `hash_file_chunk` documents the state machine — one stream per path per round; finalize seals the stored path; `is_final` on the first call is a legal single-chunk stream; sealed paths throw until `reset_resources()`; excluded paths (never stored) stay re-callable; two non-final streams for the same path cannot be distinguished and merge (caller contract: one stream per path). `reset_resources` documents that it starts a new resources round (builder, active streams, and seals cleared). `add_symlink` doc notes it keeps last-wins duplicate semantics and sits outside the sealing machine.

- [ ] **Step 3: Gates green, commit**

Both gates pass (3 dual + 2 wasm-only tests added).
Commit: `fix(zsign-wasm): seal code-resources paths against stream interleaving (ZSN-40)`

---

### Task 5: stable error codes on every thrown error

**Files:**
- Modify: `crates/zsign-wasm/src/lib.rs` (every `JsError::new` site; crate-level doc comment at lines 1-12)

- [ ] **Step 1: Write the failing test (red)**

```rust
    fn error_code(err: &JsValue) -> Option<String> {
        js_sys::Reflect::get(err, &JsValue::from_str("code"))
            .ok()
            .and_then(|v| v.as_string())
    }

    #[wasm_bindgen_test]
    fn errors_carry_stable_zsign_codes_and_real_error_instances() {
        let e = WasmSigner::new(&decode_base64(LEAF_P12_B64), "wrong-password", None)
            .expect_err("bad password");
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PASSWORD".into()));

        let e = new_signer()
            .sign_macho(build_fat_macho(), "com.zsign.test", None, None)
            .expect_err("fat input");
        assert_eq!(error_code(&e), Some("ZSIGN_FAT_UNSUPPORTED".into()));

        let e = WasmSigner::new(&vec![0u8; MAX_P12_BYTES + 1], "test", None)
            .expect_err("oversize");
        assert_eq!(error_code(&e), Some("ZSIGN_INPUT_TOO_LARGE".into()));

        let mut signer = new_signer();
        signer.hash_file_chunk("c.bin", b"x", true).unwrap();
        let e = signer.hash_file_chunk("c.bin", b"y", true).expect_err("sealed path");
        assert_eq!(error_code(&e), Some("ZSIGN_PATH_ALREADY_FINALIZED".into()));

        let mut signer = new_signer();
        let e = signer
            .set_entitlements(Some(b"junk".to_vec()))
            .expect_err("invalid entitlements");
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_ENTITLEMENTS".into()));

        let e = WasmSigner::parse_info_plist(b"not a plist").expect_err("bad plist");
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PLIST".into()));

        // the thrown value is a real Error with a non-empty message
        assert!(e.is_instance_of::<js_sys::Error>());
        assert!(!err_message(e).is_empty());
    }
```

Red check: compile failure — before the migration the methods return `Result<_, JsError>` while `error_code(&e)` takes `&JsValue` (the mismatch is the red). After Steps 2-3 the types line up and the assertions then fail at runtime only if a `.code` property is missing.

- [ ] **Step 2: Implement the machinery**

```rust
/// Stable, machine-readable error categories surfaced to JavaScript as the
/// `code` property of the thrown `Error`. These strings are a public contract
/// and only change across major versions; the message text is human-facing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WasmErrorCode {
    InvalidMachO,
    EncryptedBinary,
    SigningFailed,
    InvalidCertificate,
    InvalidPassword,
    MissingCredentials,
    Config,
    InvalidProfile,
    InvalidPlist,
    DerEncoding,
    Verification,
    InputTooLarge,
    InvalidEntitlements,
    UnfinishedHashes,
    PathAlreadyFinalized,
    PathInProgress,
    FatUnsupported,
    Internal,
}

impl WasmErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidMachO => "ZSIGN_INVALID_MACHO",
            Self::EncryptedBinary => "ZSIGN_ENCRYPTED_BINARY",
            Self::SigningFailed => "ZSIGN_SIGNING_FAILED",
            Self::InvalidCertificate => "ZSIGN_INVALID_CERTIFICATE",
            Self::InvalidPassword => "ZSIGN_INVALID_PASSWORD",
            Self::MissingCredentials => "ZSIGN_MISSING_CREDENTIALS",
            Self::Config => "ZSIGN_CONFIG",
            Self::InvalidProfile => "ZSIGN_INVALID_PROFILE",
            Self::InvalidPlist => "ZSIGN_INVALID_PLIST",
            Self::DerEncoding => "ZSIGN_DER_ENCODING",
            Self::Verification => "ZSIGN_VERIFICATION",
            Self::InputTooLarge => "ZSIGN_INPUT_TOO_LARGE",
            Self::InvalidEntitlements => "ZSIGN_INVALID_ENTITLEMENTS",
            Self::UnfinishedHashes => "ZSIGN_UNFINISHED_HASHES",
            Self::PathAlreadyFinalized => "ZSIGN_PATH_ALREADY_FINALIZED",
            Self::PathInProgress => "ZSIGN_PATH_IN_PROGRESS",
            Self::FatUnsupported => "ZSIGN_FAT_UNSUPPORTED",
            Self::Internal => "ZSIGN_INTERNAL",
        }
    }
}

/// Exhaustive over `zsign_core::Error`: a new core variant must be categorized
/// here before the crate compiles.
fn code_for_core_error(e: &zsign_core::Error) -> WasmErrorCode {
    use zsign_core::Error as E;
    match e {
        E::MachO(_) | E::Goblin(_) => WasmErrorCode::InvalidMachO,
        E::EncryptedBinary(_) => WasmErrorCode::EncryptedBinary,
        E::Signing(_) => WasmErrorCode::SigningFailed,
        E::Certificate(_) => WasmErrorCode::InvalidCertificate,
        E::InvalidPassword => WasmErrorCode::InvalidPassword,
        E::MissingCredentials(_) => WasmErrorCode::MissingCredentials,
        E::Config(_) => WasmErrorCode::Config,
        E::ProvisioningProfile(_) => WasmErrorCode::InvalidProfile,
        E::Plist(_) => WasmErrorCode::InvalidPlist,
        E::DerEncoding(_) => WasmErrorCode::DerEncoding,
        E::Verification(_) => WasmErrorCode::Verification,
    }
}

fn js_err(code: WasmErrorCode, message: impl std::fmt::Display) -> JsValue {
    let err = js_sys::Error::new(&message.to_string());
    let _ = js_sys::Reflect::set(
        &err,
        &JsValue::from_str("code"),
        &JsValue::from_str(code.as_str()),
    );
    err.into()
}

fn core_err(e: zsign_core::Error) -> JsValue {
    let code = code_for_core_error(&e);
    js_err(code, e)
}

/// `from_p12` wraps every PKCS#12 failure — including wrong-password
/// failures — as `Error::Certificate` (crypto/cert.rs:203-205). Both
/// password-layer Display markers are classified: the MAC mismatch text
/// (crypto/pkcs12.rs:79, the standard unencrypted-authSafe flow proven
/// across all nine core fixtures) and `PKCS#12 decryption failed`
/// (encrypted AuthenticatedSafe/key-bag files, where a wrong password
/// fails at decryption before any MAC check). A wrong password that
/// degenerates into a malformed-ASN.1 parse error carries no password
/// signal and degrades to the generic certificate code (fail-safe,
/// documented). Anything else keeps the generic code.
fn p12_err(e: zsign_core::Error) -> JsValue {
    let text = e.to_string();
    let code = if text.contains("invalid PKCS#12 password (MAC mismatch)")
        || text.contains("PKCS#12 decryption failed")
    {
        WasmErrorCode::InvalidPassword
    } else {
        code_for_core_error(&e)
    };
    js_err(code, e)
}
```

- [ ] **Step 3: Migrate every error site (clean cutover, no residue)**

- Change every `Result<T, JsError>` in the file to `Result<T, JsValue>` (`new`, `set_entitlements`, `hash_file`, `hash_file_chunk`, `build_code_resources`, `extract_entitlements`, `parse_macho`, `sign_macho`, `sign_macho_fat`, `parse_info_plist`).
- `ensure_size` returns `Result<(), JsValue>`; its `Err` becomes `js_err(WasmErrorCode::InputTooLarge, format!(...))` with the same message text.
- `.map_err(|e| JsError::new(&e.to_string()))` over core results → `.map_err(core_err)` — EXCEPT the constructor's `from_p12` call, which becomes `.map_err(p12_err)` (wrong-password classification); the constructor's profile-extract call stays `.map_err(core_err)`. Other sites: build, extract, parse ×2, sign ×2.
- Synthetic errors: unfinished-streams guard → `js_err(WasmErrorCode::UnfinishedHashes, <verbatim existing format!>)`; FAT reject → `js_err(WasmErrorCode::FatUnsupported, <same message>)`; `hash_file` active-stream guard → `PathInProgress`; both "already finalized" guards → `PathAlreadyFinalized`; setter validation branches → `InvalidEntitlements` (keep both message texts); `parse_info_plist` parse/not-dict → `InvalidPlist` (messages verbatim); `Reflect::set` failures → `Internal` (messages verbatim).
- Grep self-check: after migration, `grep -c JsError crates/zsign-wasm/src/lib.rs` must be 0 (the `prelude::*` import stays).
- Crate doc: append an "## Error codes" section with the full `ZSIGN_*` table (from the design doc § item 5) and the sentence: match on `error.code`; `error.message` is human-facing and may change.

- [ ] **Step 4: Upgrade existing wasm-only error tests — ADD code assertions, KEEP message assertions**

The message-text assertions written in tasks 1-4 are part of the "keep the message text" contract; the new test above covers representative codes across categories, plus `ZSIGN_INVALID_PASSWORD`, `ZSIGN_INVALID_ENTITLEMENTS`-adjacent paths. Do not delete any prior assertion.

- [ ] **Step 5: Gates green, commit**

Both gates pass; `grep -c JsError` = 0 (excluding doc text).
Commit: `feat(zsign-wasm): throw errors with stable zsign codes (ZSN-40)`

---

### Task 6: complete the wasm-bindgen-test suite

**Files:**
- Modify: `crates/zsign-wasm/src/lib.rs` (tests module only, plus any doc line the tests prove wrong)

- [ ] **Step 1: Write the failing tests (red)**

```rust
    #[wasm_bindgen_test(unsupported = test)]
    fn constructor_extracts_profile_entitlements_and_team_id() {
        let signer = new_signer_with_profile();
        assert_eq!(signer.team_id().as_deref(), Some("ZSN40TEST"));
        let ents = signer.entitlements().expect("profile entitlements");
        let dict = parse_dict(&ents);
        assert_eq!(
            dict.get("application-identifier").and_then(|v| v.as_string()),
            Some("ZSN40TEST.com.zsign.test")
        );
    }

    #[wasm_bindgen_test]
    fn constructor_rejects_bad_profile() {
        let e = WasmSigner::new(&decode_base64(LEAF_P12_B64), "test", Some(b"<not a profile".to_vec()))
            .expect_err("bad profile");
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PROFILE".into()));
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn adhoc_sign_round_trip_verifies_without_credentials() {
        let signed = zsign_core::macho::sign_macho_adhoc(
            &zsign_core::macho::MachOFile::parse(MINIMAL_MACHO.to_vec()).unwrap(),
            "com.zsign.test",
            None,
            None,
            None,
            false,
        ).expect("adhoc sign");
        let report = zsign_core::macho::verify::verify_macho(
            &signed,
            &zsign_core::codesign::verify::SignatureInputs::none(),
        ).expect("verify report");
        let slice = &report.slices[0];
        assert!(slice.signed && slice.adhoc);
        assert_eq!(slice.pages, zsign_core::codesign::verify::PageCheck::Matched);
        assert!(report.is_valid(), "adhoc round-trip must verify: {:?}", slice.errors);
    }

    #[wasm_bindgen_test]
    fn parse_info_plist_handles_xml_binary_absent_keys_and_bad_input() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.zsign.test</string>
  <key>CFBundleExecutable</key><string>Test</string>
</dict></plist>"#;
        let v = WasmSigner::parse_info_plist(xml).expect("xml parses");
        assert_eq!(js_sys::Reflect::get(&v, &"bundle_id".into()).unwrap().as_string().as_deref(), Some("com.zsign.test"));
        assert_eq!(js_sys::Reflect::get(&v, &"executable".into()).unwrap().as_string().as_deref(), Some("Test"));

        // binary plist round-trip
        let mut dict = plist::Dictionary::new();
        dict.insert("CFBundleIdentifier".into(), "com.zsign.binary".into());
        let value = plist::Value::Dictionary(dict);
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, &value).expect("serialize binary plist");
        let v = WasmSigner::parse_info_plist(&buf).expect("binary parses");
        assert_eq!(js_sys::Reflect::get(&v, &"bundle_id".into()).unwrap().as_string().as_deref(), Some("com.zsign.binary"));

        // absent keys default to empty strings (matches the method's docs)
        let v = WasmSigner::parse_info_plist(
            br#"<plist version="1.0"><dict/></plist>"#).expect("empty dict");
        assert_eq!(js_sys::Reflect::get(&v, &"bundle_id".into()).unwrap().as_string().as_deref(), Some(""));

        // non-dictionary plist → coded error
        let e = WasmSigner::parse_info_plist(
            br#"<plist version="1.0"><array><string>x</string></array></plist>"#)
            .expect_err("not a dictionary");
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PLIST".into()));
    }
```

Notes for the implementer:
- The non-executable/entitlements pin lives in Task 1 (comparison form — it must not depend on blob internals); do not re-add a slot-bytes test here.
- `plist::to_writer_binary` is the binary serializer in plist 1.x; if the exact name differs (`plist::to_writer` with binary format), use the crate's binary writer — assert `buf.starts_with(b"bplist00")` first if unsure.

- [ ] **Step 2: Run red, implement any failures, gates green**

- [ ] **Step 3: Commit**

`test(zsign-wasm): add wasm-bindgen-test suite for signing surface (ZSN-40)`

---

## Final gates (after Task 6)

Run and capture verbatim output for the final report:

```bash
mkdir -p .tmptmp
TMPDIR=$PWD/.tmptmp cargo test -p zsign-wasm
PATH="$HOME/.local/bin:$PATH" TMPDIR=$PWD/.tmptmp wasm-pack test --node crates/zsign-wasm
```

The wasm-pack run is job-equivalent to `.github/workflows/ci.yml:96` and must show every test (dual-target + wasm-only) passing under node. Native `cargo test -p zsign-wasm` shows the `unsupported = test` subset. No fmt/clippy/hk — the orchestrator gates those at merge. Do not merge, do not push.

## Self-review record

- Spec coverage: design §2 item 1 → Task 1; item 2 → Task 2; item 3 → Task 3; item 4 → Task 4; item 5 → Task 5; item 6 test matrix → Tasks 1-6 (each row maps to a named test above; rows for wrong-password/bad-profile codes land in Tasks 5-6, parse_info_plist rows in Task 6).
- Placeholders: the only deferred decisions are explicitly-logged fallbacks (macho fixture suitability, `special_slot_hash` visibility byte-layout fallback, binary-plist writer name) — each has a primary instruction and a fallback, no TBDs.
- Type consistency: `effective_entitlements()` is the single reader from Task 2 on; `ensure_size` is the only size check; `js_err`/`core_err`/`p12_err` are the only error constructors from Task 5 on; `Result<T, JsValue>` is uniform after Task 5; test helpers are `err_message`, `cd_layout`, `anchored_verify`/`anchored_verify_slice`, `entitlements_slot`, `resource_digests`, `parse_dict` (→ `plist::Dictionary`), `error_code`, `build_fat_macho` — no other helper names appear.
- Round-1 cold-review findings B1-B15 are addressed in the design doc (§ evidence, items 2/4/5, matrix, API delta) and in this plan (Task 1-6 edits); round 2 re-review confirms.
