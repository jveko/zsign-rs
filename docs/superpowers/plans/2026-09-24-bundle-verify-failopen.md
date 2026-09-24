# Bundle/CodeResources Verify Fail-Opens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with
> dispatching-parallel-agents for independent tasks. NOTE for this plan: every task
> edits the same file (`crates/zsign/src/verify.rs`), so tasks run **strictly
> sequentially**, one fresh Tester + one fresh Implementer per task, controller-level
> commits only. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the nine fail-open defects in `zsign -V`'s bundle verifier so missing,
tampered, symlinked, legacy-format, rule-governed, malformed, or path-escaping bundle
content can never verify as valid (design: sibling spec
`docs/superpowers/specs/2026-09-24-bundle-verify-failopen-design.md`).

**Architecture:** All work is confined to `crates/zsign/src/verify.rs` + its inline
tests. Two failure channels (hard `Err` vs report errors, spec C1/C2), a union
sealed-set with per-field hash verification (C3), a no-regex rules engine over the
builder's emitted pattern set (C4), symlink semantics (C5), depth-aware nesting
predicates (C6), and required-slot surfacing (C7).

**Tech Stack:** Rust 2021, `plist` (parse/mutate/serialize), `sha1`+`sha2`, `walkdir`,
inline `#[cfg(test)]` tests using `crate::test_util` fixtures and `crate::ZSign`.

---

## Ground rules for every task

- Edit ONLY `crates/zsign/src/verify.rs`. No `Cargo.toml`, no CLI, no builder files,
  no `.gitignore`. No `cargo fmt` / `cargo clippy` / `hk` — the pre-commit hook runs
  on the controller's commit; let it.
- Per-task gate (never project-wide):
  `cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`
- TDD: the Tester writes the task's test(s), runs them, confirms they FAIL for the
  stated reason; the Implementer makes them pass without regressing the rest of the
  gate; the controller verifies and commits.
- Known pre-existing failure: `test_ipa_signing_is_deterministic` (ZSN-15) — always
  skipped, never "fixed".
- Code comments: durable behavior comments only, never ticket IDs, no backticks
  inside comments.

## Shared test helpers (created by Task 1, reused by all later tasks)

```rust
fn build_signed_bundle(dir: &Path) -> PathBuf {
    build_signed_bundle_with(dir, |_| {})
}
```

`build_signed_bundle_with` is produced by Task 1's refactor — **precise move
instructions** (no new logic): rename the existing
`fn build_signed_bundle(dir: &Path) -> PathBuf` (verify.rs:503-528) to
`fn build_signed_bundle_with(dir: &Path, setup: impl FnOnce(&Path)) -> PathBuf`,
keep its entire body verbatim (all `fs::create_dir_all`/`fs::write` fixture lines
including the inline FMWK Info.plist literal), and insert one statement
`setup(&app);` immediately before `let zsign = ZSign::new()...` so callers can add
files/symlinks after the base tree exists but before signing seals it. Then add the
two-line delegating `build_signed_bundle` shown above. Existing tests calling
`build_signed_bundle(td.path())` are untouched.

```rust
/// Rewrites `Test.app/_CodeSignature/CodeResources` through a mutation closure.
/// NOTE: every use breaks the main executable's slot -3 binding, so tests using
/// this helper assert at the CodeResources / bundle-error layer, not report.valid().
fn rewrite_code_resources(app: &Path, mutate: impl FnOnce(&mut plist::Dictionary)) {
    let cr = app.join("_CodeSignature").join("CodeResources");
    let bytes = fs::read(&cr).unwrap();
    let mut value: plist::Value = plist::from_bytes(&bytes).unwrap();
    mutate(value.as_dictionary_mut().unwrap());
    let mut out = Vec::new();
    plist::to_writer_xml(&mut out, &value).unwrap();
    fs::write(&cr, out).unwrap();
}
```

If `plist::to_writer_xml` differs in the pinned plist version, use the crate's
equivalent XML writer — the helper's contract (read → mutate dictionary → write back
parseable plist) is what later tasks rely on.

---

### Task 1: Hard-error fail-open (queue item 1)

**Files:** Modify `crates/zsign/src/verify.rs` (helpers `read_opt`, `is_macho_file`,
`verify_bundle_dir`, `check_code_resources`, `verify_macho_file`; tests module).

- [ ] **Step 1: Refactor fixtures** — extract `build_signed_bundle_with` and add
  `rewrite_code_resources` as specified above; `build_signed_bundle` becomes a
  delegation. Existing tests must stay green.

- [ ] **Step 2: Write the failing test**

```rust
#[test]
fn missing_bundle_root_is_hard_error() {
    let td = tempfile::TempDir::new().unwrap();
    let result = verify_bundle(td.path().join("missing.app"));
    assert!(
        result.is_err(),
        "a nonexistent bundle must not verify: {:?}",
        result.map(|r| r.valid())
    );
}
```

- [ ] **Step 3: Run and confirm FAIL** —
  `cargo test -p zsign-rs missing_bundle_root_is_hard_error`
  Expected: FAIL (`result.is_err()` got `Ok(…)` — the walk error is swallowed).

- [ ] **Step 4: Implement**

1. `read_opt` → `Result<Option<Vec<u8>>>`:
   `Ok(bytes) → Some`, `Err` with `ErrorKind::NotFound → None`, any other `Err` →
   `Err(crate::Error::Io(e))`. Callers in `verify_bundle_dir` use `?`.
2. At the top of `verify_bundle_dir`, before any read:
   ```rust
   let meta = std::fs::metadata(dir).map_err(crate::Error::Io)?;
   if !meta.is_dir() {
       return Err(crate::Error::Io(std::io::Error::new(
           std::io::ErrorKind::InvalidInput,
           format!("not a bundle directory: {}", dir.display()),
       )));
   }
   ```
3. Walk error propagation. `WalkDir`'s iterator yields `Result<DirEntry,
   walkdir::Error>` **items** — there is no `Iterator::map_err` and the iterator
   itself is not `Try`, so bind each item inside the loop (the in-repo pattern,
   `crates/zsign/src/ipa/archive.rs:224-226`). This statement becomes the first
   statement inside `for entry in WalkDir::new(dir).min_depth(1) { … }`:
   ```rust
   let entry = entry.map_err(|e| {
       crate::Error::Io(std::io::Error::other(format!("Failed to walk directory: {e}")))
   })?;
   ```
   The remainder of the existing loop body follows it unchanged — `entry` is now a
   `DirEntry`, so the same `entry.path()` / `entry.file_type()` expressions feed it.
   Apply the identical first statement to the disk walk inside
   `check_code_resources` (its current `filter_map(|e| e.ok())` disappears with the
   loop rewrite required by Step 4.4). Do NOT put `map_err`/`?` on the iterator
   chain itself — that does not compile.
4. `check_code_resources`: add `errors: &mut Vec<String>` parameter, return
   `Result<CodeResourcesVerification>`; its disk walk uses the per-item binding from
   Step 4.3 and propagates the error; caller in `verify_bundle_dir` uses `?`.
   Content-error ownership for this task: move the unparseable-plist and
   "CodeResources has no files2 dictionary" strings from `unsealed` into `errors`
   (C2 channel — `files2` is required, its absence is a content error owned here).
5. `is_macho_file(path) -> Result<bool>`: `File::open` failure `NotFound →
   Ok(false)`, any other open error → `Err`; `read_exact` of the 4-byte magic
   failing with `ErrorKind::UnexpectedEof → Ok(false)` (too short to be a Mach-O —
   not an I/O fault); any other read error → `Err`; magic mismatch → `Ok(false)`.
   Caller uses `?`.
6. `verify_macho_file`: `std::fs::read(path)?` already propagates (unchanged).

- [ ] **Step 5: Run test — PASS**, then the scoped gate:
  `cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`
  Expected: all green.

- [ ] **Step 6: Commit** (controller): `fix(zsign): fail closed on unreadable bundle inputs (ZSN-26)`

---

### Task 2: CodeResources required at app/framework roots (queue item 2)

**Files:** `crates/zsign/src/verify.rs` (`verify_bundle_dir`, tests).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn missing_code_resources_is_reported_invalid() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle(td.path());
    fs::remove_dir_all(app.join("_CodeSignature")).unwrap();
    let report = verify_bundle(&app).unwrap();
    assert!(!report.valid(), "bundle without CodeResources must be invalid");
    let bundle = report.bundle.as_ref().unwrap();
    assert!(
        bundle
            .errors
            .iter()
            .any(|e| e.contains("_CodeSignature/CodeResources")),
        "bundle-level error required (a binary-level slot error exists already); got {:?}",
        bundle.errors
    );
}
```

- [ ] **Step 2: Run and confirm FAIL** — expected: assertion fails because
  `bundle.errors` is empty (today only the binary-level slot -3 message exists).

- [ ] **Step 3: Implement** — in `verify_bundle_dir`, after
  `let code_resources = read_opt(...)?;`:
  ```rust
  if code_resources.is_none() {
      out.errors
          .push("missing _CodeSignature/CodeResources".to_string());
  }
  ```
  `read_opt` now only yields `None` for genuine `NotFound` (Task 1); unreadable
  already surfaces as `Err` per design C1. Keep the later
  `if let Some(cr_bytes) = &code_resources` block unchanged (it sets
  `out.code_resources`).

- [ ] **Step 4: Run test — PASS**, then the full scoped gate. Expected: all green
  (`unsigned_bundle_fails` still fails via the unsigned Mach-O; `signed_bundle_*`
  unaffected).

- [ ] **Step 5: Commit** (controller): `fix(zsign): require code resources at bundle roots (ZSN-26)`

---

### Task 3: Depth-aware nested bundle verification (queue item 3)

**Files:** `crates/zsign/src/verify.rs` (`inside_nested_bundle` → new predicates,
`verify_bundle_dir` walk, tests).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tampered_nested_binary_is_detected_by_nested_frame() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle(td.path());
    let sub = app.join("Frameworks").join("Sub.framework").join("Sub");
    let mut data = fs::read(&sub).unwrap();
    data[0x1000] ^= 0x04;
    fs::write(&sub, data).unwrap();

    let report = verify_bundle(&app).unwrap();
    let bundle = report.bundle.as_ref().unwrap();
    assert_eq!(bundle.nested.len(), 1);
    let frame = &bundle.nested[0];
    assert!(
        !frame.binaries.is_empty(),
        "nested frame binaries must be Mach-O verified, got none"
    );
    let sub_bin = frame
        .binaries
        .iter()
        .find(|b| b.path.ends_with("/Sub") || b.path == "Sub")
        .expect("Sub binary reported by the nested frame");
    assert!(!sub_bin.valid(), "tampered nested binary must not verify");
}
```

- [ ] **Step 2: Run and confirm FAIL** — expected: `frame.binaries` is empty (the
  root-relative `inside_nested_bundle` predicate skips every file inside a bundle
  component, including during the frame's own recursion).

- [ ] **Step 3: Implement** (design C6)

1. Delete `inside_nested_bundle`. Add:
   ```rust
   /// True when any component of `rel` names a nested bundle directory. With
   /// `ignore_last` the final component is exempt, which lets a directory entry
   /// itself be the bundle while its ancestors must not be.
   fn has_nested_bundle_component(rel: &Path, ignore_last: bool) -> bool
   ```
   (`is_bundle_dir(Path::new(c.as_os_str()))` over `rel.components()`, popping the
   last component first when `ignore_last`.)
2. In the walk loop, compute the dir-relative path once:
   `let rel_dir = p.strip_prefix(dir).unwrap_or(p);` — use it for all membership
   decisions; keep `strip_prefix(root)` **only** for the reported `rel_str`.
3. Membership:
   - file entries: `if has_nested_bundle_component(rel_dir, false) { continue; }`
     before the `is_macho_file` push (replaces the `inside_nested_bundle` skip);
   - directory entries: collect for recursion only when
     `entry.file_type().is_dir() && is_bundle_dir(p) && !has_nested_bundle_component(rel_dir, true)`
     (replaces `p != dir && is_bundle_dir(p)` — also removes depth ≥ 2 duplicate
     collection);
   - **replace `p.is_dir()` with `entry.file_type().is_dir()`** (no-follow; `Path::
     is_dir` follows symlinks) and **skip symlink entries entirely**
     (`entry.file_type().is_symlink() → continue`) — symlinks are sealed as target
     strings (C5) and their real targets are verified where they live; this also
     prevents double-verifying macOS-style framework symlink chains.
4. Keep the `_CodeSignature` substring skip and `direct_binaries.push((p, rel_str))`
   unchanged.

- [ ] **Step 4: Run test — PASS**, then the full scoped gate. Expected: all green —
  in particular `signed_bundle_verifies` (the nested `Sub` frame now verifies its
  own binary against its own Info.plist/CodeResources, which the signer bound
  per-frame) and `bundle.nested.len() == 1`.

- [ ] **Step 5: Commit** (controller): `fix(zsign): verify nested bundle binaries depth-aware (ZSN-26)`

---

### Task 4: CodeResources symlink entries (queue item 4)

**Files:** `crates/zsign/src/verify.rs` (`check_code_resources`, tests).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(unix)]
#[test]
fn signed_bundle_with_framework_symlink_verifies() {
    use std::os::unix::fs::symlink;
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle_with(td.path(), |app| {
        symlink(
            "Sub",
            app.join("Frameworks").join("Sub.framework").join("SubLink"),
        )
        .unwrap();
    });
    let report = verify_bundle(&app).unwrap();
    assert!(
        report.valid(),
        "a bundle whose framework contains a sealed symlink must verify: {:?}",
        report.bundle
    );
}
```

- [ ] **Step 2: Run and confirm FAIL** — expected: invalid, `cr.unsealed` contains
  `… (sealed without a hash)` for `SubLink` (builder emits `{symlink: "Sub"}` with
  no hash fields).

- [ ] **Step 3: Implement** (design C5)

1. Sealed→disk entry dispatch (this lands before the rules/hash rework of Tasks 5–6;
   keep the current structure otherwise):
   - entry dict has `symlink` (string): treat as symlink seal —
     `fs::symlink_metadata(file_path)`: `NotFound` → `missing` (unless the entry is
     later governed by rules — for now plain missing); metadata OK but not a symlink
     → `mismatched`; symlink → `fs::read_link` equals the sealed string →
     `matched += 1`, differs → `mismatched`. No hash expectation either way.
   - entry dict without `symlink`: additionally require the on-disk object to NOT be
     a symlink before hashing (`symlink_metadata` says `is_symlink` →
     `mismatched` — a sealed file must still be a file); then hash as today.
2. Disk→sealed walk: include symlinks — `if !entry.file_type().is_file() &&
   !entry.file_type().is_symlink() { continue; }`.
3. Update the `CodeResourcesVerification::matched` doc comment: "sealed entries
   verified (hash match or symlink target match)".

- [ ] **Step 4: Run test — PASS**, then the full scoped gate. Expected: all green.

- [ ] **Step 5: Commit** (controller): `fix(zsign): verify code resources symlink entries (ZSN-26)`

---

### Task 5: Legacy hash algorithm + legacy `files` dict (queue item 5)

**Files:** `crates/zsign/src/verify.rs` (`check_code_resources`, tests; `use sha1::Sha1`).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn nested_ds_store_is_not_flagged_unsealed() {
    // Builder emission: any *.DS_Store is dropped from files2 at build, kept in
    // the legacy files dict, and omitted by rules2 (weight 2000).
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle_with(td.path(), |app| {
        fs::write(app.join("Frameworks").join(".DS_Store"), b"junk").unwrap();
    });
    let report = verify_bundle(&app).unwrap();
    assert!(
        report.valid(),
        "files-only keys are sealed; bundle: {:?}",
        report.bundle
    );
}

#[test]
fn legacy_sha1_only_entry_verifies() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle(td.path());
    let key = "Frameworks/Sub.framework/Info.plist";
    rewrite_code_resources(&app, |dict| {
        let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
        let entry = files2.get(key).unwrap().as_dictionary_mut().unwrap();
        let sha1_hash = entry.get("hash").unwrap().clone();
        let mut legacy = plist::Dictionary::new();
        legacy.insert("hash".to_string(), sha1_hash);
        files2.insert(key.to_string(), plist::Value::Dictionary(legacy));
    });
    let report = verify_bundle(&app).unwrap();
    let cr = report
        .bundle
        .as_ref()
        .unwrap()
        .code_resources
        .as_ref()
        .unwrap();
    // Deliberately CR-layer only: rewriting CodeResources also breaks the main
    // executable's slot -3 binding, which is outside this test's unit.
    assert!(cr.valid(), "SHA-1-only entries must verify: {:?}", cr);
}

#[test]
fn partial_reseal_with_updated_hash2_is_detected() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle(td.path());
    let target = app
        .join("Frameworks")
        .join("Sub.framework")
        .join("Info.plist");
    let original = fs::read(&target).unwrap();
    let mut modified = original.clone();
    modified.extend_from_slice(b"\n<!-- tampered -->\n");
    fs::write(&target, &modified).unwrap();
    rewrite_code_resources(&app, |dict| {
        let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
        let key = "Frameworks/Sub.framework/Info.plist";
        let entry = files2.get_mut(key).unwrap().as_dictionary_mut().unwrap();
        use sha2::{Digest, Sha256};
        entry.insert(
            "hash2".to_string(),
            plist::Value::Data(Sha256::digest(&modified).to_vec()),
        );
        // "hash" (SHA-1) intentionally left stale: every declared field is verified.
    });
    let report = verify_bundle(&app).unwrap();
    let cr = report
        .bundle
        .as_ref()
        .unwrap()
        .code_resources
        .as_ref()
        .unwrap();
    assert!(!cr.valid(), "a partial re-seal must be detected: {:?}", cr);
    assert!(
        cr.mismatched.iter().any(|m| m.contains("Info.plist")),
        "{:?}",
        cr.mismatched
    );
}
```

- [ ] **Step 2: Run and confirm FAIL** —
  - `nested_ds_store…`: invalid, `unsealed` contains `Frameworks/.DS_Store`
    (files2-only membership).
  - `legacy_sha1_only…`: `cr.mismatched` contains the key (20-byte SHA-1 compared
    against a SHA-256 digest).
  - `partial_reseal…`: FAILS because today `hash2` is preferred and matches →
    `cr.valid()` is true (the SHA-1 field is never consulted).

- [ ] **Step 3: Implement** (design C3)

1. `use sha1::Sha1;` next to the existing `sha2` import.
2. Restructure `check_code_resources` to build one **sealed set** =
   `files2` keys ∪ legacy `files` keys, with explicit dictionary ownership (design
   C3):
   - `files2` absent → the content error `CodeResources has no files2 dictionary`
     (already owned by Task 1) → bundle invalid, no union logic runs;
     `files2` present but not a dictionary → `CodeResources files2 is not a
     dictionary`, treated as absent (report already invalid — no silent fallback);
   - `files` absent → fine, contributes nothing; present but not a dictionary →
     `CodeResources files is not a dictionary` (same treatment);
   - no delegation of this error's ownership to Tasks 6/7 — it is fully handled here.
3. Sealed→disk: iterate `files2` entries first; then iterate `files` entries whose
   key is **not** in `files2` (files2 wins a collision — it carries both algorithms
   already). Per entry:
   - `symlink` dispatch from Task 4 unchanged;
   - value is `Data` (legal legacy form) → SHA-1 compare of the file bytes;
   - value is a dict → verify **every** declared hash field with its own
     algorithm: `hash2` → `Sha256`, `hash` → `Sha1`; all present fields must match,
     else `mismatched`; no fields at all → the existing
     "sealed without a hash" string, now pushed to `errors` (C2);
   - `String` values in `files` are malformed → `errors` (defer the message to
     Task 7's wording; pushing to `errors` now keeps one channel).
4. Missing-file handling stays as today (Task 6 adds rule-governed tolerance).
5. Disk→sealed membership test becomes `!sealed_set.contains(&rel)` (plus the rule
   lookup added in Task 6).

- [ ] **Step 4: Run tests — PASS**, then the full scoped gate. Expected: all green.

- [ ] **Step 5: Commit** (controller): `fix(zsign): verify legacy files dict with sha1 (ZSN-26)`

---

### Task 6: rules/rules2 evaluation (queue item 6)

**Files:** `crates/zsign/src/verify.rs` (`is_rule_omitted`, new rule engine,
`check_code_resources`, tests).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn optional_lproj_deletion_after_signing_stays_valid() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle_with(td.path(), |app| {
        fs::create_dir_all(app.join("en.lproj")).unwrap();
        fs::write(app.join("en.lproj").join("Localizable.strings"), b"hi").unwrap();
    });
    fs::remove_dir_all(app.join("en.lproj")).unwrap();
    let report = verify_bundle(&app).unwrap();
    assert!(
        report.valid(),
        "rules2 marks .lproj optional (weight 1000): {:?}",
        report.bundle
    );
}

#[test]
fn base_lproj_deletion_is_not_optional() {
    // Guard for weight precedence: ^Base\.lproj/ (1010, include) must beat
    // ^.*\.lproj/ (1000, optional), so a sealed Base.lproj file may not vanish.
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle_with(td.path(), |app| {
        fs::create_dir_all(app.join("Base.lproj")).unwrap();
        fs::write(app.join("Base.lproj").join("Notes.strings"), b"x").unwrap();
    });
    fs::remove_dir_all(app.join("Base.lproj")).unwrap();
    let report = verify_bundle(&app).unwrap();
    assert!(!report.valid(), "Base.lproj is required by weight precedence");
    let cr = report.bundle.as_ref().unwrap().code_resources.as_ref().unwrap();
    assert!(!cr.missing.is_empty(), "{:?}", cr);
}

#[test]
fn unsupported_rule_is_reported() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle(td.path());
    rewrite_code_resources(&app, |dict| {
        let rules2 = dict.get_mut("rules2").unwrap().as_dictionary_mut().unwrap();
        rules2.insert("^secret\\.bin$".into(), plist::Value::Boolean(true));
    });
    let report = verify_bundle(&app).unwrap();
    assert!(!report.valid());
    assert!(
        report.bundle.as_ref().unwrap().errors.iter().any(|e| e
            .contains("unsupported CodeResources rule")),
        "got {:?}",
        report.bundle.as_ref().unwrap().errors
    );
}
```

- [ ] **Step 2: Run and confirm FAIL** —
  - `optional_lproj…`: invalid, `cr.missing` contains the strings file (declared
    optional never consulted today);
  - `base_lproj…`: PASSES today (everything is missing-tolerant=nothing) — it is a
    guard against the new engine treating all `.lproj` as optional;
  - `unsupported_rule…`: FAILS — no such error exists (rules are ignored today).

- [ ] **Step 3: Implement** (design C4)

1. New private items in `verify.rs`:
   ```rust
   #[derive(Clone, Copy, PartialEq, Eq)]
   enum RuleAction { Include, Omit, Optional }
   enum RulePattern { Always, Contains(&'static str), Suffix(&'static str),
                      Prefix(&'static str), Exact(&'static str), Dsym, DsStore }
   struct Rule { pattern: RulePattern, action: RuleAction, weight: f64 }

   fn compile_rules(dict: &plist::Dictionary, errors: &mut Vec<String>) -> Vec<Rule>
   fn rule_action(rules: &[Rule], rel: &str) -> Option<RuleAction>
   ```
   **Do NOT derive `PartialOrd` on `RuleAction`** — derived order would make
   `Optional` outrank `Include` on a tie, inverting the required strictness.
   Select with an explicit comparator instead:
   ```rust
   // Tie-break on equal weight, strictest first: Include beats Omit beats Optional.
   fn tie_rank(action: RuleAction) -> u8 {
       match action {
           RuleAction::Include => 0,
           RuleAction::Omit => 1,
           RuleAction::Optional => 2,
       }
   }
   // rule_action: keep the current best rule r when
   //   r.weight > best.weight
   //   || (r.weight == best.weight && tie_rank(r.action) < tie_rank(best.action))
   ```
   `compile_rules` recognizes exactly the pattern strings in the design's C4 table
   (both `^version.plist$` spellings map to `Exact("version.plist")`); the matcher
   is plain string predicates over that subset — anchors, literal `\.`, `.*`,
   `(/)?`, `($|/)`, alternation only at that level — with a literal-prefix fast
   path where useful; **no regex engine** (`regex` is not an available dependency).
   Unknown pattern or unknown spec key/type (or `omit`+`optional` both true) →
   `errors.push(format!("unsupported CodeResources rule: {key}"))` and the rule is
   dropped. `Boolean(true/false)` → Include/Omit at weight 1.0; dict keys limited to
   `omit`/`optional`/`weight` (weight: Real or Integer → f64, default 1.0).
   Selection is **order-independent**: highest weight wins, ties by lowest
   `tie_rank` — never declaration order (`plist::Dictionary` is IndexMap-backed
   today but its docs allow the backing store to change in a minor release).
2. Rule source with fail-closed type handling (design C4): read
   `dict.get("rules2")` — present but not a dictionary →
   `errors.push("CodeResources rules2 is not a dictionary")`, treated as absent for
   evaluation (the report is already invalid — no silent fallback); otherwise use
   `rules2` when it exists, else `rules` (same wrong-type treatment for `rules`);
   **neither present** → `errors.push("CodeResources has no rules dictionary")` and
   treat lookup as "no rule matches anything" (disk check falls back to structural
   omissions only, missing entries are never tolerated).
3. `is_rule_omitted` is reduced to the two structural omissions
   (`_CodeSignature` root prefix/exact, frame main executable exact) — delete the
   `Info.plist`/`PkgInfo`/`.DS_Store`/`.lproj` arms (rules2 covers them; the
   `.lproj/` suffix arm is dead code — walked rel paths are file paths and never
   end in `/`, so it omits nothing today). Update its doc comment.
4. Wire the two check directions:
   - disk→sealed: not in sealed set → `rule_action == Omit` → exempt, else
     `unsealed.push(rel)`; no rule matched → structural check only (an unmatched
     path under a `^.*` catch-all can't happen with our rules, but don't invent
     exemptions);
   - sealed→disk: missing → tolerate **only** when `rule_action == Optional`
     (entry-level `optional` deliberately ignored — see design C4), else
     `missing.push(rel)`.
5. `use` nothing new (no regex crate — pattern predicates are plain string ops).

- [ ] **Step 4: Run tests — PASS**, then the full scoped gate. Expected: all green
  — including `signed_bundle_verifies` (Info.plist/PkgInfo/`.DS_Store` now exempted
  via rules2 instead of hard-coded arms) and `tampered_resource_fails_code_resources`
  (`data.bin` matches only the catch-all Include rule → still `unsealed`).

- [ ] **Step 5: Commit** (controller): `fix(zsign): evaluate code resources rules (ZSN-26)`

---

### Task 7: Malformed entries rejected (queue item 7)

**Files:** `crates/zsign/src/verify.rs` (`check_code_resources`, tests).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn malformed_entry_is_reported() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle(td.path());
    rewrite_code_resources(&app, |dict| {
        let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
        files2.insert(
            "Frameworks/Sub.framework/Info.plist".to_string(),
            plist::Value::String("garbage".into()),
        );
    });
    let report = verify_bundle(&app).unwrap();
    assert!(!report.valid());
    let bundle = report.bundle.as_ref().unwrap();
    assert!(
        bundle
            .errors
            .iter()
            .any(|e| e.contains("malformed CodeResources entry")),
        "got {:?}",
        bundle.errors
    );
}
```

- [ ] **Step 2: Run and confirm FAIL** — expected: the non-dict entry is silently
  skipped today (`continue`), `bundle.errors` has no malformed message.

- [ ] **Step 3: Implement** — in the sealed→disk entry dispatch: a `files2` value
  that is not a dictionary (and not reached via the Task 5 legacy-`Data` path —
  `Data` is only legal for `files`) →
  `errors.push(format!("malformed CodeResources entry: {rel}"))`, skip hash
  verification for that key, continue the loop. Same treatment for a `files` value
  that is neither `Data` nor a dictionary (Task 5 already routed it to `errors`;
  unify on this message). The bundle is invalid via `bundle.errors` regardless of
  the hash lists.

- [ ] **Step 4: Run test — PASS**, then the full scoped gate. Expected: all green.

- [ ] **Step 5: Commit** (controller): `fix(zsign): reject malformed code resources entries (ZSN-26)`

---

### Task 8: Plist-key path traversal rejected (queue item 8)

**Files:** `crates/zsign/src/verify.rs` (`check_code_resources`, tests).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn path_traversal_keys_are_rejected() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle(td.path());
    rewrite_code_resources(&app, |dict| {
        let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
        for key in ["../../../../etc/passwd", "/etc/passwd"] {
            let mut entry = plist::Dictionary::new();
            entry.insert("hash2".to_string(), plist::Value::Data(vec![0u8; 32]));
            files2.insert(key.to_string(), plist::Value::Dictionary(entry));
        }
    });
    let report = verify_bundle(&app).unwrap();
    assert!(!report.valid());
    let bundle = report.bundle.as_ref().unwrap();
    for key in ["../../../../etc/passwd", "/etc/passwd"] {
        assert!(
            bundle.errors.iter().any(|e| {
                e.contains("escapes the bundle") && e.contains(key)
            }),
            "key {key:?} must be rejected; got {:?}",
            bundle.errors
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_parent_traversal_is_rejected() {
    use std::os::unix::fs::symlink;
    use sha2::{Digest, Sha256};
    let td = tempfile::TempDir::new().unwrap();
    let outside = td.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"outside content").unwrap();
    // A legitimately sealed symlink pointing out of the bundle: the builder
    // hashes whatever read_link returns, so this signs cleanly.
    let app = build_signed_bundle_with(td.path(), |app| {
        symlink(&outside, app.join("Escape")).unwrap();
    });
    // Lexical-clean key whose intermediate component is that symlink; the
    // attacker-chosen hash2 even matches the real outside content.
    rewrite_code_resources(&app, |dict| {
        let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
        let mut entry = plist::Dictionary::new();
        entry.insert(
            "hash2".to_string(),
            plist::Value::Data(Sha256::digest(b"outside content").to_vec()),
        );
        files2.insert("Escape/secret.txt".to_string(), plist::Value::Dictionary(entry));
    });
    let report = verify_bundle(&app).unwrap();
    assert!(!report.valid());
    let bundle = report.bundle.as_ref().unwrap();
    assert!(
        bundle
            .errors
            .iter()
            .any(|e| e.contains("escapes the bundle") && e.contains("Escape/secret.txt")),
        "symlink-parent key must be rejected before any read; got {:?}",
        bundle.errors
    );
}
```

- [ ] **Step 2: Run and confirm FAIL** — expected: no escape errors for either
  test (today the keys join out of the bundle and are read/hash-compared without
  complaint; the symlink-parent key even hash-*matches*).

- [ ] **Step 3: Implement** (design C8, two stages)

1. Stage-1 helper:
   ```rust
   /// A sealed key may only address files strictly inside the bundle: every
   /// path component must be a plain name (no `..`, no absolute prefix, no `.`).
   fn is_safe_bundle_key(key: &str) -> bool {
       let path = Path::new(key);
       path.components().next().is_some()
           && path.components().all(|c| matches!(c, std::path::Component::Normal(_)))
   }
   ```
2. Stage 1: in the sealed→disk loop, validate the key **before** any `join`;
   violation → `errors.push(format!("CodeResources entry path escapes the bundle: {rel}"))`
   and `continue`. Applies to `files2` and `files` keys alike.
3. Stage 2 (resolved containment — stage 1 alone is bypassable via an in-bundle
   symlink directory, which `fs::read`/`fs::read_link` follow): at the top of
   `check_code_resources` compute
   `let bundle_real = std::fs::canonicalize(bundle).map_err(crate::Error::Io)?;`
   Then, for **every** entry — before *any* content access, i.e. before both the
   `symlink` dispatch and the hash read — canonicalize the entry's parent directory
   (the parent is `bundle` itself for root-level keys):
   - `Err(NotFound)` → the parent directory does not exist, so the sealed entry is
     absent: apply the **same rule-aware missing decision the sealed→disk loop
     already uses after Task 6** — if `rule_action(rel) == Some(Optional)` →
     tolerate (skip the entry), else `missing.push(rel)` — and `continue` without
     reading anything. (An unconditional `missing.push` here would break Task 6's
     `optional_lproj_deletion_after_signing_stays_valid` test, which deletes the
     whole `en.lproj` directory and expects a valid report.)
   - `Ok(resolved)` where `!resolved.starts_with(&bundle_real)` →
     `errors.push(format!("CodeResources entry path escapes the bundle: {rel}"))`
     and `continue`;
   - other `Err(e)` → `errors.push(format!("cannot resolve CodeResources entry path {rel}: {e}"))`
     and `continue`;
   - `Ok(resolved)` inside the bundle → proceed to the dispatch.
   The residual TOCTOU window between canonicalize and read is documented as out of
   threat model in design C8 (the verified tree is read-only to us by contract).
4. The disk→sealed walk needs no stage: its keys come from a non-following WalkDir.

- [ ] **Step 4: Run test — PASS**, then the full scoped gate. Expected: all green.

- [ ] **Step 5: Commit** (controller): `fix(zsign): reject path-escaping code resources keys (ZSN-26)`

---

### Task 9: Unchecked required special slots surfaced (queue item 9)

**Files:** `crates/zsign/src/verify.rs` (`verify_bundle_dir` slot branches,
`verify_macho_file`, tests).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn bare_verify_of_bundle_binary_reports_unchecked_slots() {
    let td = tempfile::TempDir::new().unwrap();
    let app = build_signed_bundle(td.path());
    let extracted = td.path().join("extracted-bin");
    fs::write(&extracted, fs::read(app.join("Test")).unwrap()).unwrap();
    let report = verify_macho_file(&extracted).unwrap();
    assert!(
        !report.valid(),
        "a binary binding bundle resources cannot verify bare"
    );
    assert!(
        report.errors.iter().any(|e| e.contains("without bundle context")),
        "got {:?}",
        report.errors
    );
}
```

- [ ] **Step 2: Run and confirm FAIL** — expected: `report.valid()` is `true` today
  (core reports `NotChecked`, which never flips `SliceVerifyReport::is_valid`).

- [ ] **Step 3: Implement** (design C7)

1. Bare path — after `verify_macho` succeeds in `verify_macho_file`, for each
   **signed** slice:
   ```rust
   if slice.special_slots.first() == Some(&SpecialSlotCheck::NotChecked) {
       macho_errors.push("cannot verify special slot -1 (Info.plist) without bundle context".to_string());
   }
   if slice.special_slots.get(2) == Some(&SpecialSlotCheck::NotChecked) {
       macho_errors.push("cannot verify special slot -3 (CodeResources) without bundle context".to_string());
   }
   ```
   push into `VerifyReport.errors` (import `SpecialSlotCheck` like the bundle loop
   does). Gate on `slice.signed`; never surface indices 3/5 (`-4`/`-6` content is
   defined as unavailable at Mach-O level); `Missing` (zero-filled) stays silent.
2. Bundle path — in the binary loop, drop the `&& info_plist.is_none()` /
   `&& code_resources.is_none()` gates so the invariant is explicit and covers both
   required slots symmetrically: any `NotChecked` at index 0 →
   `"signature binds Info.plist (slot -1) but the file is missing"`; at index 2 →
   `"signature binds CodeResources (slot -3) but the file is missing"`. (With Task 1,
   `NotChecked` at these indices implies the file is genuinely absent; an unreadable
   file is already a hard `Err`.)

- [ ] **Step 4: Run test — PASS**, then the full scoped gate. Expected: all green —
  `bare_macho_verifies` stays green (bare signing zero-fills -1/-3 → `Missing`,
  not `NotChecked`), `signed_bundle_*` unaffected (slots matched against present
  files).

- [ ] **Step 5: Commit** (controller): `fix(zsign): surface unchecked required special slots (ZSN-26)`

---

## Self-review (plan vs spec)

- **Spec coverage:** queue items 1–9 each map to exactly one task (Task 1…9), in
  brief order; all six mandated regressions are covered (missing root → Task 1;
  framework symlink → Task 4; tampered sealed file → guard-test exception, keep-green
  in every gate — the brief defines it as "existing tests keep passing" and they
  pass at baseline 7/7; traversal keys + symlink-parent containment → Task 8;
  missing CodeResources → Task 2; tampered nested binary → Task 3).
- **Placeholders:** none — every task carries literal test code, literal error
  strings, and literal commands; the shared helper refactor is specified as
  verbatim-move instructions outside any code stub.
- **Type consistency:** `read_opt → Result<Option<Vec<u8>>>` (Task 1) is used
  identically by Tasks 2/9; `check_code_resources(…, errors: &mut Vec<String>) ->
  Result<CodeResourcesVerification>` (Task 1) carries the `errors` channel consumed
  by Tasks 5–8; `build_signed_bundle_with` / `rewrite_code_resources` (Task 1) are
  used verbatim by Tasks 3–8; rule-engine names (`compile_rules`, `rule_action`,
  `RuleAction`, `RulePattern`, `tie_rank`) are defined once in Task 6 and referenced
  only there; `bundle_real` containment (Task 8 stage 2) is defined inside
  `check_code_resources` once.
- **Deviations recorded:** entry-level `optional` is not honored (rules are the
  single authority — design C4); `base_lproj_deletion_is_not_optional` is a guard
  test that passes pre-fix by construction; mandated regression #3 is a keep-green
  guard per the brief's own wording (see Spec coverage).

## Execution handoff

Executed by subagent-driven-development, strictly sequential (one shared file):
per task — fresh Tester (failing test first) → fresh Implementer → controller runs
the scoped gate, reviews, and commits. No task starts before the previous task's
commit is green.
