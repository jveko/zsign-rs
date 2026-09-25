# ZSN-4 Fuzz Regression Net — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended)
> with dispatching-parallel-agents for independent tasks to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Six cargo-fuzz targets + committed seed corpus + weekly CI smoke over the hardened
parser surfaces, with every found panic reported (never fixed) to its owning lane.

**Architecture:** `fuzz/` workspace member whose `[[bin]]`s carry
`required-features = ["fuzzing"]` so normal workspace builds never touch them; raw-`&[u8]`
harnesses over the six verified public entries; seeds copied/generated under
`fuzz/corpus/<target>/`; a standalone scheduled `fuzz.yml`. Design rationale and citations:
`docs/superpowers/specs/2026-09-25-fuzz-targets-design.md` (read before executing).

**Tech Stack:** cargo-fuzz 0.13.2 + libfuzzer-sys 0.4 (nightly required: local toolchain
`nightly-2026-04-30`), `zsign-core` path dep, `time` 0.3 (fixed clock).

**Hard rules for every task:** edit only `fuzz/**`, root `Cargo.toml` (members line only),
`.github/workflows/fuzz.yml`; never run `cargo fmt`/`cargo clippy`/`hk`; never merge/push;
set `TMPDIR=$PWD/.tmptmp` on every cargo command; ticket ID in commit subjects only, never in
code comments; conventional commit subjects (imperative, lowercase); verify
`git status --short` shows exactly the intended paths before each commit.

---

### Task 1: Fuzz crate scaffold, six targets, workspace wiring

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/.gitignore`
- Create: `fuzz/fuzz_targets/superblob.rs`
- Create: `fuzz/fuzz_targets/code_directory.rs`
- Create: `fuzz/fuzz_targets/verify_code_signature.rs`
- Create: `fuzz/fuzz_targets/pkcs12.rs`
- Create: `fuzz/fuzz_targets/plist_to_der.rs`
- Create: `fuzz/fuzz_targets/provisioning.rs`
- Modify: `Cargo.toml` (members line only)
- Modified by cargo: `Cargo.lock`

- [ ] **Step 1: Write `fuzz/Cargo.toml`**

```toml
[package]
name = "zsign-fuzz"
version = "0.0.0"
publish = false
edition = "2021"
rust-version.workspace = true

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = { version = "0.4", optional = true }
zsign-core = { path = "../crates/zsign-core" }
time = { version = "0.3", features = ["parsing", "formatting"] }

[features]
fuzzing = ["dep:libfuzzer-sys"]

[[bin]]
name = "superblob"
path = "fuzz_targets/superblob.rs"
test = false
doc = false
bench = false
required-features = ["fuzzing"]

[[bin]]
name = "code_directory"
path = "fuzz_targets/code_directory.rs"
test = false
doc = false
bench = false
required-features = ["fuzzing"]

[[bin]]
name = "verify_code_signature"
path = "fuzz_targets/verify_code_signature.rs"
test = false
doc = false
bench = false
required-features = ["fuzzing"]

[[bin]]
name = "pkcs12"
path = "fuzz_targets/pkcs12.rs"
test = false
doc = false
bench = false
required-features = ["fuzzing"]

[[bin]]
name = "plist_to_der"
path = "fuzz_targets/plist_to_der.rs"
test = false
doc = false
bench = false
required-features = ["fuzzing"]

[[bin]]
name = "provisioning"
path = "fuzz_targets/provisioning.rs"
test = false
doc = false
bench = false
required-features = ["fuzzing"]
```

Notes: no `[workspace]` table (member + workspace table = "multiple workspace roots" error);
dependency path is `../crates/zsign-core` (never `path = ".."`); no `arbitrary` dep (raw-byte
targets only).

- [ ] **Step 2: Write `fuzz/.gitignore`**

```
target/
artifacts/
coverage/
```

(`corpus/` must stay trackable — the committed seeds live there. Listing `target/` here is
intentionally redundant with the root `.gitignore`'s bare `target/` rule: the scratch-corpus
hygiene in Tasks 2/4 depends on `fuzz/target/` being ignored, so this lane pins it itself.)

- [ ] **Step 3: Add `"fuzz"` to root `Cargo.toml` members**

```toml
members = ["crates/zsign", "crates/zsign-core", "crates/zsign-wasm", "crates/zsign-cli", "fuzz"]
```

No other root-manifest change (root has no `[workspace.dependencies]`/`[workspace.lints]`).

- [ ] **Step 4: Write the six target files**

`fuzz/fuzz_targets/superblob.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::codesign::constants::CSSLOT_REQUIREMENTS;
use zsign_core::codesign::verify::{
    check_special_slots, parse_requirements, parse_superblob, SignatureInputs,
};

fuzz_target!(|data: &[u8]| {
    let Ok(blob) = parse_superblob(data) else {
        return;
    };
    let mut inputs = SignatureInputs::none();
    let (info_plist, code_resources) = data.split_at(data.len() / 2);
    inputs.info_plist = Some(info_plist);
    inputs.code_resources = Some(code_resources);
    for entry in &blob.entries {
        let _ = entry.payload();
        if entry.slot == CSSLOT_REQUIREMENTS {
            let _ = parse_requirements(entry.blob);
        }
    }
    if let Some(cd) = &blob.code_directory {
        let _ = cd.identifier();
        let _ = cd.team_id();
        let _ = cd.raw();
        let _ = cd.cdhash();
        let _ = cd.cdhash_sha256();
        let _ = cd.effective_code_limit();
        let _ = cd.code_hashes();
        let _ = check_special_slots(cd, &inputs, &blob);
    }
    for cd in &blob.alternate_code_directories {
        let _ = cd.cdhash();
        let _ = cd.effective_code_limit();
    }
});
```

`fuzz/fuzz_targets/code_directory.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::codesign::verify::{check_code_pages, CodeDirectory};

fuzz_target!(|data: &[u8]| {
    let Ok(cd) = CodeDirectory::parse(data) else {
        return;
    };
    let _ = cd.identifier();
    let _ = cd.team_id();
    let _ = cd.cdhash();
    let _ = cd.cdhash_sha256();
    let _ = cd.effective_code_limit();
    let _ = cd.code_hashes();
    let _ = check_code_pages(&cd, data);
});
```

(`check_code_pages` at `codesign/verify.rs:856` is the pub entry that executes
`1usize << cd.page_size_log2` — deliberately exercised; any shift-overflow panic found here
is a REPORT routed to ZSN-29, never a fix in this lane.)

`fuzz/fuzz_targets/verify_code_signature.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::codesign::verify::SignatureInputs;
use zsign_core::crypto::cms_verify::verify_code_signature;
use zsign_core::macho::verify_macho;

fuzz_target!(|data: &[u8]| {
    let _ = verify_macho(data, &SignatureInputs::none());
    let zero = [0u8; 32];
    let _ = verify_code_signature(data, data, None, &zero);
});
```

`fuzz/fuzz_targets/pkcs12.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::crypto::SigningCredentials;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let declared_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let password_len = declared_len.min(data.len() - 4);
    let password = String::from_utf8_lossy(&data[4..4 + password_len]);
    // PBKDF2 iteration counts up to 10 million are in-range by design; slow inputs are expected here.
    let _ = SigningCredentials::from_p12(&data[4 + password_len..], &password);
});
```

(Split convention — `u32`-BE password length prefix; seeds carry the same prefix so real
fixture bytes decode verbatim.)

`fuzz/fuzz_targets/plist_to_der.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use zsign_core::codesign::der::plist_to_der;

fuzz_target!(|data: &[u8]| {
    let _ = plist_to_der(data);
});
```

`fuzz/fuzz_targets/provisioning.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;
use zsign_core::provisioning::{
    extract_entitlements_from_profile, validate_and_extract_profile, ProfileRequest,
};

fuzz_target!(|data: &[u8]| {
    let Ok(now) = OffsetDateTime::from_unix_timestamp(1_800_000_000) else {
        return;
    };
    let request = ProfileRequest {
        now: Some(now),
        ..ProfileRequest::default()
    };
    let _ = validate_and_extract_profile(data, &request);
    let _ = extract_entitlements_from_profile(data);
});
```

(Fixed clock `1_800_000_000` = repo convention; both pub provisioning entries per input.)

- [ ] **Step 5: Type-check the fuzz crate on stable (fast iteration gate)**

Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-fuzz --features fuzzing`
Expected: `Finished` with zero warnings (this compiles the bins + `libfuzzer-sys` build.rs;
clang++ 22 is present). Fix any type error in the targets — do NOT touch library source.

- [ ] **Step 6: Scoped build gate (verbatim for the final report)**

Run:
```
TMPDIR=$PWD/.tmptmp cargo +nightly-2026-04-30 fuzz build --features fuzzing
```
Expected: all six bins build under ASan; exit 0. If it fails with a missing `rust-src`
(`-Zbuild-std` path), run `rustup component add rust-src --toolchain nightly-2026-04-30`
once and retry; any other failure → diagnose with the systematic-debugging skill, and if the
cause is in library source, REPORT it (do not fix).

- [ ] **Step 7: Workspace gate**

Run: `TMPDIR=$PWD/.tmptmp cargo check --workspace`
Expected: passes; fuzz bins are skipped (required-features) — confirms the non-fuzz build is
unaffected. Then inspect `git diff Cargo.lock`: expect exactly three added entries
(`libfuzzer-sys`, `arbitrary`, the path member `zsign-fuzz`) with no version changes —
cargo produced this diff; never hand-edit the lock. (A five-package list with a `cc` bump is
a fresh-project artifact, not this repo's diff.)

- [ ] **Step 8: Commit the series' first commit**

```
git add fuzz/ Cargo.toml Cargo.lock
git status --short   # must show exactly: Cargo.toml, Cargo.lock, fuzz/**
git commit -m "feat(fuzz): add cargo-fuzz crate with six parser targets (ZSN-4)"
```

---

### Task 2: Seed corpus (derive + generate + ingestion evidence)

**Files:**
- Create: `fuzz/corpus/pkcs12/*.bin` (13 files)
- Create: `fuzz/corpus/verify_code_signature/*.bin` (3 files)
- Create: `fuzz/corpus/superblob/*.bin` (3 files)
- Create: `fuzz/corpus/code_directory/*.bin` (3 files)
- Create: `fuzz/corpus/plist_to_der/*.xml` (9 files)
- Create: `fuzz/corpus/provisioning/*` (2 files)
- Temporary (deleted before commit): `.tmptmp/gen/` throwaway generator crate

Total: 33 committed seed files.

- [ ] **Step 1: Copy the plain-derived seeds**

```sh
mkdir -p fuzz/corpus/verify_code_signature
cp crates/zsign/src/ipa/fixtures/minimal_macho.bin fuzz/corpus/verify_code_signature/minimal_macho.bin
```

- [ ] **Step 2: Build the PKCS#12 seeds with the password prefix**

Password rule (verified in source): every fixture uses `testpassword` except
`empty_password.p12` (empty string) — cross-check against the `VARIANTS` table at
`crates/zsign-core/src/crypto/pkcs12.rs:913-923`, the identity/weak fixtures at
`cert.rs:885/:896/:1232`, and `raw_keybag` at `pkcs12.rs:1353`. Then, from
`crates/zsign-core/src/crypto/fixtures/*.p12`, write one
`fuzz/corpus/pkcs12/<stem>.bin` per fixture as
`u32::BE(password.len()) ‖ password bytes ‖ p12 bytes` (Python one-liner loop is fine;
`empty_password` gets length 0). Print each output size — expected ≈1.7–3.4 KB + 4.

- [ ] **Step 3: Write the throwaway generator `.tmptmp/gen`**

`.tmptmp/gen/Cargo.toml`:

```toml
[package]
name = "corpus-gen"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
zsign-core = { path = "../../crates/zsign-core" }
sha2 = "0.10"
```

(The empty `[workspace]` detaches this throwaway from the parent workspace; it lives under
`.tmptmp/` and is deleted at the end of this task.)

`.tmptmp/gen/src/main.rs`:

```rust
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use zsign_core::codesign::constants::{
    CSMAGIC_BLOBWRAPPER, CSSLOT_CODEDIRECTORY, CSSLOT_ENTITLEMENTS, CSSLOT_REQUIREMENTS,
};
use zsign_core::codesign::{
    build_entitlements_blob, build_requirements_blob, build_superblob, BlobEntry,
    CodeDirectoryBuilder,
};
use zsign_core::crypto::cms::sign_code_directory;
use zsign_core::crypto::SigningCredentials;
use zsign_core::macho::{sign_macho_adhoc, MachOFile};

const ENTITLEMENTS_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>get-task-allow</key><false/></dict></plist>"#;

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, bytes).expect("write");
    println!("{} ({} bytes)", path.display(), bytes.len());
}

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = manifest.join("../../fuzz/corpus");
    let code: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();

    let cd_sha256 = CodeDirectoryBuilder::new("com.example.fuzzseed", &code).build_sha256();
    let cd_sha1 = CodeDirectoryBuilder::new("com.example.fuzzseed", &code).build_sha1();
    let cd_team = CodeDirectoryBuilder::new("com.example.fuzzseed", &code)
        .team_id("ABCDE12345")
        .build_sha256();

    write(&out.join("code_directory/cd_sha256.bin"), &cd_sha256);
    write(&out.join("code_directory/cd_sha1.bin"), &cd_sha1);
    write(&out.join("code_directory/cd_team.bin"), &cd_team);

    write(
        &out.join("superblob/sb_cd_req.bin"),
        &build_superblob(vec![
            BlobEntry::new(CSSLOT_CODEDIRECTORY, cd_sha256.clone()),
            BlobEntry::new(CSSLOT_REQUIREMENTS, build_requirements_blob()),
        ]),
    );
    write(
        &out.join("superblob/sb_full.bin"),
        &build_superblob(vec![
            BlobEntry::new(CSSLOT_CODEDIRECTORY, cd_sha256.clone()),
            BlobEntry::new(CSSLOT_ENTITLEMENTS, build_entitlements_blob(ENTITLEMENTS_XML)),
            BlobEntry::new(CSSLOT_REQUIREMENTS, build_requirements_blob()),
        ]),
    );
    write(&out.join("superblob/sb_empty.bin"), &build_superblob(vec![]));

    let macho_bytes = fs::read(manifest.join("../../crates/zsign/src/ipa/fixtures/minimal_macho.bin"))
        .expect("macho fixture");
    let macho = MachOFile::parse(macho_bytes).expect("fixture parses");
    let signed = sign_macho_adhoc(&macho, "com.example.fuzzseed", None, None, None, false)
        .expect("adhoc sign");
    write(&out.join("verify_code_signature/signed_macho_adhoc.bin"), &signed);

    let p12 = fs::read(manifest.join(
        "../../crates/zsign-core/src/crypto/fixtures/modern_pbes2_aes256.p12",
    ))
    .expect("p12 fixture");
    let creds = SigningCredentials::from_p12(&p12, "testpassword").expect("fixture loads");
    let cd_hash: [u8; 32] = Sha256::digest(&cd_sha256).into();
    let cms = sign_code_directory(&cd_sha256, &creds, None, &cd_hash).expect("cms mint");
    // sign_code_directory returns a bare DER ContentInfo; verify_code_signature
    // needs the blob-wrapper header, verify_cms_envelope must not get one.
    let mut wrapped = Vec::with_capacity(8 + cms.len());
    wrapped.extend_from_slice(&CSMAGIC_BLOBWRAPPER.to_be_bytes());
    wrapped.extend_from_slice(&((8 + cms.len()) as u32).to_be_bytes());
    wrapped.extend_from_slice(&cms);
    write(
        &out.join("verify_code_signature/code_directory_cms_wrapped.bin"),
        &wrapped,
    );
    write(&out.join("provisioning/cms_signed_data.bin"), &cms);
}
```

Expected output: every `expect` succeeds and prints the seed sizes. Contingencies (record
which applied): if `SigningCredentials::from_p12` rejects `modern_pbes2_aes256.p12`, retry
`identity_single.p12` then `modern_aes128.p12`; if `sign_code_directory` errors, record the
error verbatim and drop both CMS seeds (31 of 33 files remain; state this as a plan
deviation).

- [ ] **Step 4: Run the generator and delete it**

```
TMPDIR=$PWD/.tmptmp cargo run --manifest-path .tmptmp/gen/Cargo.toml --release
rm -rf .tmptmp/gen
```

- [ ] **Step 5: Transcribe the plist seeds (exactly 9 files)**

- Transcribe these **input** plist literals of the golden tests in
  `crates/zsign-core/src/codesign/der.rs` (tests span `:384-723`), one file each:
  `dict_empty.xml`, `dict_simple.xml`, `dict_nested.xml`, `dict_array.xml`, `dict_time.xml`
  (the date/GeneralizedTime case), and `dict_bigint.xml` (the out-of-i64 rejection input at
  `der.rs:610`). If one of these tests builds its input with `format!` instead of a literal,
  construct the equivalent XML from the test's intent and note it.
- Construct (no copyable literal exists — verified): `dict_long.xml` = the same
  single-`<key>`/`<string>` XML the long-form test builds with `"x".repeat(130)`
  (`test_plist_to_der_long_form_lengths`, `der.rs:653-677`); `dict_negint.xml` = a dict with
  one `<integer>-42</integer>` entry (the negative-int cases at `der.rs:705-723` are
  `encode_value` unit tests with no XML fixture).
- Copy `PROFILE_XML` (`crates/zsign-wasm/src/lib.rs:703-716`) to
  `fuzz/corpus/provisioning/profile_plist.xml` **and**
  `fuzz/corpus/plist_to_der/profile_plist.xml`.

- [ ] **Step 6: Corpus hygiene gates (verbatim for the final report)**

```sh
git check-ignore fuzz/corpus/superblob/sb_empty.bin; echo "ignore-exit=$?"    # expect exit 1 (a real corpus path)
du -sk fuzz/corpus/*                                                        # every dir < 256
find fuzz/corpus -type f | wc -l                                            # expect exactly 33
git status --short                                                          # exactly fuzz/corpus/** (plus .tmptmp/ which must be EMPTY/removed)
```

- [ ] **Step 7: Seed-ingestion + deliberate-mutation evidence (Tester-red equivalent)**

For each of the six targets:
```sh
mkdir -p fuzz/target/smoke-corpus/<target>
TMPDIR=$PWD/.tmptmp cargo +nightly-2026-04-30 fuzz run <target> --features fuzzing \
  fuzz/target/smoke-corpus/<target> fuzz/corpus/<target> -- -runs=2000 -timeout=25 -print_final_stats=1
```
Both corpus dirs are passed explicitly — cargo-fuzz adds the automatic `fuzz/corpus/<target>`
only when *no* user dir is given (`project.rs` `if !run.corpus.is_empty()`), so a scratch-only
command would load zero seeds. Scratch goes first (libFuzzer's writeback dir), committed
seeds second (read-only). `-print_final_stats=1` is required for the
`stat::number_of_executed_units:` line to print (verified against cargo-fuzz 0.13.2). Record verbatim per target: the `#N INITED cov: … corp: M …` line
(M ≥ committed seed count proves ingestion) and the closing `stat::number_of_executed_units:`
summary (a nonzero count proves mutation ran). All six
must exit 0 (a crash here is a REPORT under the design-doc §8 classification — record it,
keep going; do not fix). The first-dir writeback keeps run output in the scratch dir —
verify `git status` stays clean afterward.

- [ ] **Step 8: Commit**

```
git add fuzz/corpus
git status --short   # exactly fuzz/corpus/**
git commit -m "feat(fuzz): add seed corpus derived from committed fixtures (ZSN-4)"
```

---

### Task 3: Weekly CI smoke workflow

**Files:**
- Create: `.github/workflows/fuzz.yml` (the only file in this task)

- [ ] **Step 1: Write the workflow**

```yaml
name: fuzz

on:
  schedule:
    - cron: "43 3 * * 1"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: fuzz-${{ github.ref }}
  cancel-in-progress: true

jobs:
  fuzz-smoke:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: nightly-2026-04-30
      - uses: taiki-e/install-action@v2.87.20
        with:
          tool: cargo-fuzz
      - uses: Swatinem/rust-cache@v2
      - name: build fuzz targets
        run: cargo fuzz build --features fuzzing
      - name: fuzz smoke
        run: |
          set -eu
          targets=$(cargo fuzz list)
          status=0
          for target in $targets; do
            mkdir -p "fuzz/target/smoke-corpus/$target"
            [ -d "fuzz/corpus/$target" ] || { echo "missing seed corpus for $target"; exit 1; }
            cargo fuzz run "$target" --features fuzzing \
              "fuzz/target/smoke-corpus/$target" "fuzz/corpus/$target" -- \
              -max_total_time=30 -timeout=25 -rss_limit_mb=2048 || status=$?
          done
          exit $status
      - name: upload crash artifacts
        if: failure() || cancelled()
        uses: actions/upload-artifact@v7.0.1
        with:
          name: fuzz-artifacts
          path: fuzz/artifacts/
```

Conventions matched (design §7): action pins exactly as `ci.yml`/`examples-web.yml` use them,
with one deliberate documented exception — `dtolnay/rust-toolchain@master` + explicit
`toolchain: nightly-2026-04-30` (README's documented input form; a dated nightly so weekly
reds are attributable to repo changes, not a floating channel; matches the locally validated
toolchain); own `fuzz-` concurrency prefix (ZSN-31 block shape); bare `workflow_dispatch` like
`examples-web.yml`; loop driven by `cargo fuzz list` (assignment-captured so a list failure
trips `set -eu`) with a per-target seed-dir precondition and accumulated exit status so one
crash cannot forfeit the other targets; scratch corpus dir first so CI never mutates the
committed corpus; artifacts uploaded on `failure() || cancelled()`; `--features fuzzing` on
both cargo-fuzz invocations — load-bearing: without it cargo-fuzz
matches no targets (hard error on `run`, "no targets matched" warning on bare `build`),
gutting the workflow either way.

- [ ] **Step 2: Lint gate (verbatim for the final report)**

Run: `actionlint .github/workflows/fuzz.yml`
Expected: no output, exit 0 (actionlint 1.7.12 from mise). Fix only `fuzz.yml`.

- [ ] **Step 3: Structural cross-check**

Confirm against `ci.yml:8-13` and `examples-web.yml:4-6` that the permissions/concurrency/
trigger blocks use the same shapes; confirm no other workflow file changed
(`git status --short` shows exactly `.github/workflows/fuzz.yml`).

- [ ] **Step 4: Commit**

```
git add .github/workflows/fuzz.yml
git commit -m "ci(fuzz): add weekly fuzz smoke workflow (ZSN-4)"
```

---

### Task 4: 60-second-per-target smoke runs (recorded evidence)

**Files:** none (evidence goes to the final report).

- [ ] **Step 1: Run each target for 60 s, verbatim**

For each of the six targets:
```sh
mkdir -p fuzz/target/smoke-corpus/<target>
TMPDIR=$PWD/.tmptmp cargo +nightly-2026-04-30 fuzz run <target> --features fuzzing \
  fuzz/target/smoke-corpus/<target> fuzz/corpus/<target> -- -max_total_time=60 -timeout=25 -rss_limit_mb=2048 -print_final_stats=1
```
(Both dirs mandatory — see Task 2 Step 7: scratch first for writeback, committed corpus
second so the seeds actually load.)
Record the full command, the `#N INITED cov: … corp: M …` init line, the closing
`stat::number_of_executed_units:` summary, wall-clock result, and exit code for every target.

- [ ] **Step 2: Classify and route**

Apply design §8: `CLEAN` is a valid recorded result; any `PANIC`/`ABORT`/`TIMEOUT`/`OOM`
yields a REPORT with panic site `file:line`, owning lane (ZSN-29 codesign/*+cms_verify BER ·
ZSN-33 macho signer/writer/parser/builder · ZSN-39 ipa/* · ZSN-5 main.rs · otherwise
supervisor-routed candidate), and a one-line repro
`cargo fuzz run <target> --features fuzzing fuzz/artifacts/<target>/<file> -- -runs=0`.
**Stale-finding rule (ZSN-29 landed on main as `2e06a17` after this branch's base):** a crash
in the shift / multiply / special-slot / BER classes is expected on this pre-fix branch —
record it verbatim but classify `STALE (fixed on main 2e06a17; no routing)`; only classes
still open on main (design §8: plist_to_der encode recursion, PBKDF2 TIMEOUT) route to an
owner, and any of the fixed classes crashing AFTER `2e06a17` merges would be a NEW finding.
Artifacts land in
`fuzz/artifacts/` (gitignored). `ENV` failures: retry once with `TMPDIR=$PWD/.tmptmp`, then
record honestly.

- [ ] **Step 3: Final hygiene check**

`git status --short` — only untracked/ignored paths under `fuzz/target/`, `.tmptmp/` are
acceptable; **no** modifications under `fuzz/corpus/` (writeback went to the scratch dir).
If any generated corpus file appeared anyway, `git checkout -- fuzz/corpus` / remove it —
the committed corpus is immutable during runs.

---

## Self-review (plan author)

- **Spec coverage:** six targets (Task 1) · corpus provenance + ingestion evidence (Task 2) ·
  scheduled+dispatch workflow + actionlint (Task 3) · 60s recorded smoke + classification
  routing (Task 4) · workspace wiring + `cargo check --workspace` gate (Task 1 Steps 3/7) ·
  lock committed with the fuzz-crate commit (Task 1 Step 8) · no library edits anywhere.
- **Placeholders:** none — every target, manifest, and workflow is complete code; corpus
  transcriptions cite their exact source lines; generator contingencies are explicit rules,
  not gaps.
- **Type consistency:** entry-point names/signatures match the design doc §3 table and the
  in-tree `file:line` citations; `required-features = ["fuzzing"]` is paired with
  `--features fuzzing` on every cargo-fuzz invocation (Tasks 1, 2, 3, 4).
