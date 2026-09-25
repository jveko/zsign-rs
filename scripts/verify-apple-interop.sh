#!/usr/bin/env bash
# Apple codesign interop verification.
#
# Signs a generated app bundle (with a nested framework) using zsign-cli, then
# verifies the output with Apple's own `codesign --verify --deep --strict`.
# This is the ground-truth trust net: if Apple's verifier accepts our output,
# the signature is actually valid. It covers the failure classes that produced
# the historical iOS install/launch rejections (0xe8008015/0xe8008017/0xe8008029
# and the iOS 26 AMFI extension kill) at the format level.
#
# Runs only on macOS. No sudo, no persisted state (the signing certificate is
# a self-signed end-entity certificate that is its own implicit trust anchor).
#
# Usage: scripts/verify-apple-interop.sh        (requires target/release/zsign-cli)

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: interop verification requires macOS (codesign)" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIGN="${ROOT}/target/release/zsign-cli"
if [[ ! -x "$ZIGN" ]]; then
    echo "error: build a release zsign-cli first (target/release/zsign-cli)" >&2
    exit 2
fi

DIAG="${ROOT}/target/interop-diagnostics.log"
{
    echo "=== zsign interop diagnostics: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    uname -a
    sw_vers
    openssl version
} >"$DIAG"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "FAIL: $*" >&2
    {
        echo "FAIL: $*"
        echo "--- workdir at failure ---"
        ls -laR "$WORK" 2>/dev/null || true
    } >>"$DIAG"
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Self-signed end-entity code-signing certificate.
#    EKU codeSigning + KU digitalSignature + CA:FALSE satisfy the leaf rules
#    enforced by the strict verifier (codeSigning EKU, digitalSignature KU,
#    CA=false); the certificate is its own implicit trust anchor.
# ---------------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK/cs_key.pem" -out "$WORK/cs_cert.pem" -days 3 \
    -subj "/CN=zsign interop CI" \
    -addext "keyUsage=digitalSignature" \
    -addext "extendedKeyUsage=codeSigning" \
    -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1
openssl pkcs12 -export -out "$WORK/cs.p12" \
    -inkey "$WORK/cs_key.pem" -in "$WORK/cs_cert.pem" \
    -passout pass:test >/dev/null 2>&1

# ---------------------------------------------------------------------------
# 2. Build a minimal app bundle with one nested framework.
# ---------------------------------------------------------------------------
build_fixture() {
    local app="$1"
    mkdir -p "$app/Frameworks/Bar.framework"

    # Use the active macOS SDK (Xcode or CommandLineTools) so clang links
    # without a hardcoded sysroot.
    cc() { xcrun --sdk macosx clang "$@"; }

    printf 'int main(void){return 42;}\n' > "$WORK/main.c"
    printf 'int bar(void){return 7;}\n'  > "$WORK/bar.c"
    cc -arch arm64 "$WORK/main.c" -o "$app/Test"
    cc -arch arm64 -dynamiclib "$WORK/bar.c" \
        -o "$app/Frameworks/Bar.framework/Bar" \
        -install_name "@rpath/Bar.framework/Bar"
    # clang/ld may ad-hoc sign; strip so we sign from an unsigned input.
    codesign --remove-signature "$app/Test" 2>/dev/null || true
    codesign --remove-signature "$app/Frameworks/Bar.framework/Bar" 2>/dev/null || true

    cat > "$app/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Test</string>
<key>CFBundleIdentifier</key><string>com.zsign.interop</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>Test</string>
</dict></plist>
PLIST
    sed -e 's|<string>Test</string>|<string>Bar</string>|' \
        -e 's|com.zsign.interop</string>|com.zsign.interop.bar</string>|' \
        "$app/Info.plist" > "$app/Frameworks/Bar.framework/Info.plist"
}

sign_and_verify() {
    local out_dir="$1" kind="$2"; shift 2
    local app="$out_dir/Test.app"
    build_fixture "$app"
    if ! "$ZIGN" "$@" "$app" >/dev/null 2>&1; then
        fail "zsign $kind signing"
    fi
    local v
    if ! v="$(codesign --verify --deep --strict --verbose=2 "$app" 2>&1)"; then
        fail "codesign --verify --deep --strict ($kind): $v"
    fi
    grep -q "valid on disk" <<<"$v" || fail "output not reported valid ($kind): $v"
    grep -q "satisfies its Designated Requirement" <<<"$v" \
        || fail "designated requirement not satisfied ($kind): $v"
    echo "OK  $kind: ${v//$'\n'/ ; }"
}

# ---------------------------------------------------------------------------
# 3. Cert-signed: Apple's verifier must accept the full-signature output.
# ---------------------------------------------------------------------------
sign_and_verify "$WORK/cert" "cert-signed (RSA, sha256-only)" \
    -p "$WORK/cs.p12" --password test

# ---------------------------------------------------------------------------
# 4. Ad-hoc: structural path (no CMS identity) must also verify.
# ---------------------------------------------------------------------------
sign_and_verify "$WORK/adhoc" "ad-hoc" -a

# ---------------------------------------------------------------------------
# 5. Entitlements ground truth: profile-derived slot -7 DER must round-trip
#    through Apple's own tools (display decode + generator cross-check).
# ---------------------------------------------------------------------------
cat > "$WORK/entitlements.xml" <<'ENTXML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>zz-counter</key><integer>42</integer>
<key>get-task-allow</key><true/>
<key>zsign-data-sample</key><data>AQID</data>
<key>application-groups</key><array><string>group.com.zsign.interop</string></array>
<key>com.zsign.interop.nested</key><dict><key>enabled</key><true/></dict>
<key>application-identifier</key><string>TEAMID.com.zsign.interop</string>
</dict></plist>
ENTXML

# Minimal fixture profile: the entitlements extractor only needs the XML
# plist window, not a real CMS signature.
python3 - "$WORK/entitlements.xml" "$WORK/fixture.mobileprovision" <<'PYPROF'
import plistlib, sys
ent = plistlib.load(open(sys.argv[1], "rb"))
with open(sys.argv[2], "wb") as fh:
    plistlib.dump({"Entitlements": ent}, fh, fmt=plistlib.FMT_XML)
PYPROF

sign_and_verify "$WORK/ent" "cert-signed (RSA, entitlements)" \
    -p "$WORK/cs.p12" --password test -m "$WORK/fixture.mobileprovision"

app="$WORK/ent/Test.app"
D=$(codesign -d --verbose=4 "$app/Test" 2>&1)
printf '%s\n' "$D" >>"$DIAG"

codesign -d --entitlements - --der "$app/Test" >"$WORK/displayed.der" 2>/dev/null \
    || fail "codesign cannot dump DER entitlements of our signature"
codesign -d --entitlements - --xml "$app/Test" >"$WORK/displayed.xml" 2>/dev/null \
    || fail "codesign cannot dump XML entitlements of our signature"

# Apple's own DER for the same XML: the documented cross-check for the
# golden-vector tests (they pin literals locally; this pins them to Apple).
build_fixture "$WORK/ref/Test.app"
codesign --force --sign - --entitlements "$WORK/entitlements.xml" \
    --generate-entitlement-der "$WORK/ref/Test.app/Test" >/dev/null 2>&1 \
    || fail "codesign --generate-entitlement-der reference signing"

if ! python3 - "$app/Test" "$WORK/ref/Test.app/Test" \
    "$WORK/displayed.der" "$WORK/displayed.xml" "$WORK/entitlements.xml" <<'PYDER'
import plistlib, struct, sys, pathlib

def slot_blob(path, wanted_type):
    data = pathlib.Path(path).read_bytes()
    off = data.rfind(b"\xfa\xde\x0c\xc0")
    count = struct.unpack(">I", data[off + 8:off + 12])[0]
    for i in range(count):
        typ, eoff = struct.unpack(">II", data[off + 12 + i * 8:off + 20 + i * 8])
        if typ == wanted_type:
            base = off + eoff
            size = struct.unpack(">I", data[base + 4:base + 8])[0]
            return data[base:base + size]
    return None

ours = slot_blob(sys.argv[1], 7)
reference = slot_blob(sys.argv[2], 7)
if ours is None:
    sys.exit("our signature has no slot 7 (DER entitlements) blob")
if reference is None:
    sys.exit("codesign reference signature has no slot 7 blob")
if ours[8:] != reference[8:]:
    sys.exit("slot -7 MISMATCH vs codesign --generate-entitlement-der:\n"
             + "  ours:     " + ours[8:].hex() + "\n  codesign: " + reference[8:].hex())
displayed = pathlib.Path(sys.argv[3]).read_bytes()
if displayed != ours[8:]:
    sys.exit("codesign --entitlements - --der output differs from our slot -7 payload")
expected = plistlib.load(open(sys.argv[5], "rb"))
shown = plistlib.load(open(sys.argv[4], "rb"))
if shown != expected:
    sys.exit("XML round-trip mismatch:\n  expected: %r\n  shown:    %r"
             % (expected, shown))
print("OK  entitlements: slot -7 matches codesign --generate-entitlement-der")
PYDER
then
    fail "der entitlements round-trip (slot -7 ground truth)"
fi

# ---------------------------------------------------------------------------
# 6. Structural asserts on the signed main binary (format regressions).
# ---------------------------------------------------------------------------
app="$WORK/cert/Test.app"
D=$(codesign -d --verbose=4 "$app/Test" 2>&1)
printf '%s\n' "$D" >>"$DIAG"
grep -q "CodeDirectory v=20400" <<<"$D"   || fail "CD version must be 0x20400"
grep -q "Hash type=sha256"       <<<"$D" || fail "primary CD must be SHA-256"
if grep -q "Hash choices=sha1" <<<"$D"; then
    fail "SHA-1 primary CodeDirectory present; modern macOS verify rejects it"
fi
grep -q "Info.plist entries=" <<<"$D" || fail "Info.plist not bound to the signature"

# ---------------------------------------------------------------------------
# 7. CMS binding: the embedded CMS must cryptographically verify over the
#    primary CodeDirectory (independent of codesign's trust evaluation).
# ---------------------------------------------------------------------------
python3 - "$app/Test" "$WORK" <<'PY'
import struct, subprocess, sys, pathlib
path, work = sys.argv[1], pathlib.Path(sys.argv[2])
data = pathlib.Path(path).read_bytes()
off = data.rfind(b"\xfa\xde\x0c\xc0")
n = struct.unpack(">I", data[off+8:off+12])[0]
slots = {}
for i in range(n):
    typ, eoff = struct.unpack(">II", data[off+12+i*8:off+20+i*8])
    slots[typ] = off + eoff
cd = data[slots[0]:slots[0]+struct.unpack(">I", data[slots[0]+4:slots[0]+8])[0]]
cms = data[slots[0x10000]+8:slots[0x10000]+struct.unpack(">I", data[slots[0x10000]+4:slots[0x10000]+8])[0]]
(work/"cd.der").write_bytes(cd)
(work/"cms.der").write_bytes(cms)
PY
openssl cms -verify -binary -inform DER \
    -in "$WORK/cms.der" -content "$WORK/cd.der" \
    -noverify -out /dev/null

# ---------------------------------------------------------------------------
# 8. zsign -V agreement: our verifier must agree with Apple's in both
#    directions — accept what codesign accepts, reject what codesign rejects.
# ---------------------------------------------------------------------------
agree_valid() {
    local label="$1" target="$2"
    local out
    if ! out="$("$ZIGN" -V "$target" 2>&1)"; then
        fail "zsign -V disagrees with codesign on $label:\n$out"
    fi
    grep -q "^verified: yes" <<<"$out" || fail "zsign -V rejected valid $label:\n$out"
    echo "OK  zsign -V accepts $label"
}

agree_invalid() {
    local label="$1" target="$2"
    local out
    out="$("$ZIGN" -V "$target" 2>&1 || true)"
    if grep -q "^verified: yes" <<<"$out"; then
        fail "zsign -V accepted $label that codesign rejects"
    fi
    echo "OK  zsign -V rejects $label"
}

# 8a. Cert-signed bundle: codesign accepts it (step 3), but zsign -V anchors
#     only to the Apple Root, so a self-signed signature must never report
#     verified: yes — pin structural validity plus the anchoring failure.
VB=$("$ZIGN" -V "$WORK/cert/Test.app" 2>&1 || true)
printf '%s\n' "$VB" >>"$DIAG"
grep -q '^verified: no'                     <<<"$VB" || fail "zsign -V must not report verified: yes for the cert-signed bundle:\n$VB"
grep -q '^    arm64: pages ok, CMS INVALID' <<<"$VB" || fail "zsign -V did not reach the structural+CMS verdict for the cert-signed bundle:\n$VB"
grep -q '^  code resources: ok'             <<<"$VB" || fail "zsign -V did not confirm sealed top-level code resources for the cert-signed bundle:\n$VB"
if grep -qi mismatch <<<"$VB"; then
    fail "zsign -V reported structural mismatches on the cert-signed bundle:\n$VB"
fi

# The detached main binary exposes the anchoring verdict: the bundle report
# keeps CMS details internal, so pin the parse evidence and the expected
# failure text on the binary instead.
VM=$("$ZIGN" -V "$WORK/cert/Test.app/Test" 2>&1 || true)
printf '%s\n' "$VM" >>"$DIAG"
grep -q '^verified: no'                   <<<"$VM" || fail "zsign -V accepted the self-signed main binary:\n$VM"
grep -q 'not anchored to a trusted root'   <<<"$VM" || fail "zsign -V missing the expected anchoring failure:\n$VM"
grep -q 'signer: CN=zsign interop CI'      <<<"$VM" || fail "zsign -V did not parse the self-signed CMS signer:\n$VM"
grep -q 'cms: INVALID (chain: CN=zsign interop CI, anchor: false)' <<<"$VM" || fail "zsign -V did not report the expected unanchored self-signed CMS state:\n$VM"
if grep -qi mismatch <<<"$VM"; then
    fail "zsign -V reported structural mismatches on the cert-signed main binary:\n$VM"
fi
echo "OK  zsign -V dual-pin: structure valid + unanchored (expected) for cert-signed bundle"

# 8b. The ad-hoc bundle codesign accepted in step 4.
agree_valid "ad-hoc bundle"       "$WORK/adhoc/Test.app"

# 8c. A real Apple-signed system binary (FAT, 16 KB pages, Apple chain).
agree_valid "Apple-signed /bin/ls" /bin/ls

# 8d. An ad-hoc signature produced by codesign itself.
cp /bin/ls "$WORK/ls-adhoc"
codesign --force -s - "$WORK/ls-adhoc" 2>/dev/null
agree_valid "codesign ad-hoc output" "$WORK/ls-adhoc"

# 8d. Negative control: tamper a signed binary — codesign and zsign must both
#     reject it.
cp "$WORK/cert/Test.app/Test" "$WORK/Test.tampered"
printf '\x90' | dd of="$WORK/Test.tampered" bs=1 seek=64 conv=notrunc 2>/dev/null
if codesign --verify "$WORK/Test.tampered" >/dev/null 2>&1; then
    fail "codesign accepted tampered binary (negative control broken)"
fi
agree_invalid "tampered binary" "$WORK/Test.tampered"

echo "PASS: Apple codesign interop verification (incl. zsign -V agreement)"
