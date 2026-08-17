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
# a self-signed code-signing CA that is its own implicit trust anchor).
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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Self-signed code-signing certificate.
#    EKU codeSigning + KU digitalSignature + CA:TRUE make it valid under
#    SecTrustEvaluate's code-signing policy even without a system anchor.
# ---------------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK/cs_key.pem" -out "$WORK/cs_cert.pem" -days 3 \
    -subj "/CN=zsign interop CI" \
    -addext "keyUsage=digitalSignature" \
    -addext "extendedKeyUsage=codeSigning" \
    -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
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
# 5. Structural asserts on the signed main binary (format regressions).
# ---------------------------------------------------------------------------
app="$WORK/cert/Test.app"
D=$(codesign -d --verbose=4 "$app/Test" 2>&1)
grep -q "CodeDirectory v=20400" <<<"$D"   || fail "CD version must be 0x20400"
grep -q "Hash type=sha256"       <<<"$D" || fail "primary CD must be SHA-256"
if grep -q "Hash choices=sha1" <<<"$D"; then
    fail "SHA-1 primary CodeDirectory present; modern macOS verify rejects it"
fi
grep -q "Info.plist entries=" <<<"$D" || fail "Info.plist not bound to the signature"

# ---------------------------------------------------------------------------
# 6. CMS binding: the embedded CMS must cryptographically verify over the
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

echo "PASS: Apple codesign interop verification"
