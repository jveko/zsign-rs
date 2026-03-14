# @jveko/zsign-wasm

WebAssembly bindings for [zsign-rs](https://github.com/jveko/zsign-rs) — iOS code signing in the browser.

## Features

- **Mach-O Signing** — Sign single-arch and FAT/Universal binaries
- **CodeResources** — Build `_CodeSignature/CodeResources` with file hashes
- **Streaming Hashes** — Hash large files in chunks to avoid memory pressure
- **Certificate Loading** — Parse PKCS#12 (`.p12`) files
- **Provisioning Profiles** — Extract entitlements
- **Pure Rust** — No native dependencies, runs in any WASM environment

## Usage

```javascript
import init, { WasmSigner } from '@jveko/zsign-wasm';

await init();

// Load credentials
const signer = new WasmSigner(p12Bytes, "password", profileBytes);
signer.set_main_executable("App");

// Hash resource files for CodeResources
signer.hash_file("Base.lproj/Main.storyboardc", storyboardData);
signer.hash_file("Assets.car", assetData);

// Build CodeResources and sign the main executable
const codeResources = signer.build_code_resources();
const signed = signer.sign_macho_fat(
  machoData,
  "com.example.app",
  infoPlistData,
  codeResources
);
```

### Streaming large files

```javascript
// For files too large to fit in memory at once
for (const chunk of fileChunks) {
  const isFinal = chunk === fileChunks.at(-1);
  signer.hash_file_chunk("large-asset.car", chunk, isFinal);
}
```

### Parse Mach-O metadata

```javascript
const info = WasmSigner.parse_macho(binaryData);
console.log(info.is_fat, info.slices_count);
```

### Parse Info.plist

```javascript
const plist = WasmSigner.parse_info_plist(plistData);
console.log(plist.bundle_id, plist.executable);
```

## Building from source

```bash
# Requires wasm-pack: https://rustwasm.github.io/wasm-pack/
wasm-pack build crates/zsign-wasm --target web --release --scope jveko
```

## License

MIT
