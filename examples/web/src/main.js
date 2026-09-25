import initWasm, { WasmSigner } from "zsign-wasm";
import wasmUrl from "zsign-wasm/zsign_wasm_bg.wasm?url";
import {
  ZipReader,
  ZipWriter,
  BlobReader,
  BlobWriter,
  Uint8ArrayReader,
  Uint8ArrayWriter,
} from "@zip.js/zip.js";

const $ = (sel) => document.querySelector(sel);
const logEl = $("#log-lines");
let startTime;

// --- State ---
let ipaFile = null;
let ipaEntries = null;
let appPrefix = "";
let appName = "";
let p12Bytes = null;
let profileBytes = null;
let signingInProgress = false;
let wasmReady = false;

// --- DOM refs ---
const dropZone = $("#drop-zone");
const fileInput = $("#file-input");
const dropLabel = $("#drop-label");
const configSection = $("#config-section");
const p12Input = $("#p12-input");
const p12Btn = $("#p12-btn");
const p12Password = $("#p12-password");
const profileInput = $("#profile-input");
const profileBtn = $("#profile-btn");
const bundleIdInput = $("#bundle-id");
const signBtn = $("#sign-btn");
const downloadBtn = $("#download-btn");

// --- Logging ---

function log(msg, cls = "") {
  const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
  const line = document.createElement("div");
  line.className = `log-line ${cls}`;
  const ts = document.createElement("span");
  ts.className = "ts";
  ts.textContent = `[${elapsed}s]`;
  const body = document.createElement("span");
  body.className = "msg";
  body.textContent = msg;
  line.append(ts, body);
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function fmtErr(e) {
  const code = e && e.code ? `[${e.code}] ` : "";
  return `${code}${(e && e.message) || e}`;
}

function section(msg) {
  log(msg, "section");
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// --- Mach-O detection ---

function isMachO(data) {
  if (data.length < 4) return false;
  const magic =
    (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
  return [
    0xfeedface, 0xfeedfacf, // big-endian (MH_MAGIC, MH_MAGIC_64)
    0xcefaedfe, 0xcffaedfe, // little-endian (MH_CIGAM, MH_CIGAM_64)
    0xcafebabe, 0xbebafeca, // FAT (big-endian, little-endian)
  ].includes(magic >>> 0);
}

// --- Bundle layout helpers ---

// Last path component without its extension; the identifier for a binary
// that is not a bundle's main executable.
function fileStem(path) {
  const parts = path.split("/").filter((part) => part.length > 0);
  const name = parts.length > 0 ? parts[parts.length - 1] : path;
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(0, dot) : name;
}

function isSymlinkEntry(entry) {
  if ((entry.versionMadeBy >> 8) !== 3) return false;
  const mode =
    ((entry.externalFileAttributes >>> 16) & 0xffff) || (entry.unixMode ?? 0);
  return (mode & 0xf000) === 0xa000;
}

const HASH_FILE_MAX = 128 * 1024 * 1024; // landed wasm hash_file buffer limit
const HASH_CHUNK = 64 * 1024 * 1024;

function hashEntry(signer, relPath, bytes) {
  if (bytes.length <= HASH_FILE_MAX) {
    signer.hash_file(relPath, bytes);
    return;
  }
  for (let off = 0; off < bytes.length; off += HASH_CHUNK) {
    const end = Math.min(off + HASH_CHUNK, bytes.length);
    signer.hash_file_chunk(relPath, bytes.subarray(off, end), end >= bytes.length);
  }
}

// --- Info.plist parsing via WASM ---

function tryExtractBundleId(plistData, wasmReady) {
  if (wasmReady) {
    try {
      const info = WasmSigner.parse_info_plist(plistData);
      return info.bundle_id || null;
    } catch (_) {
      // fall through to text-based fallback
    }
  }
  // Fallback: try XML regex
  const text = new TextDecoder("utf-8", { fatal: false }).decode(plistData);
  const xmlMatch = text.match(
    /<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/,
  );
  return xmlMatch ? xmlMatch[1] : null;
}

function tryExtractExecutableName(plistData, wasmReady) {
  if (wasmReady) {
    try {
      const info = WasmSigner.parse_info_plist(plistData);
      return info.executable || null;
    } catch (_) {
      // fall through to text-based fallback
    }
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(plistData);
  const match = text.match(
    /<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/,
  );
  return match ? match[1] : null;
}

// --- IPA loading ---

async function loadIpa(file) {
  if (signingInProgress) return; // a mid-run drop must not start a second run
  startTime = performance.now();
  const logContainer = $("#log");
  logContainer.classList.add("visible");
  logEl.replaceChildren();
  $("#summary").classList.add("hidden");
  $("#plist-output").classList.add("hidden");
  downloadBtn.classList.remove("visible");

  section(`▸ Reading ${file.name} (${formatSize(file.size)})`);

  // Init WASM early so we can parse binary plists
  let wasmReady = false;
  try {
    const wasmResponse = await fetch(wasmUrl);
    const wasmBytes = await wasmResponse.arrayBuffer();
    await initWasm({ module_or_path: wasmBytes });
    wasmReady = true;
    log("WASM module loaded", "ok");
  } catch (_) {
    log("WASM not loaded yet — using fallback plist parser");
  }

  const zipReader = new ZipReader(new BlobReader(file));
  const entries = await zipReader.getEntries();
  log(`Found ${entries.length} entries in archive`);

  // Find .app bundle root
  const appEntry = entries.find((e) =>
    e.filename.match(/Payload\/[^/]+\.app\/$/),
  );
  if (!appEntry) {
    log("No .app bundle found in IPA", "err");
    await zipReader.close();
    return;
  }
  appPrefix = appEntry.filename;
  appName = appPrefix.match(/\/([^/]+)\.app\/$/)[1];
  log(`Found bundle: ${appName}.app`, "ok");

  // Read Info.plist to extract bundle ID
  const infoPlistEntry = entries.find(
    (e) => e.filename === `${appPrefix}Info.plist`,
  );
  if (infoPlistEntry) {
    const plistData = await infoPlistEntry.getData(new Uint8ArrayWriter());
    const bundleId = tryExtractBundleId(plistData, wasmReady);
    if (bundleId) {
      bundleIdInput.value = bundleId;
      log(`Bundle ID: ${bundleId}`, "ok");
    } else {
      bundleIdInput.value = "";
      log("Could not auto-detect bundle ID — please enter manually", "err");
    }
    const execName = tryExtractExecutableName(plistData, wasmReady);
    if (execName && execName !== appName) {
      log(`CFBundleExecutable: ${execName} (differs from .app name)`, "ok");
    }
  } else {
    log("Info.plist not found in bundle", "err");
  }

  await zipReader.close();

  ipaFile = file;
  ipaEntries = null; // will re-read during signing

  // Update UI
  dropZone.classList.add("loaded");
  dropLabel.textContent = `${file.name} loaded`;
  configSection.classList.add("visible");
  updateSignButton();
}

// --- Sign button readiness ---

function updateSignButton() {
  if (signingInProgress) return; // a run owns the button until finally recomputes state
  const ready =
    ipaFile !== null &&
    p12Bytes !== null &&
    p12Password.value.length > 0 &&
    profileBytes !== null &&
    bundleIdInput.value.length > 0;
  signBtn.disabled = !ready;
  signBtn.classList.toggle("ready", ready);
}

// --- File chooser helpers ---

function readFileAsUint8Array(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

p12Btn.addEventListener("click", () => p12Input.click());
p12Input.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  p12Bytes = await readFileAsUint8Array(file);
  p12Btn.textContent = file.name;
  p12Btn.classList.add("has-file");
  updateSignButton();
});

profileBtn.addEventListener("click", () => profileInput.click());
profileInput.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  profileBytes = await readFileAsUint8Array(file);
  profileBtn.textContent = file.name;
  profileBtn.classList.add("has-file");
  updateSignButton();
});

p12Password.addEventListener("input", updateSignButton);
bundleIdInput.addEventListener("input", updateSignButton);

// --- Signing flow ---

async function signIpa() {
  // Snapshot inputs so a mid-run DOM mutation cannot change this run; disabling is a belt.
  const run = {
    ipaFile,
    p12Bytes,
    password: p12Password.value,
    profileBytes,
    bundleId: bundleIdInput.value,
  };
  signingInProgress = true;
  for (const el of [p12Input, profileInput, p12Password, bundleIdInput, fileInput]) {
    el.disabled = true;
  }
  startTime = performance.now();
  const logContainer = $("#log");
  logContainer.classList.add("visible");
  logEl.replaceChildren();
  $("#summary").classList.add("hidden");
  $("#plist-output").classList.add("hidden");
  downloadBtn.classList.remove("visible");
  signBtn.disabled = true;

  let rootSigner = null;
  let nestedSigner = null;
  let zipReader = null;
  let machoSigned = 0;
  try {
    // 1. Init WASM
    section("▸ Initializing WASM module");
    const wasmResponse = await fetch(wasmUrl);
    const wasmBytes = await wasmResponse.arrayBuffer();
    await initWasm({ module_or_path: wasmBytes });
    log("WASM module loaded", "ok");

    // 2. Create signer with credentials
    section("▸ Loading signing credentials");
    rootSigner = new WasmSigner(run.p12Bytes, run.password, run.profileBytes);
    nestedSigner = new WasmSigner(run.p12Bytes, run.password, null);
    const teamId = rootSigner.team_id();
    if (teamId) {
      log(`Team ID: ${teamId}`, "ok");
    }
    log("Signer initialized with certificate and profile", "ok");

    // 3. Extract IPA
    section(`▸ Extracting ${run.ipaFile.name} (${formatSize(run.ipaFile.size)})`);
    zipReader = new ZipReader(new BlobReader(run.ipaFile));
    const entries = await zipReader.getEntries();
    log(`Found ${entries.length} entries in archive`);

    // Find .app bundle root
    const appEntry = entries.find((e) =>
      e.filename.match(/Payload\/[^/]+\.app\/$/),
    );
    if (!appEntry) {
      log("No .app bundle found in IPA", "err");
      await zipReader.close();
      zipReader = null;
      return;
    }
    const currentAppPrefix = appEntry.filename;
    const currentAppName = currentAppPrefix.match(
      /\/([^/]+)\.app\/$/,
    )[1];
    log(`Bundle: ${currentAppName}.app`, "ok");

    // Every bundle's Info.plist, including the root's, is read once in the
    // resolution pass below. The root's bytes are then the single authority:
    // the signedFiles key, the plist embedded in the signature, and the
    // emitted archive all come from that one read.

    // Full zip path -> bytes that replace the source entry in the output.
    const signedFiles = new Map();
    signedFiles.set(`${currentAppPrefix}embedded.mobileprovision`, run.profileBytes);

    // 4. Walk the entry table: validate names, record source directories, and
    // discover every nested bundle by its ancestor path.
    section("▸ Inspecting archive layout");
    const rootSignatureDir = `${currentAppPrefix}_CodeSignature/`;
    const isRootSignaturePath = (p) => p.startsWith(rootSignatureDir);

    const sourceDirs = new Set(); // zip directory entry paths, trailing slash
    const bundleDepths = new Map(); // bundle prefix -> bundle components below root
    bundleDepths.set(currentAppPrefix, 0);
    let processedFiles = 0;

    const BUNDLE_DIR = /^(.+)\.(app|framework|appex)$/i;
    for (const entry of entries) {
      if (entry.filename !== entry.filename.trim()) {
        throw new Error(`entry name has leading or trailing whitespace: ${JSON.stringify(entry.filename)}`);
      }
      if (entry.directory) {
        // The root _CodeSignature subtree is reserved for regenerated output.
        if (!isRootSignaturePath(entry.filename)) sourceDirs.add(entry.filename);
        continue;
      }
      if (!entry.filename.startsWith(currentAppPrefix)) continue;
      processedFiles++;
      let dir = entry.filename.slice(0, entry.filename.lastIndexOf("/") + 1);
      for (;;) {
        const leaf = dir.slice(dir.lastIndexOf("/", currentAppPrefix.length - 1) + 1, -1);
        const component = dir.slice(currentAppPrefix.length);
        if (
          component.length > 0 &&
          !isRootSignaturePath(dir) &&
          BUNDLE_DIR.test(leaf)
        ) {
          bundleDepths.set(dir, component.split("/").filter(Boolean).length);
        }
        if (dir.length <= currentAppPrefix.length) break;
        dir = dir.slice(0, dir.lastIndexOf("/", currentAppPrefix.length - 1) + 1);
      }
    }

    const bundleOrder = [...bundleDepths].sort((a, b) => b[1] - a[1]);
    log(
      `${processedFiles} files, ${bundleOrder.length} bundles (${bundleOrder.length - 1} nested)`,
      "ok",
    );

    // 5. Reject a symlink anywhere a generated output must land.
    const generatedPaths = new Set([
      `${currentAppPrefix}Info.plist`,
      `${currentAppPrefix}embedded.mobileprovision`,
    ]);
    for (const [prefix] of bundleOrder) {
      generatedPaths.add(`${prefix}_CodeSignature/CodeResources`);
    }
    for (const entry of entries) {
      if (!entry.directory && isSymlinkEntry(entry) && generatedPaths.has(entry.filename)) {
        throw new Error(`generated output path is a symlink: ${entry.filename}`);
      }
    }

    // 6. Resolve every bundle's main executable before any signing: the
    // executables are what the child CodeResources files are scoped against.
    const bundles = [];
    for (const [prefix] of bundleOrder) {
      const isRoot = prefix === currentAppPrefix;
      const plistPath = `${prefix}Info.plist`;
      const plistEntry = entries.find((e) => e.filename === plistPath);
      if (!plistEntry) {
        throw new Error(`bundle ${prefix} has no Info.plist`);
      }
      const plistData = await plistEntry.getData(new Uint8ArrayWriter());
      const execName = tryExtractExecutableName(plistData, wasmReady);
      if (!execName) {
        throw new Error(`bundle ${prefix} has no CFBundleExecutable`);
      }
      const execRel = execName;
      const execFull = `${prefix}${execRel}`;
      let found = false;
      for (const entry of entries) {
        if (entry.directory || entry.filename !== execFull || isSymlinkEntry(entry)) continue;
        if (isMachO(await entry.getData(new Uint8ArrayWriter()))) {
          found = true;
          break;
        }
      }
      if (!found) {
        throw new Error(
          `main executable "${execFull}" of bundle ${prefix} is missing or is not a Mach-O file`,
        );
      }
      const identifier = isRoot
        ? run.bundleId
        : (tryExtractBundleId(plistData, wasmReady) || fileStem(prefix));
      bundles.push({ prefix, isRoot, execRel, execFull, identifier });
      // One authority per bundle: the map key, the plist embedded in the main
      // executable's signature, and the emitted bytes all read from here.
      signedFiles.set(`${prefix}Info.plist`, plistData);
    }
    log(
      `Sealing ${bundles.length} bundles innermost-first: ${bundles.map((b) => b.prefix).join(", ")}`,
      "ok",
    );

    // 7. Seal each bundle innermost-first so a parent's CodeResources covers
    // already-signed child binaries and freshly built child signatures.
    for (const bundle of bundles) {
      const { prefix, isRoot, execRel, execFull } = bundle;
      const signer = isRoot ? rootSigner : nestedSigner;

      // a. Sign this bundle's own non-main Mach-O files, before any hashing.
      const signFailures = [];
      let signedHere = 0;
      for (const entry of entries) {
        if (entry.directory || !entry.filename.startsWith(prefix)) continue;
        if (isSymlinkEntry(entry) || entry.filename === execFull) continue;
        // Descendant bundles own their own subtree.
        if (bundles.some((b) => b !== bundle && b.prefix.length > prefix.length && entry.filename.startsWith(b.prefix))) {
          continue;
        }
        const name = entry.filename.slice(prefix.length);
        if (name.startsWith("_CodeSignature/")) continue;
        // One decompression serves both the Mach-O test and the sign call.
        const data = await entry.getData(new Uint8ArrayWriter());
        if (!isMachO(data)) continue;
        try {
          const signed = signer.sign_macho_fat(data, fileStem(name), null, null);
          signedFiles.set(entry.filename, signed);
          machoSigned++;
          signedHere++;
          log(`  ✓ ${name} (${formatSize(data.length)} → ${formatSize(signed.length)})`);
        } catch (e) {
          log(`  ✗ ${name}: ${fmtErr(e)}`, "err");
          signFailures.push(`${name}: ${fmtErr(e)}`);
        }
      }
      if (signFailures.length > 0) {
        throw new Error(
          `Signing failed for ${signFailures.length} binaries — no output produced:\n` +
            signFailures.join("\n"),
        );
      }
      if (signedHere > 0) log(`Signed ${signedHere} nested binaries in ${prefix}`, "ok");

      // b. Start this bundle's resources round.
      signer.reset_resources();
      signer.set_main_executable(execRel);

      // c. Hash the bundle subtree, plus every generated child output that has
      //    no source entry (child CodeResources plists).
      let filesHashed = 0;
      let totalBytes = 0;
      const hashOne = (relPath, bytes) => {
        hashEntry(signer, relPath, bytes);
        filesHashed++;
        totalBytes += bytes.length;
        if (filesHashed % 100 === 0) log(`  hashed ${filesHashed} files…`);
      };
      for (const entry of entries) {
        if (entry.directory || !entry.filename.startsWith(prefix)) continue;
        if (entry.filename === execFull) continue;
        const relPath = entry.filename.slice(prefix.length);
        if (relPath === "" || relPath.startsWith("_CodeSignature/")) continue;
        if (relPath === "embedded.mobileprovision") {
          // The root's profile is replaced by the run's; a nested bundle keeps
          // whatever profile it shipped, so its own round must seal those bytes.
          if (isRoot) {
            hashOne(relPath, run.profileBytes);
          } else {
            hashOne(relPath, signedFiles.get(entry.filename) || (await entry.getData(new Uint8ArrayWriter())));
          }
          continue;
        }
        hashOne(relPath, signedFiles.get(entry.filename) || (await entry.getData(new Uint8ArrayWriter())));
      }
      for (const [fullPath, bytes] of signedFiles) {
        if (!fullPath.startsWith(prefix) || fullPath === execFull) continue;
        if (entries.some((e) => !e.directory && e.filename === fullPath)) continue;
        hashOne(fullPath.slice(prefix.length), bytes);
      }
      log(`Hashed ${filesHashed} files for ${prefix} (${formatSize(totalBytes)})`, "ok");

      // d. Build and record this bundle's CodeResources.
      const codeResourcesBytes = signer.build_code_resources();
      signedFiles.set(`${prefix}_CodeSignature/CodeResources`, codeResourcesBytes);
      log(`CodeResources for ${prefix}: ${formatSize(codeResourcesBytes.length)}`, "ok");

      // e. Sign this bundle's main executable last: it embeds the signature.
      const mainData = signedFiles.get(execFull) || (await entries.find((e) => e.filename === execFull).getData(new Uint8ArrayWriter()));
      try {
        const signed = signer.sign_macho_fat(
          mainData,
          bundle.identifier,
          signedFiles.get(`${prefix}Info.plist`),
          codeResourcesBytes,
        );
        signedFiles.set(execFull, signed);
        machoSigned++;
        log(
          `Main executable signed for ${prefix} (${formatSize(mainData.length)} → ${formatSize(signed.length)})`,
          "ok",
        );
      } catch (e) {
        log(`Main executable signing failed for ${prefix}: ${fmtErr(e)}`, "err");
        throw new Error(`Main executable signing failed for ${prefix}: ${fmtErr(e)}`);
      }
    }

    // 8. Every generated output must exist before the archive is rewritten.
    for (const bundle of bundles) {
      for (const path of [bundle.execFull, `${bundle.prefix}_CodeSignature/CodeResources`]) {
        if (!signedFiles.has(path)) {
          throw new Error(`missing generated output for ${path}`);
        }
      }
    }
    for (const path of [`${currentAppPrefix}Info.plist`, `${currentAppPrefix}embedded.mobileprovision`]) {
      if (!signedFiles.has(path)) {
        throw new Error(`missing generated output for ${path}`);
      }
    }

    // 9. Build output ZIP
    section("▸ Creating signed IPA");
    const zipWriter = new ZipWriter(new BlobWriter("application/zip"), {
      dataDescriptor: false,
    });

    // Unix permissions encoded as externalFileAttributes (mode << 16)
    const UNIX_FILE_0644 = 0o100644 << 16;
    const UNIX_DIR_0755 = 0o40755 << 16;
    // versionMadeBy: Unix (system=3) + zip version 2.0 (20)
    const VERSION_UNIX_20 = (3 << 8) | 20;

    let filesWritten = 0;
    const emitted = new Set();
    for (const entry of entries) {
      // Skip __MACOSX resource fork entries — iOS rejects these
      if (entry.filename.startsWith("__MACOSX/")) continue;

      if (entry.directory) {
        // The root _CodeSignature subtree is reserved; the write pass recreates it.
        if (isRootSignaturePath(entry.filename)) continue;
        await zipWriter.add(entry.filename, undefined, {
          directory: true,
          externalFileAttributes: entry.externalFileAttributes || UNIX_DIR_0755,
          lastModDate: entry.lastModDate,
          versionMadeBy: VERSION_UNIX_20,
        });
        emitted.add(entry.filename);
        continue;
      }

      // Stale signature subtree and the old profile are replaced, not copied.
      if (isRootSignaturePath(entry.filename)) continue;
      if (entry.filename === `${currentAppPrefix}embedded.mobileprovision`) continue;

      const override = signedFiles.get(entry.filename);
      if (override !== undefined) {
        await zipWriter.add(
          entry.filename,
          new Uint8ArrayReader(override),
          {
            externalFileAttributes: entry.externalFileAttributes || UNIX_FILE_0644,
            lastModDate: entry.lastModDate,
            versionMadeBy: VERSION_UNIX_20,
          },
        );
        emitted.add(entry.filename);
        filesWritten++;
        continue;
      }

      // Symlinks keep their own payload and attributes. The read and the write
      // options here are transitional; they are finalized separately.
      if (isSymlinkEntry(entry)) {
        const target = await entry.getData(new Uint8ArrayWriter());
        await zipWriter.add(entry.filename, new Uint8ArrayReader(target), {
          externalFileAttributes: entry.externalFileAttributes,
          lastModDate: entry.lastModDate,
          versionMadeBy: VERSION_UNIX_20,
        });
        emitted.add(entry.filename);
        filesWritten++;
        continue;
      }

      const data = await entry.getData(new Uint8ArrayWriter());
      await zipWriter.add(entry.filename, new Uint8ArrayReader(data), {
        externalFileAttributes: entry.externalFileAttributes || UNIX_FILE_0644,
        lastModDate: entry.lastModDate,
        versionMadeBy: VERSION_UNIX_20,
      });
      emitted.add(entry.filename);
      filesWritten++;
    }

    // Append generated outputs the archive never carried, creating their
    // signature directory when the source archive had none.
    for (const name of [...signedFiles.keys()].filter((k) => !emitted.has(k)).sort()) {
      const dir = name.slice(0, name.lastIndexOf("/") + 1);
      if (!sourceDirs.has(dir) && !emitted.has(dir)) {
        await zipWriter.add(dir, undefined, {
          directory: true,
          externalFileAttributes: UNIX_DIR_0755,
          versionMadeBy: VERSION_UNIX_20,
        });
        emitted.add(dir);
      }
      await zipWriter.add(name, new Uint8ArrayReader(signedFiles.get(name)), {
        externalFileAttributes: UNIX_FILE_0644,
        versionMadeBy: VERSION_UNIX_20,
      });
      emitted.add(name);
      filesWritten++;
    }

    const blob = await zipWriter.close();
    log(`Wrote ${filesWritten} files (${formatSize(blob.size)})`, "ok");

    // 10. Offer download
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
    log(`Done in ${elapsed}s ✓`, "ok");

    const summaryEl = $("#summary");
    summaryEl.classList.remove("hidden");
    summaryEl.replaceChildren(
      ...[
        [String(processedFiles), "Files Processed"],
        [String(machoSigned), "Mach-O Signed"],
        [formatSize(blob.size), "Output Size"],
        [`${elapsed}s`, "Elapsed"],
      ].map(([value, label]) => {
        const stat = document.createElement("div");
        stat.className = "stat";
        const v = document.createElement("div");
        v.className = "value";
        v.textContent = value;
        const l = document.createElement("div");
        l.className = "label";
        l.textContent = label;
        stat.append(v, l);
        return stat;
      }),
    );

    const url = URL.createObjectURL(blob);
    const outputName = run.ipaFile.name.replace(/\.ipa$/i, "_signed.ipa");
    downloadBtn.href = url;
    downloadBtn.download = outputName;
    downloadBtn.textContent = `⬇ Download ${outputName}`;
    downloadBtn.classList.add("visible");
  } catch (e) {
    log(`Error: ${fmtErr(e)}`, "err");
    console.error(e);
  } finally {
    if (rootSigner) {
      rootSigner.free();
      rootSigner = null;
    }
    if (nestedSigner) {
      nestedSigner.free();
      nestedSigner = null;
    }
    if (zipReader) {
      await zipReader.close();
      zipReader = null;
    }
    signingInProgress = false;
    for (const el of [p12Input, profileInput, p12Password, bundleIdInput, fileInput]) {
      el.disabled = false;
    }
    updateSignButton();
  }
}

// --- Wire up drop zone ---

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});
dropZone.addEventListener("dragleave", () =>
  dropZone.classList.remove("dragover"),
);
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) loadIpa(file);
});
fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) loadIpa(file);
});

signBtn.addEventListener("click", () => {
  if (!signBtn.disabled) signIpa();
});
