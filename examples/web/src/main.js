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
  line.innerHTML = `<span class="ts">[${elapsed}s]</span><span class="msg">${msg}</span>`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
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
  startTime = performance.now();
  const logContainer = $("#log");
  logContainer.classList.add("visible");
  logEl.innerHTML = "";
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
  startTime = performance.now();
  const logContainer = $("#log");
  logContainer.classList.add("visible");
  logEl.innerHTML = "";
  $("#summary").classList.add("hidden");
  $("#plist-output").classList.add("hidden");
  downloadBtn.classList.remove("visible");
  signBtn.disabled = true;

  try {
    // 1. Init WASM
    section("▸ Initializing WASM module");
    const wasmResponse = await fetch(wasmUrl);
    const wasmBytes = await wasmResponse.arrayBuffer();
    await initWasm({ module_or_path: wasmBytes });
    log("WASM module loaded", "ok");

    // 2. Create signer with credentials
    section("▸ Loading signing credentials");
    const password = p12Password.value;
    const signer = new WasmSigner(p12Bytes, password, profileBytes);
    const teamId = signer.team_id();
    if (teamId) {
      log(`Team ID: ${teamId}`, "ok");
    }
    log("Signer initialized with certificate and profile", "ok");

    // 3. Extract IPA
    section(`▸ Extracting ${ipaFile.name} (${formatSize(ipaFile.size)})`);
    const zipReader = new ZipReader(new BlobReader(ipaFile));
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
    const currentAppPrefix = appEntry.filename;
    const currentAppName = currentAppPrefix.match(
      /\/([^/]+)\.app\/$/,
    )[1];
    log(`Bundle: ${currentAppName}.app`, "ok");

    // Determine main executable name from Info.plist
    let mainExecName = currentAppName;
    const infoPlistEntry = entries.find(
      (e) => e.filename === `${currentAppPrefix}Info.plist`,
    );
    let infoPlistData = null;
    if (infoPlistEntry) {
      infoPlistData = await infoPlistEntry.getData(new Uint8ArrayWriter());
      const execName = tryExtractExecutableName(infoPlistData);
      if (execName) mainExecName = execName;
    }

    // 4. Read all bundle files, classify them
    section("▸ Reading bundle files");
    const bundleEntries = entries.filter(
      (e) => e.filename.startsWith(currentAppPrefix) && !e.directory,
    );

    const fileMap = new Map(); // relativePath -> Uint8Array
    const machoFiles = []; // relativePaths of Mach-O files
    let mainExecPath = null;

    for (const entry of bundleEntries) {
      const relativePath = entry.filename.slice(currentAppPrefix.length);
      if (!relativePath) continue;

      const data = await entry.getData(new Uint8ArrayWriter());
      fileMap.set(relativePath, data);

      if (isMachO(data)) {
        machoFiles.push(relativePath);
        if (relativePath === mainExecName) {
          mainExecPath = relativePath;
        }
      }
    }
    log(
      `Read ${fileMap.size} files, ${machoFiles.length} Mach-O binaries`,
      "ok",
    );
    if (mainExecPath) {
      log(`Main executable: ${mainExecPath}`, "ok");
    } else {
      log(
        `Warning: main executable "${mainExecName}" not found as Mach-O`,
        "err",
      );
    }

    // 5. Sign dylibs/frameworks first (everything except main executable)
    const signedFiles = new Map(); // relativePath -> signed Uint8Array
    const dylibsToSign = machoFiles.filter((p) => p !== mainExecPath);

    if (dylibsToSign.length > 0) {
      section(`▸ Signing ${dylibsToSign.length} dylibs/frameworks`);
      for (const relPath of dylibsToSign) {
        const data = fileMap.get(relPath);
        // Use filename as identifier for dylibs
        const identifier = relPath.split("/").pop().replace(/\.dylib$/, "");
        try {
          const signed = signer.sign_macho_fat(data, identifier, null, null);
          signedFiles.set(relPath, signed);
          log(`  ✓ ${relPath} (${formatSize(data.length)} → ${formatSize(signed.length)})`);
        } catch (e) {
          log(`  ✗ ${relPath}: ${e.message}`, "err");
          // Keep original if signing fails
          signedFiles.set(relPath, data);
        }
      }
      log(`Signed ${dylibsToSign.length} dylibs/frameworks`, "ok");
    }

    // 6. Hash all files for CodeResources (using signed versions where available)
    section("▸ Hashing bundle resources for CodeResources");
    signer.set_main_executable(mainExecName);

    let filesHashed = 0;
    let totalBytes = 0;

    for (const [relPath, data] of fileMap) {
      // Skip _CodeSignature (will be regenerated) and old mobileprovision
      if (relPath.startsWith("_CodeSignature/")) continue;
      if (relPath === "embedded.mobileprovision") continue;

      const fileData = signedFiles.get(relPath) || data;
      totalBytes += fileData.length;
      signer.hash_file(relPath, fileData);
      filesHashed++;

      if (filesHashed % 100 === 0) {
        log(`  hashed ${filesHashed} files…`);
      }
    }
    // Hash the new provisioning profile
    signer.hash_file("embedded.mobileprovision", profileBytes);
    filesHashed++;
    totalBytes += profileBytes.length;
    log(`Hashed ${filesHashed} files (${formatSize(totalBytes)})`, "ok");

    // 7. Build CodeResources
    section("▸ Building CodeResources plist");
    const codeResourcesBytes = signer.build_code_resources();
    log(
      `CodeResources generated: ${formatSize(codeResourcesBytes.length)}`,
      "ok",
    );

    // 8. Sign main executable
    if (mainExecPath) {
      section("▸ Signing main executable");
      const mainData = signedFiles.get(mainExecPath) || fileMap.get(mainExecPath);
      const bundleId = bundleIdInput.value;
      try {
        const signed = signer.sign_macho_fat(
          mainData,
          bundleId,
          infoPlistData,
          codeResourcesBytes,
        );
        signedFiles.set(mainExecPath, signed);
        log(
          `Main executable signed (${formatSize(mainData.length)} → ${formatSize(signed.length)})`,
          "ok",
        );
      } catch (e) {
        log(`Main executable signing failed: ${e.message}`, "err");
        signedFiles.set(mainExecPath, mainData);
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
    for (const entry of entries) {
      // Skip __MACOSX resource fork entries — iOS rejects these
      if (entry.filename.startsWith("__MACOSX/")) continue;

      if (entry.directory) {
        // Skip old _CodeSignature directory (will be recreated)
        if (entry.filename.startsWith(currentAppPrefix) &&
            entry.filename.slice(currentAppPrefix.length).startsWith("_CodeSignature")) {
          continue;
        }
        await zipWriter.add(entry.filename, undefined, {
          directory: true,
          externalFileAttributes: entry.externalFileAttributes || UNIX_DIR_0755,
          lastModDate: entry.lastModDate,
          versionMadeBy: VERSION_UNIX_20,
        });
        continue;
      }

      const isInBundle = entry.filename.startsWith(currentAppPrefix);
      const relativePath = isInBundle
        ? entry.filename.slice(currentAppPrefix.length)
        : null;

      if (isInBundle && relativePath) {
        // Skip old _CodeSignature (dir + files) and embedded.mobileprovision
        if (relativePath === "_CodeSignature" || relativePath.startsWith("_CodeSignature/")) continue;
        if (relativePath === "embedded.mobileprovision") continue;

        // Use signed version if available
        const data = signedFiles.get(relativePath) || fileMap.get(relativePath);
        if (data) {
          await zipWriter.add(
            entry.filename,
            new Uint8ArrayReader(data),
            {
              externalFileAttributes: entry.externalFileAttributes || UNIX_FILE_0644,
              lastModDate: entry.lastModDate,
              versionMadeBy: VERSION_UNIX_20,
            },
          );
          filesWritten++;
          continue;
        }
      }

      // Non-bundle files: copy as-is
      const data = await entry.getData(new Uint8ArrayWriter());
      await zipWriter.add(entry.filename, new Uint8ArrayReader(data), {
        externalFileAttributes: entry.externalFileAttributes || UNIX_FILE_0644,
        lastModDate: entry.lastModDate,
        versionMadeBy: VERSION_UNIX_20,
      });
      filesWritten++;
    }

    // Add _CodeSignature/ directory entry
    await zipWriter.add(
      `${currentAppPrefix}_CodeSignature/`,
      undefined,
      {
        directory: true,
        externalFileAttributes: UNIX_DIR_0755,
        versionMadeBy: VERSION_UNIX_20,
      },
    );

    // Add new CodeResources
    await zipWriter.add(
      `${currentAppPrefix}_CodeSignature/CodeResources`,
      new Uint8ArrayReader(codeResourcesBytes),
      {
        externalFileAttributes: UNIX_FILE_0644,
        versionMadeBy: VERSION_UNIX_20,
      },
    );
    filesWritten++;

    // Add provisioning profile
    await zipWriter.add(
      `${currentAppPrefix}embedded.mobileprovision`,
      new Uint8ArrayReader(profileBytes),
      {
        externalFileAttributes: UNIX_FILE_0644,
        versionMadeBy: VERSION_UNIX_20,
      },
    );
    filesWritten++;

    const blob = await zipWriter.close();
    log(`Wrote ${filesWritten} files (${formatSize(blob.size)})`, "ok");

    await zipReader.close();
    signer.free();

    // 10. Offer download
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
    log(`Done in ${elapsed}s ✓`, "ok");

    const summaryEl = $("#summary");
    summaryEl.classList.remove("hidden");
    summaryEl.innerHTML = `
      <div class="stat"><div class="value">${fileMap.size}</div><div class="label">Files Processed</div></div>
      <div class="stat"><div class="value">${machoFiles.length}</div><div class="label">Mach-O Signed</div></div>
      <div class="stat"><div class="value">${formatSize(blob.size)}</div><div class="label">Output Size</div></div>
      <div class="stat"><div class="value">${elapsed}s</div><div class="label">Elapsed</div></div>
    `;

    const url = URL.createObjectURL(blob);
    const outputName = ipaFile.name.replace(/\.ipa$/i, "_signed.ipa");
    downloadBtn.href = url;
    downloadBtn.download = outputName;
    downloadBtn.textContent = `⬇ Download ${outputName}`;
    downloadBtn.classList.add("visible");
  } catch (e) {
    log(`Error: ${e.message || e}`, "err");
    console.error(e);
  } finally {
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
