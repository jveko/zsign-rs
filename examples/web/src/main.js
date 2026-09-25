import initWasm, { WasmSigner } from "zsign-wasm";
import wasmUrl from "zsign-wasm/zsign_wasm_bg.wasm?url";
import {
  ZipReader,
  ZipWriter,
  BlobReader,
  BlobWriter,
  Uint8ArrayReader,
  Uint8ArrayWriter,
  Writer,
} from "@zip.js/zip.js";

const $ = (sel) => document.querySelector(sel);
const logEl = $("#log-lines");
let startTime;

// --- State ---
let ipaFile = null;
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

// The single app root is derived from file paths, not from directory entries:
// an archive may legitimately omit those, and only paths say which bundle the
// files belong to. Ambiguity is an error rather than a silent first match.
function findAppRoot(entries) {
  const prefixes = new Set();
  for (const entry of entries) {
    if (entry.directory) continue;
    const m = entry.filename.match(/^Payload\/([^/]+\.app)\//);
    if (m) prefixes.add(`Payload/${m[1]}/`);
  }
  if (prefixes.size === 0) {
    throw new Error("No Payload/<name>.app bundle found in the archive");
  }
  if (prefixes.size > 1) {
    throw new Error(
      `Archive contains ${prefixes.size} top-level apps (${[...prefixes].join(", ")}) — expected exactly one`,
    );
  }
  const prefix = [...prefixes][0];
  return { prefix, name: prefix.slice("Payload/".length, -".app/".length) };
}

class CappedWriter extends Writer {
  constructor(max) {
    super();
    this.max = max;
    this.parts = [];
    this.total = 0;
    this.capError = null;
  }

  init(initSize) {
    this.parts = [];
    this.total = 0;
    this.capError = null;
    super.init(initSize);
  }

  writeUint8Array(array) {
    this.total += array.length;
    if (this.total > this.max) {
      this.capError = new Error(`entry expands past ${this.max} bytes`);
      throw this.capError;
    }
    this.parts.push(array.slice());
  }

  getData() {
    const out = new Uint8Array(this.total);
    let off = 0;
    for (const part of this.parts) {
      out.set(part, off);
      off += part.length;
    }
    return out;
  }
}

async function readCapped(entry, max) {
  const writer = new CappedWriter(max);
  try {
    return await entry.getData(writer);
  } catch (e) {
    // the reader's teardown can mask the cap error — surface ours
    if (writer.capError) throw writer.capError;
    throw e;
  }
}

function decodeStrict(bytes, what) {
  try {
    // ignoreBOM keeps a leading U+FEFF in the string, so re-encoding yields the
    // exact input bytes; the default would strip it and the sealed text would
    // no longer match the bytes the write pass emits.
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (_) {
    throw new Error(`${what} is not valid UTF-8`);
  }
}

const HASH_FILE_MAX = 128 * 1024 * 1024; // landed wasm hash_file buffer limit
const HASH_CHUNK = 64 * 1024 * 1024;

const MAX_P12_BYTES = 4 * 1024 * 1024; // landed wasm credential limits, checked here for a friendlier error
const MAX_PROFILE_BYTES = 16 * 1024 * 1024;

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
    // A ready parser is authoritative: its errors carry a code and the regex
    // below cannot read binary plists, so swallowing them hides the failure.
    const info = WasmSigner.parse_info_plist(plistData);
    return info.bundle_id || null;
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
    const info = WasmSigner.parse_info_plist(plistData);
    return info.executable || null;
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(plistData);
  const match = text.match(
    /<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/,
  );
  return match ? match[1] : null;
}

function rewriteBundleIdentifier(plistBytes, newId) {
  if (!/^[A-Za-z0-9._-]+$/.test(newId) || newId.length > 255) {
    throw new Error(
      `Bundle ID "${newId}" is invalid — letters, digits, dot, dash and underscore only (max 255)`,
    );
  }
  if (plistBytes.length < 8) {
    throw new Error("Info.plist is too short to be a plist");
  }
  const head = String.fromCharCode(
    plistBytes[0], plistBytes[1], plistBytes[2], plistBytes[3],
    plistBytes[4], plistBytes[5], plistBytes[6], plistBytes[7],
  );
  if (head === "bplist00") return rewriteBinaryBundleId(plistBytes, newId);
  const text = new TextDecoder("utf-8", { fatal: false }).decode(plistBytes);
  if (text.startsWith("<?xml") || text.startsWith("<plist")) {
    return rewriteXmlBundleId(plistBytes, newId);
  }
  throw new Error("Unsupported Info.plist format — expected XML or binary plist");
}

function rewriteXmlBundleId(bytes, newId) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (_) {
    throw new Error("Info.plist XML is not valid UTF-8");
  }
  if (text.indexOf("<plist") === -1) {
    throw new Error("Unsupported Info.plist format — expected XML or binary plist");
  }
  // Depth-aware scan: only ROOT-dict direct entries count, and the value element
  // immediately following the key must be a bounded <string>. Matches are COUNTED
  // during the scan (no early return — plist parsers are last-wins, so rewriting
  // only the first of two root keys would desynchronize the emitted plist from the
  // signed identifier) and rejected unless exactly one exists.
  const tagRe = /<[^>]*>/g;
  tagRe.lastIndex = text.indexOf("<");
  let depth = 0;
  let pendingRootKey = false;
  let matches = 0;
  let valueStart = -1;
  let innerLen = -1;
  let m;
  while ((m = tagRe.exec(text)) !== null) {
    const tag = m[0];
    if (pendingRootKey) {
      // Consumed by the very next tag — BEFORE any close-tag handling, so a stray
      // close between the key and its value fails closed instead of deferring the
      // pending key onto a later, unrelated <string>.
      if (!tag.startsWith("<string>")) {
        throw new Error("CFBundleIdentifier value is not a string");
      }
      const start = m.index + "<string>".length;
      // Element-bounded match: stop at THIS element's close; a '<' before it means
      // malformed content — never search onward through the document.
      const sm = /^([^<]*)<\/string>/.exec(text.slice(start));
      if (!sm) throw new Error("CFBundleIdentifier string value is unterminated");
      matches += 1;
      if (matches === 1) {
        valueStart = start;
        innerLen = sm[1].length;
      }
      pendingRootKey = false;
      tagRe.lastIndex = start + sm[0].length;
      continue;
    }
    if (tag.startsWith("</")) {
      if (tag.startsWith("</dict") || tag.startsWith("</array")) depth -= 1;
      continue;
    }
    if (tag.startsWith("<dict") || tag.startsWith("<array")) {
      if (!tag.endsWith("/>")) depth += 1;
      continue;
    }
    if (depth !== 1) continue;
    if (tag.startsWith("<key>")) {
      const keyStart = m.index + tag.length;
      const keyEnd = text.indexOf("</key>", keyStart);
      if (keyEnd === -1) throw new Error("Info.plist has an unterminated key");
      const km = /^([^<]*)<\/key>/.exec(text.slice(keyStart));
      if (!km) throw new Error("Info.plist has a malformed key element");
      if (km[1] === "CFBundleIdentifier") pendingRootKey = true;
      tagRe.lastIndex = keyStart + km[0].length;
    }
  }
  if (pendingRootKey) throw new Error("CFBundleIdentifier has no value element");
  if (matches === 0) {
    throw new Error("Info.plist root dictionary has no CFBundleIdentifier key");
  }
  if (matches > 1) {
    throw new Error(
      `Info.plist has ${matches} root CFBundleIdentifier keys — refusing to rewrite (ambiguous)`,
    );
  }
  const current = text.slice(valueStart, valueStart + innerLen);
  if (current === newId) return bytes;
  const updated = text.slice(0, valueStart) + newId + text.slice(valueStart + innerLen);
  return new TextEncoder().encode(updated);
}

function readPlistU64(view, offset) {
  return view.getUint32(offset) * 0x100000000 + view.getUint32(offset + 4);
}

function rewriteBinaryBundleId(bytes, newId) {
  const len = bytes.length;
  if (len < 40) throw new Error("Malformed binary plist (too short)");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const offsetIntSize = bytes[len - 26];
  const objectRefSize = bytes[len - 25];
  const numObjects = readPlistU64(view, len - 24);
  const topObject = readPlistU64(view, len - 16);
  const offsetTableOffset = readPlistU64(view, len - 8);
  if (offsetIntSize < 1 || offsetIntSize > 8 || objectRefSize < 1 || objectRefSize > 8 ||
      numObjects < 1 || topObject >= numObjects ||
      offsetTableOffset + numObjects * offsetIntSize !== len - 32) {
    throw new Error("Unsupported binary plist layout (trailer not adjacent to offset table)");
  }
  const readOffset = (i) => {
    let o = 0;
    for (let k = 0; k < offsetIntSize; k++) o = o * 256 + bytes[offsetTableOffset + i * offsetIntSize + k];
    if (o >= offsetTableOffset) {
      throw new Error("Malformed binary plist: object offset outside object table");
    }
    return o;
  };
  const readRef = (p) => {
    let r = 0;
    for (let k = 0; k < objectRefSize; k++) r = r * 256 + bytes[p + k];
    if (r >= numObjects) {
      throw new Error("Malformed binary plist: object reference out of range");
    }
    return r;
  };
  const parseHeader = (off) => {
    if (off < 8 || off >= offsetTableOffset) {
      throw new Error("Malformed binary plist: object starts outside object table");
    }
    const marker = bytes[off];
    if (marker === 0x0f) {
      // One-byte fill object (Apple CFBinaryPList.c): never a length prefix and
      // never a container — object censuses must skip it, not reject the file.
      return { type: 0, count: 0, headerEnd: off + 1 };
    }
    let count = marker & 0x0f;
    let p = off + 1;
    if (count === 0x0f) {
      const intMarker = bytes[p];
      if (intMarker >> 4 !== 1) throw new Error("Malformed binary plist length");
      const n = 1 << (intMarker & 0x0f);
      count = 0;
      for (let k = 0; k < n; k++) count = count * 256 + bytes[p + 1 + k];
      p += 1 + n;
    }
    if (p > offsetTableOffset) {
      throw new Error("Malformed binary plist: header past object table");
    }
    return { type: marker >> 4, count, headerEnd: p };
  };
  const decodeString = (off) => {
    const h = parseHeader(off);
    const unit = h.type === 5 ? 1 : h.type === 6 ? 2 : 0;
    if (unit === 0) return null;
    if (h.headerEnd + h.count * unit > offsetTableOffset) {
      throw new Error("Malformed binary plist: string payload past object table");
    }
    if (h.type === 5) {
      return { text: new TextDecoder("utf-8", { fatal: false })
          .decode(bytes.subarray(h.headerEnd, h.headerEnd + h.count)),
        end: h.headerEnd + h.count };
    }
    if (h.type === 6) {
      let s = "";
      for (let i = 0; i < h.count; i++) {
        s += String.fromCharCode((bytes[h.headerEnd + 2 * i] << 8) | bytes[h.headerEnd + 2 * i + 1]);
      }
      return { text: s, end: h.headerEnd + 2 * h.count };
    }
    return null;
  };
  const top = parseHeader(readOffset(topObject));
  if (top.type !== 13) throw new Error("Binary plist root is not a dictionary");
  if (top.headerEnd + top.count * 2 * objectRefSize > offsetTableOffset) {
    throw new Error("Malformed binary plist: dictionary payload past object table");
  }
  const keyCount = top.count;
  const keysAt = top.headerEnd;
  const valsAt = keysAt + keyCount * objectRefSize;
  // Binary plists may deduplicate equal strings: a value object referenced from
  // more than just this dict slot must not be spliced (it would corrupt the other
  // reference) — count every container ref pointing at it and reject if shared.
  // Comparison currency is the OBJECT-TABLE INDEX (what readRef returns), never a
  // byte offset.
  const countRefsTo = (targetIndex) => {
    let refs = 0;
    for (let i = 0; i < numObjects; i++) {
      const h = parseHeader(readOffset(i));
      if (h.type !== 10 && h.type !== 12 && h.type !== 13) continue;
      const refCount = h.type === 13 ? h.count * 2 : h.count;
      if (h.headerEnd + refCount * objectRefSize > offsetTableOffset) {
        throw new Error("Malformed binary plist: container payload past object table");
      }
      for (let j = 0; j < refCount; j++) {
        if (readRef(h.headerEnd + j * objectRefSize) === targetIndex) refs++;
      }
    }
    return refs;
  };
  // Count FIRST: binary plists may contain the root key more than once and the
  // plist parser is last-wins — rewriting only the first would desynchronize the
  // emitted plist from the signed identifier.
  let matchIdx = -1;
  let matches = 0;
  for (let i = 0; i < keyCount; i++) {
    const key = decodeString(readOffset(readRef(keysAt + i * objectRefSize)));
    if (key && key.text === "CFBundleIdentifier") {
      matches += 1;
      if (matchIdx === -1) matchIdx = i;
    }
  }
  if (matches === 0) throw new Error("Info.plist has no CFBundleIdentifier key");
  if (matches > 1) {
    throw new Error(
      `Info.plist has ${matches} root CFBundleIdentifier keys — refusing to rewrite (ambiguous)`,
    );
  }
  const i = matchIdx;
  const valIdx = readRef(valsAt + i * objectRefSize);
  const valOff = readOffset(valIdx);
  const val = decodeString(valOff);
  if (!val) throw new Error("CFBundleIdentifier is not a string in the binary plist");
  if (val.text === newId) return bytes;
  if (countRefsTo(valIdx) > 1) {
    throw new Error(
      "CFBundleIdentifier value is shared with other plist entries — refusing to rewrite",
    );
  }
  // Re-encode the value object as an ASCII string (type 5) with an extended count.
  const payload = new Uint8Array(3 + newId.length);
  payload[0] = 0x5f;
  payload[1] = 0x10;
  payload[2] = newId.length;
  for (let j = 0; j < newId.length; j++) payload[3 + j] = newId.charCodeAt(j);
  const delta = payload.length - (val.end - valOff);
  const out = new Uint8Array(bytes.length + delta);
  out.set(bytes.subarray(0, valOff), 0);
  out.set(payload, valOff);
  const tableShifted = offsetTableOffset + delta;
  out.set(bytes.subarray(val.end, offsetTableOffset), valOff + payload.length);
  const maxShifted =
    offsetIntSize >= 6 ? Number.MAX_SAFE_INTEGER : 2 ** (8 * offsetIntSize) - 1;
  for (let k = 0; k < numObjects; k++) {
    const old = readOffset(k);
    const shifted = old > valOff ? old + delta : old;
    if (shifted > maxShifted || shifted < 0) {
      throw new Error(
        "Unsupported binary plist layout: shifted offsets are out of range for the offset table width",
      );
    }
    for (let w = offsetIntSize - 1, v = shifted; w >= 0; w--, v = Math.floor(v / 256)) {
      out[tableShifted + k * offsetIntSize + w] = v & 0xff;
    }
  }
  const newTrailerOffset = tableShifted + numObjects * offsetIntSize;
  out.set(bytes.subarray(len - 32), newTrailerOffset);
  const t = new DataView(out.buffer, out.byteOffset, out.byteLength);
  const newOffsetTable = offsetTableOffset + delta;
  t.setUint32(newTrailerOffset + 24, Math.floor(newOffsetTable / 0x100000000));
  t.setUint32(newTrailerOffset + 28, newOffsetTable >>> 0);
  return out;
}

// --- IPA loading ---

async function loadIpa(file) {
  if (signingInProgress) return; // a mid-run drop must not start a second run
  // A rejected replacement must not leave the previous IPA signable.
  ipaFile = null;
  updateSignButton();
  startTime = performance.now();
  const logContainer = $("#log");
  logContainer.classList.add("visible");
  logEl.replaceChildren();
  $("#summary").classList.add("hidden");
  $("#plist-output").classList.add("hidden");
  downloadBtn.classList.remove("visible");

  section(`▸ Reading ${file.name} (${formatSize(file.size)})`);

  // Init WASM early so we can parse binary plists
  try {
    const wasmResponse = await fetch(wasmUrl);
    const wasmBytes = await wasmResponse.arrayBuffer();
    await initWasm({ module_or_path: wasmBytes });
    wasmReady = true;
    log("WASM module loaded", "ok");
  } catch (_) {
    wasmReady = false;
    log("WASM not loaded yet — using fallback plist parser");
  }

  // The drop and file handlers fire this without awaiting or catching, so
  // every later failure is contained here: logged, reader closed, no new
  // IPA selected.
  let zipReader = null;
  try {
    zipReader = new ZipReader(new BlobReader(file));
    const entries = await zipReader.getEntries();
    log(`Found ${entries.length} entries in archive`);

    let app;
    try {
      app = findAppRoot(entries);
    } catch (e) {
      log(fmtErr(e), "err");
      return;
    }
    log(`Found bundle: ${app.name}.app`, "ok");

    // Read Info.plist to extract bundle ID
    const infoPlistEntry = entries.find(
      (e) => e.filename === `${app.prefix}Info.plist`,
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
      if (execName && execName !== app.name) {
        log(`CFBundleExecutable: ${execName} (differs from .app name)`, "ok");
      }
    } else {
      log("Info.plist not found in bundle", "err");
    }

    ipaFile = file;

    // Update UI
    dropZone.classList.add("loaded");
    dropLabel.textContent = `${file.name} loaded`;
    configSection.classList.add("visible");
    updateSignButton();
  } catch (e) {
    log(`Error: ${fmtErr(e)}`, "err");
    console.error(e);
    ipaFile = null;
    updateSignButton();
  } finally {
    if (zipReader) {
      await zipReader.close();
      zipReader = null;
    }
  }
}

// --- Sign button readiness ---

function updateSignButton() {
  if (signingInProgress) return; // a run owns the button until finally recomputes state
  const ready =
    ipaFile !== null &&
    p12Bytes !== null &&
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
  if (file.size > MAX_P12_BYTES) {
    log(`P12 is ${formatSize(file.size)} — at most ${formatSize(MAX_P12_BYTES)} supported`, "err");
    e.target.value = "";
    return;
  }
  p12Bytes = await readFileAsUint8Array(file);
  p12Btn.textContent = file.name;
  p12Btn.classList.add("has-file");
  updateSignButton();
});

profileBtn.addEventListener("click", () => profileInput.click());
profileInput.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > MAX_PROFILE_BYTES) {
    log(`Profile is ${formatSize(file.size)} — at most ${formatSize(MAX_PROFILE_BYTES)} supported`, "err");
    e.target.value = "";
    return;
  }
  profileBytes = await readFileAsUint8Array(file);
  profileBtn.textContent = file.name;
  profileBtn.classList.add("has-file");
  updateSignButton();
});

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
    try {
      await initWasm({ module_or_path: wasmBytes });
      wasmReady = true;
    } catch (e) {
      wasmReady = false;
      throw e;
    }
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

    const { prefix: currentAppPrefix, name: currentAppName } =
      findAppRoot(entries);
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
      generatedPaths.add(`${prefix}Info.plist`);
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
        throw new Error(
          isRoot
            ? "Cannot determine main executable — Info.plist has no CFBundleExecutable (or it could not be parsed)"
            : `bundle ${prefix} has no CFBundleExecutable`,
        );
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

    const rootInfoPlistPath = `${currentAppPrefix}Info.plist`;
    const infoPlistData = signedFiles.get(rootInfoPlistPath);
    const previousId = tryExtractBundleId(infoPlistData, wasmReady) ?? "(none)";
    const rewritten = rewriteBundleIdentifier(infoPlistData, run.bundleId);
    if (rewritten !== infoPlistData) {
      log(`Bundle ID rewritten: ${previousId} → ${run.bundleId}`, "ok");
    }
    signedFiles.set(rootInfoPlistPath, rewritten);
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
        // A symlink seals the link itself, not the bytes it points at: the
        // builder records {"symlink": target} instead of a resource hash, so
        // the target never reaches hashEntry. This branch precedes every
        // generic read so no symlink is ever sealed as a file. The declared
        // size is the cap gate — a hostile archive cannot make us decompress
        // an unbounded target — and the capped read bounds the real one.
        // Every path this pipeline regenerates (each bundle's Info.plist, the
        // root's profile, each bundle's CodeResources) is rejected as a symlink
        // before this loop, so no such entry reaches here as a link.
        if (isSymlinkEntry(entry)) {
          if (entry.uncompressedSize > 4096) {
            throw new Error(`Symlink target too long: ${entry.filename}`);
          }
          const target = await readCapped(entry, 4096);
          const targetText = decodeStrict(target, "Symlink target");
          // The sealed text is strict-decoded from these exact bytes, so the
          // form the builder hashes is byte-identical to the target the write
          // pass re-emits: seal and archive cannot diverge.
          signer.add_symlink(relPath, targetText);
          continue;
        }
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

      if (isSymlinkEntry(entry)) {
        if (entry.uncompressedSize > 4096) {
          throw new Error(`Symlink target too long: ${entry.filename}`);
        }
        const target = await readCapped(entry, 4096);
        decodeStrict(target, `Symlink target for ${entry.filename}`);
        // Single representation end-to-end: the mode that made detection succeed, written
        // into externalFileAttributes (zip.js treats that field as authoritative —
        // index.d.ts:1000-1014). On every input where detection matched, this expression
        // equals the detector's; the 0o120777 tail only covers the unreachable
        // both-sources-zero case so the value is never 0 and zip-writer.js:459-465's
        // regular-file default cannot fire (recomposition at :488 preserves it).
        const mode =
          ((entry.externalFileAttributes >>> 16) & 0xffff) || (entry.unixMode ?? 0o120777);
        await zipWriter.add(entry.filename, new Uint8ArrayReader(target), {
          externalFileAttributes: ((mode & 0xffff) << 16) | (entry.externalFileAttributes & 0xff),
          lastModDate: entry.lastModDate,
          versionMadeBy: VERSION_UNIX_20,
          compressionMethod: 0, // Stored — matches native symlink output
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
