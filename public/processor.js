const SOURCE_PACKAGE = 'pro.sketchware';
const TARGET_PACKAGE = 'neo.sketchware';
const enc = new TextEncoder();
const dec = new TextDecoder();

const SIG_EXT = /\.(RSA|DSA|EC|SF)$/i;
const SIGNATURE_NAMES = new Set(['META-INF/MANIFEST.MF']);

function readU16(bytes, off) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(off - bytes.byteOffset, true);
}
function readU32(bytes, off) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(off - bytes.byteOffset, true);
}
function writeU16(out, off, value) { new DataView(out.buffer).setUint16(off, value & 0xffff, true); }
function writeU32(out, off, value) { new DataView(out.buffer).setUint32(off, value >>> 0, true); }

const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

function locateEocd(bytes) {
  const start = Math.max(0, bytes.length - 0x10016);
  for (let i = bytes.length - 22; i >= start; i--) {
    if (readU32(bytes, i) === 0x06054b50) return i;
  }
  throw new Error('Invalid APK/ZIP: End Of Central Directory was not found.');
}

function contains(hay, needle) {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

function replaceAllSameLength(data, from, to) {
  if (from.length !== to.length) throw new Error('Package strings must be equal length.');
  const out = new Uint8Array(data);
  let count = 0;
  for (let i = 0; i <= out.length - from.length; i++) {
    let ok = true;
    for (let j = 0; j < from.length; j++) if (out[i + j] !== from[j]) { ok = false; break; }
    if (!ok) continue;
    out.set(to, i);
    count++;
    i += from.length - 1;
  }
  return { data: out, count };
}

function packageVariants() {
  const from8 = enc.encode(SOURCE_PACKAGE);
  const to8 = enc.encode(TARGET_PACKAGE);
  const from16 = new Uint8Array(from8.length * 2);
  const to16 = new Uint8Array(to8.length * 2);
  for (let i = 0; i < from8.length; i++) {
    from16[i * 2] = from8[i];
    to16[i * 2] = to8[i];
  }
  return { from8, to8, from16, to16 };
}

async function inflateRaw(data) {
  const ds = new DecompressionStream('deflate-raw');
  return new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(ds)).arrayBuffer());
}

async function deflateRaw(data) {
  const cs = new CompressionStream('deflate-raw');
  const writer = cs.writable.getWriter();
  await writer.write(data);
  await writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

function isSignatureEntry(name) {
  if (!name.startsWith('META-INF/')) return false;
  const upper = name.toUpperCase();
  return SIGNATURE_NAMES.has(upper) || SIG_EXT.test(name);
}

function crc32(data) {
  let crc = 0xffffffff;
  for (const b of data) {
    crc ^= b;
    for (let k = 0; k < 8; k++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function makeLocalHeader(e, compressedSize, uncompressedSize, crc, extraOverride = null) {
  const name = enc.encode(e.name);
  const extra = extraOverride ?? e.localExtra;
  const h = new Uint8Array(30 + name.length + extra.length);
  writeU32(h, 0, 0x04034b50);
  writeU16(h, 4, e.versionNeeded);
  // bit 3 (data descriptor) is cleared because we write exact sizes in the header.
  writeU16(h, 6, e.flags & ~0x0008);
  writeU16(h, 8, e.method);
  writeU16(h, 10, e.modTime);
  writeU16(h, 12, e.modDate);
  writeU32(h, 14, crc);
  writeU32(h, 18, compressedSize);
  writeU32(h, 22, uncompressedSize);
  writeU16(h, 26, name.length);
  writeU16(h, 28, extra.length);
  h.set(name, 30);
  h.set(extra, 30 + name.length);
  return h;
}

function makeCentralHeader(e, compressedSize, uncompressedSize, crc, localOffset) {
  const name = enc.encode(e.name);
  const extra = e.centralExtra;
  const comment = e.comment;
  const h = new Uint8Array(46 + name.length + extra.length + comment.length);
  writeU32(h, 0, 0x02014b50);
  writeU16(h, 4, e.versionMadeBy);
  writeU16(h, 6, e.versionNeeded);
  writeU16(h, 8, e.flags & ~0x0008);
  writeU16(h, 10, e.method);
  writeU16(h, 12, e.modTime);
  writeU16(h, 14, e.modDate);
  writeU32(h, 16, crc);
  writeU32(h, 20, compressedSize);
  writeU32(h, 24, uncompressedSize);
  writeU16(h, 28, name.length);
  writeU16(h, 30, extra.length);
  writeU16(h, 32, comment.length);
  writeU16(h, 34, e.diskStart);
  writeU16(h, 36, e.internalAttrs);
  writeU32(h, 38, e.externalAttrs);
  writeU32(h, 42, localOffset);
  h.set(name, 46);
  h.set(extra, 46 + name.length);
  h.set(comment, 46 + name.length + extra.length);
  return h;
}

function makeEocd(entryCount, cdSize, cdOffset, comment = new Uint8Array()) {
  const h = new Uint8Array(22 + comment.length);
  writeU32(h, 0, 0x06054b50);
  writeU16(h, 4, 0);
  writeU16(h, 6, 0);
  writeU16(h, 8, entryCount);
  writeU16(h, 10, entryCount);
  writeU32(h, 12, cdSize);
  writeU32(h, 16, cdOffset);
  writeU16(h, 20, comment.length);
  h.set(comment, 22);
  return h;
}

function parseLocalMeta(bytes, localOffset) {
  if (readU32(bytes, localOffset) !== 0x04034b50) throw new Error('Invalid local header.');
  const nameLen = readU16(bytes, localOffset + 26);
  const extraLen = readU16(bytes, localOffset + 28);
  const name = bytes.subarray(localOffset + 30, localOffset + 30 + nameLen);
  const extra = bytes.subarray(localOffset + 30 + nameLen, localOffset + 30 + nameLen + extraLen);
  const dataStart = localOffset + 30 + nameLen + extraLen;
  return { name, extra, dataStart };
}

export async function readApk(file) {
  const bytes = file instanceof Uint8Array ? file : new Uint8Array(await file.arrayBuffer());
  const eocd = locateEocd(bytes);
  const entryCount = readU16(bytes, eocd + 10);
  const cdSize = readU32(bytes, eocd + 12);
  const cdOffset = readU32(bytes, eocd + 16);
  if (cdOffset + cdSize > bytes.length) throw new Error('Invalid ZIP central directory bounds.');
  if (entryCount === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) throw new Error('ZIP64 APKs are not supported by this browser demo.');
  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < entryCount; i++) {
    if (readU32(bytes, p) !== 0x02014b50) throw new Error('Unsupported ZIP structure: bad central directory entry.');
    const versionMadeBy = readU16(bytes, p + 4);
    const versionNeeded = readU16(bytes, p + 6);
    const flags = readU16(bytes, p + 8);
    const method = readU16(bytes, p + 10);
    const modTime = readU16(bytes, p + 12);
    const modDate = readU16(bytes, p + 14);
    const crc = readU32(bytes, p + 16);
    const compressedSize = readU32(bytes, p + 20);
    const uncompressedSize = readU32(bytes, p + 24);
    const nameLen = readU16(bytes, p + 28);
    const extraLen = readU16(bytes, p + 30);
    const commentLen = readU16(bytes, p + 32);
    const diskStart = readU16(bytes, p + 34);
    const internalAttrs = readU16(bytes, p + 36);
    const externalAttrs = readU32(bytes, p + 38);
    const localOffset = readU32(bytes, p + 42);
    if (localOffset === 0xffffffff || compressedSize === 0xffffffff || uncompressedSize === 0xffffffff) throw new Error('ZIP64 entry found.');
    const nameBytes = bytes.subarray(p + 46, p + 46 + nameLen);
    const name = dec.decode(nameBytes);
    const centralExtra = bytes.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
    const comment = bytes.subarray(p + 46 + nameLen + extraLen, p + 46 + nameLen + extraLen + commentLen);
    const local = parseLocalMeta(bytes, localOffset);
    const compressed = bytes.subarray(local.dataStart, local.dataStart + compressedSize);
    if (local.dataStart + compressedSize > bytes.length) throw new Error(`Corrupt entry ${name}: data extends past file.`);
    entries.push({
      name, versionMadeBy, versionNeeded, flags, method, modTime, modDate, crc,
      compressedSize, uncompressedSize, diskStart, internalAttrs, externalAttrs,
      localOffset, localName: new Uint8Array(local.name), localExtra: new Uint8Array(local.extra),
      centralExtra: new Uint8Array(centralExtra), comment: new Uint8Array(comment),
      compressed: new Uint8Array(compressed),
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  const manifest = entries.find(e => e.name === 'AndroidManifest.xml');
  if (!manifest) throw new Error('AndroidManifest.xml is missing.');
  return { bytes, eocd, eocdComment: new Uint8Array(bytes.subarray(eocd + 22, eocd + 22 + readU16(bytes, eocd + 20))), cdOffset, entries, manifest };
}

async function decodeEntry(e) {
  if (e.method === 0) return new Uint8Array(e.compressed);
  if (e.method === 8) return await inflateRaw(e.compressed);
  throw new Error(`Unsupported compression method ${e.method} in ${e.name}.`);
}

function patchData(data, variants) {
  let out = new Uint8Array(data);
  let count = 0;
  const r8 = replaceAllSameLength(out, variants.from8, variants.to8);
  out = r8.data; count += r8.count;
  const r16 = replaceAllSameLength(out, variants.from16, variants.to16);
  out = r16.data; count += r16.count;
  return { data: out, count };
}

function hasZipAlignField(extra) {
  // APK/zipalign padding field is commonly stored as header id 0xD935.
  for (let p = 0; p + 4 <= extra.length;) {
    const id = extra[p] | (extra[p + 1] << 8);
    const len = extra[p + 2] | (extra[p + 3] << 8);
    if (id === 0xD935) return true;
    p += 4 + len;
  }
  return false;
}

function padLocalExtraForAlignment(extra, dataOffset, alignment = 4) {
  const remainder = dataOffset % alignment;
  if (remainder === 0) return extra;
  const needed = alignment - remainder;
  // Preserve existing extra fields; append a standard padding field.
  const fieldLen = needed;
  if (fieldLen > 0xffff) return extra;
  const field = new Uint8Array(4 + fieldLen);
  writeU16(field, 0, 0xD935);
  writeU16(field, 2, fieldLen);
  return concat(extra, field);
}

async function buildApk(entries, eocdComment) {
  const localParts = [];
  const centralEntries = [];
  let offset = 0;
  const outputMeta = [];

  for (const e of entries) {
    let localExtra = e.localExtra;
    let compressed = e.compressed;
    let crc = e.crc;
    let uncompressedSize = e.uncompressedSize;
    let compressedSize = e.compressedSize;

    // Re-align stored native libraries if an upstream edited entry changed offsets.
    if (e.method === 0 && e.name.startsWith('lib/')) localExtra = padLocalExtraForAlignment(localExtra, offset + 30 + enc.encode(e.name).length + localExtra.length);

    const localHeader = makeLocalHeader(e, compressedSize, uncompressedSize, crc, localExtra);
    const localDataOffset = offset + localHeader.length;
    if (e.method === 0 && e.name.startsWith('lib/') && localDataOffset % 4 !== 0) {
      localExtra = padLocalExtraForAlignment(localExtra, offset + 30 + enc.encode(e.name).length + localExtra.length);
      compressedSize = compressed.length;
      uncompressedSize = e.uncompressedSize;
      crc = e.crc;
    }
    const finalLocalHeader = makeLocalHeader(e, compressedSize, uncompressedSize, crc, localExtra);
    const local = concat(finalLocalHeader, compressed);
    localParts.push(local);
    centralEntries.push({ e, compressed, crc, compressedSize, uncompressedSize, localOffset: offset });
    outputMeta.push({ name: e.name, compressedBytesPreserved: compressed === e.compressed });
    offset += local.length;
  }

  const localBytes = concat(...localParts);
  const centralParts = [];
  let cdOffset = localBytes.length;
  for (const item of centralEntries) {
    centralParts.push(makeCentralHeader(item.e, item.compressedSize, item.uncompressedSize, item.crc, item.localOffset));
  }
  const centralBytes = concat(...centralParts);
  const eocd = makeEocd(centralEntries.length, centralBytes.length, cdOffset, eocdComment);
  return { bytes: concat(localBytes, centralBytes, eocd), outputMeta };
}

export async function renameApk(file, onProgress = null) {
  const progress = (stage, percent, detail = {}) => {
    try { onProgress?.({ stage, percent: Math.max(0, Math.min(100, Math.round(percent))), ...detail }); } catch (_) {}
  };
  if (!/\.apk$/i.test(file.name || '')) throw new Error('Please select an APK file.');
  if (file.size > 300 * 1024 * 1024) throw new Error('APK is larger than the 300 MB browser safety limit.');
  progress('Reading APK', 8, { message: 'Reading ZIP central directory…' });
  const apk = await readApk(file);
  progress('APK analyzed', 14, { message: `${apk.entries.length.toLocaleString()} archive entries found.`, totalEntries: apk.entries.length });
  const variants = packageVariants();
  progress('Checking manifest', 18, { message: 'Checking AndroidManifest.xml for the source package…', currentEntry: 'AndroidManifest.xml' });
  const manifest = await decodeEntry(apk.manifest);
  const manifestResult = patchData(manifest, variants);
  if (manifestResult.count === 0) throw new Error(`Exact package ${SOURCE_PACKAGE} was not found in AndroidManifest.xml.`);

  const processed = [];
  let totalReplacements = 0;
  let changedFiles = [];
  let signatureRemoved = [];
  let unchangedCount = 0;
  let changedCount = 0;
  const totalEntries = apk.entries.length;
  let processedEntries = 0;
  let lastProgressAt = 0;
  progress('Scanning archive', 20, { message: `Scanning 0/${totalEntries.toLocaleString()} entries…`, processedEntries: 0, totalEntries });

  for (const e of apk.entries) {
    const scanPercent = 20 + (processedEntries / totalEntries) * 50;
    if (scanPercent - lastProgressAt >= 0.5 || processedEntries === 0) {
      lastProgressAt = scanPercent;
      progress('Scanning archive', scanPercent, { message: `Processing ${processedEntries.toLocaleString()}/${totalEntries.toLocaleString()} entries…`, processedEntries, totalEntries, currentEntry: e.name, changedCount, totalReplacements });
    }
    if (isSignatureEntry(e.name)) {
      signatureRemoved.push(e.name);
      processedEntries++;
      const percent = 20 + (processedEntries / totalEntries) * 50;
      if (percent - lastProgressAt >= 0.5 || processedEntries === totalEntries) {
        lastProgressAt = percent;
        progress('Scanning archive', percent, { message: `Scanning ${processedEntries.toLocaleString()}/${totalEntries.toLocaleString()} entries…`, processedEntries, totalEntries, currentEntry: e.name, changedCount, totalReplacements });
      }
      continue;
    }
    const data = await decodeEntry(e);
    const patched = patchData(data, variants);
    if (patched.count > 0) {
      const newData = patched.data;
      let newCompressed = e.compressed;
      if (e.method === 0) newCompressed = newData;
      else if (e.method === 8) newCompressed = await deflateRaw(newData);
      else throw new Error(`Unsupported compression method ${e.method} for changed entry ${e.name}.`);
      processed.push({ ...e, compressed: newCompressed, compressedSize: newCompressed.length, uncompressedSize: newData.length, crc: crc32(newData) });
      totalReplacements += patched.count;
      changedFiles.push({ name: e.name, method: e.method, oldCompressed: e.compressedSize, newCompressed: newCompressed.length, oldUncompressed: e.uncompressedSize, newUncompressed: newData.length });
      changedCount++;
    } else {
      processed.push(e);
      unchangedCount++;
    }
    processedEntries++;
    const percent = 20 + (processedEntries / totalEntries) * 50;
    if (percent - lastProgressAt >= 0.5 || processedEntries === totalEntries) {
      lastProgressAt = percent;
      progress('Scanning archive', percent, { message: `Scanning ${processedEntries.toLocaleString()}/${totalEntries.toLocaleString()} entries…`, processedEntries, totalEntries, currentEntry: e.name, changedCount, totalReplacements });
    }
    // Give the browser a chance to paint progress updates during large APK scans.
    if (processedEntries % 24 === 0) await new Promise(resolve => setTimeout(resolve, 0));
  }

  progress('Rebuilding APK', 72, { message: `Rebuilding archive with ${changedCount} changed entries…`, changedCount, totalReplacements });
  if (totalReplacements === 0) throw new Error(`No exact ${SOURCE_PACKAGE} references were found.`);
  const built = await buildApk(processed, apk.eocdComment);
  progress('Verifying output', 88, { message: 'Re-opening the generated APK and checking archive integrity…' });
  const out = await readApk(built.bytes);

  let sourceRemaining = 0;
  let targetCount = 0;
  for (const e of out.entries) {
    const data = await decodeEntry(e);
    sourceRemaining += countExact(data, variants.from8) + countExact(data, variants.from16);
    targetCount += countExact(data, variants.to8) + countExact(data, variants.to16);
  }

  if (sourceRemaining > 0) throw new Error('Safety stop: source package references remain in output APK. No download was created.');
  if (out.entries.some(e => isSignatureEntry(e.name))) throw new Error('Safety stop: stale signing metadata remains.');
  if (!out.entries.some(e => e.name === 'AndroidManifest.xml')) throw new Error('Safety stop: AndroidManifest.xml is missing after rebuild.');
  progress('Final validation', 96, { message: `Validation passed: ${targetCount.toLocaleString()} target references found.`, targetReferences: targetCount, sourceGone: true });

  const outputName = (file.name || 'app.apk').replace(/\.apk$/i, '-neo-unsigned.apk');
  return {
    bytes: built.bytes,
    originalPackage: SOURCE_PACKAGE,
    targetPackage: TARGET_PACKAGE,
    inputSize: file.size,
    outputSize: built.bytes.length,
    manifestReplacements: manifestResult.count,
    totalReplacements,
    changedFiles,
    changedFileCount: changedCount,
    preservedFileCount: unchangedCount,
    signatureRemoved,
    validation: {
      sourceGone: sourceRemaining === 0,
      targetReferences: targetCount,
      manifestTargetPresent: countExact(await decodeEntry(out.entries.find(e => e.name === 'AndroidManifest.xml')), variants.to8) > 0 || countExact(await decodeEntry(out.entries.find(e => e.name === 'AndroidManifest.xml')), variants.to16) > 0,
      signatureEntriesRemoved: !out.entries.some(e => isSignatureEntry(e.name)),
      sizeDeltaPercent: ((built.bytes.length - file.size) / file.size) * 100,
    },
    outputName,
    processedEntries: apk.entries.length,
    totalEntries: apk.entries.length,
  };
}

function countExact(data, needle) {
  let c = 0;
  for (let i = 0; i <= data.length - needle.length; i++) {
    let ok = true;
    for (let j = 0; j < needle.length; j++) if (data[i + j] !== needle[j]) { ok = false; break; }
    if (ok) { c++; i += needle.length - 1; }
  }
  return c;
}

export { SOURCE_PACKAGE, TARGET_PACKAGE, isSignatureEntry };
