const SOURCE_PACKAGE = 'pro.sketchware';
const TARGET_PACKAGE = 'neo.sketchware';
const enc = new TextEncoder();
const dec = new TextDecoder();

const SIG_EXT = /\.(RSA|DSA|EC|SF)$/i;
const SIGNATURE_NAMES = new Set(['META-INF/MANIFEST.MF']);
const ZIP_LOCAL = 0x04034b50;
const ZIP_CENTRAL = 0x02014b50;
const ZIP_EOCD = 0x06054b50;
const ZIP64 = 0xffffffff;
const MAX_EOCD_SCAN = 0x10016;

function readU16(bytes, off) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(off - bytes.byteOffset, true); }
function readU32(bytes, off) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(off - bytes.byteOffset, true); }
function writeU16(out, off, value) { new DataView(out.buffer, out.byteOffset, out.byteLength).setUint16(off, value & 0xffff, true); }
function writeU32(out, off, value) { new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(off, value >>> 0, true); }
const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const yieldToBrowser = () => new Promise(resolve => setTimeout(resolve, 0));

function locateEocd(tailBytes, tailStart, fileSize) {
  for (let i = tailBytes.length - 22; i >= 0; i--) {
    if (readU32(tailBytes, tailBytes.byteOffset + i) === ZIP_EOCD) {
      return tailStart + i;
    }
  }
  throw new Error('Invalid APK/ZIP: End Of Central Directory was not found.');
}

function contains(hay, needle) {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
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

async function inflateRawStream(file, start, size, report) {
  const source = file.slice(start, start + size).stream();
  let readBytes = 0;
  const tracker = new TransformStream({
    transform(chunk, controller) {
      readBytes += chunk.byteLength;
      if (report) report(readBytes, size);
      controller.enqueue(chunk);
    }
  });
  const stream = source.pipeThrough(tracker).pipeThrough(new DecompressionStream('deflate-raw'));
  const output = await new Response(stream).arrayBuffer();
  if (report) report(size, size);
  return new Uint8Array(output);
}

async function decodeEntry(file, e, onCompressedProgress = null) {
  const raw = await file.slice(e.dataStart, e.dataStart + e.compressedSize).arrayBuffer();
  if (e.method === 0) {
    onCompressedProgress?.(e.compressedSize, e.compressedSize);
    return new Uint8Array(raw);
  }
  if (e.method === 8) {
    // Feed the exact compressed bytes to DecompressionStream while reporting
    // compressed input progress. This is what prevents a large classes.dex or
    // resources.arsc entry from looking frozen on mobile Chrome.
    const source = new Blob([raw]).stream();
    let readBytes = 0;
    const tracker = new TransformStream({
      transform(chunk, controller) {
        readBytes += chunk.byteLength;
        onCompressedProgress?.(readBytes, e.compressedSize);
        controller.enqueue(chunk);
      }
    });
    const stream = source.pipeThrough(tracker).pipeThrough(new DecompressionStream('deflate-raw'));
    const output = await new Response(stream).arrayBuffer();
    onCompressedProgress?.(e.compressedSize, e.compressedSize);
    return new Uint8Array(output);
  }
  throw new Error(`Unsupported compression method ${e.method} in ${e.name}.`);
}

async function compressRaw(data) {
  const cs = new CompressionStream('deflate-raw');
  const writer = cs.writable.getWriter();
  await writer.write(data);
  await writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
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

function countExact(data, needle) {
  let c = 0;
  for (let i = 0; i <= data.length - needle.length; i++) {
    let ok = true;
    for (let j = 0; j < needle.length; j++) if (data[i + j] !== needle[j]) { ok = false; break; }
    if (ok) { c++; i += needle.length - 1; }
  }
  return c;
}

async function readTail(file, onProgress) {
  const size = file.size;
  const length = Math.min(size, MAX_EOCD_SCAN);
  const start = size - length;
  const bytes = new Uint8Array(await file.slice(start, size).arrayBuffer());
  onProgress?.(0, length);
  const eocd = locateEocd(bytes, start, size);
  onProgress?.(length, length);
  return { bytes, start, eocd };
}

async function parseEntries(file, onProgress) {
  const { bytes: tail, start: tailStart, eocd } = await readTail(file, onProgress);
  const entryCount = readU16(tail, eocd - tailStart + 10);
  const cdSize = readU32(tail, eocd - tailStart + 12);
  const cdOffset = readU32(tail, eocd - tailStart + 16);
  const commentLen = readU16(tail, eocd - tailStart + 20);
  if (entryCount === 0xffff || cdOffset === ZIP64 || cdSize === ZIP64) throw new Error('ZIP64 APKs are not supported by this browser build.');
  if (cdOffset + cdSize > file.size) throw new Error('Invalid ZIP central directory bounds.');
  const comment = new Uint8Array(tail.subarray(eocd - tailStart + 22, eocd - tailStart + 22 + commentLen));
  const cd = new Uint8Array(await file.slice(cdOffset, cdOffset + cdSize).arrayBuffer());
  const entries = [];
  let p = 0;
  for (let i = 0; i < entryCount; i++) {
    if (p + 46 > cd.length || readU32(cd, p) !== ZIP_CENTRAL) throw new Error('Unsupported ZIP structure: bad central directory entry.');
    const versionMadeBy = readU16(cd, p + 4);
    const versionNeeded = readU16(cd, p + 6);
    const flags = readU16(cd, p + 8);
    const method = readU16(cd, p + 10);
    const modTime = readU16(cd, p + 12);
    const modDate = readU16(cd, p + 14);
    const crc = readU32(cd, p + 16);
    const compressedSize = readU32(cd, p + 20);
    const uncompressedSize = readU32(cd, p + 24);
    const nameLen = readU16(cd, p + 28);
    const extraLen = readU16(cd, p + 30);
    const commentLength = readU16(cd, p + 32);
    const diskStart = readU16(cd, p + 34);
    const internalAttrs = readU16(cd, p + 36);
    const externalAttrs = readU32(cd, p + 38);
    const localOffset = readU32(cd, p + 42);
    if ([compressedSize, uncompressedSize, localOffset].some(v => v === ZIP64)) throw new Error('ZIP64 entry found.');
    if (p + 46 + nameLen + extraLen + commentLength > cd.length) throw new Error('Corrupt central directory lengths.');
    const name = dec.decode(cd.subarray(p + 46, p + 46 + nameLen));
    const centralExtra = new Uint8Array(cd.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen));
    const entryComment = new Uint8Array(cd.subarray(p + 46 + nameLen + extraLen, p + 46 + nameLen + extraLen + commentLength));
    entries.push({ name, versionMadeBy, versionNeeded, flags, method, modTime, modDate, crc, compressedSize, uncompressedSize, diskStart, internalAttrs, externalAttrs, localOffset, centralExtra, comment: entryComment, index: i });
    p += 46 + nameLen + extraLen + commentLength;
    if (i === 0 || i % 64 === 0 || i === entryCount - 1) {
      onProgress?.(i + 1, entryCount, entries[i]?.name || '');
      await yieldToBrowser();
    }
  }
  if (p !== cd.length) throw new Error('Central directory size mismatch.');
  entries.sort((a, b) => a.localOffset - b.localOffset);
  for (let i = 0; i < entries.length; i++) entries[i].nextLocalOffset = i + 1 < entries.length ? entries[i + 1].localOffset : cdOffset;
  const manifest = entries.find(e => e.name === 'AndroidManifest.xml');
  if (!manifest) throw new Error('AndroidManifest.xml is missing.');
  return { entries, manifest, cdOffset, eocdComment: comment };
}

async function readLocalInfo(file, e) {
  const hdr = new Uint8Array(await file.slice(e.localOffset, e.localOffset + 30).arrayBuffer());
  if (hdr.length < 30 || readU32(hdr, 0) !== ZIP_LOCAL) throw new Error(`Invalid local header for ${e.name}.`);
  const nameLen = readU16(hdr, 26);
  const extraLen = readU16(hdr, 28);
  return {
    flags: readU16(hdr, 6),
    method: readU16(hdr, 8),
    nameLen,
    extraLen,
    dataStart: e.localOffset + 30 + nameLen + extraLen
  };
}

async function readLocalMeta(file, e, info = null) {
  const localInfo = info || await readLocalInfo(file, e);
  const full = new Uint8Array(await file.slice(e.localOffset, localInfo.dataStart).arrayBuffer());
  const name = full.subarray(30, 30 + localInfo.nameLen);
  const extra = full.subarray(30 + localInfo.nameLen, 30 + localInfo.nameLen + localInfo.extraLen);
  return { ...localInfo, header: full, name: new Uint8Array(name), extra: new Uint8Array(extra), dataStart: localInfo.dataStart };
}

async function originalRecordEnd(file, e, info) {
  let end = info.dataStart + e.compressedSize;
  if (info.flags & 0x0008) {
    const tail = new Uint8Array(await file.slice(end, Math.min(file.size, end + 16)).arrayBuffer());
    if (tail.length >= 4 && readU32(tail, 0) === 0x08074b50) end += tail.length >= 16 ? 16 : Math.min(12, tail.length);
    else end += Math.min(12, tail.length);
  }
  return end;
}

function makeLocalHeader(e, localExtra, compressedSize, uncompressedSize, crc) {
  const name = enc.encode(e.name);
  const h = new Uint8Array(30 + name.length + localExtra.length);
  writeU32(h, 0, ZIP_LOCAL);
  writeU16(h, 4, e.versionNeeded);
  writeU16(h, 6, e.flags & ~0x0008);
  writeU16(h, 8, e.method);
  writeU16(h, 10, e.modTime);
  writeU16(h, 12, e.modDate);
  writeU32(h, 14, crc);
  writeU32(h, 18, compressedSize);
  writeU32(h, 22, uncompressedSize);
  writeU16(h, 26, name.length);
  writeU16(h, 28, localExtra.length);
  h.set(name, 30);
  h.set(localExtra, 30 + name.length);
  return h;
}

function makeCentralHeader(e, compressedSize, uncompressedSize, crc, localOffset) {
  const name = enc.encode(e.name);
  const extra = e.centralExtra;
  const comment = e.comment;
  const h = new Uint8Array(46 + name.length + extra.length + comment.length);
  writeU32(h, 0, ZIP_CENTRAL);
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

function makeEocd(entryCount, cdSize, cdOffset, comment) {
  const out = new Uint8Array(22 + comment.length);
  writeU32(out, 0, ZIP_EOCD);
  writeU16(out, 4, 0); writeU16(out, 6, 0);
  writeU16(out, 8, entryCount); writeU16(out, 10, entryCount);
  writeU32(out, 12, cdSize); writeU32(out, 16, cdOffset);
  writeU16(out, 20, comment.length); out.set(comment, 22);
  return out;
}

function paddingFor4(dataOffset) {
  const remainder = dataOffset % 4;
  return remainder === 0 ? null : (4 - remainder);
}

function appendPaddingExtra(extra, totalBytesNeeded) {
  if (!totalBytesNeeded) return extra;
  // The whole ZIP extra field (4-byte id/length + payload) must add exactly
  // the requested number of bytes modulo 4. Minimum record size is 4.
  let total = totalBytesNeeded;
  while (total < 4) total += 4;
  const fieldLen = total - 4;
  const field = new Uint8Array(total);
  writeU16(field, 0, 0xD935);
  writeU16(field, 2, fieldLen);
  return concat(extra, field);
}

async function rawLocalRecord(file, e) {
  if (e.nextLocalOffset <= e.localOffset) throw new Error(`Invalid local offsets for ${e.name}.`);
  return file.slice(e.localOffset, e.nextLocalOffset);
}

function overlapSearch(prev, chunk, needle) {
  const combined = new Uint8Array(prev.length + chunk.length);
  combined.set(prev, 0); combined.set(chunk, prev.length);
  return { found: contains(combined, needle), tail: combined.slice(Math.max(0, combined.length - (needle.length - 1))) };
}

function verifyOutputStructure(bytes, apk) {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (apk.cdOffset <= 0 || apk.cdOffset > u.length) throw new Error('Safety stop: invalid output central-directory offset.');
  for (const e of apk.entries) {
    if (e.localOffset + 30 > u.length) throw new Error(`Safety stop: local header is outside output for ${e.name}.`);
    if (readU32(u, e.localOffset) !== ZIP_LOCAL) throw new Error(`Safety stop: invalid local header for ${e.name}.`);
    const nameLen = readU16(u, e.localOffset + 26);
    const extraLen = readU16(u, e.localOffset + 28);
    const dataStart = e.localOffset + 30 + nameLen + extraLen;
    if (dataStart + e.compressedSize > apk.cdOffset || dataStart + e.compressedSize > u.length) throw new Error(`Safety stop: output data bounds are invalid for ${e.name}.`);
    if (readU16(u, e.localOffset + 8) !== e.method) throw new Error(`Safety stop: compression method mismatch for ${e.name}.`);
    if (readU32(u, e.localOffset + 22) !== e.uncompressedSize && !(e.flags & 0x0008)) throw new Error(`Safety stop: size mismatch for ${e.name}.`);
  }
}

/**
 * Browser/Worker APK rename core.
 * The source file stays in the File/Blob; unchanged records are copied by
 * slice, so the whole 130 MB APK is not duplicated in JS memory.
 */
export async function renameApk(file, onProgress = null) {
  const progress = (stage, percent, detail = {}) => {
    try { onProgress?.({ stage, percent: Math.max(0, Math.min(100, Math.round(percent))), ...detail }); } catch (_) {}
  };
  if (!(file instanceof Blob) || !/\.apk$/i.test(file.name || '')) throw new Error('Please select an APK file.');
  if (file.size > 300 * 1024 * 1024) throw new Error('APK is larger than the 300 MB browser safety limit.');

  const variants = packageVariants();
  progress('Reading APK', 5, { message: 'Reading APK footer…' });
  const apk = await parseEntries(file, (done, total) => {
    const pct = total ? 5 + (done / total) * 8 : 5;
    progress('Reading APK', pct, { message: `Reading ZIP directory ${done.toLocaleString()}/${total.toLocaleString()}…`, processedEntries: done, totalEntries: total, currentEntry: 'Central directory' });
  });
  progress('APK analyzed', 14, { message: `${apk.entries.length.toLocaleString()} archive entries found.`, totalEntries: apk.entries.length });

  progress('Checking manifest', 18, { message: 'Checking AndroidManifest.xml for the source package…', currentEntry: 'AndroidManifest.xml' });
  const manifestInfo = await readLocalInfo(file, apk.manifest);
  apk.manifest.dataStart = manifestInfo.dataStart;
  const manifest = await decodeEntry(file, apk.manifest);
  const manifestResult = patchData(manifest, variants);
  if (manifestResult.count === 0) throw new Error(`Exact package ${SOURCE_PACKAGE} was not found in AndroidManifest.xml.`);

  const changed = new Map();
  let totalReplacements = 0;
  let changedCount = 0;
  let processedEntries = 0;
  let signatureRemoved = [];
  const totalEntries = apk.entries.length;
  let lastEmit = performance.now();

  for (const e of apk.entries) {
    const isSignature = isSignatureEntry(e.name);
    const basePct = 20 + (processedEntries / Math.max(1, totalEntries)) * 50;
    progress('Scanning archive', basePct, {
      message: `Processing ${Math.min(processedEntries + 1, totalEntries).toLocaleString()}/${totalEntries.toLocaleString()} entries…`,
      processedEntries, totalEntries, currentEntry: e.name, changedCount, totalReplacements
    });
    await yieldToBrowser();

    if (isSignature) {
      signatureRemoved.push(e.name);
      processedEntries++;
      continue;
    }

    const localInfo = await readLocalInfo(file, e);
    e.dataStart = localInfo.dataStart;
    let subProgressLast = 0;
    const data = await decodeEntry(file, e, (done, total) => {
      if (!total) return;
      const now = performance.now();
      const ratio = Math.max(0, Math.min(1, done / total));
      if (now - subProgressLast < 120 && done !== total) return;
      subProgressLast = now;
      const p = 20 + ((processedEntries + ratio * 0.95) / totalEntries) * 50;
      progress('Scanning archive', p, {
        message: `Decompressing ${e.name} · ${Math.round(ratio * 100)}%`,
        processedEntries, totalEntries, currentEntry: e.name, changedCount, totalReplacements
      });
    });
    const patched = patchData(data, variants);

    if (patched.count > 0) {
      let compressed = new Uint8Array(patched.data);
      if (e.method === 8) compressed = await compressRaw(patched.data);
      else if (e.method !== 0) throw new Error(`Unsupported compression method ${e.method} for changed entry ${e.name}.`);
      const local = await readLocalMeta(file, e, localInfo);
      changed.set(e.index, { compressed, uncompressedSize: patched.data.length, crc: crc32(patched.data), localExtra: local.extra, localName: local.name });
      totalReplacements += patched.count;
      changedCount++;
      progress('Scanning archive', 20 + ((processedEntries + 0.95) / totalEntries) * 50, {
        message: `Changed ${e.name} · ${patched.count} exact reference${patched.count === 1 ? '' : 's'}`,
        processedEntries, totalEntries, currentEntry: e.name, changedCount, totalReplacements
      });
    }

    processedEntries++;
    const p = 20 + (processedEntries / totalEntries) * 50;
    const now = performance.now();
    if (now - lastEmit > 100 || processedEntries === totalEntries) {
      lastEmit = now;
      progress('Scanning archive', p, { message: `Scanning ${processedEntries.toLocaleString()}/${totalEntries.toLocaleString()} entries…`, processedEntries, totalEntries, currentEntry: e.name, changedCount, totalReplacements });
    }
    await yieldToBrowser();
  }

  if (totalReplacements === 0) throw new Error(`No exact ${SOURCE_PACKAGE} references were found.`);

  progress('Rebuilding APK', 72, { message: 'Rebuilding archive from original records + changed entries…', changedCount, totalReplacements, totalEntries });
  const localParts = [];
  const centralMeta = [];
  let outputOffset = 0;

  // Keep archive order by original local offset. Unchanged deflated entries
  // are copied as exact local records. Stored entries are rebuilt with their
  // original payload but an aligned local header, which keeps APK zipalign
  // requirements intact after earlier records change size. The final entry's
  // gap before the central directory (where APK v2/v3 signing blocks live) is
  // deliberately NOT copied.
  for (let i = 0; i < apk.entries.length; i++) {
    const e = apk.entries[i];
    if (isSignatureEntry(e.name)) continue;
    const mod = changed.get(e.index);
    const info = await readLocalInfo(file, e);

    if (!mod && e.method !== 0) {
      const end = i === apk.entries.length - 1 ? await originalRecordEnd(file, e, info) : e.nextLocalOffset;
      if (end < e.localOffset + 30 + info.nameLen + info.extraLen + e.compressedSize) throw new Error(`Invalid original record bounds for ${e.name}.`);
      const record = file.slice(e.localOffset, end);
      localParts.push(record);
      centralMeta.push({ e, compressedSize: e.compressedSize, uncompressedSize: e.uncompressedSize, crc: e.crc, localOffset: outputOffset });
      outputOffset += record.size;
    } else {
      const local = mod?.localExtra ? mod : await readLocalMeta(file, e, info);
      const originalExtra = mod?.localExtra || local.extra;
      const name = enc.encode(e.name);
      const desiredDataOffset = outputOffset + 30 + name.length + originalExtra.length;
      const remainder = desiredDataOffset % 4;
      const addBytes = remainder === 0 ? 0 : (remainder === 1 ? 7 : remainder === 2 ? 6 : 5);
      const extra = addBytes ? appendPaddingExtra(originalExtra, addBytes) : originalExtra;
      const compressed = mod ? mod.compressed : new Uint8Array(await file.slice(info.dataStart, info.dataStart + e.compressedSize).arrayBuffer());
      const compressedSize = mod ? mod.compressed.length : e.compressedSize;
      const uncompressedSize = mod ? mod.uncompressedSize : e.uncompressedSize;
      const crc = mod ? mod.crc : e.crc;
      const localHeader = makeLocalHeader(e, extra, compressedSize, uncompressedSize, crc);
      const record = new Blob([localHeader, compressed]);
      localParts.push(record);
      centralMeta.push({ e, compressedSize, uncompressedSize, crc, localOffset: outputOffset });
      outputOffset += record.size;
    }
    if (i % 24 === 0 || i === apk.entries.length - 1) {
      progress('Rebuilding APK', 72 + (i / Math.max(1, apk.entries.length)) * 14, { message: `Writing ${Math.min(i + 1, apk.entries.length).toLocaleString()}/${apk.entries.length.toLocaleString()} archive records…`, processedEntries: i + 1, totalEntries: apk.entries.length, changedCount, totalReplacements });
      await yieldToBrowser();
    }
  }

  const centralParts = centralMeta.map(m => makeCentralHeader(m.e, m.compressedSize, m.uncompressedSize, m.crc, m.localOffset));
  const centralBytes = concat(...centralParts);
  const eocd = makeEocd(centralMeta.length, centralBytes.length, outputOffset, apk.eocdComment);
  const outputBlob = new Blob([...localParts, centralBytes, eocd], { type: 'application/vnd.android.package-archive' });

  progress('Verifying output', 88, { message: 'Verifying ZIP structure, manifest, and changed entries…' });
  // Load the finished Blob once. The result is ultimately returned as bytes, so
  // this avoids a second full-memory copy later.
  const outputBytes = new Uint8Array(await outputBlob.arrayBuffer());
  const out = await parseEntries(new File([outputBytes], 'output.apk', { type: 'application/vnd.android.package-archive' }), null);
  if (out.entries.length !== apk.entries.length - signatureRemoved.length) throw new Error(`Safety stop: output entry count ${out.entries.length} != expected ${apk.entries.length - signatureRemoved.length}.`);
  if (out.entries.some(e => isSignatureEntry(e.name))) throw new Error('Safety stop: stale APK signing metadata remains.');
  verifyOutputStructure(outputBytes, out);
  const outManifest = out.entries.find(e => e.name === 'AndroidManifest.xml');
  if (!outManifest) throw new Error('Safety stop: AndroidManifest.xml is missing after rebuild.');
  const outFile = new File([outputBytes], 'output.apk', { type: 'application/vnd.android.package-archive' });
  outManifest.dataStart = (await readLocalInfo(outFile, outManifest)).dataStart;
  const outManifestData = await decodeEntry(outFile, outManifest);
  const manifestTarget = countExact(outManifestData, variants.to8) + countExact(outManifestData, variants.to16);
  const manifestSource = countExact(outManifestData, variants.from8) + countExact(outManifestData, variants.from16);
  if (manifestTarget === 0 || manifestSource !== 0) throw new Error('Safety stop: rebuilt manifest package validation failed.');
  // Re-open only the files that were actually changed. Unchanged entries were
  // already fully decoded and proven to contain zero source-package matches.
  for (const index of changed.keys()) {
    const e = out.entries.find(x => x.name === apk.entries.find(a => a.index === index)?.name);
    if (!e) throw new Error(`Safety stop: changed output entry is missing for index ${index}.`);
    e.dataStart = (await readLocalInfo(outFile, e)).dataStart;
    const data = await decodeEntry(outFile, e);
    const source = countExact(data, variants.from8) + countExact(data, variants.from16);
    if (source !== 0) throw new Error(`Safety stop: source package remains in changed entry ${e.name}.`);
  }
  progress('Final validation', 96, { message: `Validation passed: ${totalReplacements.toLocaleString()} exact replacements applied; manifest target present.`, targetReferences: totalReplacements, sourceGone: true });

  return {
    bytes: outputBytes,
    blob: outputBlob,
    originalPackage: SOURCE_PACKAGE,
    targetPackage: TARGET_PACKAGE,
    inputSize: file.size,
    outputSize: outputBlob.size,
    manifestReplacements: manifestResult.count,
    totalReplacements,
    changedFiles: [...changed.keys()].map(index => { const e = apk.entries.find(x => x.index === index); const m = changed.get(index); return { name: e.name, method: e.method, newCompressed: m.compressed.length, oldCompressed: e.compressedSize, oldUncompressed: e.uncompressedSize, newUncompressed: m.uncompressedSize }; }),
    changedFileCount: changedCount,
    preservedFileCount: apk.entries.length - changedCount - signatureRemoved.length,
    signatureRemoved,
    validation: {
      sourceGone: true,
      targetReferences: totalReplacements,
      manifestTargetPresent: manifestTarget > 0,
      signatureEntriesRemoved: !out.entries.some(e => isSignatureEntry(e.name)),
      sizeDeltaPercent: ((outputBlob.size - file.size) / file.size) * 100,
    },
    outputName: (file.name || 'app.apk').replace(/\.apk$/i, '-neo-unsigned.apk'),
    processedEntries: apk.entries.length,
    totalEntries: apk.entries.length,
  };
}

function mb(n) { return `${(n / 1024 / 1024).toFixed(1)} MB`; }

export { SOURCE_PACKAGE, TARGET_PACKAGE, isSignatureEntry, parseEntries, packageVariants, patchData, countExact };
