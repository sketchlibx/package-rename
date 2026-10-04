import { renameApk, SOURCE_PACKAGE, TARGET_PACKAGE } from './processor.js';

const $ = id => document.getElementById(id);
const input = $('apkInput');
const drop = $('dropzone');
const status = $('statusCard');
const result = $('resultGrid');
let outputBlob = null;
let outputName = 'neo-sketchware-unsigned.apk';

$('pickBtn').onclick = () => input.click();
input.onchange = () => input.files[0] && processFile(input.files[0]);
['dragenter','dragover'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('drag'); }));
['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove('drag'); }));
drop.addEventListener('drop', ev => { const f = ev.dataTransfer.files[0]; if (f) processFile(f); });
$('downloadBtn').onclick = () => {
  if (!outputBlob) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(outputBlob);
  a.download = outputName;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
};

function setStatus(title, text, pct, mode='ok') {
  status.classList.remove('hidden');
  $('statusDot').className = `dot ${mode}`;
  $('statusTitle').textContent = title;
  $('statusText').textContent = text;
  $('statusPct').textContent = pct != null ? `${pct}%` : '';
  $('progressBar').style.width = `${pct || 0}%`;
}
const mb = n => `${(n / 1024 / 1024).toFixed(1)} MB`;
const pct = n => `${n >= 0 ? '+' : ''}${n.toFixed(2)}%`;

async function processFile(file) {
  result.classList.add('hidden');
  outputBlob = null;
  $('downloadBtn').disabled = true;
  setStatus('Reading APK', 'Reading ZIP central directory without unpacking the entire APK.', 10);
  try {
    const res = await renameApk(file);
    setStatus('Package references replaced', `${res.changedFileCount} archive entries changed; ${res.preservedFileCount} preserved.`, 72);
    outputBlob = new Blob([res.bytes], { type: 'application/vnd.android.package-archive' });
    outputName = res.outputName;

    $('origPkg').textContent = res.originalPackage;
    $('targetPkg').textContent = res.targetPackage;
    $('manifestHits').textContent = res.manifestReplacements;
    $('totalHits').textContent = res.totalReplacements;
    $('sizeInfo').textContent = `${mb(res.inputSize)} → ${mb(res.outputSize)} (${pct(res.validation.sizeDeltaPercent)})`;
    $('changedCount').textContent = res.changedFileCount;
    $('preservedCount').textContent = res.preservedFileCount;
    $('removedSignatures').textContent = res.signatureRemoved.length || '0';
    $('vManifest').textContent = res.validation.manifestTargetPresent ? 'PASS' : 'FAIL';
    $('vOld').textContent = res.validation.sourceGone ? 'NOT FOUND' : 'FOUND';
    $('vOld').className = res.validation.sourceGone ? 'pass' : 'fail';
    $('vMeta').textContent = res.validation.signatureEntriesRemoved ? 'CLEAN' : 'FAIL';
    $('vSize').textContent = Math.abs(res.validation.sizeDeltaPercent) < 5 ? 'NORMAL' : 'CHECK';
    $('changedFiles').textContent = res.changedFiles.map(x => x.name).join(', ');
    $('resultTitle').textContent = 'Rename complete — unsigned APK';
    result.classList.remove('hidden');
    $('downloadBtn').disabled = false;
    setStatus('Complete', 'Download the unsigned APK, then sign it with your own signing key/tool before installation.', 100);
  } catch (e) {
    outputBlob = null;
    $('downloadBtn').disabled = true;
    setStatus('Stopped safely', e?.message || String(e), 0, 'error');
  }
}

$('origPkg').textContent = SOURCE_PACKAGE;
$('targetPkg').textContent = TARGET_PACKAGE;

function previewMode() {
  const params = new URLSearchParams(location.search);
  const step = params.get('step');
  if (!step) return;
  if (step === 'upload') {
    setStatus('Ready for APK', 'Select the Sketchware Pro APK with source package pro.sketchware.', 18);
  } else if (step === 'processing') {
    setStatus('Renaming safely', 'Preserving compression and archive metadata while replacing exact package bytes.', 62);
  } else if (step === 'result') {
    $('origPkg').textContent = SOURCE_PACKAGE;
    $('targetPkg').textContent = TARGET_PACKAGE;
    $('manifestHits').textContent = '3';
    $('totalHits').textContent = '8';
    $('sizeInfo').textContent = '130.2 MB → 130.1 MB (-0.08%)';
    $('changedCount').textContent = '7';
    $('preservedCount').textContent = '4185';
    $('removedSignatures').textContent = '2';
    $('vManifest').textContent = 'PASS';
    $('vOld').textContent = 'NOT FOUND';
    $('vMeta').textContent = 'CLEAN';
    $('vSize').textContent = 'NORMAL';
    $('changedFiles').textContent = 'AndroidManifest.xml, classes6.dex, classes16.dex, resources.arsc, res/K51.xml, res/d21.xml, assets/debug/SketchLogger.java';
    result.classList.remove('hidden');
    setStatus('Complete', 'Unsigned APK ready. Sign with your own release/test key, then install.', 100);
  }
}
previewMode();
