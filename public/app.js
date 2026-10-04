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

const progressState = { logs: [], startedAt: 0, currentEntry: '', processedEntries: 0, totalEntries: 0, changedCount: 0, totalReplacements: 0 };

function setStatus(title, text, pctValue, mode='ok') {
  status.classList.remove('hidden');
  $('statusDot').className = `dot ${mode}`;
  $('statusTitle').textContent = title;
  $('statusText').textContent = text;
  $('statusPct').textContent = pctValue != null ? `${Math.round(pctValue)}%` : '';
  $('progressBar').style.width = `${Math.max(0, Math.min(100, pctValue || 0))}%`;
}

function escapeHtml(v) { return String(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c])); }
function renderDetails() {
  const list = $('detailLog');
  if (!list) return;
  list.innerHTML = progressState.logs.slice().reverse().map(x => `<div class="log-row"><span>${x.time}</span><b>${escapeHtml(x.stage)}</b><em>${x.percent ?? 0}%</em><p>${escapeHtml(x.message || '')}</p></div>`).join('');
}
function addLog(event) {
  const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  progressState.logs.push({ time, ...event });
  if (progressState.logs.length > 80) progressState.logs.shift();
  renderDetails();
}
function updateProgress(event) {
  Object.assign(progressState, event);
  // Keep the main status readable; the exact current entry is shown in the
  // dedicated Current field and the Details panel.
  setStatus(event.stage, event.message || '', event.percent);
  const last = progressState.logs.at(-1);
  if (!last || last.stage !== event.stage || Math.abs((last.percent || 0) - (event.percent || 0)) >= 2 || event.percent >= 100 || event.percent === 0) addLog(event);
  $('detailCurrent').textContent = event.currentEntry || '—';
  $('detailCount').textContent = event.totalEntries ? `${event.processedEntries || 0} / ${event.totalEntries}` : '—';
  $('detailChanged').textContent = String(event.changedCount ?? progressState.changedCount ?? 0);
  $('detailReplacements').textContent = String(event.totalReplacements ?? progressState.totalReplacements ?? 0);
}
function resetDetails() {
  progressState.logs = [];
  progressState.startedAt = performance.now();
  progressState.currentEntry = '';
  progressState.processedEntries = 0;
  progressState.totalEntries = 0;
  progressState.changedCount = 0;
  progressState.totalReplacements = 0;
  $('detailCurrent').textContent = '—';
  $('detailCount').textContent = '—';
  $('detailChanged').textContent = '0';
  $('detailReplacements').textContent = '0';
  renderDetails();
}

$('detailsBtn').onclick = () => $('detailsPanel').classList.toggle('hidden');
$('closeDetails').onclick = () => $('detailsPanel').classList.add('hidden');

async function processFile(file) {
  result.classList.add('hidden');
  outputBlob = null;
  $('downloadBtn').disabled = true;
  resetDetails();
  // Details must remain available DURING processing, not only after it ends.
  $('detailsBtn').classList.remove('hidden');
  updateProgress({ stage: 'Preparing', percent: 3, message: `Preparing ${file.name}…` });
  try {
    const res = await renameApk(file, updateProgress);
    updateProgress({ stage: 'Complete', percent: 100, message: 'All checks passed. Unsigned APK is ready.', processedEntries: res.processedEntries, totalEntries: res.totalEntries, changedCount: res.changedFileCount, totalReplacements: res.totalReplacements });
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
    $('detailsBtn').classList.remove('hidden');
  } catch (e) {
    outputBlob = null;
    $('downloadBtn').disabled = true;
    updateProgress({ stage: 'Stopped safely', percent: 0, message: e?.message || String(e) });
    $('statusDot').className = 'dot error';
    $('detailsBtn').classList.remove('hidden');
  }
}

const mb = n => `${(n / 1024 / 1024).toFixed(1)} MB`;
const pct = n => `${n >= 0 ? '+' : ''}${n.toFixed(2)}%`;
$('origPkg').textContent = SOURCE_PACKAGE;
$('targetPkg').textContent = TARGET_PACKAGE;

function previewMode() {
  const params = new URLSearchParams(location.search);
  const step = params.get('step');
  if (!step) return;
  resetDetails();
  const fake = [
    ['Reading APK', 8, 'Reading ZIP central directory…'],
    ['APK analyzed', 14, '4,192 archive entries found.'],
    ['Checking manifest', 18, 'Checking AndroidManifest.xml…'],
    ['Scanning archive', 28, 'Scanning 830/4,192 entries…'],
    ['Scanning archive', 46, 'Scanning 1,930/4,192 entries…'],
    ['Scanning archive', 63, 'Scanning 3,610/4,192 entries…'],
    ['Scanning archive', 70, 'Scanning 4,192/4,192 entries…'],
    ['Rebuilding APK', 76, 'Rebuilding archive with 7 changed entries…'],
    ['Verifying output', 88, 'Re-opening generated APK and checking integrity…'],
    ['Final validation', 96, 'Validation passed: target references found.'],
    ['Complete', 100, 'All checks passed. Unsigned APK is ready.']
  ];
  if (step === 'upload') {
    updateProgress({ stage: 'Ready for APK', percent: 3, message: 'Select the Sketchware Pro APK with source package pro.sketchware.' });
  } else if (step === 'processing') {
    $('detailsBtn').classList.remove('hidden');
    $('detailsPanel').classList.remove('hidden');
    let i = 0;
    const tick = () => {
      if (i >= fake.length) return;
      const [stage, percent, message] = fake[i++];
      updateProgress({ stage, percent, message, processedEntries: Math.min(4192, Math.round((Math.max(percent - 20, 0) / 50) * 4192)), totalEntries: 4192, changedCount: percent >= 70 ? 7 : 0, totalReplacements: percent >= 70 ? 8 : 0 });
      if (i < fake.length) setTimeout(tick, 650);
    };
    tick();
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
    updateProgress({ stage: 'Complete', percent: 100, message: 'Unsigned APK ready. Sign with your own key, then install.', processedEntries: 4192, totalEntries: 4192, changedCount: 7, totalReplacements: 8 });
    $('detailsBtn').classList.remove('hidden');
  }
}
previewMode();
