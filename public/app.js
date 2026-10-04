import { renameApk, SOURCE_PACKAGE, TARGET_PACKAGE } from './processor.js';

const $ = id => document.getElementById(id);
const input = $('apkInput');
const drop = $('dropzone');
const status = $('statusCard');
const result = $('resultGrid');
let outputBlob = null;
let outputName = 'neo-sketchware.apk';

$('pickBtn').onclick = () => input.click();
input.onchange = () => input.files[0] && processFile(input.files[0]);
['dragenter','dragover'].forEach(e => drop.addEventListener(e, ev => {ev.preventDefault();drop.classList.add('drag');}));
['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => {ev.preventDefault();drop.classList.remove('drag');}));
drop.addEventListener('drop', ev => {const f=ev.dataTransfer.files[0];if(f)processFile(f);});
$('downloadBtn').onclick = () => { if(!outputBlob)return; const a=document.createElement('a');a.href=URL.createObjectURL(outputBlob);a.download=outputName;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2000); };

function setStatus(title,text,pct){
  status.classList.remove('hidden');
  $('statusDot').style.background = pct === 0 ? '#f0a5a5' : 'var(--primary)';
  $('statusTitle').textContent=title;
  $('statusText').textContent=text;
  $('statusPct').textContent=pct?`${pct}%`:'';
  $('progressBar').style.width=`${pct||0}%`;
}
const mb=n=>`${(n/1024/1024).toFixed(1)} MB`;

async function processFile(file){
  result.classList.add('hidden');
  outputBlob = null;
  $('downloadBtn').disabled = true;
  try{
    setStatus('Reading APK','Opening ZIP and locating AndroidManifest.xml…',12);
    if(!/\.apk$/i.test(file.name)) throw new Error('Please select an APK file.');
    if(file.size>250*1024*1024) throw new Error('For this demo, APKs larger than 250 MB are blocked to avoid browser memory exhaustion.');
    $('statusDot').style.background='var(--primary)';
    setStatus('Analyzing package','Checking exact source package before changing anything…',27);
    await new Promise(r=>setTimeout(r,20));
    setStatus('Renaming package','Patching exact package references and rebuilding APK…',54);
    const res=await renameApk(file);
    setStatus('Signing output','Creating v1 + v2 signatures and final APK…',88);
    await new Promise(r=>setTimeout(r,20));
    outputBlob=new Blob([res.bytes],{type:'application/vnd.android.package-archive'});
    outputName=res.outputName;
    $('origPkg').textContent=res.originalPackage;$('targetPkg').textContent=res.targetPackage;$('manifestHits').textContent=res.manifestReplacements;$('totalHits').textContent=res.totalReplacements;$('sizeInfo').textContent=`${mb(res.inputSize)} → ${mb(res.outputSize)}`;
    $('vManifest').textContent=res.validation.manifestTargetPresent?'PASS':'FAIL';
    $('vOld').textContent=res.validation.sourceExactStillPresentInOutput?'FOUND':'NOT FOUND';
    $('vOld').style.color=res.validation.sourceExactStillPresentInOutput?'#f4a6a6':'var(--success)';
    $('vSign').textContent=res.validation.v1AndV2?'STRUCTURE OK':'FAIL';
    $('resultTitle').textContent='APK generated successfully';
    result.classList.remove('hidden');
    $('downloadBtn').disabled = false;
    setStatus('Complete','The transformed APK is ready for download.',100);
  }catch(e){
    outputBlob = null;
    $('downloadBtn').disabled = true;
    $('statusDot').style.background='#f0a5a5';
    setStatus('Stopped',e?.message||String(e),0);
  }
}

// Keep the UI explicit about the fixed transformation.
$('origPkg').textContent=SOURCE_PACKAGE;$('targetPkg').textContent=TARGET_PACKAGE;
