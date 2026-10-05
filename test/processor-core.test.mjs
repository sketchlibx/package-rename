import assert from 'node:assert/strict';
import { deflateRaw, unzipSync, zipSync } from './test-zip-helpers.mjs';
import { renameApk } from '../public/processor-core.js';


function addFakeSigningGap(zip, gapLen=64) {
  const z = new Uint8Array(zip);
  const sig = new Uint8Array([0x50,0x4b,0x05,0x06]);
  let eocd = -1;
  for (let i=z.length-22;i>=0;i--) { let ok=true; for(let j=0;j<4;j++) if(z[i+j]!==sig[j]) {ok=false;break;} if(ok){eocd=i;break;} }
  if(eocd<0) throw new Error('EOCD not found in test fixture');
  const cdOffset = z[eocd+16] | (z[eocd+17]<<8) | (z[eocd+18]<<16) | (z[eocd+19]<<24);
  const gap = new Uint8Array(gapLen);
  gap.set(new TextEncoder().encode('APK Sig Block 42 TEST'),0);
  const out = new Uint8Array(z.length+gapLen);
  out.set(z.slice(0,cdOffset),0);
  out.set(gap,cdOffset);
  out.set(z.slice(cdOffset),cdOffset+gapLen);
  const newCd=cdOffset+gapLen;
  out[eocd+gapLen+16]=newCd&255; out[eocd+gapLen+17]=(newCd>>>8)&255; out[eocd+gapLen+18]=(newCd>>>16)&255; out[eocd+gapLen+19]=(newCd>>>24)&255;
  return out;
}

const entries = {};
entries['AndroidManifest.xml'] = new TextEncoder().encode('<manifest package="pro.sketchware"><application android:name="pro.sketchware.App"/></manifest>');
entries['assets/debug/SketchLogger.java'] = new TextEncoder().encode('package pro.sketchware; class X { String p="pro.sketchware"; }');
entries['classes6.dex'] = new TextEncoder().encode('DEX pro.sketchware pro.sketchware');
entries['res/x.bin'] = new TextEncoder().encode('keep me');
entries['META-INF/LICENSE.txt'] = new TextEncoder().encode('license metadata');
entries['META-INF/FOO.SF'] = new TextEncoder().encode('signature');
entries['META-INF/FOO.RSA'] = new Uint8Array([1,2,3]);
for (let i=0;i<4296-7;i++) entries[`assets/filler/${String(i).padStart(4,'0')}.txt`] = new TextEncoder().encode(`filler ${i}`);
const zip = zipSync(entries);
const signedLikeZip = addFakeSigningGap(zip);
const file = new File([signedLikeZip], 'sketchware.apk', { type: 'application/vnd.android.package-archive' });
const progress=[];
const res = await renameApk(file, p => progress.push(p));
assert.equal(res.originalPackage, 'pro.sketchware');
assert.equal(res.targetPackage, 'neo.sketchware');
assert.ok(res.totalReplacements >= 4);
assert.ok(res.changedFileCount >= 3);
assert.equal(res.signatureRemoved.length, 2);
assert.equal(res.validation.sourceGone, true);
assert.equal(res.validation.manifestTargetPresent, true);
assert.equal(res.validation.signatureEntriesRemoved, true);
assert.equal(progress.some(p => p.message?.includes('Decompressing')), true);
const out = unzipSync(res.bytes);
assert.match(new TextDecoder().decode(out['AndroidManifest.xml']), /neo\.sketchware/);
assert.equal(out['META-INF/FOO.SF'], undefined);
assert.equal(out['META-INF/FOO.RSA'], undefined);
assert.equal(new TextDecoder().decode(out['assets/filler/0000.txt']), 'filler 0');
assert.equal(new TextDecoder().decode(res.bytes).includes('APK Sig Block 42 TEST'), false);
console.log('processor-core test: PASS', { entries:Object.keys(entries).length, changed:res.changedFileCount, replacements:res.totalReplacements, progress:progress.length });
