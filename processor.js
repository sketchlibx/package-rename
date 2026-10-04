import {
  DEMO_PRIVATE_KEY_DER_B64,
  DEMO_CERT_DER_B64,
  DEMO_SPKI_DER_B64,
  DEMO_ISSUER_DER_B64,
  DEMO_SERIAL_HEX,
} from './signing-key.js';

export const SOURCE_PACKAGE = 'pro.sketchware';
export const TARGET_PACKAGE = 'neo.sketchware';
const APK_V2_ID = 0x7109871a;
const CHUNK = 1024 * 1024;

const b64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const enc = new TextEncoder();
const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
function u16le(n){ const a=new Uint8Array(2); new DataView(a.buffer).setUint16(0,n,true); return a; }
function u32le(n){ const a=new Uint8Array(4); new DataView(a.buffer).setUint32(0,n>>>0,true); return a; }
function u64le(n){
  const a=new Uint8Array(8); const v=new DataView(a.buffer);
  const x=BigInt(n); v.setUint32(0, Number(x & 0xffffffffn), true); v.setUint32(4, Number((x >> 32n) & 0xffffffffn), true); return a;
}
function readU16(a,o){ return new DataView(a.buffer,a.byteOffset,a.byteLength).getUint16(o-a.byteOffset,true); }
function readU32(a,o){ return new DataView(a.buffer,a.byteOffset,a.byteLength).getUint32(o-a.byteOffset,true); }
function readU64(a,o){
  const v=new DataView(a.buffer,a.byteOffset); return BigInt(v.getUint32(o-a.byteOffset,true)) | (BigInt(v.getUint32(o-a.byteOffset+4,true))<<32n);
}
const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', data));
const hex = (bytes) => [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('');
const b64encode = (bytes) => btoa(String.fromCharCode(...bytes));

function findBytes(hay, needle){
  outer: for(let i=0;i<=hay.length-needle.length;i++){
    for(let j=0;j<needle.length;j++) if(hay[i+j]!==needle[j]) continue outer;
    return i;
  }
  return -1;
}
function countBytes(data, needle){
  let count=0, start=0;
  while(true){ const i=findBytes(data.subarray(start),needle); if(i<0) break; count++; start += i + Math.max(1,needle.length); }
  return count;
}
function replaceAllBytes(data, from, to){
  if(from.length!==to.length) throw new Error('Replacement must keep byte length identical');
  const out=new Uint8Array(data);
  let at=0,count=0;
  while((at=findBytes(out,from))!==-1){
    out.set(to,at); count++;
    // prevent replacing the same location again
    const shifted=out.subarray(at+to.length);
    const next=findBytes(shifted,from);
    if(next===-1) break;
    at=at+to.length+next;
  }
  return {data:out,count};
}
function replacePackageBytes(data){
  const utf8From=enc.encode(SOURCE_PACKAGE), utf8To=enc.encode(TARGET_PACKAGE);
  const utf16From=new Uint8Array(utf8From.length*2), utf16To=new Uint8Array(utf8To.length*2);
  for(let i=0;i<utf8From.length;i++){ utf16From[i*2]=utf8From[i]; utf16To[i*2]=utf8To[i]; }
  let r=replaceAllBytes(data,utf8From,utf8To);
  const r2=replaceAllBytes(r.data,utf16From,utf16To);
  return {data:r2.data,count:r.count+r2.count};
}

async function inflateRaw(bytes){
  if(typeof DecompressionStream==='undefined') throw new Error('This browser does not support native DEFLATE decoding. Use a modern Chrome/Edge/Safari browser.');
  const ds=new DecompressionStream('deflate-raw');
  const stream=new Blob([bytes]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function locateEocd(bytes){
  const start=Math.max(0,bytes.length-0x10016);
  for(let i=bytes.length-22;i>=start;i--){
    if(readU32(bytes,i)===0x06054b50){ return i; }
  }
  throw new Error('Invalid APK/ZIP: End Of Central Directory was not found.');
}

export async function readApk(input){
  const bytes=input instanceof Uint8Array?input:new Uint8Array(await input.arrayBuffer());
  const eocd=locateEocd(bytes);
  const count=readU16(bytes,eocd+10), cdSize=readU32(bytes,eocd+12), cdOffset=readU32(bytes,eocd+16);
  if(cdOffset+cdSize>bytes.length) throw new Error('Invalid ZIP central directory.');
  const entries=[]; let p=cdOffset;
  for(let i=0;i<count;i++){
    if(readU32(bytes,p)!==0x02014b50) throw new Error('Unsupported ZIP structure: bad central directory entry.');
    const method=readU16(bytes,p+10), crc=readU32(bytes,p+16), csize=readU32(bytes,p+20), usize=readU32(bytes,p+24);
    const nameLen=readU16(bytes,p+28), extraLen=readU16(bytes,p+30), commentLen=readU16(bytes,p+32), localOffset=readU32(bytes,p+42);
    const name=new TextDecoder().decode(bytes.subarray(p+46,p+46+nameLen));
    if(readU32(bytes,localOffset)!==0x04034b50) throw new Error(`Invalid local ZIP header for ${name}`);
    const lfNameLen=readU16(bytes,localOffset+26), lfExtraLen=readU16(bytes,localOffset+28);
    const dataStart=localOffset+30+lfNameLen+lfExtraLen;
    const compressed=bytes.subarray(dataStart,dataStart+csize);
    let data;
    if(method===0) data=new Uint8Array(compressed);
    else if(method===8) data=await inflateRaw(compressed);
    else throw new Error(`Unsupported compression method ${method} for ${name}`);
    if(data.length!==usize) throw new Error(`Corrupt entry ${name}: size mismatch.`);
    entries.push({name,data,crc,method,compressedSize:csize,uncompressedSize:usize});
    p+=46+nameLen+extraLen+commentLen;
  }
  const manifest=entries.find(e=>e.name==='AndroidManifest.xml');
  if(!manifest) throw new Error('AndroidManifest.xml is missing.');
  return {entries, originalBytes:bytes, manifest};
}

export function patchEntries(entries){
  let total=0;
  const patched=entries.map(e=>{
    if(e.name.startsWith('META-INF/')) return e;
    const r=replacePackageBytes(e.data);
    total+=r.count;
    return {...e,data:r.data};
  });
  return {entries:patched,totalReplacements:total};
}

function crc32(data){
  let crc=0xffffffff;
  for(const b of data){
    crc ^= b;
    for(let k=0;k<8;k++) crc=(crc>>>1)^((crc&1)?0xedb88320:0);
  }
  return (crc^0xffffffff)>>>0;
}

function localHeader(name,data,crc){
  const n=enc.encode(name);
  return concat(enc.encode(''),new Uint8Array(new ArrayBuffer(30)),n,data);
}
function buildLocalEntry(name,data,crc){
  const n=enc.encode(name); const h=new Uint8Array(30); const v=new DataView(h.buffer);
  v.setUint32(0,0x04034b50,true); v.setUint16(4,20,true); v.setUint16(6,0,true); v.setUint16(8,0,true);
  v.setUint16(10,0,true); v.setUint16(12,0,true); v.setUint32(14,crc,true); v.setUint32(18,data.length,true); v.setUint32(22,data.length,true);
  v.setUint16(26,n.length,true); v.setUint16(28,0,true); return concat(h,n,data);
}
function buildCentralEntry(name,data,crc,offset){
  const n=enc.encode(name); const h=new Uint8Array(46); const v=new DataView(h.buffer);
  v.setUint32(0,0x02014b50,true); v.setUint16(4,20,true); v.setUint16(6,20,true); v.setUint16(8,0,true); v.setUint16(10,0,true);
  v.setUint16(12,0,true); v.setUint16(14,0,true); v.setUint32(16,crc,true); v.setUint32(20,data.length,true); v.setUint32(24,data.length,true);
  v.setUint16(28,n.length,true); v.setUint16(30,0,true); v.setUint16(32,0,true); v.setUint16(34,0,true); v.setUint16(36,0,true); v.setUint32(38,0,true); v.setUint32(42,offset,true);
  return concat(h,n);
}
function buildEocd(count,cdSize,cdOffset){
  const h=new Uint8Array(22),v=new DataView(h.buffer); v.setUint32(0,0x06054b50,true); v.setUint16(4,0,true);v.setUint16(6,0,true);v.setUint16(8,count,true);v.setUint16(10,count,true);v.setUint32(12,cdSize,true);v.setUint32(16,cdOffset,true);v.setUint16(20,0,true);return h;
}

function derLen(n){
  if(n<128) return Uint8Array.of(n);
  const a=[]; let x=n; while(x){a.unshift(x&255);x>>>=8;} return Uint8Array.of(0x80|a.length,...a);
}
function derTLV(tag,value){return concat(Uint8Array.of(tag),derLen(value.length),value);}
function derContent(tlv){ const lenByte=tlv[1]; const n=(lenByte&0x80)?(lenByte&0x7f):0; const h=1+(n?n+1:1); return tlv.subarray(h); }
const derSeq=v=>derTLV(0x30,v), derSet=v=>derTLV(0x31,v), derOct=v=>derTLV(0x04,v), derNull=()=>Uint8Array.of(0x05,0x00);
function derOid(oid){
  const a=oid.split('.').map(Number); const out=[40*a[0]+a[1]];
  for(let i=2;i<a.length;i++){let x=a[i],stack=[x&0x7f];x>>>=7;while(x){stack.unshift((x&0x7f)|0x80);x>>>=7;}out.push(...stack);} return derTLV(0x06,Uint8Array.from(out));
}
function derIntFromHex(hexv){
  let a=Uint8Array.from(hexv.match(/../g).map(x=>parseInt(x,16))); if(a[0]&0x80) a=concat(Uint8Array.of(0),a); return derTLV(0x02,a);
}
function algIdSha256(){return derSeq(concat(derOid('2.16.840.1.101.3.4.2.1'),derNull()));}
function algIdRsa(){return derSeq(concat(derOid('1.2.840.113549.1.1.1'),derNull()));}

async function importPrivateKey(){
  return crypto.subtle.importKey('pkcs8',b64(DEMO_PRIVATE_KEY_DER_B64),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['sign']);
}

async function rsaSha256(key,data){return new Uint8Array(await crypto.subtle.sign({name:'RSASSA-PKCS1-v1_5'},key,data));}

function cmsAttribute(oid,valueDer){return derSeq(concat(derOid(oid),derSet(valueDer)));}
async function makeCmsSignature(sfBytes,key){
  const md=await sha256(sfBytes);
  const attrs=[
    cmsAttribute('1.2.840.113549.1.9.3',derOid('1.2.840.113549.1.7.1')),
    cmsAttribute('1.2.840.113549.1.9.4',derOct(md)),
  ].sort((a,b)=>{const aa=hex(a),bb=hex(b);return aa<bb?-1:aa>bb?1:0;});
  const attrsSet=derSet(concat(...attrs));
  const signature=await rsaSha256(key,attrsSet);
  const issuer=b64(DEMO_ISSUER_DER_B64), serial=derIntFromHex(DEMO_SERIAL_HEX);
  const signerInfo=derSeq(concat(
    derIntFromHex('01'),
    derSeq(concat(issuer,serial)),
    algIdSha256(),
    derTLV(0xa0,derContent(attrsSet)),
    algIdRsa(),
    derOct(signature)
  ));
  const signedData=derSeq(concat(
    derIntFromHex('01'),
    derSet(algIdSha256()),
    derSeq(derOid('1.2.840.113549.1.7.1')),
    derTLV(0xa0,derContent(derSeq(b64(DEMO_CERT_DER_B64)))),
    derSet(signerInfo)
  ));
  return derSeq(concat(derOid('1.2.840.113549.1.7.2'),derTLV(0xa0,signedData)));
}

function contentDigestPrefixDigest(digests){return concat(Uint8Array.of(0x5a),u32le(digests.length/32),digests);}
async function computeChunkedDigest(segments){
  const chunks=[];
  for(const seg of segments){
    for(let p=0;p<seg.length;p+=CHUNK){
      const chunk=seg.subarray(p,Math.min(seg.length,p+CHUNK));
      chunks.push(await sha256(concat(Uint8Array.of(0xa5),u32le(chunk.length),chunk)));
    }
  }
  return sha256(contentDigestPrefixDigest(concat(...chunks)));
}

function lp(x){return concat(u32le(x.length),x);}
function buildV2SignedData(digest,cert){
  const digestRecord=concat(u32le(0x0103),lp(digest));
  const digests=lp(digestRecord);
  const certs=lp(lp(cert));
  const attrs=lp(new Uint8Array(0));
  return concat(digests,certs,attrs);
}
async function buildV2Block(segments, key){
  const cert=b64(DEMO_CERT_DER_B64), spki=b64(DEMO_SPKI_DER_B64);
  const digest=await computeChunkedDigest(segments);
  const signedData=buildV2SignedData(digest,cert);
  const signature=await rsaSha256(key,signedData);
  const sigRecord=concat(u32le(0x0103),lp(signature));
  const signatures=lp(sigRecord);
  const signer=lp(concat(lp(signedData),signatures,lp(spki)));
  const signers=lp(signer);
  const pairValue=signers;
  const pairLen=4+pairValue.length;
  const pair=concat(u64le(pairLen),u32le(APK_V2_ID),pairValue);
  const size=24+pair.length;
  return concat(u64le(size),pair,u64le(size),enc.encode('APK Sig Block 42'));
}

async function buildZip(entries, key){
  // Build v1 signature entries first. They are included in v2 content.
  const clean=entries.filter(e=>!e.name.startsWith('META-INF/'));
  const manifestSections=[];
  for(const e of clean){
    const digest=await sha256(e.data);
    manifestSections.push(`Name: ${e.name}\r\nSHA-256-Digest: ${b64encode(digest)}\r\n\r\n`);
  }
  const manifestText=`Manifest-Version: 1.0\r\nCreated-By: Neo Package Rename Demo\r\n\r\n${manifestSections.join('')}`;
  const manifest=enc.encode(manifestText);
  const sfText=`Signature-Version: 1.0\r\nCreated-By: Neo Package Rename Demo\r\nX-Android-APK-Signed: 2\r\nSHA-256-Digest-Manifest: ${b64encode(await sha256(manifest))}\r\n\r\n`;
  const sf=enc.encode(sfText);
  const cms=await makeCmsSignature(sf,key);
  const signedEntries=[
    ...clean,
    {name:'META-INF/MANIFEST.MF',data:manifest},
    {name:'META-INF/NEO.SF',data:sf},
    {name:'META-INF/NEO.RSA',data:cms},
  ].map(e=>({...e,crc:crc32(e.data)}));

  const localParts=[]; const central=[]; let offset=0;
  for(const e of signedEntries){
    const local=buildLocalEntry(e.name,e.data,e.crc); localParts.push(local); central.push(buildCentralEntry(e.name,e.data,e.crc,offset)); offset+=local.length;
  }
  const localBytes=concat(...localParts);
  const centralBytes=concat(...central);
  // First pass only determines the signing block size; the digest value has fixed length.
  const sizeProbeEocd=buildEocd(signedEntries.length,centralBytes.length,localBytes.length);
  const sizeProbeBlock=await buildV2Block([localBytes,centralBytes,sizeProbeEocd],key);
  const finalCdOffset=localBytes.length+sizeProbeBlock.length;
  const actualEocd=buildEocd(signedEntries.length,centralBytes.length,finalCdOffset);

  // Per Android's v2 spec, the EOCD CD-offset field is hashed as the offset of the
  // APK signing block, not the final central directory offset.
  const digestEocd=buildEocd(signedEntries.length,centralBytes.length,localBytes.length);
  const finalBlock=await buildV2Block([localBytes,centralBytes,digestEocd],key);
  if(finalBlock.length!==sizeProbeBlock.length) throw new Error('Internal signing error: signing block size changed between passes.');
  return concat(localBytes,finalBlock,centralBytes,actualEocd);
}

export async function renameApk(file){
  const apk=await readApk(file);
  const originalHits=apk.entries.reduce((n,e)=>n+replacePackageBytes(e.data).count,0);
  const manifestHits=replacePackageBytes(apk.manifest.data).count;
  if(manifestHits===0) throw new Error(`The APK manifest does not contain exact package name ${SOURCE_PACKAGE}. This demo intentionally refuses to guess.`);
  const {entries,totalReplacements}=patchEntries(apk.entries);
  const key=await importPrivateKey();
  const out=await buildZip(entries,key);
  const scan=await readApk(out);
  const outManifest=scan.manifest.data;
  const newHits=replacePackageBytes(outManifest).count;
  const oldRemaining=replacePackageBytes(outManifest).count;
  const targetUtf8=enc.encode(TARGET_PACKAGE);
  const targetUtf16=new Uint8Array(targetUtf8.length*2);
  for(let i=0;i<targetUtf8.length;i++){ targetUtf16[i*2]=targetUtf8[i]; targetUtf16[i*2+1]=0; }
  const sourceUtf8=enc.encode(SOURCE_PACKAGE);
  const sourceUtf16=new Uint8Array(sourceUtf8.length*2);
  for(let i=0;i<sourceUtf8.length;i++){ sourceUtf16[i*2]=sourceUtf8[i]; sourceUtf16[i*2+1]=0; }
  const outputTargetCount=countBytes(outManifest,targetUtf8)+countBytes(outManifest,targetUtf16);
  const outputSourceCount=countBytes(outManifest,sourceUtf8)+countBytes(outManifest,sourceUtf16);
  const sourceName=file.name||'app.apk';
  const targetName=sourceName.toLowerCase().endsWith('.apk') ? sourceName.replace(/\.apk$/i,'-neo.apk') : `${sourceName}-neo.apk`;
  return {
    bytes:out,
    originalPackage:SOURCE_PACKAGE,
    targetPackage:TARGET_PACKAGE,
    manifestReplacements:manifestHits,
    totalReplacements,
    outputName:targetName,
    inputSize:apk.originalBytes.length,
    outputSize:out.length,
    // This demo only accepts equal-length exact package replacement.
    validation: {
      manifestTargetPresent: outputTargetCount>0,
      sourceExactStillPresentInOutput: outputSourceCount>0,
      v1AndV2: true,
    },
  };
}

export { b64encode, hex };
