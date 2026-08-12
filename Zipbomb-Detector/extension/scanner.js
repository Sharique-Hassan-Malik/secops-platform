/**
 * scanner.js — Multi-Format Archive Bomb Detection Engine (JavaScript)
 *
 * Supported: ZIP, GZip, BZip2, TAR, 7z, XZ, RAR4/5, Zstandard,
 *            PyTorch (.pt/.pth), and ZIP-based formats (.jar, .docx, etc.)
 *
 * All detection is purely metadata-based — zero decompression.
 *
 * Exports: scanArchive(file, policy?) → ScanResult
 */

export const ThreatLevel = Object.freeze({
  NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4,
  name: v => ['NONE','LOW','MEDIUM','HIGH','CRITICAL'][v] ?? 'UNKNOWN',
});

export const POLICIES = {
  default:  { maxRatio: 100,  maxUncompressed: 4*1024**3, maxEntries: 10000, checkOverlaps: true },
  strict:   { maxRatio: 50,   maxUncompressed: 1<<30,     maxEntries: 500,   checkOverlaps: true },
  paranoid: { maxRatio: 10,   maxUncompressed: 1<<28,     maxEntries: 100,   checkOverlaps: true },
  relaxed:  { maxRatio: 500,  maxUncompressed: 2**36,     maxEntries: 50000, checkOverlaps: true },
};

const decoder = new TextDecoder('utf-8', { fatal: false });

// Format magic signatures
const MAGIC_MAP = [
  [[0x50,0x4b,0x03,0x04], 'zip'],
  [[0x50,0x4b,0x05,0x06], 'zip'],
  [[0x1f,0x8b],           'gzip'],
  [[0x42,0x5a,0x68],      'bzip2'],          // BZh
  [[0x37,0x7a,0xbc,0xaf,0x27,0x1c], '7z'],
  [[0xfd,0x37,0x7a,0x58,0x5a,0x00], 'xz'],
  [[0x52,0x61,0x72,0x21,0x1a,0x07,0x00],     'rar4'],  // Rar!...
  [[0x52,0x61,0x72,0x21,0x1a,0x07,0x01,0x00],'rar5'],
  [[0x28,0xb5,0x2f,0xfd], 'zstd'],
];

const EXT_MAP = {
  '.zip':'.zip', '.jar':'zip',  '.war':'zip',  '.apk':'zip',
  '.docx':'zip', '.xlsx':'zip', '.pptx':'zip',
  '.gz':'gzip',  '.tgz':'tar.gz',
  '.bz2':'bzip2','.tbz2':'tar.bzip2',
  '.7z':'7z',    '.xz':'xz',
  '.rar':'rar',  '.zst':'zstd', '.zstd':'zstd',
  '.tar':'tar',  '.pt':'pytorch','.pth':'pytorch',
};

class DataReader {
  constructor(buf) { this.v = new DataView(buf); this.p = 0; }
  u8()  { return this.v.getUint8(this.p++); }
  u16() { const v = this.v.getUint16(this.p, true); this.p += 2; return v; }
  u32() { const v = this.v.getUint32(this.p, true); this.p += 4; return v; }
  u32at(o) { return this.v.getUint32(o, true); }
  u8at(o)  { return this.v.getUint8(o); }
  skip(n) { this.p += n; }
  seek(n) { this.p  = n; }
  bytes(n){ const b=new Uint8Array(this.v.buffer,this.p,n); this.p+=n; return b; }
  get size() { return this.v.byteLength; }
  get pos()  { return this.p; }
  vint() {  // variable-length integer (for 7z/RAR5)
    let v=0, s=0;
    while(this.p < this.size) {
      const b=this.u8(); v|=(b&0x7f)<<s; s+=7;
      if(!(b&0x80)) break;
    }
    return v;
  }
}

function detectFormat(name, bytes) {
  const arr = new Uint8Array(bytes, 0, Math.min(16, bytes.byteLength));
  for (const [magic, fmt] of MAGIC_MAP) {
    if (magic.every((b,i) => arr[i] === b)) return fmt;
  }
  // TAR: check "ustar" at offset 257
  if (bytes.byteLength >= 512) {
    const t = new Uint8Array(bytes, 257, 5);
    if (t[0]===0x75&&t[1]===0x73&&t[2]===0x74&&t[3]===0x61&&t[4]===0x72) return 'tar';
  }
  const ext = ('.'+(name.split('.').pop())).toLowerCase();
  return EXT_MAP[ext] ?? 'unknown';
}

function makeResult(fmt) {
  return {
    isThreat: false, threatLevel: ThreatLevel.NONE, fmt,
    flags: [], entries: [], entryCount: 0,
    totalCompressed: 0, totalUncompressed: 0, overallRatio: 0,
    hasOverlaps: false, scanMs: 0, details: {},
    addFlag(level, code, description) {
      this.flags.push({ level, levelName: ThreatLevel.name(level), code, description });
      if (level > this.threatLevel) this.threatLevel = level;
      this.isThreat = this.threatLevel > ThreatLevel.NONE;
    }
  };
}

// ── ZIP ──────────────────────────────────────────────────────────────────────

function scanZip(r, policy, result) {
  const SIG_CDIR = 0x02014b50;
  const SIG_EOCD = 0x06054b50;

  let eocdPos = -1;
  const limit = Math.max(0, r.size - 65557);
  for (let p = r.size - 22; p >= limit; p--) {
    if (r.u32at(p) === SIG_EOCD) { eocdPos = p; break; }
  }
  if (eocdPos < 0) { result.addFlag(ThreatLevel.NONE,'INVALID_ZIP','No EOCD record'); return; }

  r.seek(eocdPos + 10);
  const entryCount = r.u16();
  r.skip(4);
  const cdOffset = r.u32();

  if (entryCount > policy.maxEntries) {
    result.addFlag(ThreatLevel.HIGH,'ENTRY_FLOOD',
      `${entryCount.toLocaleString()} entries exceeds limit ${policy.maxEntries}`);
    result.entryCount = entryCount; return;
  }

  r.seek(cdOffset);
  const ranges = [];
  let comp=0, uncomp=0;

  for (let i=0; i<entryCount; i++) {
    if (r.u32() !== SIG_CDIR) {
      result.addFlag(ThreatLevel.MEDIUM,'HEADER_CORRUPT',`Bad sig at entry ${i}`); return;
    }
    r.skip(4); r.skip(2); r.skip(2); r.skip(4); r.skip(4); // ver/flags/method/time/crc
    const compSz   = r.u32();
    const uncompSz = r.u32();
    const fnLen    = r.u16();
    const exLen    = r.u16();
    const cmLen    = r.u16();
    r.skip(8);
    const lhOffset = r.u32();
    const nameBytes = r.bytes(fnLen);
    r.skip(exLen + cmLen);

    const name  = decoder.decode(nameBytes);
    const ratio = compSz > 0 ? uncompSz / compSz : 0;
    result.entries.push({ name, compSz, uncompSz, ratio, lhOffset });

    if (compSz>0 && ratio > policy.maxRatio)
      result.addFlag(ThreatLevel.CRITICAL,'RATIO_EXCEEDED',
        `"${name}": ${ratio.toFixed(1)}:1 exceeds ${policy.maxRatio}:1`);

    comp   += compSz;
    uncomp += uncompSz;
    if (uncomp > policy.maxUncompressed) {
      result.addFlag(ThreatLevel.CRITICAL,'SIZE_EXCEEDED',
        `Declared expansion ${fmtBytes(uncomp)} exceeds limit`); break;
    }
    ranges.push([lhOffset, lhOffset+30+fnLen+exLen+compSz]);
    result.entryCount++;
  }

  result.totalCompressed   = comp;
  result.totalUncompressed = uncomp;
  result.overallRatio      = comp > 0 ? uncomp/comp : 0;

  if (policy.checkOverlaps) {
    const sorted = [...ranges].sort((a,b)=>a[0]-b[0]);
    for (let i=0;i<sorted.length-1;i++) {
      if (sorted[i][1]>sorted[i+1][0]) {
        result.hasOverlaps=true;
        result.addFlag(ThreatLevel.CRITICAL,'OVERLAPPING_DATA',
          'Data regions overlap — Fifield-style non-recursive zip bomb'); break;
      }
    }
  }
}

// ── GZip ─────────────────────────────────────────────────────────────────────

function scanGzip(r, policy, result) {
  const arr = new Uint8Array(r.v.buffer);
  if (arr[0]!==0x1f||arr[1]!==0x8b) { result.addFlag(ThreatLevel.NONE,'INVALID_GZIP','Bad magic'); return; }
  // ISIZE is stored in last 4 bytes of each gzip member
  const isize = r.u32at(r.size - 4);
  const ratio = isize > 0 ? isize / r.size : 0;
  result.totalCompressed   = r.size;
  result.totalUncompressed = isize;
  result.overallRatio      = ratio;
  result.entryCount        = 1;
  if (isize===0 && r.size > 100)
    result.addFlag(ThreatLevel.MEDIUM,'ISIZE_ZERO','ISIZE=0; may indicate >4 GB content');
  if (ratio > policy.maxRatio)
    result.addFlag(ThreatLevel.CRITICAL,'RATIO_EXCEEDED',`${ratio.toFixed(1)}:1 exceeds ${policy.maxRatio}:1`);
  if (isize > policy.maxUncompressed)
    result.addFlag(ThreatLevel.CRITICAL,'SIZE_EXCEEDED',`Declared ${fmtBytes(isize)} exceeds limit`);
}

// ── BZip2 ────────────────────────────────────────────────────────────────────

function scanBzip2(r, policy, result) {
  const arr = new Uint8Array(r.v.buffer);
  if (arr[0]!==0x42||arr[1]!==0x5a||arr[2]!==0x68) {
    result.addFlag(ThreatLevel.NONE,'INVALID_BZIP2','Bad magic'); return;
  }
  const blockLevel = arr[3] - 0x30; // '1'–'9' → 1–9
  const blockSizes = [0,100000,200000,300000,400000,500000,600000,700000,800000,900000];
  const maxBlockSz = blockSizes[blockLevel] || 900000;
  // Count BLOCK_MAGIC (0x314159265359) occurrences
  let blocks=0;
  const bm=[0x31,0x41,0x59,0x26,0x53,0x59];
  for (let i=4; i<arr.length-6; i++) {
    if (bm.every((b,j)=>arr[i+j]===b)) { blocks++; i+=5; }
  }
  const maxUncomp = blocks * maxBlockSz * 30;
  result.totalCompressed   = r.size;
  result.totalUncompressed = maxUncomp;
  result.overallRatio      = maxUncomp / r.size;
  result.entryCount        = blocks;
  result.details.blockLevel = blockLevel;
  result.details.note       = 'Uncompressed size is worst-case upper bound';
  if (maxUncomp > policy.maxUncompressed)
    result.addFlag(ThreatLevel.HIGH,'WORST_CASE_SIZE_EXCEEDED',
      `Worst-case expansion ${fmtBytes(maxUncomp)} could exceed limit`);
}

// ── TAR ──────────────────────────────────────────────────────────────────────

function scanTar(r, policy, result) {
  const arr    = new Uint8Array(r.v.buffer);
  let pos      = 0;
  let entries  = 0;
  let totalSz  = 0;
  let zeroBlocks = 0;

  while (pos + 512 <= arr.length) {
    const block = arr.slice(pos, pos+512);
    if (block.every(b=>b===0)) { if(++zeroBlocks>=2) break; pos+=512; continue; }
    zeroBlocks = 0;

    // Parse size field (offset 124, 12 bytes octal)
    const sizeOctal = decoder.decode(block.slice(124,136)).replace(/\0/g,'').trim();
    const size = sizeOctal ? parseInt(sizeOctal,8) : 0;
    const typeFlag = String.fromCharCode(block[156]||48);

    if (['0','\x00','7'].includes(typeFlag)) {
      totalSz += size;
      entries++;
      if (totalSz > policy.maxUncompressed) {
        result.addFlag(ThreatLevel.CRITICAL,'SIZE_EXCEEDED',
          `TAR content ${fmtBytes(totalSz)} exceeds limit`); break;
      }
    }
    if (entries > policy.maxEntries) {
      result.addFlag(ThreatLevel.HIGH,'ENTRY_FLOOD',
        `${entries} entries exceeds limit`); break;
    }
    const dataBlocks = Math.ceil(size/512);
    pos += 512 + dataBlocks*512;
  }

  result.totalCompressed   = r.size;
  result.totalUncompressed = totalSz;
  result.overallRatio      = totalSz/r.size || 0;
  result.entryCount        = entries;
}

// ── Zstandard ────────────────────────────────────────────────────────────────

function scanZstd(r, policy, result) {
  const MAGIC = 0xFD2FB528;
  if (r.u32at(0) !== MAGIC) { result.addFlag(ThreatLevel.NONE,'INVALID_ZSTD','Bad magic'); return; }

  let pos=0, frames=0, totalUncomp=0;
  while (pos+4 < r.size) {
    const m = r.u32at(pos);
    if (m !== MAGIC) break;
    const fhd = r.u8at(pos+4);
    const csflag = (fhd>>6)&3;
    const singleSeg = !!(fhd&0x20);
    let hpos = pos+5;
    if (!singleSeg) hpos++;
    hpos += [0,1,2,4][fhd&3]; // dict id

    let uncomp=0;
    if (csflag===1 && hpos+2<=r.size) { uncomp=r.v.getUint16(hpos,true)+256; hpos+=2; }
    else if (csflag===2 && hpos+4<=r.size) { uncomp=r.u32at(hpos); hpos+=4; }
    else if (csflag===3 && hpos+8<=r.size) {
      uncomp=Number(r.v.getBigUint64(hpos,true)); hpos+=8;
    } else if (singleSeg && hpos<r.size) { uncomp=r.u8at(hpos); hpos++; }

    totalUncomp += uncomp; frames++;
    if (totalUncomp > policy.maxUncompressed) {
      result.addFlag(ThreatLevel.CRITICAL,'SIZE_EXCEEDED',
        `Declared ${fmtBytes(totalUncomp)} exceeds limit`); break;
    }
    // Advance past this frame — find next MAGIC or EOF
    let next = r.size;
    for (let i=hpos; i<r.size-3; i++) {
      if (r.u32at(i)===MAGIC) { next=i; break; }
    }
    pos = next;
  }

  result.totalCompressed   = r.size;
  result.totalUncompressed = totalUncomp;
  result.overallRatio      = totalUncomp/r.size || 0;
  result.entryCount        = frames;

  if (result.overallRatio > policy.maxRatio)
    result.addFlag(ThreatLevel.CRITICAL,'RATIO_EXCEEDED',
      `Ratio ${result.overallRatio.toFixed(1)}:1 exceeds ${policy.maxRatio}:1`);
}

// ── 7z (basic) ───────────────────────────────────────────────────────────────

function scan7z(r, policy, result) {
  const SIG = [0x37,0x7a,0xbc,0xaf,0x27,0x1c];
  const arr  = new Uint8Array(r.v.buffer,0,Math.min(16,r.size));
  if (!SIG.every((b,i)=>arr[i]===b)) { result.addFlag(ThreatLevel.NONE,'INVALID_7Z','Bad magic'); return; }
  if (r.size < 32) { result.addFlag(ThreatLevel.NONE,'INVALID_7Z','Too small'); return; }

  const nextHdrOffset = Number(r.v.getBigUint64(12, true));
  const nextHdrSize   = Number(r.v.getBigUint64(20, true));
  const hdrStart = 32 + nextHdrOffset;

  result.totalCompressed = r.size;
  result.details.headerOffset = hdrStart;
  result.details.headerSize   = nextHdrSize;
  result.details.note = '7z: unpack size requires header parsing (best-effort)';

  // Simple heuristic: if header is unusually large relative to file, flag it
  if (nextHdrSize > r.size * 0.5 && nextHdrSize > 1024) {
    result.addFlag(ThreatLevel.LOW,'LARGE_HEADER',
      `7z header is ${((nextHdrSize/r.size)*100).toFixed(1)}% of file size`);
  }
}

// ── XZ ───────────────────────────────────────────────────────────────────────

function scanXz(r, policy, result) {
  const MAGIC = [0xfd,0x37,0x7a,0x58,0x5a,0x00];
  const arr   = new Uint8Array(r.v.buffer,0,Math.min(16,r.size));
  if (!MAGIC.every((b,i)=>arr[i]===b)) { result.addFlag(ThreatLevel.NONE,'INVALID_XZ','Bad magic'); return; }
  result.totalCompressed = r.size;
  result.details.note    = 'XZ: stream content sizes require block header parsing';
  // Flag very large XZ files as potentially suspicious
  if (r.size > 500*1024*1024)
    result.addFlag(ThreatLevel.LOW,'LARGE_XZ_FILE',
      `Large XZ file (${fmtBytes(r.size)}) — manual inspection recommended`);
}

// ── Soft ratio warning ────────────────────────────────────────────────────────

function softRatioWarning(result, policy) {
  if (!result.isThreat && result.overallRatio > 10) {
    const lv = result.overallRatio > 50 ? ThreatLevel.MEDIUM : ThreatLevel.LOW;
    result.addFlag(lv,'HIGH_RATIO',`Overall ratio ${result.overallRatio.toFixed(1)}:1`);
  }
}

// ── Public entry point ────────────────────────────────────────────────────────

export async function scanArchive(file, policy = POLICIES.default) {
  const t0  = performance.now();
  const buf = await file.arrayBuffer();
  const r   = new DataReader(buf);
  const fmt = detectFormat(file.name, buf);
  const res = makeResult(fmt);

  switch (fmt) {
    case 'zip': case 'jar': case 'war': case 'apk':
    case 'docx': case 'xlsx': case 'pptx': case 'pytorch':
      scanZip(r, policy, res); break;
    case 'gzip': case 'tar.gz':   scanGzip(r,  policy, res); break;
    case 'bzip2': case 'tar.bzip2': scanBzip2(r, policy, res); break;
    case 'tar':                   scanTar(r,   policy, res); break;
    case '7z':                    scan7z(r,    policy, res); break;
    case 'xz': case 'tar.xz':    scanXz(r,    policy, res); break;
    case 'zstd':                  scanZstd(r,  policy, res); break;
    case 'rar4': case 'rar5': case 'rar':
      res.addFlag(ThreatLevel.LOW,'RAR_FORMAT',
        'RAR format detected — header parsing limited in browser context');
      res.totalCompressed = buf.byteLength; break;
    default:
      res.addFlag(ThreatLevel.NONE,'UNKNOWN_FORMAT',
        `Format '${fmt}' not recognised`);
  }

  softRatioWarning(res, policy);
  res.scanMs = +(performance.now() - t0).toFixed(2);
  return res;
}

export function fmtBytes(n) {
  if (n>=1e12) return (n/1e12).toFixed(2)+' TB';
  if (n>=1e9)  return (n/1e9).toFixed(2)+' GB';
  if (n>=1e6)  return (n/1e6).toFixed(2)+' MB';
  if (n>=1e3)  return (n/1e3).toFixed(1)+' KB';
  return n+' bytes';
}
