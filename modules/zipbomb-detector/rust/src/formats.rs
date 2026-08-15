// formats.rs  —  Per-format scanners for gzip, bzip2, tar, 7z, xz, rar, zstd

use std::fs;
use std::path::Path;
use crate::policy::ScanPolicy;
use crate::types::{ScanResult, ThreatLevel};

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o+1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o+4].try_into().unwrap_or([0;4]))
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o+8].try_into().unwrap_or([0;8]))
}

fn vint(data: &[u8], pos: &mut usize) -> u64 {
    let mut v = 0u64;
    let mut shift = 0;
    while *pos < data.len() {
        let b = data[*pos]; *pos += 1;
        v |= (b as u64 & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 { break; }
    }
    v
}

fn soft_ratio(r: &mut ScanResult, pol: &ScanPolicy) {
    if !r.is_threat && r.overall_ratio > 10.0 {
        let level = if r.overall_ratio > 50.0 { ThreatLevel::Medium } else { ThreatLevel::Low };
        r.add_flag(level, "HIGH_RATIO", format!("Overall ratio {:.2}:1", r.overall_ratio));
    }
}

// ── GZip ─────────────────────────────────────────────────────────────────────

pub fn scan_gzip(path: &Path, pol: &ScanPolicy) -> ScanResult {
    let mut r = ScanResult::new(path.display().to_string(), 0);
    let Ok(data) = fs::read(path) else {
        r.add_flag(ThreatLevel::None, "IO_ERROR", "Cannot read file".into()); return r;
    };
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b {
        r.add_flag(ThreatLevel::None, "INVALID_GZIP", "Bad magic or too small".into());
        return r;
    }

    let isize = u32le(&data, data.len() - 4);
    let fsz   = data.len() as u64;
    r.total_compressed   = fsz;
    r.total_uncompressed = isize as u64;
    r.entry_count        = 1;

    if isize == 0 && fsz > 100 {
        r.add_flag(ThreatLevel::Medium, "ISIZE_ZERO", "ISIZE=0; may indicate >4 GB content".into());
    } else {
        r.overall_ratio = if fsz > 0 { isize as f64 / fsz as f64 } else { 0.0 };
        if r.overall_ratio > pol.max_ratio {
            r.add_flag(ThreatLevel::Critical, "RATIO_EXCEEDED",
                format!("Ratio {:.1}:1 exceeds limit {:.1}:1", r.overall_ratio, pol.max_ratio));
        }
        if isize == 0xFFFF_FFFF {
            r.add_flag(ThreatLevel::High, "MAX_ISIZE", "ISIZE at max (4 GB-1); possible truncation".into());
        }
        soft_ratio(&mut r, pol);
    }
    r
}

// ── BZip2 ────────────────────────────────────────────────────────────────────

pub fn scan_bzip2(path: &Path, pol: &ScanPolicy) -> ScanResult {
    let mut r = ScanResult::new(path.display().to_string(), 0);
    let Ok(data) = fs::read(path) else {
        r.add_flag(ThreatLevel::None, "IO_ERROR", "Cannot read file".into()); return r;
    };
    if data.len() < 4 || data[0] != 0x42 || data[1] != 0x5a || data[2] != 0x68 {
        r.add_flag(ThreatLevel::None, "INVALID_BZIP2", "Bad magic".into()); return r;
    }

    let level = (data[3].saturating_sub(b'0') as usize).clamp(1, 9);
    let block_sizes = [0u64,100000,200000,300000,400000,500000,600000,700000,800000,900000];
    let max_block   = block_sizes[level];

    let bm = [0x31u8,0x41,0x59,0x26,0x53,0x59];
    let mut blocks: u64 = 0;
    let mut i = 4usize;
    while i + 6 <= data.len() {
        if data[i..i+6] == bm { blocks += 1; i += 6; } else { i += 1; }
    }

    let max_uncomp = blocks * max_block * 30;
    r.total_compressed   = data.len() as u64;
    r.total_uncompressed = max_uncomp;
    r.entry_count        = blocks as u32;
    r.overall_ratio      = if data.len() > 0 { max_uncomp as f64 / data.len() as f64 } else { 0.0 };

    if max_uncomp > pol.max_uncompressed {
        r.add_flag(ThreatLevel::High, "WORST_CASE_SIZE",
            format!("Worst-case expansion {} GB may exceed limit", max_uncomp >> 30));
    }
    soft_ratio(&mut r, pol);
    r
}

// ── TAR ──────────────────────────────────────────────────────────────────────

pub fn scan_tar(path: &Path, pol: &ScanPolicy) -> ScanResult {
    let mut r = ScanResult::new(path.display().to_string(), 0);
    let Ok(data) = fs::read(path) else {
        r.add_flag(ThreatLevel::None, "IO_ERROR", "Cannot read file".into()); return r;
    };

    let fsz = data.len() as u64;
    let mut pos   = 0usize;
    let mut total = 0u64;
    let mut zero_blocks = 0u32;

    while pos + 512 <= data.len() {
        let block = &data[pos..pos+512];
        if block.iter().all(|&b| b == 0) {
            zero_blocks += 1;
            if zero_blocks >= 2 { break; }
            pos += 512; continue;
        }
        zero_blocks = 0;

        // Parse octal size at offset 124
        let octal: String = block[124..136].iter()
            .take_while(|&&b| b >= b'0' && b <= b'7')
            .map(|&b| b as char)
            .collect();
        let sz = u64::from_str_radix(&octal, 8).unwrap_or(0);

        let typeflag = block[156];
        if typeflag == b'0' || typeflag == 0 || typeflag == b'7' {
            total += sz;
            r.entry_count += 1;
            if total > pol.max_uncompressed {
                r.add_flag(ThreatLevel::Critical, "SIZE_EXCEEDED",
                    "TAR content exceeds size limit".into());
                break;
            }
        }
        if r.entry_count as u32 > pol.max_entries {
            r.add_flag(ThreatLevel::High, "ENTRY_FLOOD",
                format!("{} entries exceeds limit {}", r.entry_count, pol.max_entries));
            break;
        }
        let skip = ((sz + 511) / 512) * 512;
        pos += 512 + skip as usize;
    }

    r.total_compressed   = fsz;
    r.total_uncompressed = total;
    r.overall_ratio      = if fsz > 0 { total as f64 / fsz as f64 } else { 0.0 };
    soft_ratio(&mut r, pol);
    r
}

// ── 7z ───────────────────────────────────────────────────────────────────────

pub fn scan_7z(path: &Path, pol: &ScanPolicy) -> ScanResult {
    let mut r = ScanResult::new(path.display().to_string(), 0);
    let Ok(data) = fs::read(path) else {
        r.add_flag(ThreatLevel::None, "IO_ERROR", "Cannot read file".into()); return r;
    };
    if data.len() < 32 {
        r.add_flag(ThreatLevel::None, "INVALID_7Z", "Too small".into()); return r;
    }
    if &data[..6] != b"\x37\x7a\xbc\xaf\x27\x1c" {
        r.add_flag(ThreatLevel::None, "INVALID_7Z", "Bad signature".into()); return r;
    }

    let hdr_off  = u64le(&data, 12) as usize;
    let hdr_size = u64le(&data, 20) as usize;
    let hdr_start = 32 + hdr_off;
    r.total_compressed = data.len() as u64;

    if hdr_start + hdr_size > data.len() {
        r.add_flag(ThreatLevel::Medium, "TRUNCATED_HEADER", "End header beyond file".into());
        return r;
    }

    let hdr = &data[hdr_start..hdr_start+hdr_size];
    let mut total_unpack: u64 = 0;
    let mut i = 0usize;
    while i + 1 < hdr.len() {
        if hdr[i] == 0x09 {
            let mut pos = i + 1;
            let sz = vint(hdr, &mut pos);
            if sz > 0 && sz < (1u64 << 40) { total_unpack += sz; i = pos; continue; }
        }
        i += 1;
    }

    if total_unpack > 0 {
        r.total_uncompressed = total_unpack;
        r.overall_ratio = if data.len() > 0 { total_unpack as f64 / data.len() as f64 } else { 0.0 };
        if r.overall_ratio > pol.max_ratio {
            r.add_flag(ThreatLevel::Critical, "RATIO_EXCEEDED",
                format!("Ratio {:.1}:1 exceeds limit", r.overall_ratio));
        }
        if total_unpack > pol.max_uncompressed {
            r.add_flag(ThreatLevel::Critical, "SIZE_EXCEEDED", "Declared unpack size exceeds limit".into());
        }
        soft_ratio(&mut r, pol);
    }
    r
}

// ── XZ ───────────────────────────────────────────────────────────────────────

pub fn scan_xz(path: &Path, pol: &ScanPolicy) -> ScanResult {
    let mut r = ScanResult::new(path.display().to_string(), 0);
    let Ok(data) = fs::read(path) else {
        r.add_flag(ThreatLevel::None, "IO_ERROR", "Cannot read file".into()); return r;
    };
    if data.len() < 32 || &data[..6] != b"\xfd7zXZ\x00" {
        r.add_flag(ThreatLevel::None, "INVALID_XZ", "Bad magic or too small".into()); return r;
    }

    let mut pos: usize = 12;
    let mut total_uncomp: u64 = 0;
    let mut blocks: u32 = 0;

    while pos + 4 < data.len() {
        if data[pos] == 0 { break; }
        let bh_size = ((data[pos] as usize) + 1) * 4;
        if pos + bh_size > data.len() { break; }
        let bflags = data[pos + 1];
        let has_comp   = (bflags >> 6) & 1 != 0;
        let has_uncomp = (bflags >> 7) & 1 != 0;
        let mut bpos = pos + 2;
        let comp   = if has_comp   { vint(&data, &mut bpos) } else { 0 };
        let uncomp = if has_uncomp { vint(&data, &mut bpos) } else { 0 };

        total_uncomp += uncomp; blocks += 1;
        if total_uncomp > pol.max_uncompressed {
            r.add_flag(ThreatLevel::Critical, "SIZE_EXCEEDED", "XZ content exceeds limit".into());
            break;
        }
        if comp > 0 && uncomp > 0 {
            let ratio = uncomp as f64 / comp as f64;
            if ratio > pol.max_ratio {
                r.add_flag(ThreatLevel::Critical, "RATIO_EXCEEDED",
                    format!("Block ratio {ratio:.1}:1 exceeds limit"));
            }
        }
        if has_comp {
            let padded = ((comp + 3) / 4) * 4;
            pos += bh_size + padded as usize + 4;
        } else { break; }
    }

    r.total_compressed   = data.len() as u64;
    r.total_uncompressed = total_uncomp;
    r.entry_count        = blocks;
    r.overall_ratio      = if data.len() > 0 { total_uncomp as f64 / data.len() as f64 } else { 0.0 };
    soft_ratio(&mut r, pol);
    r
}

// ── RAR ──────────────────────────────────────────────────────────────────────

pub fn scan_rar(path: &Path, pol: &ScanPolicy) -> ScanResult {
    let mut r = ScanResult::new(path.display().to_string(), 0);
    let Ok(data) = fs::read(path) else {
        r.add_flag(ThreatLevel::None, "IO_ERROR", "Cannot read file".into()); return r;
    };
    if data.len() < 8 {
        r.add_flag(ThreatLevel::None, "INVALID_RAR", "Too small".into()); return r;
    }

    let is5 = data[6] == 0x01 && data[7] == 0x00;
    let is4 = data[6] == 0x00 && !is5;
    if !is4 && !is5 {
        r.add_flag(ThreatLevel::None, "INVALID_RAR", "Bad RAR magic".into()); return r;
    }

    let mut tc: u64 = 0;
    let mut tu: u64 = 0;

    if is4 {
        let mut pos = 7usize;
        while pos + 7 < data.len() {
            let htype  = data[pos + 2];
            let hflags = u16le(&data, pos+3) as u32;
            let hsize  = u16le(&data, pos+5) as u32;
            if hsize == 0 { break; }
            let mut bsz = hsize;
            if hflags & 0x8000 != 0 && pos+11 < data.len() { bsz += u32le(&data, pos+7); }
            if htype == 0x7b { break; }
            if htype == 0x74 && hsize >= 32 {
                let csz = u32le(&data, pos+7) as u64;
                let usz = u32le(&data, pos+11) as u64;
                tc += csz; tu += usz; r.entry_count += 1;
                if csz > 0 && usz as f64 / csz as f64 > pol.max_ratio {
                    r.add_flag(ThreatLevel::Critical, "RATIO_EXCEEDED", "Entry exceeds ratio limit".into());
                }
                if tu > pol.max_uncompressed {
                    r.add_flag(ThreatLevel::Critical, "SIZE_EXCEEDED", "Cumulative size exceeds limit".into());
                    break;
                }
            }
            pos += bsz as usize;
        }
    } else {
        let mut pos = 8usize;
        while pos + 8 < data.len() {
            pos += 4;
            let hsz   = vint(&data, &mut pos) as usize;
            let hend  = pos + hsz;
            let htype = vint(&data, &mut pos);
            let hflags= vint(&data, &mut pos);
            if hflags & 1 != 0 { vint(&data, &mut pos); }
            let dsz = if hflags & 2 != 0 { vint(&data, &mut pos) } else { 0 };
            if htype == 2 {
                vint(&data, &mut pos);
                let usz = vint(&data, &mut pos);
                tc += dsz; tu += usz; r.entry_count += 1;
                if dsz > 0 && usz as f64 / dsz as f64 > pol.max_ratio {
                    r.add_flag(ThreatLevel::Critical, "RATIO_EXCEEDED", "Entry exceeds ratio limit".into());
                }
                if tu > pol.max_uncompressed {
                    r.add_flag(ThreatLevel::Critical, "SIZE_EXCEEDED", "Cumulative size exceeds limit".into());
                    break;
                }
            }
            if hend + dsz as usize > data.len() { break; }
            pos = hend + dsz as usize;
        }
    }

    r.total_compressed   = if tc > 0 { tc } else { data.len() as u64 };
    r.total_uncompressed = tu;
    r.overall_ratio      = if tc > 0 { tu as f64 / tc as f64 } else { 0.0 };
    soft_ratio(&mut r, pol);
    r
}

// ── Zstandard ────────────────────────────────────────────────────────────────

pub fn scan_zstd(path: &Path, pol: &ScanPolicy) -> ScanResult {
    let mut r = ScanResult::new(path.display().to_string(), 0);
    let Ok(data) = fs::read(path) else {
        r.add_flag(ThreatLevel::None, "IO_ERROR", "Cannot read file".into()); return r;
    };
    if data.len() < 8 || u32le(&data, 0) != 0xFD2F_B528 {
        r.add_flag(ThreatLevel::None, "INVALID_ZSTD", "Bad magic or too small".into()); return r;
    }

    let mut pos: usize = 0;
    let mut frames: u32 = 0;
    let mut total: u64  = 0;

    while pos + 4 < data.len() {
        if u32le(&data, pos) != 0xFD2F_B528 { break; }
        if pos + 5 >= data.len() { break; }
        let fhd      = data[pos + 4];
        let csflag   = (fhd >> 6) & 3;
        let single   = fhd & 0x20 != 0;
        let dict_sz  = [0usize, 1, 2, 4][(fhd & 3) as usize];
        let mut hpos = pos + 5 + if single { 0 } else { 1 } + dict_sz;

        let uncomp: u64 = match csflag {
            0 if single && hpos < data.len() => { let v = data[hpos] as u64; hpos += 1; v }
            1 if hpos + 2 <= data.len() => { let v = u16le(&data, hpos) as u64 + 256; hpos += 2; v }
            2 if hpos + 4 <= data.len() => { let v = u32le(&data, hpos) as u64; hpos += 4; v }
            3 if hpos + 8 <= data.len() => { let v = u64le(&data, hpos); hpos += 8; v }
            _ => 0,
        };

        total += uncomp; frames += 1;
        if total > pol.max_uncompressed {
            r.add_flag(ThreatLevel::Critical, "SIZE_EXCEEDED", "Declared content exceeds limit".into());
            break;
        }

        let next = (hpos..data.len().saturating_sub(3))
            .find(|&i| u32le(&data, i) == 0xFD2F_B528)
            .unwrap_or(data.len());
        if next <= pos { break; }
        pos = next;
    }

    r.total_compressed   = data.len() as u64;
    r.total_uncompressed = total;
    r.entry_count        = frames;
    r.overall_ratio      = if data.len() > 0 { total as f64 / data.len() as f64 } else { 0.0 };
    if r.overall_ratio > pol.max_ratio {
        r.add_flag(ThreatLevel::Critical, "RATIO_EXCEEDED",
            format!("Ratio {:.1}:1 exceeds limit", r.overall_ratio));
    }
    soft_ratio(&mut r, pol);
    r
}
