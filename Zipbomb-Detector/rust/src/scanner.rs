use std::io::{self, Read, Seek, SeekFrom};
use std::fs::File;
use std::path::Path;

use crate::policy::ScanPolicy;
use crate::types::{EntryInfo, ScanResult, ThreatLevel};

const SIG_CDIR: u32 = 0x02014b50;
const SIG_EOCD: u32 = 0x06054b50;

fn read_u16(f: &mut File) -> io::Result<u16> {
    let mut b = [0u8; 2];
    f.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(f: &mut File) -> io::Result<u32> {
    let mut b = [0u8; 4];
    f.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn skip(f: &mut File, n: i64) -> io::Result<()> {
    f.seek(SeekFrom::Current(n))?;
    Ok(())
}

fn find_eocd(f: &mut File, file_size: u64) -> io::Result<Option<(u16, u32)>> {
    let limit = file_size.saturating_sub(65_557);
    let start = file_size.saturating_sub(22);

    let mut pos = start as i64;
    while pos >= limit as i64 {
        f.seek(SeekFrom::Start(pos as u64))?;
        let mut b = [0u8; 4];
        if f.read_exact(&mut b).is_ok() && u32::from_le_bytes(b) == SIG_EOCD {
            skip(f, 6)?;                        // disk numbers + entries on disk
            let count  = read_u16(f)?;
            skip(f, 4)?;                        // cd size
            let offset = read_u32(f)?;
            return Ok(Some((count, offset)));
        }
        pos -= 1;
    }
    Ok(None)
}

fn detect_overlaps(mut ranges: Vec<(u32, u32)>) -> bool {
    if ranges.len() < 2 { return false; }
    ranges.sort_unstable_by_key(|r| r.0);
    ranges.windows(2).any(|w| w[0].1 > w[1].0)
}

pub struct Scanner {
    policy: ScanPolicy,
}

impl Scanner {
    pub fn new(policy: ScanPolicy) -> Self {
        Self { policy }
    }

    pub fn scan(&self, path: &Path, depth: u32) -> ScanResult {
        let start = std::time::Instant::now();
        let mut result = ScanResult::new(path.display().to_string(), depth);

        if depth > self.policy.max_nesting_depth {
            result.add_flag(ThreatLevel::Critical, "DEPTH_EXCEEDED",
                format!("Depth {} exceeds limit {}", depth, self.policy.max_nesting_depth));
            return result;
        }

        let mut f = match File::open(path) {
            Ok(f)  => f,
            Err(e) => {
                result.add_flag(ThreatLevel::None, "IO_ERROR", e.to_string());
                return result;
            }
        };

        let file_size = f.seek(SeekFrom::End(0)).unwrap_or(0);
        f.rewind().ok();

        let (entry_count, cd_offset) = match find_eocd(&mut f, file_size) {
            Ok(Some(v)) => v,
            _ => {
                result.add_flag(ThreatLevel::None, "INVALID_ZIP", "No EOCD record found".into());
                return result;
            }
        };

        if entry_count as u32 > self.policy.max_entries {
            result.add_flag(ThreatLevel::High, "ENTRY_FLOOD",
                format!("{} entries exceeds limit {}", entry_count, self.policy.max_entries));
            result.entry_count = entry_count as u32;
            return result;
        }

        if f.seek(SeekFrom::Start(cd_offset as u64)).is_err() {
            result.add_flag(ThreatLevel::None, "IO_ERROR", "Cannot seek to central directory".into());
            return result;
        }

        let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(entry_count as usize);
        let mut total_comp:   u64 = 0;
        let mut total_uncomp: u64 = 0;

        for i in 0..entry_count {
            let sig = match read_u32(&mut f) {
                Ok(s)  => s,
                Err(_) => break,
            };
            if sig != SIG_CDIR {
                result.add_flag(ThreatLevel::Medium, "HEADER_CORRUPT",
                    format!("Bad central dir signature at entry {i}"));
                result.scan_us = start.elapsed().as_micros();
                return result;
            }

            skip(&mut f, 4).ok();           // ver made, ver needed
            skip(&mut f, 2).ok();           // flags
            let method    = read_u16(&mut f).unwrap_or(0);
            skip(&mut f, 4).ok();           // mod time/date
            skip(&mut f, 4).ok();           // CRC
            let comp_sz   = read_u32(&mut f).unwrap_or(0);
            let uncomp_sz = read_u32(&mut f).unwrap_or(0);
            let fname_len = read_u16(&mut f).unwrap_or(0);
            let extra_len = read_u16(&mut f).unwrap_or(0);
            let comm_len  = read_u16(&mut f).unwrap_or(0);
            skip(&mut f, 8).ok();           // disk, attrs
            let lh_offset = read_u32(&mut f).unwrap_or(0);

            let mut fname_bytes = vec![0u8; fname_len as usize];
            f.read_exact(&mut fname_bytes).ok();
            skip(&mut f, (extra_len + comm_len) as i64).ok();

            let name = String::from_utf8_lossy(&fname_bytes).into_owned();
            let lo   = name.to_lowercase();
            let is_archive = lo.ends_with(".zip") || lo.ends_with(".gz") || lo.ends_with(".bz2");

            let ratio = if comp_sz > 0 { uncomp_sz as f64 / comp_sz as f64 } else { 0.0 };

            if comp_sz > 0 && ratio > self.policy.max_ratio {
                result.add_flag(ThreatLevel::Critical, "RATIO_EXCEEDED",
                    format!("Entry '{name}' ratio {ratio:.1}:1 exceeds {:.1}:1", self.policy.max_ratio));
            }

            total_comp   += comp_sz as u64;
            total_uncomp += uncomp_sz as u64;

            result.entries.push(EntryInfo {
                name, compressed_size: comp_sz, uncompressed_size: uncomp_sz,
                ratio, method, local_offset: lh_offset, is_nested_archive: is_archive,
            });

            if total_uncomp > self.policy.max_uncompressed {
                result.add_flag(ThreatLevel::Critical, "SIZE_EXCEEDED",
                    format!("Cumulative {total_uncomp} bytes exceeds limit {}", self.policy.max_uncompressed));
                result.total_compressed   = total_comp;
                result.total_uncompressed = total_uncomp;
                result.entry_count        = i as u32 + 1;
                result.scan_us            = start.elapsed().as_micros();
                return result;
            }

            ranges.push((lh_offset, lh_offset + 30 + fname_len as u32 + extra_len as u32 + comp_sz));
            result.entry_count += 1;
        }

        result.total_compressed   = total_comp;
        result.total_uncompressed = total_uncomp;
        result.overall_ratio = if total_comp > 0 {
            total_uncomp as f64 / total_comp as f64
        } else { 0.0 };

        if self.policy.check_overlaps && detect_overlaps(ranges) {
            result.has_overlaps = true;
            result.add_flag(ThreatLevel::Critical, "OVERLAPPING_DATA",
                "Data regions overlap — Fifield-style non-recursive zip bomb".into());
        }

        if !result.is_threat && result.overall_ratio > 10.0 {
            let level = if result.overall_ratio > 50.0 { ThreatLevel::Medium } else { ThreatLevel::Low };
            result.add_flag(level, "HIGH_RATIO",
                format!("Overall ratio {:.2}:1", result.overall_ratio));
        }

        result.scan_us = start.elapsed().as_micros();
        result
    }

    pub fn scan_directory(&self, dir: &Path) -> Vec<ScanResult> {
        let Ok(entries) = std::fs::read_dir(dir) else { return vec![] };
        entries
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "zip").unwrap_or(false))
            .map(|e| self.scan(&e.path(), 0))
            .collect()
    }
}

pub fn detect_format(path: &Path) -> &'static str {
    let Ok(mut f) = File::open(path) else { return "unknown" };
    let mut magic = [0u8; 8];
    let _ = f.read_exact(&mut magic);

    if magic[0]==0x50 && magic[1]==0x4b                               { return "zip";   }
    if magic[0]==0x1f && magic[1]==0x8b                               { return "gzip";  }
    if magic[0]==0x42 && magic[1]==0x5a && magic[2]==0x68             { return "bzip2"; }
    if magic[0]==0x37 && magic[1]==0x7a && magic[2]==0xbc && magic[3]==0xaf { return "7z"; }
    if magic[0]==0xfd && magic[1]==0x37 && magic[2]==0x7a             { return "xz";    }
    if magic[0]==0x52 && magic[1]==0x61 && magic[2]==0x72 && magic[3]==0x21 { return "rar"; }
    if magic[0]==0x28 && magic[1]==0xb5 && magic[2]==0x2f && magic[3]==0xfd { return "zstd"; }

    // TAR: "ustar" at offset 257
    let Ok(mut f2) = File::open(path) else { return "unknown" };
    let mut buf = [0u8; 512];
    if f2.read_exact(&mut buf).is_ok()
       && &buf[257..262] == b"ustar" { return "tar"; }

    // Extension fallback
    match path.extension().and_then(|e| e.to_str()) {
        Some("zip"|"jar"|"war"|"apk"|"docx"|"xlsx"|"pptx"|"pt"|"pth") => "zip",
        Some("gz"|"tgz")   => "gzip",
        Some("bz2"|"tbz2") => "bzip2",
        Some("7z")         => "7z",
        Some("xz")         => "xz",
        Some("rar")        => "rar",
        Some("zst"|"zstd") => "zstd",
        Some("tar")        => "tar",
        _                  => "unknown",
    }
}
