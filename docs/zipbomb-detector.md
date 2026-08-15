# Architecture

## Design Philosophy

Every implementation in this project shares one constraint:
**no actual decompression occurs during scanning.**

All threat detection reads format metadata — declared sizes, block counts, and byte offsets embedded in archive headers. This means:

- Scanning a 42 KB zip bomb takes **microseconds**
- The scanner cannot be DoS'd by its own targets
- Detection is purely structural and mathematical

---

## Supported Format Overview

| Format | Magic Bytes | Size Source |
|--------|-------------|-------------|
| ZIP | `50 4b 03 04` | Central directory declared sizes |
| GZip | `1f 8b` | ISIZE field (last 4 bytes of stream) |
| BZip2 | `42 5a 68` | Block count × max block size × 30× expansion ceiling |
| TAR | `ustar` at offset 257 | 512-byte POSIX header octal size fields |
| 7-Zip | `37 7a bc af 27 1c` | End-header packed/unpacked stream sizes |
| XZ | `fd 37 7a 58 5a 00` | Block header content size flags |
| RAR4 | `52 61 72 21 1a 07 00` | File block PACK_SIZE / UNP_SIZE fields |
| RAR5 | `52 61 72 21 1a 07 01 00` | Variable-length integer block walk |
| Zstandard | `28 b5 2f fd` | Frame header FHD content size field |
| PyTorch (.pt/.pth) | ZIP magic | ZIP scanner + suspicious entry checks |

---

## ZIP File Structure

```
┌──────────────────────────────────────────────────────────────────┐
│  Local File Header  │  File Data  │  ...  (repeated per entry)  │
├──────────────────────────────────────────────────────────────────┤
│              Central Directory  (one record per entry)           │
├──────────────────────────────────────────────────────────────────┤
│              End of Central Directory (EOCD)                     │
└──────────────────────────────────────────────────────────────────┘
```

The **central directory** stores declared compressed and uncompressed sizes for every entry. We read these fields directly — no decompression needed.

---

## Detection Vectors

### 1. Compression Ratio Check
```
ratio = declared_uncompressed_size / compressed_size
```
Applied per entry and overall. Default threshold: 100:1.

Legitimate archives rarely exceed 50:1. Even all-zero files peak around 1000:1, so the threshold is conservative enough to avoid false positives on normal data while catching bombs that declare thousands-to-one expansion.

### 2. Absolute Size Guard
Cumulative declared uncompressed size is summed across all entries. Default limit: 4 GB. Triggers before the ratio check can catch multi-entry bombs that individually stay below the ratio limit.

### 3. Entry Count Flood
High entry counts (tens of thousands) indicate a density attack — many individually small entries that sum to a dangerous total.

### 4. Overlapping Data Regions (Non-Recursive ZIP Bomb Detection)

This is the key technique for detecting **Fifield-style bombs** (2019):

```
Entry A: local_header_offset=100, compressed_size=500 → region [100, 600)
Entry B: local_header_offset=100, compressed_size=500 → region [100, 600)
                                         ↑ same offset — same data expanded twice
```

Detection algorithm:
1. Record `(lh_offset, lh_offset + header_size + compressed_size)` per entry
2. Sort ranges by start offset
3. Check for any range where `ranges[i].end > ranges[i+1].start`

This is O(n log n) and requires no decompression.

### 5. Format-Specific Heuristics

**GZip:** ISIZE field stores uncompressed size mod 2³². If ISIZE is 0 on a non-trivial file, content may exceed 4 GB.

**BZip2:** No uncompressed size is stored anywhere in the format. We use `block_count × max_block_size × 30` as a worst-case expansion bound. The factor 30 is the theoretical maximum bzip2 expansion ratio for highly compressible data.

**TAR:** Walk 512-byte POSIX headers summing octal size fields. TAR is uncompressed by design, so the ratio is normally 1:1 — a high ratio here indicates a deliberately inflated TAR.

**7-Zip:** The end header contains stream metadata including packed and unpacked sizes. We walk the property list scanning for kSize (0x09) records and sum vint-encoded values.

**XZ/LZMA2:** Block headers include optional content size fields encoded using variable-length integers. We extract these without decompressing any block data.

**RAR4/RAR5:** Each file block header contains packed and unpacked sizes. RAR5 uses variable-length integers throughout; RAR4 uses fixed-width 32-bit fields with optional 64-bit extensions.

**Zstandard:** The Frame Header Descriptor byte encodes how many bytes store the content size (0, 1, 2, 4, or 8 bytes). We decode this field to get the declared uncompressed size per frame.

### 6. Entropy / Uniformity Heuristic (Python and MATLAB)
When all entries share nearly identical compression ratios (very low coefficient of variation), this suggests shared underlying data — a statistical signal of shared-block bombs.

---

## Component Map

| Feature | C | C++ | C# | Python | Rust | MATLAB | JS |
|---------|:-:|:---:|:--:|:------:|:----:|:------:|:--:|
| ZIP scan | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GZip scan | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| BZip2 scan | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| TAR scan | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| 7z scan | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| XZ scan | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| RAR scan | ✓ | ✓ | — | ✓ | ✓ | ✓ | — |
| Zstd scan | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| PyTorch checks | — | — | — | ✓ | — | — | — |
| Overlap detection | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| Entropy heuristic | — | — | — | ✓ | — | ✓ | — |
| JSON output | — | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| Configurable policy | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Batch/dir scan | — | ✓ | ✓ | ✓ | ✓ | — | — |

---

## Data Flow

```
          Archive file on disk
                 │
                 ▼
    ┌──────────────────────┐
    │   Format Detector    │  Magic bytes → format ID → dispatch
    └──────────┬───────────┘
               │
    ┌──────────▼───────────┐
    │   Per-Format Parser  │  Read declared sizes from headers only
    │   (no decompression) │  ZIP/GZip/BZip2/TAR/7z/XZ/RAR/Zstd
    └──────────┬───────────┘
               │
        ┌──────┼──────────────────────────────┐
        ▼      ▼                              ▼
  Ratio     Size              Overlap / structural checks
  check     accumulator       (overlap detection, entry flood)
        │      │                              │
        └──────┴──────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   FormatResult  │
                    │   ThreatFlags   │
                    └─────────────────┘
```

---

## Why Not Use Library Decoders?

Standard library functions like Python's `zipfile.ZipFile`, Java's `ZipFile`, or .NET's `ZipArchive` are perfectly safe for reading metadata — they do not auto-extract. However, raw binary parsing is used to:

1. Enable overlap detection (library APIs hide local header offsets)
2. Demonstrate the exact byte layout for educational value
3. Keep the code dependency-free and portable
4. Mirror precisely what the C/C++/Rust implementations do

Both approaches are equally valid for detection. The raw parser gives more control.

---

## References

1. Fifield, D. (2019). *A better zip bomb.* https://www.bamsoftware.com/hacks/zipbomb/
2. PKWARE (2023). *ZIP File Format Specification.* Version 6.3.10.
3. RFC 1952 — GZIP file format specification.
4. POSIX.1-2017 — TAR interchange format.
5. 7-Zip SDK documentation — 7z format specification.
6. RFC 8478 — Zstandard Compression and the 'application/zstd' Media Type.
7. XZ Utils documentation — XZ/LZMA2 file format.
