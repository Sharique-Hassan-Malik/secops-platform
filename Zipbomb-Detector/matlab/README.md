# MATLAB Component

Two MATLAB scripts covering ZIP statistical analysis and full multi-format scanning.

## Files

| File | Purpose |
|------|---------|
| `analyze_compression.m` | ZIP deep analysis — per-entry ratios, statistics, IQR outliers, 4-panel plots |
| `scan_archive.m` | Multi-format dispatcher — detects format and scans ZIP/GZip/BZip2/TAR/7z/XZ/RAR/Zstd |

## Requirements

- MATLAB R2019b or newer
- No additional toolboxes for core scanning
- Statistics & ML Toolbox (optional, for K-S normality test in `analyze_compression.m`)

## Usage

```matlab
% Scan any format — auto-detects by magic bytes
result = scan_archive('suspicious.7z');
result = scan_archive('suspicious.tar.gz', 'policy', 'strict');
result = scan_archive('suspicious.bz2',    'policy', 'paranoid');

% ZIP-specific deep statistical analysis with plot
result = analyze_compression('suspicious.zip', 'policy', 'strict', 'plot', true);
```

## How Format Detection Works

`scan_archive.m` reads the first 16 bytes of the file and matches against known magic byte signatures. If no magic matches, it falls back to the file extension. TAR is detected by checking for the `ustar` string at byte offset 257.

## BZip2 Note

BZip2 stores no uncompressed size in its headers. The scanner counts compressed block magic sequences and computes a worst-case expansion: `blocks × max_block_size × 30`. This is an upper bound, not the actual uncompressed size.

## Output Structure

| Field | Type | Description |
|-------|------|-------------|
| `fmt` | char | Detected format name |
| `is_threat` | logical | Whether any threshold was exceeded |
| `threat_level` | char | NONE / LOW / MEDIUM / HIGH / CRITICAL |
| `total_compressed` | double | File size in bytes |
| `total_uncompressed` | double | Declared or estimated uncompressed size |
| `overall_ratio` | double | Expansion ratio |
| `entry_count` | double | Number of entries/blocks/frames |
| `flags` | cell | Human-readable detection flag strings |
