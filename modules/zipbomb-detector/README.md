# ZIP Bomb Detector

> Part of the [Security Operations Platform](../../README.md). Runs standalone
> from this folder, and reports into the shared event pipeline via `secops`.

![Languages](https://img.shields.io/badge/languages-C%20%7C%20C%2B%2B%20%7C%20C%23%20%7C%20Python%20%7C%20Rust%20%7C%20MATLAB-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A multi-language static analysis framework for detecting archive bomb attacks across **9 formats** — without decompressing any data.

---

## What Is an Archive Bomb?

An archive bomb (zip bomb, gzip bomb, etc.) is a maliciously crafted file designed to exhaust memory, disk, or CPU when a program tries to decompress it. The classic `42.zip` is 42 KB compressed but declares 4.5 **petabytes** of output. Modern single-layer variants (Fifield, 2019) achieve the same effect from a few dozen kilobytes.

See [`docs/threat-model.md`](docs/threat-model.md) for a full attack taxonomy.

---

## Core Design Principle

> **Zero decompression. Pure metadata analysis.**

Every implementation reads only the declared sizes in archive headers — never the compressed data itself. Scanning a 42 KB zip bomb takes microseconds and cannot exhaust resources.

---

## Supported Formats

| Format | Extensions | Detection method |
|--------|------------|-----------------|
| ZIP | .zip .jar .war .apk .docx .xlsx .pptx | EOCD + central directory walk |
| GZip | .gz .tgz | ISIZE field in stream footer |
| BZip2 | .bz2 .tbz2 | Block count × max expansion bound |
| TAR | .tar .tar.gz .tgz .tar.bz2 | 512-byte POSIX header walk |
| 7-Zip | .7z | End-header packed/unpacked stream sizes |
| XZ/LZMA2 | .xz .tar.xz | Block header content size fields |
| RAR | .rar | RAR4 + RAR5 block header walk |
| Zstandard | .zst .zstd | Frame header FHD content size |
| PyTorch | .pt .pth | ZIP scanner + path traversal + pickle checks |

---

## Detection Techniques

| Technique | Description |
|-----------|-------------|
| Ratio check | `declared_uncompressed / compressed > threshold` |
| Absolute size guard | Cumulative declared size across all entries |
| Entry count limit | Rejects archives with excessive entry counts |
| Nesting depth limit | Limits recursive archive depth |
| Overlap detection | Entries sharing byte regions (Fifield pattern) |
| Entropy heuristic | Suspiciously uniform high ratios (Python/MATLAB) |

---

## Repository Structure

```
zipbomb-detector/
├── c/
│   ├── zip_detector.c/h        ZIP-only scanner
│   ├── formats.c/h             Multi-format scanner (all formats)
│   ├── multi_detector.c        Multi-format CLI entry point
│   └── Makefile
├── cpp/
│   ├── ArchiveAnalyzer.cpp/h   ZIP-only scanner
│   ├── FormatScanner.cpp/h     Multi-format scanner
│   ├── archive_analyzer_main.cpp / multi_detector.cpp
│   └── Makefile
├── csharp/ZipBombScanner/
│   ├── Scanner.cs              ZIP scanner + FormatDetector
│   └── Program.cs
├── python/
│   ├── zipbomb_detector.py     CLI (scan / batch / info)
│   └── formats/                One module per format
│       ├── base.py             Shared types + scan_any() dispatcher
│       ├── zip_scanner.py
│       ├── gzip_scanner.py
│       ├── bzip2_scanner.py
│       ├── tar_scanner.py
│       ├── sevenz_scanner.py
│       ├── xz_scanner.py
│       ├── rar_scanner.py
│       ├── zstd_scanner.py
│       └── pytorch_scanner.py
├── rust/src/
│   ├── main.rs                 CLI + format dispatch
│   ├── scanner.rs              ZIP scanner
│   ├── formats.rs              All non-ZIP format scanners
│   ├── policy.rs
│   └── types.rs
├── matlab/
│   ├── analyze_compression.m   ZIP statistical analyzer
│   └── scan_archive.m          Multi-format dispatcher
├── extension/                  Chrome/Edge MV3 extension
│   ├── scanner.js              In-browser multi-format engine
│   ├── popup.html/js
│   ├── background.js
│   └── content.js
└── docs/
    ├── architecture.md
    └── threat-model.md
```

---

## Quick Start

### C
```bash
cd c && make
./zip_detector   suspicious.zip
./multi_detector suspicious.7z
./multi_detector suspicious.tar.gz
```

### C++
```bash
cd cpp && make
./archive_analyzer suspicious.zip --policy strict --json
./multi_detector   suspicious.gz  --policy strict
./multi_detector   suspicious.rar --json
```

### C# (.NET 8)
```bash
cd csharp/ZipBombScanner
dotnet run -- suspicious.zip --policy strict
dotnet run -- --dir /uploads --json
```

### Python
```bash
cd python
python zipbomb_detector.py scan  suspicious.7z   --policy strict
python zipbomb_detector.py scan  suspicious.tar
python zipbomb_detector.py batch /uploads        --csv report.csv
python zipbomb_detector.py info  suspicious.zst
```

### Rust
```bash
cd rust && cargo build --release
./target/release/zipbomb_detector suspicious.bz2 --policy strict
./target/release/zipbomb_detector --dir /uploads --json
```

### MATLAB
```matlab
result = scan_archive('suspicious.7z');
result = scan_archive('suspicious.tar', 'policy', 'strict', 'plot', true);
result = analyze_compression('suspicious.zip');
```

### Browser Extension
1. Open `chrome://extensions` → enable **Developer mode**
2. Click **Load unpacked** → select the `extension/` folder
3. Drop any archive onto the popup for instant analysis

---

## Running Tests

```bash
cd python && python test_corpus.py run --outdir ./test_zips
```

```
======================================================================
TEST CASE                           EXPECTED   GOT        STATUS
======================================================================
clean.zip                           CLEAN      CLEAN      ✓ PASS
ratio_trigger.zip                   THREAT     THREAT     ✓ PASS
entry_flood.zip                     THREAT     THREAT     ✓ PASS
elevated_ratio.zip                  THREAT     THREAT     ✓ PASS
multi_entry_clean.zip               CLEAN      CLEAN      ✓ PASS
zero_entries.zip                    CLEAN      CLEAN      ✓ PASS
======================================================================
Results: 6 passed, 0 failed out of 6 cases
```

---

## Continuous Integration

This project lives inside the [`security`](https://github.com/Sharique-Hassan-Malik/security)
repository, so its workflow sits at that repository's root as
`.github/workflows/zipbomb-detector-ci.yml` and runs with `Zipbomb-Detector` as
its working directory. It builds the C, C++, C#, and Rust targets and runs the
Python test corpus on 3.10 / 3.11 / 3.12.

**It does not run automatically.** Pushing to `main` or `dev` will not start it —
every job is gated behind a repository Variable, so CI stays off until you
deliberately switch it on:

| To do this | Do that |
|---|---|
| **Run CI once, now** | *Actions → Zipbomb-Detector CI → Run workflow*. Always available, no setup needed. |
| **Enable CI on every push** | *Settings → Secrets and variables → Actions → Variables* → add `CI_ENABLED` = `true`. |
| **Turn it back off** | Delete `CI_ENABLED`, or set it to anything other than `true`. |

The switch is exact-match: only the literal string `true` enables it, so a typo
leaves CI off rather than silently on.

Lint settings live in [`.flake8`](.flake8) in this directory, so `flake8 python/`
run from here checks exactly what CI checks.

---

## Scan Policies

| Policy | Max Ratio | Max Uncompressed | Max Entries | Max Depth |
|--------|-----------|------------------|-------------|-----------|
| `default` | 100:1 | 4 GB | 10,000 | 3 |
| `strict` | 50:1 | 1 GB | 500 | 2 |
| `paranoid` | 10:1 | 250 MB | 100 | 1 |
| `relaxed` | 500:1 | 40 GB | 50,000 | 5 |

---

## Example Output (Rust, JSON)

```json
{
  "path": "suspicious.zip",
  "is_threat": true,
  "threat_level": "Critical",
  "entry_count": 1,
  "total_compressed": 16,
  "total_uncompressed": 4294967295,
  "overall_ratio": 268435455.9375,
  "has_overlaps": false,
  "scan_us": 38,
  "flags": [
    {
      "level": "Critical",
      "code": "RATIO_EXCEEDED",
      "description": "Entry 'payload.bin' ratio 268435456.0:1 exceeds 100.0:1"
    }
  ]
}
```

---

## Integration Example (Python — Flask)

```python
from python.formats import scan_any

POLICY = {'max_ratio':50,'max_uncompressed':1<<30,'max_entries':500,'check_overlaps':True}

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    tmp = f'/tmp/{secure_filename(f.filename)}'
    f.save(tmp)
    result = scan_any(tmp, POLICY)
    if result.is_threat:
        os.unlink(tmp)
        return jsonify({'error': 'Malicious archive', 'flags': [fl.code for fl in result.flags]}), 400
    process_archive(tmp)
    return jsonify({'status': 'ok'})
```

---

## Language Feature Matrix

| Feature | C | C++ | C# | Python | Rust | MATLAB | JS |
|---------|:-:|:---:|:--:|:------:|:----:|:------:|:--:|
| ZIP | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GZip | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| BZip2 | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| TAR | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| 7z | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| XZ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| RAR | ✓ | ✓ | — | ✓ | ✓ | ✓ | — |
| Zstd | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| PyTorch | — | — | — | ✓ | — | — | — |
| Overlap detection | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| Entropy heuristic | — | — | — | ✓ | — | ✓ | — |
| JSON output | — | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| Configurable policy | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Batch/dir scan | — | ✓ | ✓ | ✓ | ✓ | — | — |
| Statistical analysis | — | — | — | basic | — | full | — |

---

## References

1. Fifield, D. (2019). *A better zip bomb.* https://www.bamsoftware.com/hacks/zipbomb/
2. PKWARE (2023). *ZIP File Format Specification.* Version 6.3.10.
3. RFC 1952 — GZIP file format specification.
4. RFC 8478 — Zstandard Compression.
5. CVE-2019-16935 — ZIP bomb via Python `zipfile` module.

---

## License

MIT — see [LICENSE](LICENSE).
