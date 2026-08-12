# ZIP Bomb Detector — Browser Extension

A Chrome/Edge (Manifest V3) extension that scans archive files for bomb attacks in your browser — zero uploads, zero decompression, pure metadata analysis.

## Supported Formats

ZIP · GZip · BZip2 · TAR · 7-Zip · XZ · Zstandard · PyTorch (.pt/.pth) · and ZIP-based formats (.jar, .apk, .docx, .xlsx, .pptx)

## Features

- **Drag & drop scanning** — drop any archive onto the popup
- **Instant analysis** — runs entirely in browser, no network requests
- **9 formats** — same detection engine as the C/C++/Python/Rust implementations
- **4 policy presets** — Default / Strict / Paranoid / Relaxed
- **Detailed results** — ratio, entry count, overlap detection, per-entry table, format badge
- **Download badge** — icon badges when an archive download completes
- **Desktop notifications** — alerts on CRITICAL threats
- **Page shields** — 🛡 badges next to archive links on web pages

## Installing (Developer Mode)

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select this `extension/` folder

## Detection Techniques

| Check | Default Trigger |
|-------|----------------|
| Ratio exceeded | >100:1 declared expansion |
| Size exceeded | Declared total >4 GB |
| Entry flood | >10,000 entries |
| Overlapping data | Entries share byte ranges (Fifield pattern) |
| BZip2 worst-case | Block count × max expansion >4 GB |
| GZip ISIZE=0 | May indicate >4 GB content |

## Files

```
manifest.json     MV3 manifest
scanner.js        Multi-format detection engine (no dependencies)
popup.html/js     Extension UI
background.js     Service worker (notifications, download watch)
content.js        Page script (archive link badges)
icons/            16 × 48 × 128 px
```

## Privacy

No network requests. Files are read into memory, analysed, and discarded. Only the selected policy is saved to `chrome.storage.local`.
