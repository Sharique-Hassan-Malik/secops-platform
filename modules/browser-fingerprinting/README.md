# Browser Fingerprinting Research Tool

> Part of the [Security Operations Platform](../../README.md). Runs standalone
> from this folder, and reports into the shared event pipeline via `secops`.

A research platform that collects browser fingerprint signals from real or synthetic browsers, measures the Shannon entropy contribution of each signal, and trains a classifier to demonstrate how browser and OS identity can be predicted from hardware-level signals alone — without reading the User-Agent header.

## The Hard Parts

**Shannon entropy as a privacy metric.** Entropy H = -Σ p(x) log₂p(x) measures how many bits of identifying information a feature contributes. A feature that takes 1024 distinct values with equal probability contributes 10 bits — enough to divide the population into 1024 groups. The tool computes per-feature entropy across all collected fingerprints, ranks signals by information content and shows which source (canvas, WebGL, audio, fonts, timing, network) contributes the most.

**Why each signal is hard to measure.** The six collection subsystems each face their own problem: the AudioContext result differs by CPU because floating-point accumulation order is implementation-defined; the canvas result differs by GPU driver and OS font renderer; the WebGL result exposes the physical GPU via `WEBGL_debug_renderer_info` even though browsers present a generic string by default.

**Classifier without the User-Agent.** A RandomForest trained on canvas hash, WebGL renderer, audio hash, font count, timezone, screen dimensions, hardware concurrency and device memory achieves >90% accuracy predicting Browser/OS combinations on synthetic data. This demonstrates that even if a user spoofs their UA string, the hardware-level signals uniquely identify their browser build and machine configuration.

**Composite hash.** The server combines canvas hash, WebGL image hash, unmasked GPU renderer, audio hash, timezone, screen size and CPU count into a single MD5 fingerprint ID using pipe-delimited concatenation. This provides a stable cross-session identifier that doesn't change unless the underlying hardware or browser version changes.

## Signal Sources

| Source | What is measured | Key entropy driver |
|--------|-----------------|-------------------|
| Canvas | 2D rendering of text and arcs | GPU driver + OS font renderer |
| WebGL | GPU renderer strings, extension list, parameter limits, triangle rendering | Physical GPU model and driver version |
| AudioContext | OscillatorNode → DynamicsCompressor frequency data hash | CPU floating-point implementation |
| Fonts | Installed font detection via glyph width measurement | OS and installed software |
| Timing | Screen dimensions, CPU count, memory, timezone, clock resolution | Hardware and OS configuration |
| Network | Media device counts, ICE candidate types, connection type | Hardware peripherals and network interfaces |

## Architecture

```
collector/          JavaScript modules (ES module, one per signal)
  canvas.js         Canvas 2D text/arc rendering hash
  webgl.js          WebGL renderer strings, parameters, image hash
  audio.js          AudioContext oscillator hash (async)
  fonts.js          Font detection via DOM width measurement
  timing.js         Hardware and environment signals
  network.js        Network, media devices, ICE candidates (async)
  fingerprint.js    Orchestrator — collects all signals and POSTs to server

server/             Python backend
  database.py       SQLAlchemy models (Fingerprint, with 35 columns)
  ingest.py         Flattens raw JSON dict into ORM row + composite hash
  app.py            FastAPI — /api/collect, /api/entropy, /api/classifier, /api/stats

analysis/           Python analysis modules
  entropy.py        Shannon entropy per feature, group totals, summary
  features.py       22-feature extractor for ML (hash encoding + float passthrough)
  classifier.py     RandomForest predict Browser/OS from non-UA signals

dashboard/static/
  collect.html      Browser-side collection page (runs JS collector)
  index.html        React dashboard — entropy bars, group chart, classifier, fingerprint table

scripts/
  generate_synthetic.py   1000-sample synthetic fingerprint generator
  analyze.py              CLI — entropy + classifier from DB or synthetic data
```

## Setup

```bash
pip install -r requirements.txt
```

## Running

Start the server:

```bash
uvicorn server.app:app --reload --port 8000
```

Open `http://localhost:8000/collect` in any browser to submit a fingerprint.

Open `http://localhost:8000` to view the analysis dashboard.

## Command-Line Analysis

Run entropy analysis and classifier on 1000 synthetic fingerprints:

```bash
python scripts/analyze.py
```

Against a real database:

```bash
python scripts/analyze.py --db fingerprints.db
```

Sample output (synthetic):

```
================================================================
  Entropy Analysis — 1,000 fingerprints
================================================================
  Total bits:      32.47
  Anonymity set:   ~18 billion

  Group        Bits
  ─────────────────────────
  canvas       7.241  ██████████████████████
  webgl        9.832  ██████████████████████████████
  audio        5.219  ████████████████
  timing       6.184  ██████████████████
  fonts        2.103  ██████
  network      1.891  █████

  Feature                              Bits  Unique  Coverage
  ──────────────────────────────────────────────────────────
  webgl_unmasked_renderer              3.170      9     100%
  canvas_hash                          3.113      9     100%
  audio_hash                           3.113      9     100%
  webgl_image_hash                     3.113      9     100%
  timezone                             3.585     12     100%
  screen_width                         2.201      5     100%
  ...
```

## Running Tests

```bash
pytest tests/ -v
```

## File Map

| Path | Description |
|------|-------------|
| `collector/canvas.js` | Canvas 2D fingerprinting with DJB2 hash of data URL |
| `collector/webgl.js` | WebGL renderer strings, extension list, GPU rendering hash |
| `collector/audio.js` | AudioContext oscillator + compressor frequency data hash |
| `collector/fonts.js` | Font detection via three-fallback glyph width comparison |
| `collector/timing.js` | Hardware, screen, timing and environment signals |
| `collector/network.js` | Network type, media devices, ICE candidates, battery |
| `collector/fingerprint.js` | Async orchestrator — collects all signals and POSTs JSON |
| `server/database.py` | SQLAlchemy ORM — Fingerprint table with 35 columns |
| `server/ingest.py` | JSON flattener, composite hash computation |
| `server/app.py` | FastAPI — collect, query, entropy, classifier and stats endpoints |
| `analysis/entropy.py` | Shannon entropy per feature, group totals, anonymity set estimate |
| `analysis/features.py` | 22-feature extractor with stable categorical hash encoding |
| `analysis/classifier.py` | RandomForest Browser/OS classifier with UA-free signals |
| `dashboard/static/collect.html` | Browser collection page with signal card display |
| `dashboard/static/index.html` | React dashboard with entropy bars, group chart and classifier panel |
| `scripts/generate_synthetic.py` | Realistic synthetic fingerprint generator for 10 browser/OS profiles |
| `scripts/analyze.py` | CLI analysis script — entropy table and classifier report |
| `tests/test_entropy.py` | Entropy computation unit tests |
| `tests/test_classifier.py` | UA parser, feature extractor and classifier tests |
| `tests/test_ingest.py` | Ingestor field extraction and composite hash tests |
