# Browser Fingerprinting Research Tool — Architecture

## System Overview

Three layers: a JavaScript collection layer that runs in the browser, a Python backend that persists and analyses submissions, and a React dashboard that visualises entropy measurements and classifier results.

```
Browser (collector/*.js)
        │  POST /api/collect  (JSON)
        ▼
FastAPI server (server/app.py)
        │
        ├── server/ingest.py      flatten + composite hash
        ├── server/database.py    SQLite via SQLAlchemy
        │
        ├── GET /api/entropy  → analysis/entropy.py
        ├── GET /api/classifier → analysis/classifier.py
        └── GET /api/stats
                │
                ▼
        React dashboard (dashboard/static/index.html)
```

## Collection Layer — `collector/`

Each signal module is an ES module that exports one function (or one async function for AudioContext and network signals). `fingerprint.js` orchestrates collection: the two async modules (audio and network) run with `Promise.all`; the synchronous modules (canvas, WebGL, fonts, timing) run sequentially.

### Canvas (`canvas.js`)

Draws text in two fonts and an arc on a 280×60 canvas, then calls `toDataURL()` and hashes the resulting base64 string with DJB2. The hash is deterministic per browser build and OS because:

- Text hinting and sub-pixel rendering are controlled by the OS, not the browser
- Arc anti-aliasing is controlled by the GPU driver

A user with the same browser on the same machine will always get the same hash. A user on a different GPU or OS will get a different hash with high probability.

### WebGL (`webgl.js`)

Two distinct signals:

1. **String signals** — `VENDOR`, `RENDERER` and the `WEBGL_debug_renderer_info` extension strings. The debug extension returns the physical GPU model (e.g. "NVIDIA GeForce RTX 3070") rather than the generic string. This is the highest-entropy individual signal in the dataset.

2. **Rendering signal** — a GLSL triangle shader is compiled and drawn to a 256×256 buffer, then `readPixels()` samples the output. The pixel values differ by GPU because floating-point rounding in the fragment shader is hardware-dependent.

The extension list (sorted for stability) and numeric parameter limits further differentiate devices with the same GPU but different driver versions.

### AudioContext (`audio.js`)

An `OscillatorNode` (triangle wave, 10 kHz) is routed through a `DynamicsCompressorNode` into an `AnalyserNode`. After 500 ms, `getFloatFrequencyData()` samples 3000 frequency bins. The normalised sum of absolute values is encoded as an 8-byte float hash. The numerical output differs between browser implementations and OS audio stacks because floating-point accumulation order is not standardised.

A 3-second timeout handles browsers that implement the API but block audio contexts until user interaction.

### Fonts (`fonts.js`)

Font presence is tested by measuring the pixel width of a test string (`mmmmmmmmmmlli`) at 72px in each candidate font combined with each of three CSS generic families (monospace, serif, sans-serif). If the measured width differs from the fallback width in at least two of the three comparisons, the font is reported as present. This three-fallback consensus requirement reduces false positives from cross-platform fonts that happen to have identical metrics.

### Timing (`timing.js`)

Collects hardware and environment values (screen dimensions, CPU count, device memory, timezone, language, touch points, pixel ratio) alongside two computed signals:

- **Clock resolution**: measures the minimum observable increment of `performance.now()` across 50 samples and reports the median. Browsers with cross-origin isolation reduce this to 5 µs; others use 100 µs.
- **Math timing hash**: runs 50,000 mixed-precision floating-point operations, buckets the elapsed time into 5 ms intervals and XORs with the output checksum. This produces a signal that combines CPU speed class and FPU output variation.

### Network (`network.js`)

Three async sub-collectors:

- `navigator.connection` — network type and effective bandwidth estimate
- `MediaDevices.enumerateDevices()` — device counts and group IDs (device labels are blank without permission, but counts and grouping vary by hardware)
- RTCPeerConnection ICE gathering — creates a datagram connection with no STUN servers to collect `host` and `srflx` candidate types, revealing which network interface types are present (Ethernet, WiFi, VPN, loopback)

## Backend — `server/`

### Ingestor (`ingest.py`)

`ingest(raw: dict)` traverses the nested JSON structure and maps values to the 35 flat columns of the `Fingerprint` ORM model. String fields are truncated to 512 characters. List fields (ICE types, languages) are sorted and joined as comma-separated strings for SQLite compatibility. The raw JSON is preserved verbatim in `raw_json` for ad-hoc analysis.

The composite hash combines eight high-entropy fields (canvas hash, WebGL image hash, unmasked renderer, audio hash, timezone, screen width, screen height, CPU count) via pipe-delimited MD5. This is stable across sessions for the same device and browser version.

### Database (`database.py`)

One SQLite table (`fingerprints`) with 35 columns. Indexed on `collected_at`, `canvas_hash` and `composite_hash`. SQLAlchemy ORM is used for all queries; the session factory pattern allows the FastAPI dependency injection system to manage session lifecycle.

### API (`app.py`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/collect` | POST | Ingest raw fingerprint JSON, return ID and composite hash |
| `/api/fingerprints` | GET | Paginated list with optional offset |
| `/api/fingerprints/{id}` | GET | Single fingerprint with optional raw JSON |
| `/api/entropy` | GET | Full entropy analysis across all collected fingerprints |
| `/api/classifier` | GET | Train and evaluate classifier on current data |
| `/api/stats` | GET | Counts of unique values per signal and uniqueness rate |
| `/` | GET | Serve dashboard |
| `/collect` | GET | Serve collection page |

## Analysis — `analysis/`

### Entropy (`entropy.py`)

`compute_entropy(values)` computes Shannon entropy from a list of arbitrary values by counting occurrences and applying H = -Σ (c/n) log₂(c/n). None and empty-string values are excluded (treated as missing, not a distinct value class).

`analyse_features(rows)` applies `compute_entropy` to every column in `FEATURE_GROUPS` across the full dataset and returns `FeatureEntropy` dataclasses sorted descending by entropy. `entropy_summary(rows)` aggregates these into per-group totals and computes the anonymity set upper bound as 2^(sum of all feature entropies) — an optimistic estimate that assumes feature independence.

### Feature Extractor (`features.py`)

The 22 ML features are a subset of the database columns selected for high entropy and population coverage. Categorical features (canvas hash, GPU renderer, audio hash, timezone, platform, language) are encoded as stable integers via MD5 hash modulo 100,000. This preserves distinctness without requiring a fitted vocabulary. Continuous features (screen dimensions, CPU count, memory, font count, etc.) are passed through as floats. Missing values become -1.0 — a sentinel outside all natural feature ranges.

### Classifier (`classifier.py`)

`_parse_browser_os(ua)` derives a coarse `Browser/OS` label from the UA string using ordered regex checks. The order matters — iOS UA strings contain "Mac OS X", so iPhone/iPad must be checked before macOS.

`FingerprintClassifier` wraps a `RandomForestClassifier(200 trees, max_depth=12, class_weight="balanced")` with a `StandardScaler` and `LabelEncoder`. The `class_weight="balanced"` setting handles the unequal distribution of browser/OS combinations (Chrome/Windows is roughly 32% of traffic; Opera/Windows is 4%). Persistence uses a single pickle file containing the model, scaler and encoder.

## Dashboard — `dashboard/static/`

**`collect.html`** loads `collector/fingerprint.js` as an ES module, calls `collect()` on button click and renders signal cards showing the hash or error for each subsystem. The collected object is POSTed to `/api/collect`.

**`index.html`** is a React SPA loaded with CDN scripts (no build step). It polls four API endpoints on mount and every time the user clicks Refresh. The entropy tab renders a horizontal bar chart where bar width is proportional to entropy bits and colour encodes the source group. The classifier tab shows per-class precision/recall/F1 and a feature importance bar chart. The fingerprints tab is a scrollable table of all collected rows.

## Entropy Interpretation

A feature with entropy H bits identifies a user within an anonymity set of 2^H individuals. For reference:

- H = 0 bits — the feature is constant across all users (no information)
- H = 1 bit — the feature splits users into two equally-likely groups
- H = 10 bits — the feature alone narrows the population to 1 in 1024
- H = 33 bits — the combined fingerprint provides roughly 1-in-8-billion identification

The Panopticlick study (EFF, 2010) found that browser fingerprints were unique among 94.2% of the 470,000 participants tested, with total fingerprint entropy around 18.1 bits. WebGL and AudioContext signals were not included in that study; with those signals added the effective entropy is considerably higher.
