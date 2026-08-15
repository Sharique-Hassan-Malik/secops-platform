# CAN Bus Intrusion Detection System

> Part of the [Security Operations Platform](../../README.md). Runs standalone
> from this folder, and reports into the shared event pipeline via `secops`.

Anomaly detection on Controller Area Network (CAN) traffic captured via OBD-II
or SocketCAN. Works offline on log files. Detects injection attacks, replay
attacks, DoS attempts and unknown ECU identifiers without any external
dependencies beyond Python 3.11 and Rich.

## Detection Methods

| Detector | What it catches |
|----------|----------------|
| **Frequency** | Burst injection (10× rate spike) and silence attacks (DoS / bus-off) |
| **Timing** | Frames that arrive too early or too late relative to the ECU's schedule |
| **Replay** | Repeated frame sequences (sequence-hash) and rapid identical-payload duplicates |
| **Payload** | Byte values that are statistical outliers vs baseline and DLC mismatches |
| **Unknown ID** | Any CAN identifier absent from the baseline profile |

All detectors are statistical — they require a baseline capture of normal traffic
for the target vehicle or device. No hand-written rules and no labeled attack data.

## Installation

```
pip install rich
pip install -e .
```

Python 3.11 or later is required. No compiled extensions.

## Usage

### Quick demo (synthetic traffic with injected attacks)

```
can-ids demo
can-ids demo --attack flood --duration 30
can-ids demo --attack all --output demo.log --json report.json
```

### Analyze a real log file (split mode — no separate baseline needed)

```
can-ids analyze capture.log
can-ids analyze capture.log --train-ratio 0.6
can-ids analyze capture.log --json alerts.json
```

### Separate baseline and test files

```
can-ids analyze --baseline normal.log suspicious.log
```

### Show baseline profile only

```
can-ids baseline normal.log
```

### Tune thresholds

```
can-ids analyze capture.log \
    --freq-threshold 4.0 \
    --timing-threshold 5.0 \
    --payload-threshold 5.0 \
    --freq-window 0.5
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--baseline`, `-b` | — | Separate baseline log file |
| `--train-ratio` | 0.7 | Fraction of log used as baseline in split mode |
| `--freq-window` | 1.0 s | Sliding window for frequency analysis |
| `--freq-threshold` | 3.0 σ | Z-score threshold for frequency alerts |
| `--timing-threshold` | 4.0 σ | Z-score threshold for IAT alerts |
| `--payload-threshold` | 4.0 σ | Z-score threshold for byte anomaly alerts |
| `--replay-window` | 16 | Frame sequence length for replay hash |
| `--json`, `-j` | — | Path for JSON report output |
| `--quiet`, `-q` | — | Suppress terminal output |
| `--no-color` | — | Disable Rich color output |

## Supported Log Formats

**candump** (Linux can-utils):
```
(1609459200.000100) vcan0 1A0#DEADBEEF01020304
```

**CSV** with flexible column names (`timestamp`/`time`, `can_id`/`id`/`arbitration_id`,
`data`/`payload`). Data may be hex with or without spaces or colons.

The `load()` function auto-detects the format from the file extension and falls
back to trying both parsers.

## Python API

```python
from can_ids.analyzer import CANIntrusion, DetectorConfig
from can_ids.report import render, to_json
from rich.console import Console

cfg = DetectorConfig(freq_threshold=4.0, timing_threshold=5.0)
ids = CANIntrusion(cfg)

# Split a single capture
result = ids.analyze_split("capture.log", train_ratio=0.7)

# Or use separate files
baseline = ids.build_baseline("normal.log")
result   = ids.detect("suspicious.log", baseline)

render(result, Console())
print(to_json(result))

for alert in result.alerts:
    print(f"{alert.severity.upper():8} {alert.detector:12} {alert.message}")
```

## Synthetic Traffic Generator

The built-in generator models eight ECUs at realistic message rates and supports
four attack injectors for testing and demo purposes.

```python
from can_ids.parsers.generator import (
    generate_normal, inject_frequency_flood,
    inject_replay, inject_unknown_id, inject_payload_spoof,
)

frames = generate_normal(duration_sec=30.0, seed=0)
frames = inject_frequency_flood(frames, target_id=0x0C0,
                                flood_start=frames[0].timestamp + 20.0,
                                multiplier=10)
frames = inject_unknown_id(frames, inject_at=frames[0].timestamp + 22.0,
                           unknown_id=0x666)
```

Simulated ECUs:

| CAN ID | Signal | Period |
|--------|--------|--------|
| `0x0C0` | Engine RPM | 10 ms |
| `0x0D0` | Vehicle speed | 20 ms |
| `0x0E0` | Throttle position | 10 ms |
| `0x0F0` | Coolant temperature | 1000 ms |
| `0x100` | Brake pressure | 10 ms |
| `0x110` | Steering angle | 20 ms |
| `0x120` | Transmission gear | 100 ms |
| `0x130` | Battery voltage | 500 ms |

## JSON Report Structure

```json
{
  "source": "capture.log",
  "test_frame_count": 12430,
  "analysis_time_s": 0.032,
  "alert_summary": {
    "total": 5,
    "critical": 0,
    "high": 2,
    "medium": 2,
    "low": 1
  },
  "alerts": [
    {
      "timestamp": 1600000011.024,
      "can_id": "0C0",
      "detector": "frequency",
      "severity": "high",
      "score": 8.42,
      "message": "ID 0C0: burst detected — rate 987.3 msg/s vs baseline 100.2 msg/s (z=8.42)",
      "frame_data": "03E9",
      "extra": { "observed_rate": 987.3, "baseline_rate": 100.2 }
    }
  ],
  "baseline": {
    "total_frames": 37200,
    "duration_s": 9.0,
    "known_id_count": 8,
    "profiles": [ ... ]
  }
}
```

## Running Tests

```
pip install pytest pytest-cov
pytest tests/ -v
pytest tests/ --cov=can_ids --cov-report=term-missing
```

## Project Structure

```
can_ids/
    __init__.py
    analyzer.py           — CANIntrusion orchestrator, DetectorConfig, AnalysisResult
    cli.py                — CLI: analyze / baseline / demo subcommands
    core/
        frame.py          — CANFrame dataclass
        baseline.py       — Welford online stats, IDProfile, Baseline, build()
        alert.py          — Alert dataclass shared by all detectors
        detectors/
            frequency.py  — Rate deviation in sliding windows (burst + silence)
            timing.py     — Inter-arrival time z-score
            replay.py     — Sequence-hash window + rapid duplicate
            payload.py    — Per-byte z-score + DLC mismatch
            unknown_id.py — Unknown CAN identifier detection
    parsers/
        __init__.py       — Auto-detecting load()
        candump.py        — candump log format parser
        csv_parser.py     — CSV log parser with column alias detection
        generator.py      — Synthetic traffic generator with attack injectors
    report/
        renderer.py       — Rich terminal renderer
        json_report.py    — JSON serializer
tests/
    conftest.py
    test_core.py
    test_detectors.py
    test_parsers.py
    test_integration.py
docs/
    architecture.md
```
