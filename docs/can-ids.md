# Architecture

## Overview

The system is a pure statistical anomaly detector. It requires no labeled attack
data and no hand-written CAN database (DBC file). The only input is a capture of
normal traffic from the target bus, from which it learns per-ID behavioral
profiles. A second capture is then scored against those profiles.

```
normal.log ──► build_baseline() ──► Baseline
                                         │
suspicious.log ──► parse ──► frames ─────┤
                                         ▼
                               ┌─────────────────────┐
                               │  frequency detector  │
                               │  timing detector     │──► [Alert]
                               │  replay detector     │
                               │  payload detector    │
                               │  unknown_id detector │
                               └─────────────────────┘
                                         │
                                         ▼
                               AnalysisResult
                               ├── terminal renderer (Rich)
                               └── JSON serializer
```

## Baseline Profiling (`core/baseline.py`)

The baseline is a dictionary mapping each CAN ID to an `IDProfile`. During
ingestion, each `IDProfile` maintains running statistics using **Welford's online
algorithm**, which computes mean and variance in a single pass without storing all
samples:

```
count += 1
delta  = x - mean
mean  += delta / count
M2    += delta * (x - mean)
variance = M2 / (count - 1)
```

This approach is numerically stable and memory-efficient — the profile for a
busy ID like engine RPM (100 msg/s over a 10-second capture) is a fixed-size
object regardless of how many frames were observed.

Per `IDProfile`, the baseline stores:

- **Count** and **time span** → used to compute mean message rate
- **Inter-arrival time (IAT) statistics** (mean, variance) → used by timing and
  frequency detectors
- **Per-byte-position statistics** (mean, variance, set of observed values) →
  used by the payload detector

## Detectors

### Frequency (`core/detectors/frequency.py`)

The capture is divided into fixed-size time windows (default 1 second). Within
each window, the observed message count for each ID is converted to a rate
(messages/second) and compared to the baseline mean rate.

Anomaly score is a z-score:

```
z = (observed_rate - baseline_rate) / rate_std
```

`rate_std` is derived from the IAT coefficient of variation when available, or
estimated from a Poisson assumption otherwise. A high positive z triggers a
**burst** alert; complete absence of an expected ID triggers a **silence** alert.

Burst severity escalates: z > 3σ → medium, z > 7.5σ → high, z > 12σ → critical.

### Timing (`core/detectors/timing.py`)

Legitimate ECU messages arrive at near-fixed intervals. This detector computes
the inter-arrival time (IAT) for each consecutive frame pair per ID and z-scores
it against the baseline IAT distribution.

An injected frame typically produces a very short IAT (it lands between two
legitimate frames) or a very long one (if it displaces a legitimate frame). Both
extremes produce high |z|, so the detector uses `abs(iat - mean) / std`.

The detector is stateless — it processes frames in timestamp order, tracking only
`last_ts[can_id]`.

### Replay (`core/detectors/replay.py`)

Two complementary strategies:

**Sequence hash**: A sliding window of `window_size` frames is hashed as a
sequence of `(can_id, data)` tuples using SHA-1. If the same hash appears within
`lookback_sec` seconds of its first occurrence, a replay alert is emitted. The
hash captures inter-ID ordering, which is characteristic of a recorded segment.

**Rapid duplicate**: A specific `(can_id, data)` pair that reappears within
`rapid_dup_ratio × baseline_iat` seconds is flagged. This targets the simplest
replay form — injecting a single copy of a recently observed frame.

Both strategies deduplicate alerts: the same sequence hash or payload key triggers
at most one alert per analysis pass.

### Payload (`core/detectors/payload.py`)

For each byte position in each CAN ID, the detector computes the z-score of the
observed byte value against the baseline distribution for that position:

```
z = abs(value - mean) / std
```

When `std == 0` (the byte is always the same value in the baseline) and the
observed value differs, the z-score is reported as `inf` and triggers a critical
alert.

A secondary check compares the observed DLC to the modal DLC seen in the baseline
(computed as the highest byte-position index with a non-empty stats record plus
one).

### Unknown ID (`core/detectors/unknown_id.py`)

Any CAN ID observed in the test capture that was absent from the baseline profiles
is collected. A single occurrence is low severity. Five or more frames from the
same unknown ID escalate to high, reflecting a persistent injector rather than a
one-off glitch.

## Alert Lifecycle

All detectors emit `Alert` objects with a common schema:

```python
Alert(
    timestamp   : float      # triggering frame timestamp
    can_id      : int        # offending CAN identifier
    detector    : str        # source detector name
    severity    : str        # critical | high | medium | low | info
    message     : str        # human-readable description
    score       : float      # numeric anomaly magnitude
    frame_data  : bytes      # payload of the triggering frame
    extra       : dict       # detector-specific numeric metadata
)
```

The analyzer collects all alerts from all detectors, sorts them by
`(severity_rank, timestamp)` and returns them in a single `AnalysisResult`.
Severity ranks: critical=0, high=1, medium=2, low=3, info=4.

## False Positive Considerations

**Throttle and sinusoidal signals**: Payload values that follow a sine wave will
have a well-defined mean but a wide spread. The standard deviation captures this
spread, so the z-score threshold of 4σ corresponds to values approximately at the
extreme of the signal's physical range. Values beyond the training-window phase
range may produce low-severity alerts on clean traffic; this is expected and the
test suite documents this behavior.

**Split-capture baseline**: When a single file is split by `train_ratio`, the
test window must contain the attack traffic. Attacks injected within the training
window will be absorbed into the baseline and will not be detected. The generator
and integration tests are calibrated to inject attacks well after the 70% split
point.

**Timing jitter**: IAT z-scores for IDs with very small `iat_std` (highly
periodic signals) are sensitive. The `min_baseline_iats` guard (default 20)
requires at least 20 IAT samples before the timing detector activates for an ID.

## Design Decisions

**No DBC file required**: DBC parsing would require a database for every vehicle
variant. The statistical approach works on any CAN bus without prior knowledge of
the message schema — only the traffic pattern matters.

**Welford's algorithm instead of stored samples**: Keeping all samples would allow
more sophisticated distribution modeling but would grow proportionally with capture
length. The Welford approach keeps each `IDProfile` O(1) in memory regardless of
capture duration.

**SHA-1 for sequence hashing**: SHA-1 is fast and produces a 160-bit digest — the
collision probability for a 16-frame window hash over a 10-second capture is
negligible. A cryptographically strong hash is not needed here; the threat model
is anomaly detection, not authentication.

**No multiprocessing**: Each detector is a simple linear scan over the frame list.
For typical automotive captures (thousands of frames per second over seconds to
minutes), single-threaded Python completes analysis in tens of milliseconds.
Parallelism would add coordination overhead without meaningful speedup at this
scale.
