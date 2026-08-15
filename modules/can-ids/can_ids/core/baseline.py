"""
Baseline profiler.

Ingests a list of CANFrames and builds per-ID statistical profiles used
by all detectors. The profile captures:

  Per-ID:
    - message count
    - observed time span
    - mean and standard deviation of inter-arrival times (IAT)
    - mean and standard deviation of message rate over sliding windows
    - per-byte-position: set of observed values, mean and std

All statistics use Welford's online algorithm so they can be computed in
a single pass over the frame list.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from can_ids.core.frame import CANFrame


@dataclass
class ByteStats:
    """Running statistics for a single byte position within a CAN ID."""
    count: int = 0
    mean: float = 0.0
    _m2: float = 0.0          # sum of squared deviations (Welford)
    observed: set = field(default_factory=set)

    def update(self, value: int) -> None:
        self.observed.add(value)
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self._m2 += delta * (value - self.mean)

    @property
    def variance(self) -> float:
        return self._m2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


@dataclass
class IDProfile:
    """Statistical profile for a single CAN identifier."""
    can_id: int
    extended: bool = False

    # message count and timing span
    count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0

    # inter-arrival time (IAT) statistics — Welford
    iat_count: int = 0
    iat_mean: float = 0.0
    iat_m2: float = 0.0

    # per-byte-position statistics (up to 8 positions)
    byte_stats: Dict[int, ByteStats] = field(default_factory=dict)

    # last seen timestamp (used during ingestion only)
    _last_ts: float = field(default=0.0, repr=False)

    def ingest(self, frame: CANFrame) -> None:
        ts = frame.timestamp
        if self.count == 0:
            self.first_ts = ts
            self._last_ts = ts
        else:
            iat = ts - self._last_ts
            if iat > 0:
                self._update_iat(iat)
            self._last_ts = ts

        self.last_ts = ts
        self.count += 1

        for pos, byte_val in enumerate(frame.data):
            if pos not in self.byte_stats:
                self.byte_stats[pos] = ByteStats()
            self.byte_stats[pos].update(byte_val)

    def _update_iat(self, iat: float) -> None:
        self.iat_count += 1
        delta = iat - self.iat_mean
        self.iat_mean += delta / self.iat_count
        self.iat_m2 += delta * (iat - self.iat_mean)

    @property
    def iat_std(self) -> float:
        if self.iat_count < 2:
            return 0.0
        return math.sqrt(self.iat_m2 / (self.iat_count - 1))

    @property
    def duration(self) -> float:
        return max(self.last_ts - self.first_ts, 0.0)

    @property
    def mean_rate(self) -> float:
        """Messages per second over the observed time span."""
        if self.duration <= 0:
            return 0.0
        return self.count / self.duration

    def byte_zscore(self, pos: int, value: int) -> Optional[float]:
        """Z-score of `value` at byte position `pos` relative to baseline."""
        if pos not in self.byte_stats:
            return None
        bs = self.byte_stats[pos]
        if bs.std == 0:
            return 0.0 if value == round(bs.mean) else float("inf")
        return abs(value - bs.mean) / bs.std


@dataclass
class Baseline:
    """Complete baseline profile built from a training capture."""
    profiles: Dict[int, IDProfile] = field(default_factory=dict)
    total_frames: int = 0
    duration: float = 0.0
    start_ts: float = 0.0
    end_ts: float = 0.0

    @property
    def known_ids(self) -> frozenset:
        return frozenset(self.profiles.keys())

    def get(self, can_id: int) -> Optional[IDProfile]:
        return self.profiles.get(can_id)


def build(frames: List[CANFrame]) -> Baseline:
    """
    Build a Baseline from an ordered list of CANFrames.
    Frames must be sorted by timestamp (ascending).
    """
    if not frames:
        return Baseline()

    baseline = Baseline(
        total_frames=len(frames),
        start_ts=frames[0].timestamp,
        end_ts=frames[-1].timestamp,
        duration=frames[-1].timestamp - frames[0].timestamp,
    )

    for frame in frames:
        can_id = frame.can_id
        if can_id not in baseline.profiles:
            baseline.profiles[can_id] = IDProfile(
                can_id=can_id, extended=frame.extended
            )
        baseline.profiles[can_id].ingest(frame)

    return baseline


def split_train_test(
    frames: List[CANFrame], train_ratio: float = 0.7
) -> Tuple[List[CANFrame], List[CANFrame]]:
    """Split a frame list into train/test sets by time."""
    if not frames:
        return [], []
    split = int(len(frames) * train_ratio)
    return frames[:split], frames[split:]
