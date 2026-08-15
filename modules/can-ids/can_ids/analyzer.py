"""
CANIntrusion — orchestrates baseline building and all detection passes.

Usage (library):
    from can_ids.analyzer import CANIntrusion

    ids = CANIntrusion()
    baseline, alerts = ids.analyze_split("capture.log", train_ratio=0.7)

    # or supply separate files:
    baseline = ids.build_baseline("normal.log")
    alerts   = ids.detect("suspicious.log", baseline)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from can_ids.core.alert import Alert, SEVERITY_RANK
from can_ids.core.baseline import Baseline, build as build_baseline, split_train_test
from can_ids.core.frame import CANFrame
from can_ids.core.detectors import (
    detect_frequency,
    detect_timing,
    detect_replay,
    detect_payload,
    detect_unknown_id,
)
from can_ids.parsers import load


@dataclass
class AnalysisResult:
    baseline: Baseline
    alerts: List[Alert]
    test_frame_count: int
    analysis_time: float
    source: str = ""

    @property
    def by_severity(self) -> dict[str, List[Alert]]:
        out: dict[str, List[Alert]] = {s: [] for s in SEVERITY_RANK}
        for a in self.alerts:
            out.setdefault(a.severity, []).append(a)
        return out

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "high")


@dataclass
class DetectorConfig:
    """Tunable parameters for each detector."""
    # frequency
    freq_window_sec: float = 1.0
    freq_threshold: float = 3.0
    freq_min_baseline: int = 10

    # timing
    timing_threshold: float = 4.0
    timing_min_iats: int = 20

    # replay
    replay_window_size: int = 16
    replay_lookback_sec: float = 5.0
    replay_rapid_dup_ratio: float = 0.2

    # payload
    payload_threshold: float = 4.0
    payload_min_baseline: int = 20

    # which detectors to enable
    enable_frequency: bool = True
    enable_timing: bool = True
    enable_replay: bool = True
    enable_payload: bool = True
    enable_unknown_id: bool = True


class CANIntrusion:
    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()

    def build_baseline(self, path: str) -> Baseline:
        frames = load(path)
        return build_baseline(frames)

    def build_baseline_from_frames(self, frames: List[CANFrame]) -> Baseline:
        return build_baseline(frames)

    def detect(self, path: str, baseline: Baseline) -> AnalysisResult:
        frames = load(path)
        return self._run_detectors(frames, baseline, source=Path(path).name)

    def detect_frames(
        self, frames: List[CANFrame], baseline: Baseline, source: str = ""
    ) -> AnalysisResult:
        return self._run_detectors(frames, baseline, source=source)

    def analyze_split(
        self, path: str, train_ratio: float = 0.7
    ) -> AnalysisResult:
        """Load a single file, split by time and use the first portion as baseline."""
        frames = load(path)
        train, test = split_train_test(frames, train_ratio)
        baseline = build_baseline(train)
        return self._run_detectors(test, baseline, source=Path(path).name)

    def _run_detectors(
        self, frames: List[CANFrame], baseline: Baseline, source: str = ""
    ) -> AnalysisResult:
        t0 = time.perf_counter()
        cfg = self.config
        alerts: List[Alert] = []

        if cfg.enable_frequency:
            alerts.extend(detect_frequency(
                frames, baseline,
                window_sec=cfg.freq_window_sec,
                threshold=cfg.freq_threshold,
                min_baseline_count=cfg.freq_min_baseline,
            ))

        if cfg.enable_timing:
            alerts.extend(detect_timing(
                frames, baseline,
                threshold=cfg.timing_threshold,
                min_baseline_iats=cfg.timing_min_iats,
            ))

        if cfg.enable_replay:
            alerts.extend(detect_replay(
                frames, baseline,
                window_size=cfg.replay_window_size,
                lookback_sec=cfg.replay_lookback_sec,
                rapid_dup_ratio=cfg.replay_rapid_dup_ratio,
            ))

        if cfg.enable_payload:
            alerts.extend(detect_payload(
                frames, baseline,
                threshold=cfg.payload_threshold,
                min_baseline_count=cfg.payload_min_baseline,
            ))

        if cfg.enable_unknown_id:
            alerts.extend(detect_unknown_id(frames, baseline))

        alerts.sort(key=lambda a: (a.severity_rank, a.timestamp))

        return AnalysisResult(
            baseline=baseline,
            alerts=alerts,
            test_frame_count=len(frames),
            analysis_time=time.perf_counter() - t0,
            source=source,
        )
