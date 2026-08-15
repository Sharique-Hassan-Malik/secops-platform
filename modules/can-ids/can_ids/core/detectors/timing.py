"""
Timing anomaly detector.

For each CAN ID, legitimate ECU messages arrive at near-fixed intervals
(e.g., 10 ms for engine RPM, 20 ms for wheel speed).  An injected frame
typically arrives out of phase, producing an IAT that is either much shorter
(if injected between two legitimate frames) or much longer (if it replaced one).

The detector computes the z-score of each observed IAT against the baseline
mean and std.  A high z-score indicates the message arrived unusually early
or late relative to its expected schedule.
"""

from __future__ import annotations

import math
from typing import Dict, List

from can_ids.core.alert import Alert
from can_ids.core.baseline import Baseline
from can_ids.core.frame import CANFrame


def detect(
    frames: List[CANFrame],
    baseline: Baseline,
    threshold: float = 4.0,
    min_baseline_iats: int = 20,
) -> List[Alert]:
    """
    Parameters
    ----------
    frames               : test frames sorted by timestamp
    baseline             : learned profile
    threshold            : z-score above which an IAT is flagged
    min_baseline_iats    : minimum baseline IAT samples to trust the profile
    """
    if not frames:
        return []

    alerts: List[Alert] = []
    last_ts: Dict[int, float] = {}

    for frame in frames:
        can_id = frame.can_id
        profile = baseline.get(can_id)

        if profile is None:
            # Unknown IDs are handled by the unknown_id detector
            last_ts[can_id] = frame.timestamp
            continue

        if profile.iat_count < min_baseline_iats or profile.iat_mean <= 0:
            last_ts[can_id] = frame.timestamp
            continue

        if can_id in last_ts:
            iat = frame.timestamp - last_ts[can_id]
            if iat > 0:
                z = _zscore(iat, profile.iat_mean, profile.iat_std)
                if z > threshold:
                    alerts.append(Alert(
                        timestamp=frame.timestamp,
                        can_id=can_id,
                        detector="timing",
                        severity=_severity(z, threshold),
                        message=(
                            f"ID {can_id:03X}: IAT anomaly — "
                            f"observed {iat * 1000:.2f} ms vs "
                            f"baseline {profile.iat_mean * 1000:.2f} ± "
                            f"{profile.iat_std * 1000:.2f} ms "
                            f"(z={z:.2f})"
                        ),
                        score=z,
                        frame_data=frame.data,
                        extra={
                            "observed_iat_ms": round(iat * 1000, 3),
                            "baseline_mean_ms": round(profile.iat_mean * 1000, 3),
                            "baseline_std_ms": round(profile.iat_std * 1000, 3),
                        },
                    ))

        last_ts[can_id] = frame.timestamp

    return alerts


def _zscore(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.0 if math.isclose(value, mean, rel_tol=1e-6) else float("inf")
    return abs(value - mean) / std


def _severity(z: float, threshold: float) -> str:
    if z > threshold * 3:
        return "high"
    if z > threshold * 1.5:
        return "medium"
    return "low"
