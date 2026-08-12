"""
Payload anomaly detector.

For each CAN ID and byte position, the baseline records the mean, standard
deviation and set of observed values.  A test frame whose byte value at any
position exceeds `threshold` standard deviations from the baseline mean is
flagged.

Additionally, a DLC (data length) mismatch versus the baseline modal DLC is
flagged — injected frames often use a different length than the legitimate ECU.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List

from can_ids.core.alert import Alert
from can_ids.core.baseline import Baseline, IDProfile
from can_ids.core.frame import CANFrame


def detect(
    frames: List[CANFrame],
    baseline: Baseline,
    threshold: float = 4.0,
    min_baseline_count: int = 20,
) -> List[Alert]:
    """
    Parameters
    ----------
    frames               : test frames sorted by timestamp
    baseline             : learned profile
    threshold            : z-score threshold for a byte to be flagged
    min_baseline_count   : minimum baseline messages required to trust the profile
    """
    if not frames:
        return []

    # Pre-compute modal DLC per ID from baseline
    modal_dlc: Dict[int, int] = _build_modal_dlc(baseline)

    alerts: List[Alert] = []
    emitted: set = set()    # (can_id, pos, value) to avoid flooding

    for frame in frames:
        can_id = frame.can_id
        profile = baseline.get(can_id)
        if profile is None or profile.count < min_baseline_count:
            continue

        # DLC mismatch
        expected_dlc = modal_dlc.get(can_id)
        if expected_dlc is not None and frame.dlc != expected_dlc:
            key = (can_id, "dlc", frame.dlc)
            if key not in emitted:
                emitted.add(key)
                alerts.append(Alert(
                    timestamp=frame.timestamp,
                    can_id=can_id,
                    detector="payload",
                    severity="medium",
                    message=(
                        f"ID {can_id:03X}: DLC mismatch — "
                        f"observed {frame.dlc} bytes, baseline modal {expected_dlc} bytes"
                    ),
                    score=float(abs(frame.dlc - expected_dlc)),
                    frame_data=frame.data,
                    extra={"observed_dlc": frame.dlc, "expected_dlc": expected_dlc},
                ))

        # Per-byte z-score
        for pos, byte_val in enumerate(frame.data):
            bs = profile.byte_stats.get(pos)
            if bs is None or bs.count < min_baseline_count:
                continue

            z = profile.byte_zscore(pos, byte_val)
            if z is None or z <= threshold:
                continue

            key = (can_id, pos, byte_val)
            if key not in emitted:
                emitted.add(key)
                alerts.append(Alert(
                    timestamp=frame.timestamp,
                    can_id=can_id,
                    detector="payload",
                    severity=_severity(z, threshold),
                    message=(
                        f"ID {can_id:03X} byte[{pos}]: value 0x{byte_val:02X} "
                        f"is {z:.1f}σ from baseline mean {bs.mean:.1f} "
                        f"(std={bs.std:.2f})"
                    ),
                    score=z,
                    frame_data=frame.data,
                    extra={
                        "byte_pos": pos,
                        "observed": byte_val,
                        "baseline_mean": round(bs.mean, 2),
                        "baseline_std": round(bs.std, 2),
                        "z_score": round(z, 3),
                    },
                ))

    return alerts


def _build_modal_dlc(baseline: Baseline) -> Dict[int, int]:
    """
    For each ID in the baseline, find the most commonly observed DLC
    by scanning frame data byte counts.  Since we store byte stats
    per position, the highest position index with data is the modal DLC.
    """
    modal: Dict[int, int] = {}
    for can_id, profile in baseline.profiles.items():
        if profile.byte_stats:
            modal[can_id] = max(profile.byte_stats.keys()) + 1
    return modal


def _severity(z: float, threshold: float) -> str:
    if z > threshold * 3:
        return "high"
    if z > threshold * 1.5:
        return "medium"
    return "low"
