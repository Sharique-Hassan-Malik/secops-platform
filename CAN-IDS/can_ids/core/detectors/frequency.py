"""
Frequency anomaly detector.

Splits the test capture into fixed-size time windows and computes the
observed message rate for each CAN ID in each window.  A rate that
deviates more than `threshold` standard deviations from the baseline
mean rate triggers an alert.

Two alert types:
  - "burst"   : observed rate >> baseline (injection attack, replay flood)
  - "silence" : observed rate << baseline (DoS / bus-off attack on a sensor)
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
    window_sec: float = 1.0,
    threshold: float = 3.0,
    min_baseline_count: int = 10,
) -> List[Alert]:
    """
    Parameters
    ----------
    frames              : test frames, sorted by timestamp
    baseline            : learned profile
    window_sec          : width of the analysis window in seconds
    threshold           : z-score threshold to trigger an alert
    min_baseline_count  : minimum baseline messages for an ID to participate
    """
    if not frames:
        return []

    alerts: List[Alert] = []
    t_start = frames[0].timestamp

    # bucket frames into windows
    buckets: Dict[float, Dict[int, int]] = {}   # window_start → {can_id: count}
    for frame in frames:
        w = math.floor((frame.timestamp - t_start) / window_sec) * window_sec + t_start
        buckets.setdefault(w, {})
        buckets[w][frame.can_id] = buckets[w].get(frame.can_id, 0) + 1

    for w_start, counts in sorted(buckets.items()):
        w_end = w_start + window_sec

        # check observed IDs for burst
        for can_id, count in counts.items():
            profile = baseline.get(can_id)
            if profile is None or profile.count < min_baseline_count:
                continue

            observed_rate = count / window_sec
            baseline_rate = profile.mean_rate
            # Use a Poisson-style coefficient of variation if std is unavailable
            if baseline_rate <= 0:
                continue

            # Estimate std from Poisson assumption when baseline has no rate std
            # (we have per-IAT std; convert to rate std over the window)
            if profile.iat_std > 0 and profile.iat_mean > 0:
                # CV of IAT → CV of rate is approximately the same
                rate_std = baseline_rate * (profile.iat_std / profile.iat_mean)
            else:
                rate_std = math.sqrt(baseline_rate / window_sec)

            if rate_std == 0:
                continue

            z = (observed_rate - baseline_rate) / rate_std

            if z > threshold:
                alerts.append(Alert(
                    timestamp=w_end,
                    can_id=can_id,
                    detector="frequency",
                    severity=_burst_severity(z, threshold),
                    message=(
                        f"ID {can_id:03X}: burst detected — "
                        f"rate {observed_rate:.1f} msg/s vs baseline {baseline_rate:.1f} msg/s "
                        f"(z={z:.2f})"
                    ),
                    score=z,
                    extra={"observed_rate": observed_rate, "baseline_rate": baseline_rate,
                           "window_start": w_start, "window_end": w_end},
                ))

        # check for silence on IDs expected in this window
        for can_id, profile in baseline.profiles.items():
            if profile.count < min_baseline_count or profile.mean_rate <= 0:
                continue
            if can_id in counts:
                continue    # observed — not silent

            # expected at least 1 message per window?
            expected_in_window = profile.mean_rate * window_sec
            if expected_in_window < 0.5:
                continue    # ID not expected every window

            alerts.append(Alert(
                timestamp=w_end,
                can_id=can_id,
                detector="frequency",
                severity="medium",
                message=(
                    f"ID {can_id:03X}: silence detected — "
                    f"expected ~{expected_in_window:.1f} messages in window, got 0"
                ),
                score=expected_in_window,
                extra={"expected_in_window": expected_in_window,
                       "window_start": w_start, "window_end": w_end},
            ))

    return alerts


def _burst_severity(z: float, threshold: float) -> str:
    if z > threshold * 4:
        return "critical"
    if z > threshold * 2.5:
        return "high"
    if z > threshold:
        return "medium"
    return "low"
