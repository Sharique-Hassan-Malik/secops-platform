"""
Unknown ID detector.

Flags any CAN identifier in the test capture that was not observed during
the baseline profiling phase.  An unknown ID can indicate:

  - A newly installed ECU not present during baseline capture
  - Malicious frame injection from an external device (OBD dongle, etc.)
  - A firmware update that changed the CAN message set

Alerts for the same unknown ID are deduplicated — only the first occurrence
is reported along with the total count of frames from that ID.
"""

from __future__ import annotations

from collections import Counter
from typing import List

from can_ids.core.alert import Alert
from can_ids.core.baseline import Baseline
from can_ids.core.frame import CANFrame


def detect(
    frames: List[CANFrame],
    baseline: Baseline,
) -> List[Alert]:
    if not frames:
        return []

    alerts: List[Alert] = []
    unknown_counts: Counter = Counter()
    first_seen: dict = {}
    first_data: dict = {}

    for frame in frames:
        can_id = frame.can_id
        if can_id not in baseline.known_ids:
            if can_id not in first_seen:
                first_seen[can_id] = frame.timestamp
                first_data[can_id] = frame.data
            unknown_counts[can_id] += 1

    for can_id, count in unknown_counts.items():
        # More frames from an unknown ID → more likely malicious
        severity = "high" if count >= 5 else "medium" if count >= 2 else "low"
        alerts.append(Alert(
            timestamp=first_seen[can_id],
            can_id=can_id,
            detector="unknown_id",
            severity=severity,
            message=(
                f"ID {can_id:03X}: unknown CAN identifier — "
                f"not present in baseline ({count} frame{'s' if count != 1 else ''} observed)"
            ),
            score=float(count),
            frame_data=first_data[can_id],
            extra={"frame_count": count, "first_seen": first_seen[can_id]},
        ))

    alerts.sort(key=lambda a: a.score, reverse=True)
    return alerts
