"""Joins the CAN bus IDS to the platform as a monitor.

Every alert becomes an event whose entity is the CAN arbitration ID, not the
capture file. That is what lets `sustained-intrusion` fire: forty injected
frames against `0x2C4` are forty events about one entity, and volume against a
single ID is the signal. Keying on the file instead would flatten that into
"this capture had alerts".
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE.parents[1]):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from can_ids.analyzer import CANIntrusion, DetectorConfig  # noqa: E402
from secops.core.event import Category, Event, SensorResult, Severity  # noqa: E402
from secops.core.sensor import Sensor, spec  # noqa: E402


class CanIdsSensor(Sensor):
    def observe(self, target: Any, **options: Any) -> SensorResult:
        path = Path(str(target))
        result = self.result(str(path))

        detector = CANIntrusion(DetectorConfig())
        baseline_path = options.get("baseline")
        if baseline_path:
            analysis = detector.detect(str(path), detector.build_baseline(str(baseline_path)))
        else:
            # No separate baseline: learn from the first part of the capture.
            # Honest but weaker — an attack present throughout becomes the norm.
            analysis = detector.analyze_split(
                str(path), train_ratio=float(options.get("train_ratio", 0.7))
            )

        for alert in analysis.alerts:
            result.emit(
                Event(
                    sensor=self.name,
                    category=Category.INTRUSION,
                    severity=Severity.parse(alert.severity),
                    title=f"can_{alert.detector}",
                    message=alert.message,
                    entity=f"CAN:{alert.id_str}",
                    score=alert.score,
                    fields={
                        "can_id": alert.id_str,
                        "detector": alert.detector,
                        "frame_time": alert.timestamp,
                        **alert.extra,
                    },
                )
            )

        result.metrics.update({
            "frames_tested": analysis.test_frame_count,
            "alerts": len(analysis.alerts),
            "critical": analysis.critical_count,
            "high": analysis.high_count,
            "baseline": "supplied" if baseline_path else "learned from capture",
        })
        return result


SENSOR = CanIdsSensor(spec("can-ids"))
