"""Joins the archive bomb detector to the platform as a scanner.

The detector's own vocabulary is a `ThreatLevel` and a list of `ThreatFlag`s;
the platform's is events. Each flag becomes one event, so a nested bomb that
trips three separate policy limits produces three observations rather than one
verdict — correlation reasons about them individually.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE / "python", _HERE, _HERE.parents[1]):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from formats.base import ThreatLevel  # noqa: E402
from secops.core.event import Category, Event, SensorResult, Severity  # noqa: E402
from secops.core.sensor import Sensor, spec  # noqa: E402
from zipbomb_detector import DEFAULT_POLICY, POLICIES, scan_file  # noqa: E402

_SEVERITY = {
    ThreatLevel.NONE: Severity.INFO,
    ThreatLevel.LOW: Severity.LOW,
    ThreatLevel.MEDIUM: Severity.MEDIUM,
    ThreatLevel.HIGH: Severity.HIGH,
    ThreatLevel.CRITICAL: Severity.CRITICAL,
}


class ZipbombSensor(Sensor):
    def observe(self, target: Any, **options: Any) -> SensorResult:
        path = Path(str(target))
        result = self.result(str(path))

        policy = POLICIES.get(str(options.get("policy", "default")), DEFAULT_POLICY)
        scanned = scan_file(path, policy)

        for flag in scanned.flags:
            result.emit(
                Event(
                    sensor=self.name,
                    # A decompression bomb is an availability attack first: the
                    # damage is the resource exhaustion, not the content.
                    category=Category.AVAILABILITY,
                    severity=_SEVERITY.get(flag.level, Severity.MEDIUM),
                    title=flag.code,
                    message=flag.description,
                    entity=str(path),
                    fields={"format": scanned.fmt, "policy": options.get("policy", "default")},
                )
            )

        if scanned.has_overlaps:
            result.emit(
                Event(
                    sensor=self.name,
                    # Overlapping entries are a parser-confusion trick, not a
                    # size problem — a different claim from the ratio flags.
                    category=Category.EVASION,
                    severity=Severity.HIGH,
                    title="OVERLAPPING_ENTRIES",
                    message="Archive entries share byte ranges — different readers "
                            "will extract different content from the same file.",
                    entity=str(path),
                    fields={"format": scanned.fmt},
                )
            )

        result.metrics.update({
            "format": scanned.fmt,
            "entries": scanned.entry_count,
            "compressed": scanned.total_compressed,
            "uncompressed": scanned.total_uncompressed,
            "ratio": round(scanned.overall_ratio, 2),
        })
        return result


SENSOR = ZipbombSensor(spec("zipbomb-detector"))
