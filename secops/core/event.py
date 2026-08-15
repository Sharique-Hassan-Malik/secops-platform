"""The event every sensor in this repository emits.

Ten tools, ten opinions about what a detection looks like: a printed table, a
JSON blob, a `dict` with `severity="warn"`, an exit code. None of them could be
correlated with any other, which is the one thing a security platform has to do
— the interesting signal is almost never inside a single sensor.

So there is one `Event`. It is deliberately close to what a SIEM stores: a
timestamp, who saw it, what kind of thing it was, what it was about, and a bag
of sensor-specific fields that nothing else has to understand.

Stdlib only. A sensor used on its own — `cd modules/zipbomb-detector &&
python detect.py archive.zip` — imports this and gains no dependencies.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Iterator


class Severity(Enum):
    """One ladder, ordered, shared by file scanners and bus monitors alike."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _ORDER.index(self)

    def __lt__(self, other: object) -> bool:
        return self.rank < other.rank if isinstance(other, Severity) else NotImplemented

    def __le__(self, other: object) -> bool:
        return self.rank <= other.rank if isinstance(other, Severity) else NotImplemented

    def __gt__(self, other: object) -> bool:
        return self.rank > other.rank if isinstance(other, Severity) else NotImplemented

    def __ge__(self, other: object) -> bool:
        return self.rank >= other.rank if isinstance(other, Severity) else NotImplemented

    @classmethod
    def parse(cls, value: "str | Severity") -> "Severity":
        if isinstance(value, cls):
            return value
        text = str(value).strip().upper()
        # The sensors between them use every one of these spellings.
        aliases = {
            "WARN": "MEDIUM", "WARNING": "MEDIUM", "NOTICE": "LOW",
            "ERROR": "HIGH", "ERR": "HIGH", "CRIT": "CRITICAL",
            "SAFE": "INFO", "CLEAN": "INFO", "DEBUG": "INFO",
        }
        return cls[aliases.get(text, text)]


_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Category(str, Enum):
    """What kind of thing was observed.

    Coarse on purpose. These are the buckets a correlation rule reasons about;
    the sensor-specific detail lives in `Event.fields`.
    """

    MALWARE = "malware"                 # hostile artifact — bomb, packed payload
    EVASION = "evasion"                 # hidden or obfuscated content
    INTRUSION = "intrusion"             # unauthorised activity on a bus or host
    RECON = "recon"                     # fingerprinting, scanning, enumeration
    EXFILTRATION = "exfiltration"       # data leaving
    EXPLOIT = "exploit"                 # injection, overflow, protocol abuse
    SIDE_CHANNEL = "side-channel"       # timing, power, acoustic leakage
    AVAILABILITY = "availability"       # resource exhaustion, crash
    AUDIT = "audit"                     # informational, for the record


class Kind(str, Enum):
    """How a sensor is driven.

    `SCANNER` is handed an artifact. `MONITOR` consumes a stream — a log file,
    a CAN capture, a request. `SIMULATOR` is a red-team tool that *produces*
    activity, and is here so its output can be fed to the blue-team sensors and
    the detection actually tested.
    """

    SCANNER = "scanner"
    MONITOR = "monitor"
    SIMULATOR = "simulator"


@dataclass
class Event:
    """One observation, from one sensor.

    `entity` is what the event is *about* — a file path, a source IP, a CAN
    arbitration ID. It is the join key: correlation across sensors is only
    possible because they all name the thing they saw in the same field.
    """

    sensor: str
    category: Category
    severity: Severity
    title: str
    entity: str = ""
    message: str = ""
    score: float | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    fields: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if not isinstance(self.category, Category):
            self.category = Category(str(self.category))

    def __str__(self) -> str:
        where = f" {self.entity}" if self.entity else ""
        return f"[{self.severity.value:<8}]{where}  {self.title}" + (
            f" — {self.message}" if self.message else ""
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "timestamp": self.timestamp,
            "sensor": self.sensor,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
        }
        if self.entity:
            out["entity"] = self.entity
        if self.message:
            out["message"] = self.message
        if self.score is not None:
            out["score"] = round(float(self.score), 4)
        if self.fields:
            out["fields"] = self.fields
        return out


@dataclass
class Alert:
    """A correlation rule firing across events — usually across sensors.

    Separate from `Event` because it is a different claim. An event says "this
    sensor saw this". An alert says "these observations together mean
    something", and names which ones, so an analyst can disagree.
    """

    rule: str
    severity: Severity
    entity: str
    description: str
    events: list[Event] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)

    @property
    def sensors(self) -> list[str]:
        return sorted({event.sensor for event in self.events})

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "rule": self.rule,
            "severity": self.severity.value,
            "entity": self.entity,
            "description": self.description,
            "sensors": self.sensors,
            "event_count": len(self.events),
            "events": [event.to_dict() for event in self.events],
        }


@dataclass
class SensorResult:
    """What one sensor produced for one target."""

    sensor: str
    kind: Kind
    target: str = ""
    events: list[Event] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    skipped: str = ""
    elapsed: float = 0.0

    def emit(self, event: Event) -> Event:
        event.sensor = event.sensor or self.sensor
        event.entity = event.entity or self.target
        self.events.append(event)
        return event

    def extend(self, events: Iterable[Event]) -> None:
        for event in events:
            self.emit(event)

    @property
    def max_severity(self) -> Severity:
        return max((e.severity for e in self.events), default=Severity.INFO)

    @property
    def ran(self) -> bool:
        return not self.error and not self.skipped

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "sensor": self.sensor,
            "kind": self.kind.value,
            "target": self.target,
            "max_severity": self.max_severity.value,
            "events": [e.to_dict() for e in self.events],
        }
        if self.metrics:
            out["metrics"] = self.metrics
        if self.error:
            out["error"] = self.error
        if self.skipped:
            out["skipped"] = self.skipped
        if self.elapsed:
            out["elapsed_s"] = round(self.elapsed, 3)
        return out


@dataclass
class Report:
    """Everything one run produced: sensor results, plus correlated alerts."""

    target: str = ""
    results: list[SensorResult] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    def add(self, result: SensorResult) -> SensorResult:
        self.results.append(result)
        return result

    def __iter__(self) -> Iterator[SensorResult]:
        return iter(self.results)

    @property
    def events(self) -> list[Event]:
        return [e for r in self.results for e in r.events]

    @property
    def errors(self) -> list[SensorResult]:
        return [r for r in self.results if r.error]

    @property
    def max_severity(self) -> Severity:
        worst_event = max((e.severity for e in self.events), default=Severity.INFO)
        worst_alert = max((a.severity for a in self.alerts), default=Severity.INFO)
        return max(worst_event, worst_alert)

    @property
    def exit_code(self) -> int:
        """0 nothing above LOW, 1 something found, 2 a sensor failed."""
        if self.errors:
            return 2
        return 1 if self.max_severity >= Severity.MEDIUM else 0

    def counts(self) -> dict[Severity, int]:
        counts = {sev: 0 for sev in Severity}
        for event in self.events:
            counts[event.severity] += 1
        return counts

    def filtered(self, minimum: Severity) -> "Report":
        clone = Report(target=self.target, timestamp=self.timestamp, alerts=self.alerts)
        for result in self.results:
            clone.add(
                SensorResult(
                    sensor=result.sensor,
                    kind=result.kind,
                    target=result.target,
                    events=[e for e in result.events if e.severity >= minimum],
                    metrics=result.metrics,
                    error=result.error,
                    skipped=result.skipped,
                    elapsed=result.elapsed,
                )
            )
        return clone

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "max_severity": self.max_severity.value,
            "event_count": len(self.events),
            "alert_count": len(self.alerts),
            "counts": {s.value: n for s, n in self.counts().items() if n},
            "alerts": [a.to_dict() for a in self.alerts],
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
