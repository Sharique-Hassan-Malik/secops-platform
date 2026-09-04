"""Push what the sensors saw into the SIEM, so it lands where analysts look.

A scan that prints to a terminal and exits has told one person once. The same
events written to the SIEM are queryable, correlate with the log stream already
flowing in, and show up on the dashboard — which is the whole reason the SIEM
is in this repository rather than being a separate project.

The dependency runs one way. Sensors know nothing about the SIEM; this module
knows about both. If SQLAlchemy is not installed, ingestion is unavailable and
says so — the scan itself is unaffected.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import sys
from pathlib import Path
from typing import Iterable

from .core.event import Alert, Event, Report
from .core.sensor import MODULES_ROOT

SIEM_BACKEND = MODULES_ROOT / "siem" / "backend"


class SiemUnavailable(RuntimeError):
    """The SIEM cannot be reached from here."""


def available() -> tuple[bool, str]:
    if not SIEM_BACKEND.is_dir():
        return False, "the siem module is not in this repository"
    if importlib.util.find_spec("sqlalchemy") is None:
        return False, "sqlalchemy is not installed (pip install -r modules/siem/requirements.txt)"
    return True, ""


def _backend():
    usable, reason = available()
    if not usable:
        raise SiemUnavailable(reason)
    if str(SIEM_BACKEND) not in sys.path:
        sys.path.insert(0, str(SIEM_BACKEND))
    import database  # noqa: PLC0415 — imported late so a scan never pays for it

    database.init_db()
    return database


def _parse_timestamp(value: str) -> datetime.datetime:
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def ingest_events(events: Iterable[Event]) -> int:
    """Write sensor events to the SIEM's `detections` table. Returns the count."""
    database = _backend()
    session = database.SessionLocal()
    written = 0
    try:
        for event in events:
            session.add(
                database.Detection(
                    timestamp=_parse_timestamp(event.timestamp),
                    sensor=event.sensor,
                    category=event.category.value,
                    severity=event.severity.value.lower(),
                    title=event.title[:128],
                    entity=event.entity[:512],
                    message=event.message,
                    score=event.score,
                    fields=json.dumps(event.fields, default=str),
                )
            )
            written += 1
        session.commit()
    finally:
        session.close()
    return written


def ingest_alerts(alerts: Iterable[Alert]) -> int:
    """Write correlated alerts to the SIEM's existing `alerts` table.

    Reusing that table rather than adding a parallel one is deliberate: an
    analyst triaging alerts should see correlation output and the SIEM's own
    rule output in one queue, not two.
    """
    database = _backend()
    session = database.SessionLocal()
    written = 0
    try:
        for alert in alerts:
            session.add(
                database.Alert(
                    created_at=_parse_timestamp(alert.timestamp),
                    rule_name=alert.rule[:64],
                    severity=alert.severity.value.lower(),
                    description=alert.description,
                    source_ip=alert.entity[:45],
                    event_count=len(alert.events),
                    status="open",
                )
            )
            written += 1
        session.commit()
    finally:
        session.close()
    return written


def ingest(report: Report) -> dict[str, int]:
    """Push a whole report — events and correlated alerts."""
    return {
        "detections": ingest_events(report.events),
        "alerts": ingest_alerts(report.alerts),
    }
