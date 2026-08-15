import re
from datetime import datetime
from typing import Optional

_RE = re.compile(
    r"<\d+>(?P<month>\w+)\s+(?P<day>\d+) (?P<time>\d+:\d+:\d+) "
    r"(?P<host>\S+) (?P<process>[^:]+): (?P<msg>.+)"
)
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}
_SEVERITY_MAP = [
    ("critical", ["panic", "emergency", "critical"]),
    ("high",     ["error", "failure", "failed", "denied"]),
    ("medium",   ["warning", "warn"]),
    ("low",      ["notice"]),
]


def parse(line: str) -> Optional[dict]:
    m = _RE.match(line.strip())
    if not m:
        return None
    month = _MONTHS.get(m.group("month"), 1)
    now = datetime.utcnow()
    try:
        ts = datetime.strptime(
            f"{now.year} {month:02d} {int(m.group('day')):02d} {m.group('time')}",
            "%Y %m %d %H:%M:%S",
        )
    except ValueError:
        ts = now
    msg = m.group("msg").lower()
    return {
        "timestamp":   ts,
        "source_type": "syslog",
        "source_ip":   m.group("host"),
        "method":      None,
        "path":        None,
        "status_code": None,
        "user_agent":  m.group("process").strip(),
        "severity":    _classify(msg),
        "raw":         line.strip(),
    }


def _classify(msg: str) -> str:
    for level, keywords in _SEVERITY_MAP:
        if any(kw in msg for kw in keywords):
            return level
    return "info"
