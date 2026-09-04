import re
from datetime import datetime, timezone
from typing import Optional

_RE = re.compile(
    r'(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) \d+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse(line: str) -> Optional[dict]:
    m = _RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), _TIME_FMT).replace(tzinfo=None)
    except ValueError:
        ts = datetime.now(timezone.utc).replace(tzinfo=None)
    status = int(m.group("status"))
    return {
        "timestamp":   ts,
        "source_type": "nginx",
        "source_ip":   m.group("ip"),
        "method":      m.group("method"),
        "path":        m.group("path"),
        "status_code": status,
        "user_agent":  m.group("ua"),
        "severity":    _severity(status),
        "raw":         line.strip(),
    }


def _severity(status: int) -> str:
    if status >= 500:
        return "high"
    if status >= 400:
        return "low"
    return "info"
