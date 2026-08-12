import re
from datetime import datetime
from typing import Optional

_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}


def parse(line: str) -> Optional[dict]:
    if "kernel:" not in line:
        return None
    action_m = re.search(r"\b(ACCEPT|DROP|REJECT|BLOCK)\b", line)
    if not action_m:
        return None
    src_m   = re.search(r"SRC=(\S+)", line)
    proto_m = re.search(r"PROTO=(\S+)", line)
    dpt_m   = re.search(r"DPT=(\d+)", line)
    ts_m    = re.match(r"(\w+)\s+(\d+) (\d+:\d+:\d+)", line)
    if not src_m:
        return None
    ts = datetime.utcnow()
    if ts_m:
        month = _MONTHS.get(ts_m.group(1), 1)
        now = datetime.utcnow()
        try:
            ts = datetime.strptime(
                f"{now.year} {month:02d} {int(ts_m.group(2)):02d} {ts_m.group(3)}",
                "%Y %m %d %H:%M:%S",
            )
        except ValueError:
            pass
    action = action_m.group(1)
    dpt    = dpt_m.group(1) if dpt_m else None
    proto  = proto_m.group(1) if proto_m else None
    return {
        "timestamp":   ts,
        "source_type": "firewall",
        "source_ip":   src_m.group(1),
        "method":      proto,
        "path":        f":{dpt}" if dpt else None,
        "status_code": None,
        "user_agent":  None,
        "severity":    "high" if action in ("DROP", "REJECT", "BLOCK") else "info",
        "raw":         line.strip(),
    }
