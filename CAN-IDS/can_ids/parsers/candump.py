"""
Parser for the candump log format produced by the Linux can-utils suite.

Supported variants:

  Standard candump:
    (1609459200.000000) vcan0 1A0#DEADBEEF01020304

  Compact (no interface):
    (1609459200.000000) 1A0#DEADBEEF01020304

  Without parentheses:
    1609459200.000000 1A0#DEADBEEF01020304

  Extended frame (29-bit ID marked with #):
    (1609459200.000000) vcan0 1FFFFFFF#0102030405060708

  Remote frame (no data — marked with R or r after #):
    (1609459200.000000) vcan0 123#R

  Error frames (ID 20000004#...) are skipped.

Lines starting with '#' are treated as comments.
"""

from __future__ import annotations

import re
from typing import Iterator, List, Optional

from can_ids.core.frame import CANFrame

# Matches: optional '(' timestamp ')'  optional-interface  ID#DATA
_LINE_RE = re.compile(
    r"^\s*"
    r"(?:\(?)(\d+\.\d+)(?:\)?)?"     # group 1: timestamp
    r"\s+"
    r"(?:[A-Za-z0-9_]+\s+)?"          # optional interface name
    r"([0-9A-Fa-f]{1,8})"             # group 2: CAN ID (3 or 8 hex digits)
    r"#"
    r"([0-9A-Fa-f]{0,20}|[Rr]\d*)"   # group 3: data hex or remote frame marker
)

# Error frame IDs (bit 29 set in the Linux error frame convention)
_ERROR_FLAG = 0x20000000


def parse_line(line: str) -> Optional[CANFrame]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = _LINE_RE.match(line)
    if not m:
        return None

    ts_str, id_str, data_str = m.group(1), m.group(2), m.group(3)

    try:
        timestamp = float(ts_str)
        can_id = int(id_str, 16)
    except ValueError:
        return None

    # Skip error frames
    if can_id & _ERROR_FLAG:
        return None

    # Remote frames — no payload
    if data_str.upper().startswith("R"):
        data = b""
    else:
        try:
            data = bytes.fromhex(data_str) if data_str else b""
        except ValueError:
            return None

    if len(data) > 8:
        return None

    extended = len(id_str) > 3

    return CANFrame(
        timestamp=timestamp,
        can_id=can_id,
        extended=extended,
        data=data,
    )


def parse_file(path: str) -> List[CANFrame]:
    frames: List[CANFrame] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            frame = parse_line(line)
            if frame is not None:
                frames.append(frame)
    frames.sort(key=lambda f: f.timestamp)
    return frames


def parse_lines(lines: Iterator[str]) -> List[CANFrame]:
    frames: List[CANFrame] = []
    for line in lines:
        frame = parse_line(line)
        if frame is not None:
            frames.append(frame)
    frames.sort(key=lambda f: f.timestamp)
    return frames
