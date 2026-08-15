"""
CSV log parser.

Accepts CSV files exported from tools such as Vector CANalyzer, Kvaser
CanKing and various OBD-II dongles.  Column names are matched
case-insensitively and accept common aliases.

Recognised column names:
  Timestamp : "timestamp", "time", "t", "time_s", "abs_time"
  CAN ID    : "can_id", "id", "arbitration_id", "arb_id", "frame_id"
  Data      : "data", "payload", "hex_data", "raw_data"

The data field is expected as a hex string, optionally with spaces or
colons between bytes (e.g. "DE AD BE EF", "DE:AD:BE:EF", "DEADBEEF").

Rows with missing or unparseable fields are silently skipped.
"""

from __future__ import annotations

import csv
import re
from typing import List, Optional

from can_ids.core.frame import CANFrame

_TS_ALIASES = {"timestamp", "time", "t", "time_s", "abs_time"}
_ID_ALIASES = {"can_id", "id", "arbitration_id", "arb_id", "frame_id"}
_DATA_ALIASES = {"data", "payload", "hex_data", "raw_data"}

_HEX_STRIP = re.compile(r"[^0-9A-Fa-f]")


def _normalise_header(headers: list[str]) -> dict[str, int]:
    """Return a mapping of role → column index for recognised fields."""
    mapping: dict[str, int] = {}
    for i, h in enumerate(headers):
        key = h.strip().lower()
        if key in _TS_ALIASES and "ts" not in mapping:
            mapping["ts"] = i
        elif key in _ID_ALIASES and "id" not in mapping:
            mapping["id"] = i
        elif key in _DATA_ALIASES and "data" not in mapping:
            mapping["data"] = i
    return mapping


def _parse_row(row: list[str], mapping: dict[str, int]) -> Optional[CANFrame]:
    try:
        ts = float(row[mapping["ts"]])
    except (KeyError, IndexError, ValueError):
        return None

    try:
        raw_id = row[mapping["id"]].strip()
        if raw_id.lower().startswith("0x"):
            can_id = int(raw_id, 16)
        else:
            can_id = int(raw_id, 16) if any(c in raw_id for c in "abcdefABCDEF") else int(raw_id)
    except (KeyError, IndexError, ValueError):
        return None

    try:
        raw_data = row[mapping["data"]].strip()
        hex_clean = _HEX_STRIP.sub("", raw_data)
        data = bytes.fromhex(hex_clean) if hex_clean else b""
    except (KeyError, IndexError, ValueError):
        data = b""

    if len(data) > 8:
        return None

    extended = can_id > 0x7FF

    return CANFrame(timestamp=ts, can_id=can_id, extended=extended, data=data)


def parse_file(path: str) -> List[CANFrame]:
    frames: List[CANFrame] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        headers: Optional[list] = None
        mapping: dict = {}
        for row in reader:
            if headers is None:
                headers = row
                mapping = _normalise_header(headers)
                if not mapping:
                    # Try to auto-detect a headerless format: ts,id,data
                    if len(row) >= 3:
                        mapping = {"ts": 0, "id": 1, "data": 2}
                        frame = _parse_row(row, mapping)
                        if frame:
                            frames.append(frame)
                    continue
                continue
            frame = _parse_row(row, mapping)
            if frame:
                frames.append(frame)

    frames.sort(key=lambda f: f.timestamp)
    return frames
