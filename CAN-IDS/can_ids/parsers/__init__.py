"""
Auto-detecting parser entry point.

Inspects the file extension and first line to choose between candump and
CSV format.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from can_ids.core.frame import CANFrame
from can_ids.parsers import candump, csv_parser


def load(path: str) -> List[CANFrame]:
    """
    Load a CAN log file, auto-detecting the format.

    Supports:
      .log, .txt  — candump format
      .csv        — CSV format
      other       — attempts candump, falls back to CSV
    """
    p = Path(path)
    suffix = p.suffix.lower()

    if suffix == ".csv":
        return csv_parser.parse_file(path)
    if suffix in (".log", ".txt", ""):
        return candump.parse_file(path)

    # Unknown extension — try candump first
    frames = candump.parse_file(path)
    if frames:
        return frames
    return csv_parser.parse_file(path)
