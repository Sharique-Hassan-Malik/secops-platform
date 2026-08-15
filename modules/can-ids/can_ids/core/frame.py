"""
Core CAN frame representation.

A CAN 2.0 frame has:
  - 11-bit standard ID (0x000–0x7FF) or 29-bit extended ID (0x00000000–0x1FFFFFFF)
  - DLC: 0–8 data bytes
  - Payload: up to 8 bytes

This module also provides helper functions for payload analysis used by
multiple detectors.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True, order=True)
class CANFrame:
    timestamp: float          # seconds since epoch (or log start)
    can_id: int               # 11-bit or 29-bit identifier
    extended: bool            # True if 29-bit extended frame
    data: bytes               # 0–8 bytes of payload

    @property
    def dlc(self) -> int:
        return len(self.data)

    @property
    def id_str(self) -> str:
        if self.extended:
            return f"{self.can_id:08X}"
        return f"{self.can_id:03X}"

    @property
    def data_hex(self) -> str:
        return self.data.hex().upper()

    def __repr__(self) -> str:
        ext = "X" if self.extended else ""
        return f"CANFrame(t={self.timestamp:.6f} id={self.id_str}{ext} [{self.dlc}] {self.data_hex})"


def payload_key(frame: CANFrame) -> tuple[int, bytes]:
    """Hashable (id, data) key used by replay detection."""
    return (frame.can_id, frame.data)


def byte_values(frame: CANFrame) -> list[int]:
    return list(frame.data)


def pack_uint(data: bytes, offset: int, length: int, big_endian: bool = True) -> Optional[int]:
    """
    Extract an unsigned integer of `length` bytes from `data` at `offset`.
    Returns None if out of range.
    """
    if offset + length > len(data):
        return None
    chunk = data[offset : offset + length]
    if big_endian:
        return int.from_bytes(chunk, "big")
    return int.from_bytes(chunk, "little")
