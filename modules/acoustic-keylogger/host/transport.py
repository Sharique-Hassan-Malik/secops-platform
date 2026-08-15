"""
transport.py — binary serial protocol for the acoustic keylogger firmware.

Packet format:
  byte 0: 'K' (0x4B) — keystroke marker
  byte 1: label       — key label (0 = unlabelled)
  bytes 2–3: uint16   — sample count N (little-endian)
  bytes 4..(4+2N-1):  — N int16_t samples, little-endian

Special:
  'R' (0x52)          — firmware ready / identify response
    optionally followed by 2 bytes: sample rate lo, hi
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import numpy as np
import serial


@dataclass
class Keystroke:
    label:     int            # 0 = unlabelled; 1–N = key index
    samples:   np.ndarray     # int16 array of length WINDOW_SAMPLES
    timestamp: float = field(default_factory=time.monotonic)


KeystrokeCallback = Callable[[Keystroke], None]


class AcousticTransport:
    """
    Opens a serial connection to the firmware and runs a background reader
    thread. Delivers Keystroke objects to registered callbacks.
    """

    PKT_KEYSTROKE = 0x4B   # 'K'
    PKT_LABEL     = ord('L')
    PKT_IDENT     = ord('I')
    PKT_READY     = ord('R')

    def __init__(self, port: str, baud: int = 500_000) -> None:
        self._ser          = serial.Serial(port, baud, timeout=2.0)
        self._sample_rate  = 8000
        self._callbacks:   list[KeystrokeCallback] = []
        self._running      = False
        self._thread: Optional[threading.Thread] = None
        self._count        = 0
        time.sleep(2.0)   # wait for Arduino reset

    def on_keystroke(self, cb: KeystrokeCallback) -> None:
        self._callbacks.append(cb)

    @property
    def sample_rate(self) -> int:
        return self._sample_rate

    @property
    def keystroke_count(self) -> int:
        return self._count

    def identify(self) -> int:
        """Query firmware sample rate. Returns sample rate in Hz."""
        self._ser.reset_input_buffer()
        self._ser.write(bytes([self.PKT_IDENT]))
        self._ser.flush()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if self._ser.in_waiting >= 3:
                b = self._ser.read(1)
                if b[0] == self.PKT_READY:
                    lo = self._ser.read(1)[0]
                    hi = self._ser.read(1)[0]
                    self._sample_rate = lo | (hi << 8)
                    return self._sample_rate
        return self._sample_rate

    def set_label(self, label: int) -> None:
        """Send current key label to firmware (1 byte, 0 = unlabelled)."""
        self._ser.write(bytes([self.PKT_LABEL, label & 0xFF]))
        self._ser.flush()

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        self._ser.close()

    def __enter__(self) -> "AcousticTransport":
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    # ── Background reader ──────────────────────────────────────────────────────

    def _reader(self) -> None:
        while self._running:
            try:
                hdr = self._ser.read(1)
            except Exception:
                break
            if not hdr:
                continue
            b = hdr[0]

            if b == self.PKT_KEYSTROKE:
                ks = self._read_keystroke()
                if ks is not None:
                    self._count += 1
                    for cb in self._callbacks:
                        cb(ks)
            # Other bytes ('R', etc.) are silently ignored in streaming mode.

    def _read_keystroke(self) -> Optional[Keystroke]:
        # Read label + sample count (3 bytes).
        meta = self._ser.read(3)
        if len(meta) < 3:
            return None
        label = meta[0]
        n     = meta[1] | (meta[2] << 8)

        # Read n int16_t samples (2 bytes each).
        raw = self._ser.read(n * 2)
        if len(raw) < n * 2:
            return None

        samples = np.frombuffer(raw, dtype=np.int16).copy()
        return Keystroke(label=label, samples=samples)
