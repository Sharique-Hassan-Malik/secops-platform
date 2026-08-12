"""
Parses the .pyc file header and extracts the top-level code object via
the standard library's marshal module.

.pyc layout:
    [0:2]  magic number (uint16 LE)  — encodes the Python version
    [2:4]  magic \r\n suffix         — always 0x0d 0x0a
    [4:8]  bit field (uint32 LE)     — 0=timestamp, 1=hash-based (Python 3.8+)
    [8:12] source file mtime or hash (uint32 LE)
    [12:16] source file size or hash high (uint32 LE)
    [16:]  marshal'd code object

Python 3.7 and earlier:
    [4:8]  mtime (uint32 LE)
    [8:12] source size (uint32 LE)
    [12:]  marshal'd code object
"""

from __future__ import annotations

import marshal
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from types import CodeType

from config import MAGIC_TO_VERSION


@dataclass
class PycFile:
    path:           str
    magic_raw:      int         # raw uint16 from bytes [0:2]
    python_version: str         # e.g. "3.11"
    flags:          int         # bit-field (0 for pre-3.8)
    timestamp:      int         # mtime or 0
    source_size:    int         # source file size or 0
    source_hash:    bytes       # non-empty when hash-based validation
    code:           CodeType    # top-level code object


class PycParseError(ValueError):
    pass


class PycParser:
    """
    Parses a .pyc file without importing or executing the contained code.

    Only marshal.loads is called, which reconstructs Python objects from
    the serialised code object bytes.  marshal is far more limited than
    pickle and cannot execute arbitrary callables.
    """

    def parse_file(self, path: str) -> PycFile:
        data = Path(path).read_bytes()
        return self.parse_bytes(data, path=path)

    def parse_bytes(self, data: bytes, path: str = "<bytes>") -> PycFile:
        if len(data) < 16:
            raise PycParseError(f"File too short ({len(data)} bytes) to be a valid .pyc")

        magic_raw = struct.unpack_from("<H", data, 0)[0]
        # Bytes 2–3 should be 0x0d 0x0a but we tolerate deviations
        python_version = MAGIC_TO_VERSION.get(magic_raw, "unknown")

        # Determine header layout
        is_new_header = self._is_new_header(python_version)

        if is_new_header:
            # Python 3.8+: [4:8] bit-field, [8:12] mtime/hash_lo, [12:16] size/hash_hi
            flags       = struct.unpack_from("<I", data, 4)[0]
            hash_based  = bool(flags & 0x01)
            if hash_based:
                source_hash  = data[8:16]
                timestamp    = 0
                source_size  = 0
            else:
                timestamp   = struct.unpack_from("<I", data, 8)[0]
                source_size = struct.unpack_from("<I", data, 12)[0]
                source_hash = b""
            code_offset = 16
        else:
            # Python 3.7 and earlier: [4:8] mtime, [8:12] source size
            flags       = 0
            timestamp   = struct.unpack_from("<I", data, 4)[0]
            source_size = struct.unpack_from("<I", data, 8)[0]
            source_hash = b""
            code_offset = 12

        try:
            code = marshal.loads(data[code_offset:])
        except Exception as exc:
            raise PycParseError(f"marshal.loads failed: {exc}") from exc

        if not isinstance(code, type((lambda: None).__code__)):
            raise PycParseError(f"marshal payload is not a code object (got {type(code).__name__})")

        return PycFile(
            path=path,
            magic_raw=magic_raw,
            python_version=python_version,
            flags=flags,
            timestamp=timestamp,
            source_size=source_size,
            source_hash=source_hash,
            code=code,
        )

    @staticmethod
    def _is_new_header(version: str) -> bool:
        """Returns True for Python 3.8+ which added the bit-field byte."""
        if version == "unknown":
            return True   # assume modern
        try:
            major, minor = (int(x) for x in version.split("."))
            return (major, minor) >= (3, 8)
        except ValueError:
            return True

    @staticmethod
    def timestamp_str(ts: int) -> str:
        if ts == 0:
            return "N/A"
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
        except (OSError, OverflowError):
            return f"<invalid: {ts}>"
