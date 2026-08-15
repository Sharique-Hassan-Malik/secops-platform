"""
rar_scanner.py — RAR4 and RAR5 bomb detection.

RAR4: Magic "Rar!\x1a\x07\x00"
  Block structure: HEAD_TYPE + HEAD_FLAGS + HEAD_SIZE + optional fields.
  File headers (type 0x74) contain PACK_SIZE and UNP_SIZE fields.

RAR5: Magic "Rar!\x1a\x07\x01\x00"
  Uses vint (variable-length integers) and a different block layout.
  File headers contain packed_size and unpacked_size as vints.
"""

from __future__ import annotations
import struct
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel, fmt_bytes

RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"

# RAR4 block types
RAR4_MAIN_HEAD = 0x73
RAR4_FILE_HEAD = 0x74
RAR4_EOAR_HEAD = 0x7b

# RAR4 flags
RAR4_LONG_BLOCK = 0x8000


def _read_vint(data: bytes, pos: int) -> tuple[int, int]:
    """Read a RAR5 variable-length integer. Returns (value, new_pos)."""
    value = 0
    shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        value |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            break
    return value, pos


def _scan_rar4(data: bytes, policy: dict, result: FormatResult):
    pos          = len(RAR4_MAGIC)
    file_count   = 0
    total_pack   = 0
    total_unpack = 0

    while pos + 7 < len(data):
        try:
            _crc    = struct.unpack_from("<H", data, pos)[0]   # noqa: F841 (documents RAR4 header layout)
            htype   = data[pos + 2]
            hflags  = struct.unpack_from("<H", data, pos + 3)[0]
            hsize   = struct.unpack_from("<H", data, pos + 5)[0]

            if hsize < 7:
                break

            block_size = hsize
            if hflags & RAR4_LONG_BLOCK:
                if pos + 11 > len(data): break
                add_size    = struct.unpack_from("<I", data, pos + 7)[0]
                block_size += add_size

            if htype == RAR4_EOAR_HEAD:
                break

            if htype == RAR4_FILE_HEAD and hsize >= 32:
                pack_sz   = struct.unpack_from("<I", data, pos + 7)[0]
                unpack_sz = struct.unpack_from("<I", data, pos + 11)[0]
                hflags2   = struct.unpack_from("<H", data, pos + 3)[0]

                # High-part sizes (64-bit files)
                if hflags2 & 0x100:
                    pack_hi   = struct.unpack_from("<I", data, pos + hsize - 8)[0]
                    unpack_hi = struct.unpack_from("<I", data, pos + hsize - 4)[0]
                    pack_sz   |= pack_hi   << 32
                    unpack_sz |= unpack_hi << 32

                total_pack   += pack_sz
                total_unpack += unpack_sz
                file_count   += 1

                ratio = unpack_sz / pack_sz if pack_sz > 0 else 0
                if pack_sz > 0 and ratio > policy["max_ratio"]:
                    name_size = struct.unpack_from("<H", data, pos + 26)[0]
                    name = data[pos+32:pos+32+name_size].decode("utf-8", errors="replace")
                    result.add_flag(ThreatLevel.CRITICAL, "RATIO_EXCEEDED",
                        f"Entry '{name}': {ratio:.1f}:1 exceeds limit {policy['max_ratio']}:1")

                if total_unpack > policy["max_uncompressed"]:
                    result.add_flag(ThreatLevel.CRITICAL, "SIZE_EXCEEDED",
                        f"Cumulative {fmt_bytes(total_unpack)} exceeds limit")
                    break

            pos += block_size
        except (struct.error, IndexError):
            break

    result.total_pack     = total_pack
    result.total_unpack   = total_unpack
    result.entry_count    = file_count
    return total_pack, total_unpack, file_count


def _scan_rar5(data: bytes, policy: dict, result: FormatResult):
    pos          = len(RAR5_MAGIC)
    file_count   = 0
    total_pack   = 0
    total_unpack = 0

    while pos + 8 < len(data):
        try:
            _hdr_crc = struct.unpack_from("<I", data, pos)[0]  # noqa: F841 (documents RAR5 header layout)
            pos += 4

            hdr_size, pos = _read_vint(data, pos)
            if hdr_size == 0: break
            hdr_end = pos + hdr_size
            if hdr_end > len(data): break

            hdr_type, pos = _read_vint(data, pos)
            hdr_flags, pos = _read_vint(data, pos)

            # Extra data present?
            extra_size = 0
            if hdr_flags & 0x0001:
                extra_size, pos = _read_vint(data, pos)

            # Data area present?
            data_size = 0
            if hdr_flags & 0x0002:
                data_size, pos = _read_vint(data, pos)

            # File header type = 2
            if hdr_type == 2:
                file_flags, pos = _read_vint(data, pos)
                unpack_sz, pos  = _read_vint(data, pos)
                pack_sz         = data_size

                total_pack   += pack_sz
                total_unpack += unpack_sz
                file_count   += 1

                ratio = unpack_sz / pack_sz if pack_sz > 0 else 0
                if pack_sz > 0 and ratio > policy["max_ratio"]:
                    result.add_flag(ThreatLevel.CRITICAL, "RATIO_EXCEEDED",
                        f"RAR5 entry ratio {ratio:.1f}:1 exceeds limit {policy['max_ratio']}:1")

                if total_unpack > policy["max_uncompressed"]:
                    result.add_flag(ThreatLevel.CRITICAL, "SIZE_EXCEEDED",
                        f"Cumulative {fmt_bytes(total_unpack)} exceeds limit")
                    break

            pos = hdr_end + data_size
        except (struct.error, IndexError):
            break

    return total_pack, total_unpack, file_count


def scan_rar(path: Path, policy: dict) -> FormatResult:
    t0     = time.perf_counter()
    result = FormatResult(path=str(path), fmt="rar")

    try:
        data = path.read_bytes()
    except OSError as e:
        result.add_flag(ThreatLevel.NONE, "IO_ERROR", str(e))
        return result

    file_size = len(data)

    if data.startswith(RAR5_MAGIC):
        result.fmt = "rar5"
        total_pack, total_unpack, count = _scan_rar5(data, policy, result)
    elif data.startswith(RAR4_MAGIC):
        result.fmt = "rar4"
        total_pack, total_unpack, count = _scan_rar4(data, policy, result)
    else:
        result.add_flag(ThreatLevel.NONE, "INVALID_RAR", "Bad RAR signature")
        return result

    result.total_compressed   = total_pack or file_size
    result.total_uncompressed = total_unpack
    result.entry_count        = count
    result.overall_ratio = (total_unpack / total_pack) if total_pack > 0 else 0

    if not result.is_threat and result.overall_ratio > 10:
        lv = ThreatLevel.MEDIUM if result.overall_ratio > 50 else ThreatLevel.LOW
        result.add_flag(lv, "HIGH_RATIO", f"Overall ratio {result.overall_ratio:.1f}:1")

    result.scan_time_ms = (time.perf_counter() - t0) * 1000
    return result
