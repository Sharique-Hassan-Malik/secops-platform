"""
xz_scanner.py — XZ / LZMA2 bomb detection.

XZ format:
  Stream header: 6-byte magic + 2-byte stream flags + 4-byte CRC32
  Each block has a header with uncompressed_size and compressed_size
  (both optional but usually present).
  Stream footer: 4-byte CRC32 + 4-byte backward_size + 2-byte stream_flags + 6-byte magic

We scan block headers to extract declared sizes where available.
"""

from __future__ import annotations
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel, fmt_bytes

XZ_MAGIC        = b"\xfd7zXZ\x00"
XZ_FOOTER_MAGIC = b"YZ"
BLOCK_HEADER_MIN = 4   # bytes


def _decode_multibyte(data: bytes, pos: int) -> tuple[int, int]:
    """Decode XZ multibyte (vli) integer. Returns (value, consumed_bytes)."""
    value = 0
    shift = 0
    start = pos
    while pos < len(data):
        b = data[pos]; pos += 1
        value |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            break
        if shift >= 63:
            break
    return value, pos - start


def scan_xz(path: Path, policy: dict) -> FormatResult:
    t0     = time.perf_counter()
    result = FormatResult(path=str(path), fmt="xz")

    try:
        data = path.read_bytes()
    except OSError as e:
        result.add_flag(ThreatLevel.NONE, "IO_ERROR", str(e))
        return result

    file_size = len(data)

    if not data.startswith(XZ_MAGIC):
        result.add_flag(ThreatLevel.NONE, "INVALID_XZ", "Bad XZ magic")
        return result

    if file_size < 32:
        result.add_flag(ThreatLevel.NONE, "INVALID_XZ", "File too small")
        return result

    # Read stream footer to get index size
    if data[-2:] != XZ_FOOTER_MAGIC:
        result.add_flag(ThreatLevel.LOW, "TRUNCATED_XZ",
            "Missing XZ stream footer magic — file may be truncated")

    # Scan blocks starting at byte 12 (after stream header)
    pos          = 12
    blocks       = 0
    total_comp   = 0
    total_uncomp = 0

    while pos < file_size - 12:
        if pos + 4 > file_size: break

        # Block header size is encoded in first byte (0 = index, non-0 = block)
        bh_size_field = data[pos]
        if bh_size_field == 0:
            # Index record — end of blocks
            break

        bh_size = (bh_size_field + 1) * 4
        if pos + bh_size > file_size: break

        block_flags = data[pos + 1]
        has_comp_sz   = bool(block_flags & 0x40)
        has_uncomp_sz = bool(block_flags & 0x80)

        bpos = pos + 2   # skip header_size and block_flags

        comp_sz   = 0
        uncomp_sz = 0

        if has_comp_sz:
            v, consumed = _decode_multibyte(data, bpos)
            comp_sz = v; bpos += consumed

        if has_uncomp_sz:
            v, consumed = _decode_multibyte(data, bpos)
            uncomp_sz = v; bpos += consumed

        blocks       += 1
        total_comp   += comp_sz
        total_uncomp += uncomp_sz

        ratio = uncomp_sz / comp_sz if comp_sz > 0 else 0
        if comp_sz > 0 and ratio > policy["max_ratio"]:
            result.add_flag(ThreatLevel.CRITICAL, "RATIO_EXCEEDED",
                f"Block {blocks}: ratio {ratio:.1f}:1 exceeds limit {policy['max_ratio']}:1")

        if total_uncomp > policy["max_uncompressed"]:
            result.add_flag(ThreatLevel.CRITICAL, "SIZE_EXCEEDED",
                f"Cumulative {fmt_bytes(total_uncomp)} exceeds limit")
            break

        # Advance past block (header + compressed data padded to 4 bytes)
        actual_comp = comp_sz if comp_sz > 0 else (bh_size - 4)
        padded      = ((actual_comp + 3) // 4) * 4
        pos        += bh_size + padded + 4   # +4 for block check (CRC32/CRC64)

        if comp_sz == 0:
            break   # unknown block size, stop scanning

    result.total_compressed   = file_size
    result.total_uncompressed = total_uncomp
    result.entry_count        = blocks
    result.overall_ratio      = total_uncomp / file_size if file_size > 0 else 0
    result.details["xz_blocks"] = blocks

    if not result.is_threat and result.overall_ratio > 10:
        lv = ThreatLevel.MEDIUM if result.overall_ratio > 50 else ThreatLevel.LOW
        result.add_flag(lv, "HIGH_RATIO", f"Overall ratio {result.overall_ratio:.1f}:1")

    if blocks == 0:
        result.add_flag(ThreatLevel.NONE, "NO_BLOCKS",
            "No XZ blocks parsed — may be index-only or malformed")

    result.scan_time_ms = (time.perf_counter() - t0) * 1000
    return result
