"""
gzip_scanner.py — GZip bomb detection.

GZip stores the uncompressed size (mod 2^32) in the last 4 bytes (ISIZE).
For single-member gzip files we can compute the ratio directly.
Multi-member gzip files get summed across all members.
"""

from __future__ import annotations
import struct
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel, fmt_bytes


# GZip flags
FTEXT    = 1 << 0
FHCRC    = 1 << 1
FEXTRA   = 1 << 2
FNAME    = 1 << 3
FCOMMENT = 1 << 4


def _parse_member(data: bytes, offset: int) -> tuple[int, int, int] | None:
    """
    Parse one gzip member starting at offset.
    Returns (compressed_size, uncompressed_size, next_offset) or None.
    """
    if offset + 18 > len(data):
        return None

    if data[offset:offset+2] != b"\x1f\x8b":
        return None

    method = data[offset+2]
    flags  = data[offset+3]
    if method != 8:       # only deflate supported
        return None

    pos = offset + 10    # skip fixed 10-byte header

    if flags & FEXTRA:
        if pos + 2 > len(data): return None
        xlen = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + xlen

    if flags & FNAME:
        while pos < len(data) and data[pos] != 0:
            pos += 1
        pos += 1          # consume null terminator

    if flags & FCOMMENT:
        while pos < len(data) and data[pos] != 0:
            pos += 1
        pos += 1

    if flags & FHCRC:
        pos += 2

    # compressed data runs until last 8 bytes of member (CRC32 + ISIZE)
    # scan forward to find the next member or EOF
    # ISIZE is the last 4 bytes before the next member header
    # We do a simple scan: find the end of this member by looking for
    # the next 0x1f 0x8b magic or file end
    next_member = len(data)
    for i in range(pos, len(data) - 1):
        if data[i] == 0x1f and data[i+1] == 0x8b:
            next_member = i
            break

    if next_member - 8 < pos:
        return None

    isize = struct.unpack_from("<I", data, next_member - 4)[0]   # mod 2^32
    comp_sz   = next_member - offset
    uncomp_sz = isize

    return comp_sz, uncomp_sz, next_member


def scan_gzip(path: Path, policy: dict) -> FormatResult:
    t0     = time.perf_counter()
    result = FormatResult(path=str(path), fmt="gzip")

    try:
        data = path.read_bytes()
    except OSError as e:
        result.add_flag(ThreatLevel.NONE, "IO_ERROR", str(e))
        return result

    file_size  = len(data)
    offset     = 0
    members    = 0
    total_comp = 0
    total_uncomp = 0

    while offset < len(data):
        parsed = _parse_member(data, offset)
        if parsed is None:
            break
        comp_sz, uncomp_sz, next_offset = parsed
        members    += 1
        total_comp += comp_sz

        # ISIZE wraps at 2^32 — flag ambiguity for large members
        if uncomp_sz == 0 and comp_sz > 1024:
            # Could be exactly 4GB multiple — flag as suspicious
            result.add_flag(ThreatLevel.MEDIUM, "ISIZE_ZERO",
                f"Member {members}: ISIZE=0, may indicate >4 GB uncompressed content")
        else:
            ratio = uncomp_sz / comp_sz if comp_sz > 0 else 0
            if ratio > policy["max_ratio"]:
                result.add_flag(ThreatLevel.CRITICAL, "RATIO_EXCEEDED",
                    f"Member {members}: {ratio:.1f}:1 exceeds limit {policy['max_ratio']}:1")
            total_uncomp += uncomp_sz

        if total_uncomp > policy["max_uncompressed"]:
            result.add_flag(ThreatLevel.CRITICAL, "SIZE_EXCEEDED",
                f"Cumulative declared size {fmt_bytes(total_uncomp)} exceeds limit")
            break

        if next_offset == offset:
            break
        offset = next_offset

    result.total_compressed   = file_size
    result.total_uncompressed = total_uncomp
    result.overall_ratio      = total_uncomp / file_size if file_size > 0 else 0
    result.entry_count        = members
    result.details["members"] = members

    if not result.is_threat and result.overall_ratio > 10:
        lv = ThreatLevel.MEDIUM if result.overall_ratio > 50 else ThreatLevel.LOW
        result.add_flag(lv, "HIGH_RATIO", f"Overall ratio {result.overall_ratio:.1f}:1")

    if members == 0:
        result.add_flag(ThreatLevel.NONE, "INVALID_GZIP", "No valid gzip members found")

    result.scan_time_ms = (time.perf_counter() - t0) * 1000
    return result
