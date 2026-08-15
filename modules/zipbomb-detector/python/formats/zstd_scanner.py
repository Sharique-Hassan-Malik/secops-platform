"""
zstd_scanner.py — Zstandard (.zst / .zstd) bomb detection.

Zstandard frame format:
  Magic:          0xFD2FB528 (little-endian) = bytes 28 B5 2F FD
  Frame header:   FHD byte + optional fields (window descriptor,
                  dictionary ID, content size)
  Content size:   encoded in FHD[7:5] bits, 1/2/4/8 bytes

We read the content size field from each frame header to know the
declared uncompressed size without decompressing anything.

Skippable frames (magic 0x184D2A50–0x184D2A5F) are also handled.
"""

from __future__ import annotations
import struct
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel, fmt_bytes

ZSTD_MAGIC         = b"\x28\xb5\x2f\xfd"
ZSTD_MAGIC_U32     = 0xFD2FB528
SKIPPABLE_MAGIC_LO = 0x184D2A50
SKIPPABLE_MAGIC_HI = 0x184D2A5F


def _read_frame(data: bytes, pos: int) -> tuple[int, int, int] | None:
    """
    Parse one Zstandard frame starting at pos.
    Returns (compressed_size, uncompressed_size, next_pos) or None.
    compressed_size is approximate (frame header + data until next frame).
    """
    if pos + 4 > len(data): return None
    magic = struct.unpack_from("<I", data, pos)[0]

    # Skippable frame — skip it
    if SKIPPABLE_MAGIC_LO <= magic <= SKIPPABLE_MAGIC_HI:
        if pos + 8 > len(data): return None
        skip_size = struct.unpack_from("<I", data, pos + 4)[0]
        return 0, 0, pos + 8 + skip_size

    if magic != ZSTD_MAGIC_U32: return None

    if pos + 6 > len(data): return None
    fhd = data[pos + 4]    # Frame Header Descriptor

    single_segment = bool(fhd & 0x20)
    content_size_flag = (fhd >> 6) & 0x3
    has_checksum  = bool(fhd & 0x04)   # noqa: F841 (documents Zstd frame header)
    dict_id_flag  = fhd & 0x03

    header_pos = pos + 5   # after magic + FHD

    # Window descriptor (absent if single_segment)
    if not single_segment:
        header_pos += 1

    # Dictionary ID
    dict_id_sizes = [0, 1, 2, 4]
    header_pos += dict_id_sizes[dict_id_flag]

    # Content size
    content_size = 0
    if content_size_flag == 0:
        if single_segment:
            if header_pos < len(data):
                content_size = data[header_pos]
                header_pos += 1
    elif content_size_flag == 1:
        if header_pos + 2 <= len(data):
            content_size = struct.unpack_from("<H", data, header_pos)[0] + 256
            header_pos += 2
    elif content_size_flag == 2:
        if header_pos + 4 <= len(data):
            content_size = struct.unpack_from("<I", data, header_pos)[0]
            header_pos += 4
    elif content_size_flag == 3:
        if header_pos + 8 <= len(data):
            content_size = struct.unpack_from("<Q", data, header_pos)[0]
            header_pos += 8

    # Find next frame to determine this frame's compressed size
    next_frame = len(data)
    for i in range(header_pos, len(data) - 3):
        m = struct.unpack_from("<I", data, i)[0]
        if m == ZSTD_MAGIC_U32 or (SKIPPABLE_MAGIC_LO <= m <= SKIPPABLE_MAGIC_HI):
            next_frame = i
            break

    comp_size = next_frame - pos
    return comp_size, content_size, next_frame


def scan_zstd(path: Path, policy: dict) -> FormatResult:
    t0     = time.perf_counter()
    result = FormatResult(path=str(path), fmt="zstd")

    try:
        data = path.read_bytes()
    except OSError as e:
        result.add_flag(ThreatLevel.NONE, "IO_ERROR", str(e))
        return result

    if not data.startswith(ZSTD_MAGIC):
        result.add_flag(ThreatLevel.NONE, "INVALID_ZSTD", "Bad Zstandard magic")
        return result

    file_size    = len(data)
    pos          = 0
    frames       = 0
    total_comp   = 0
    total_uncomp = 0

    while pos < file_size:
        parsed = _read_frame(data, pos)
        if parsed is None: break

        comp_sz, uncomp_sz, next_pos = parsed

        if comp_sz > 0 or uncomp_sz > 0:
            frames       += 1
            total_comp   += comp_sz
            total_uncomp += uncomp_sz

            if comp_sz > 0 and uncomp_sz > 0:
                ratio = uncomp_sz / comp_sz
                if ratio > policy["max_ratio"]:
                    result.add_flag(ThreatLevel.CRITICAL, "RATIO_EXCEEDED",
                        f"Frame {frames}: {ratio:.1f}:1 exceeds limit {policy['max_ratio']}:1")

            if total_uncomp > policy["max_uncompressed"]:
                result.add_flag(ThreatLevel.CRITICAL, "SIZE_EXCEEDED",
                    f"Cumulative {fmt_bytes(total_uncomp)} exceeds limit")
                break

        if next_pos <= pos: break
        pos = next_pos

    result.total_compressed   = total_comp or file_size
    result.total_uncompressed = total_uncomp
    result.entry_count        = frames
    result.overall_ratio      = (total_uncomp / total_comp) if total_comp > 0 else 0
    result.details["zstd_frames"] = frames

    if not result.is_threat and result.overall_ratio > 10:
        lv = ThreatLevel.MEDIUM if result.overall_ratio > 50 else ThreatLevel.LOW
        result.add_flag(lv, "HIGH_RATIO", f"Overall ratio {result.overall_ratio:.1f}:1")

    result.scan_time_ms = (time.perf_counter() - t0) * 1000
    return result
