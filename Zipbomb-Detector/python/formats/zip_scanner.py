"""
zip_scanner.py — ZIP bomb detection (moved from main module, format-package version).
Handles: .zip, .jar, .war, .apk, .docx, .xlsx, .pptx and any ZIP-based format.
"""

from __future__ import annotations
import struct
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel, fmt_bytes

SIG_CDIR = 0x02014b50
SIG_EOCD = 0x06054b50

ARCHIVE_EXTS = {".zip", ".gz", ".bz2", ".tar", ".7z", ".rar", ".xz", ".zst"}


def _find_eocd(data: bytes):
    limit = max(0, len(data) - 65_557)
    for pos in range(len(data) - 22, limit - 1, -1):
        if struct.unpack_from("<I", data, pos)[0] == SIG_EOCD:
            count  = struct.unpack_from("<H", data, pos + 10)[0]
            offset = struct.unpack_from("<I", data, pos + 16)[0]
            return count, offset
    return None, None


def _detect_overlaps(ranges: list[tuple[int,int]]) -> bool:
    if len(ranges) < 2: return False
    s = sorted(ranges)
    return any(s[i][1] > s[i+1][0] for i in range(len(s)-1))


def scan_zip(path: Path, policy: dict) -> FormatResult:
    t0     = time.perf_counter()
    result = FormatResult(path=str(path), fmt="zip")

    try:
        data = path.read_bytes()
    except OSError as e:
        result.add_flag(ThreatLevel.NONE, "IO_ERROR", str(e))
        return result

    count, cd_offset = _find_eocd(data)
    if count is None:
        result.add_flag(ThreatLevel.NONE, "INVALID_ZIP", "No EOCD record")
        result.scan_time_ms = (time.perf_counter() - t0) * 1000
        return result

    if count > policy["max_entries"]:
        result.add_flag(ThreatLevel.HIGH, "ENTRY_FLOOD",
            f"{count} entries exceeds limit {policy['max_entries']}")
        result.entry_count = count
        result.scan_time_ms = (time.perf_counter() - t0) * 1000
        return result

    pos          = cd_offset
    ranges       = []
    total_comp   = 0
    total_uncomp = 0
    entries      = []

    for i in range(count):
        if pos + 46 > len(data): break
        if struct.unpack_from("<I", data, pos)[0] != SIG_CDIR:
            result.add_flag(ThreatLevel.MEDIUM, "HEADER_CORRUPT",
                f"Bad central dir sig at entry {i}")
            break

        method    = struct.unpack_from("<H", data, pos + 10)[0]
        comp_sz   = struct.unpack_from("<I", data, pos + 20)[0]
        uncomp_sz = struct.unpack_from("<I", data, pos + 24)[0]
        fn_len    = struct.unpack_from("<H", data, pos + 28)[0]
        ex_len    = struct.unpack_from("<H", data, pos + 30)[0]
        cm_len    = struct.unpack_from("<H", data, pos + 32)[0]
        lh_offset = struct.unpack_from("<I", data, pos + 42)[0]

        name_bytes = data[pos+46 : pos+46+fn_len]
        name = name_bytes.decode("utf-8", errors="replace")

        ratio = uncomp_sz / comp_sz if comp_sz > 0 else 0
        ext   = Path(name).suffix.lower()

        entries.append({
            "name": name, "compSz": comp_sz, "uncompSz": uncomp_sz,
            "ratio": ratio, "method": method, "lhOffset": lh_offset,
            "isArchive": ext in ARCHIVE_EXTS,
        })

        if comp_sz > 0 and ratio > policy["max_ratio"]:
            result.add_flag(ThreatLevel.CRITICAL, "RATIO_EXCEEDED",
                f"Entry '{name}': {ratio:.1f}:1 exceeds limit {policy['max_ratio']}:1")

        total_comp   += comp_sz
        total_uncomp += uncomp_sz

        if total_uncomp > policy["max_uncompressed"]:
            result.add_flag(ThreatLevel.CRITICAL, "SIZE_EXCEEDED",
                f"Cumulative {fmt_bytes(total_uncomp)} exceeds limit")
            break

        ranges.append((lh_offset, lh_offset + 30 + fn_len + ex_len + comp_sz))
        pos += 46 + fn_len + ex_len + cm_len

    result.entries            = entries
    result.entry_count        = len(entries)
    result.total_compressed   = total_comp
    result.total_uncompressed = total_uncomp
    result.overall_ratio      = total_uncomp / total_comp if total_comp > 0 else 0

    if policy.get("check_overlaps", True) and _detect_overlaps(ranges):
        result.has_overlaps = True
        result.add_flag(ThreatLevel.CRITICAL, "OVERLAPPING_DATA",
            "Data regions overlap — Fifield-style non-recursive zip bomb")

    if not result.is_threat and result.overall_ratio > 10:
        lv = ThreatLevel.MEDIUM if result.overall_ratio > 50 else ThreatLevel.LOW
        result.add_flag(lv, "HIGH_RATIO", f"Overall ratio {result.overall_ratio:.1f}:1")

    result.scan_time_ms = (time.perf_counter() - t0) * 1000
    return result
