"""
tar_scanner.py — TAR archive bomb detection.

TAR format uses 512-byte blocks. Each file entry has a header block
followed by data blocks. The header stores the file size in octal ASCII.
We walk all headers, sum declared sizes, and check for anomalies.
Handles POSIX ustar, GNU tar, and old-style UNIX tar.
"""

from __future__ import annotations
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel, fmt_bytes

BLOCK_SIZE  = 512
HEADER_SIZE = 512


def _read_octal(b: bytes) -> int:
    """Read a null/space-terminated octal field from a TAR header."""
    try:
        return int(b.strip(b"\x00 ").decode("ascii"), 8)
    except (ValueError, UnicodeDecodeError):
        return 0


def _checksum_valid(block: bytes) -> bool:
    """Verify TAR header checksum."""
    if len(block) < 512:
        return False
    stored = _read_octal(block[148:156])
    # Compute checksum with checksum field treated as spaces
    calc = sum(block[:148]) + sum(b" " * 8) + sum(block[156:])
    return stored == calc or stored == (calc & 0o777777)


def scan_tar(path: Path, policy: dict) -> FormatResult:
    t0     = time.perf_counter()
    result = FormatResult(path=str(path), fmt="tar")

    try:
        f = open(path, "rb")
    except OSError as e:
        result.add_flag(ThreatLevel.NONE, "IO_ERROR", str(e))
        return result

    file_size    = path.stat().st_size
    entries      = 0
    total_size   = 0
    consecutive_zero = 0

    try:
        while True:
            block = f.read(BLOCK_SIZE)
            if len(block) < BLOCK_SIZE:
                break

            # Two consecutive zero blocks = end of archive
            if block == b"\x00" * BLOCK_SIZE:
                consecutive_zero += 1
                if consecutive_zero >= 2:
                    break
                continue
            consecutive_zero = 0

            if not _checksum_valid(block):
                result.add_flag(ThreatLevel.LOW, "CHECKSUM_MISMATCH",
                    f"Invalid checksum at entry {entries} — possibly corrupt or not a TAR")
                break

            # File size is at offset 124, 12 bytes, octal ASCII
            size       = _read_octal(block[124:136])
            typeflag   = chr(block[156]) if block[156] != 0 else "0"
            name_raw   = block[0:100].rstrip(b"\x00").decode("utf-8", errors="replace")
            prefix_raw = block[345:500].rstrip(b"\x00").decode("utf-8", errors="replace")
            name = (prefix_raw + "/" + name_raw).lstrip("/") if prefix_raw else name_raw

            # Skip non-regular-file entries for size accounting
            if typeflag in ("0", "\x00", "7"):
                total_size += size
                entries    += 1

                if total_size > policy["max_uncompressed"]:
                    result.add_flag(ThreatLevel.CRITICAL, "SIZE_EXCEEDED",
                        f"Cumulative TAR content {fmt_bytes(total_size)} exceeds "
                        f"limit {fmt_bytes(policy['max_uncompressed'])}")
                    break

                # Individual entry suspiciously large
                if size > 1 * 1024**3:   # > 1 GB single entry
                    result.add_flag(ThreatLevel.HIGH, "LARGE_ENTRY",
                        f"Entry '{name}': {fmt_bytes(size)}")

            if entries > policy["max_entries"]:
                result.add_flag(ThreatLevel.HIGH, "ENTRY_FLOOD",
                    f"{entries} entries exceeds limit {policy['max_entries']}")
                break

            # Skip data blocks
            data_blocks = (size + BLOCK_SIZE - 1) // BLOCK_SIZE
            f.seek(data_blocks * BLOCK_SIZE, 1)
    finally:
        f.close()

    result.total_compressed   = file_size
    result.total_uncompressed = total_size
    result.overall_ratio      = total_size / file_size if file_size > 0 else 0
    result.entry_count        = entries
    result.details["tar_entries"] = entries

    if not result.is_threat and result.overall_ratio > 10:
        lv = ThreatLevel.MEDIUM if result.overall_ratio > 50 else ThreatLevel.LOW
        result.add_flag(lv, "HIGH_RATIO", f"Overall ratio {result.overall_ratio:.1f}:1")

    result.scan_time_ms = (time.perf_counter() - t0) * 1000
    return result
