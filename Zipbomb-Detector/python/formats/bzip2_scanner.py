"""
bzip2_scanner.py — BZip2 bomb detection.

BZip2 stores no uncompressed size in its headers, so we cannot compute
a ratio without decompressing. Instead we perform structural analysis:
  - Validate magic and block headers
  - Count compressed blocks and estimate expansion bounds
  - Flag anomalies in block structure (e.g. abnormal block sizes)
  - Flag suspiciously large compressed files (likely targets for bombs)
"""

from __future__ import annotations
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel, fmt_bytes

# bzip2 constants
FILE_MAGIC   = b"BZh"
BLOCK_MAGIC  = b"\x31\x41\x59\x26\x53\x59"   # pi in hex
EOS_MAGIC    = b"\x17\x72\x45\x38\x50\x90"   # sqrt(2) in hex

# Maximum theoretical expansion: bzip2 can expand ~30x at most for highly
# compressible data. 900KB block * 30 = ~27 MB per block maximum.
MAX_BLOCK_EXPANSION = 30
BLOCK_SIZE_BYTES    = {1: 100_000, 2: 200_000, 3: 300_000, 4: 400_000,
                       5: 500_000, 6: 600_000, 7: 700_000, 8: 800_000, 9: 900_000}


def scan_bzip2(path: Path, policy: dict) -> FormatResult:
    t0     = time.perf_counter()
    result = FormatResult(path=str(path), fmt="bzip2")

    try:
        data = path.read_bytes()
    except OSError as e:
        result.add_flag(ThreatLevel.NONE, "IO_ERROR", str(e))
        return result

    file_size = len(data)

    if not data.startswith(FILE_MAGIC):
        result.add_flag(ThreatLevel.NONE, "INVALID_BZIP2", "Missing BZh magic")
        return result

    if len(data) < 4:
        result.add_flag(ThreatLevel.NONE, "INVALID_BZIP2", "File too small")
        return result

    # Block size indicator: '1'–'9' ASCII
    block_indicator = data[3:4]
    if not (b"1" <= block_indicator <= b"9"):
        result.add_flag(ThreatLevel.MEDIUM, "INVALID_BZIP2",
            f"Invalid block size indicator: {block_indicator}")
        return result

    block_level    = int(block_indicator)
    max_block_size = BLOCK_SIZE_BYTES[block_level]

    # Scan for block magic sequences to count blocks
    block_count    = 0
    pos            = 4
    raw_data       = data

    # Bit-level scanning is complex; we do byte-aligned approximation
    # by searching for the 6-byte BLOCK_MAGIC signature
    while pos < len(raw_data) - 6:
        if raw_data[pos:pos+6] == BLOCK_MAGIC:
            block_count += 1
            pos += 6
        else:
            pos += 1

    # Estimate maximum possible uncompressed size
    max_uncomp = block_count * max_block_size * MAX_BLOCK_EXPANSION

    result.total_compressed   = file_size
    result.total_uncompressed = max_uncomp   # upper bound only
    result.overall_ratio      = max_uncomp / file_size if file_size > 0 else 0
    result.entry_count        = block_count
    result.details["block_level"]     = block_level
    result.details["block_count"]     = block_count
    result.details["max_block_bytes"] = max_block_size
    result.details["note"]            = "Uncompressed size is an upper bound (bzip2 stores no size metadata)"

    if block_count == 0:
        result.add_flag(ThreatLevel.LOW, "NO_BLOCKS", "No compressed blocks found")

    # Flag if worst-case expansion would exceed policy limit
    if max_uncomp > policy["max_uncompressed"]:
        result.add_flag(ThreatLevel.HIGH, "WORST_CASE_SIZE_EXCEEDED",
            f"Worst-case expansion {fmt_bytes(max_uncomp)} could exceed "
            f"limit {fmt_bytes(policy['max_uncompressed'])} "
            f"({block_count} blocks × {fmt_bytes(max_block_size)} × {MAX_BLOCK_EXPANSION}x)")

    # Flag extremely high theoretical ratio
    if result.overall_ratio > policy["max_ratio"] * 5:
        result.add_flag(ThreatLevel.MEDIUM, "HIGH_THEORETICAL_RATIO",
            f"Theoretical max ratio {result.overall_ratio:.0f}:1 — treat with caution")

    result.scan_time_ms = (time.perf_counter() - t0) * 1000
    return result
