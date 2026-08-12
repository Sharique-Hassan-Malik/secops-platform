"""
sevenz_scanner.py — 7-Zip bomb detection.

7z file layout:
  [0..5]   Signature  "7z\xbc\xaf\x27\x1c"
  [6..7]   ArchiveVersion (major, minor)
  [8..11]  StartHeaderCRC
  [12..19] NextHeaderOffset  (uint64 LE)
  [20..27] NextHeaderSize    (uint64 LE)
  [28..31] NextHeaderCRC

The "next header" (end header) contains the full archive metadata
including packed and unpacked sizes for all streams.

We parse the end header to extract PackSize and UnpackSize values
which allow us to compute the compression ratio without decompression.
"""

from __future__ import annotations
import struct
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel, fmt_bytes

SIGNATURE     = b"\x37\x7a\xbc\xaf\x27\x1c"
HEADER_SIZE   = 32   # fixed signature+version+CRC+next-header-info block

# 7z property IDs relevant to us
kEnd            = 0x00
kHeader         = 0x01
kArchiveProperties = 0x02
kAdditionalStreamsInfo = 0x03
kMainStreamsInfo = 0x04
kFilesInfo      = 0x05
kPackInfo       = 0x06
kUnpackInfo     = 0x07
kSubStreamsInfo  = 0x08
kSize           = 0x09
kCRC            = 0x0a
kFolder         = 0x0b
kCodersUnpackSize = 0x0c
kNumUnpackStream = 0x0d
kEmptyStream    = 0x0e
kEmptyFile      = 0x0f
kAnti           = 0x10
kName           = 0x11
kCreationTime   = 0x12
kLastAccessTime = 0x13
kLastWriteTime  = 0x14
kWinAttrib      = 0x15
kComment        = 0x16
kEncodedHeader  = 0x17
kStartPos       = 0x18
kDummy          = 0x19


class _Reader:
    """Minimal byte reader for 7z header parsing."""
    def __init__(self, data: bytes):
        self.data = data
        self.pos  = 0

    def byte(self) -> int:
        if self.pos >= len(self.data): return 0
        v = self.data[self.pos]; self.pos += 1; return v

    def u64(self) -> int:
        if self.pos + 8 > len(self.data): return 0
        v = struct.unpack_from("<Q", self.data, self.pos)[0]
        self.pos += 8; return v

    def u32(self) -> int:
        if self.pos + 4 > len(self.data): return 0
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4; return v

    def read_number(self) -> int:
        """Read 7z variable-length number."""
        first = self.byte()
        if first < 0x80:
            return first
        mask  = 0x40
        value = 0
        for i in range(8):
            if not (first & mask):
                hi = first & (mask - 1)
                value |= hi << (8 * i)
                break
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def skip(self, n: int):
        self.pos += n

    def remaining(self) -> int:
        return len(self.data) - self.pos


def _extract_sizes(header_data: bytes) -> tuple[list[int], list[int]]:
    """
    Walk 7z header blocks to find PackInfo and UnpackInfo sizes.
    Returns (pack_sizes, unpack_sizes).
    """
    r = _Reader(header_data)
    pack_sizes   = []
    unpack_sizes = []

    def read_pack_info():
        r.read_number()        # PackPos
        num_pack = r.read_number()
        while r.remaining() > 0:
            pid = r.byte()
            if pid == kEnd: break
            if pid == kSize:
                for _ in range(num_pack):
                    pack_sizes.append(r.read_number())
            else:
                # unknown property — try to skip (best effort)
                size = r.read_number()
                r.skip(size)

    def read_unpack_info():
        while r.remaining() > 0:
            pid = r.byte()
            if pid == kEnd: break
            if pid == kFolder:
                num_folders = r.read_number()
                external    = r.byte()
                if external == 0:
                    for _ in range(num_folders):
                        num_coders = r.read_number()
                        for _ in range(num_coders):
                            codec_id_size = r.byte() & 0x0f
                            r.skip(codec_id_size)   # codec ID
                            # skip flags/props
                else:
                    r.read_number()   # data stream index
            elif pid == kCodersUnpackSize:
                # We'll get sizes from substream info instead
                pass
            else:
                try:
                    size = r.read_number()
                    r.skip(size)
                except Exception:
                    break

    # Walk top-level
    while r.remaining() > 0:
        pid = r.byte()
        if pid == kEnd: break
        if pid == kHeader or pid == kMainStreamsInfo or pid == kAdditionalStreamsInfo:
            # recurse into subblock
            while r.remaining() > 0:
                sub = r.byte()
                if sub == kEnd: break
                if sub == kPackInfo:
                    read_pack_info()
                elif sub == kUnpackInfo:
                    read_unpack_info()
                elif sub == kSubStreamsInfo:
                    while r.remaining() > 0:
                        s2 = r.byte()
                        if s2 == kEnd: break
                        if s2 == kSize:
                            while r.remaining() > 0:
                                sz = r.read_number()
                                if sz == 0: break
                                unpack_sizes.append(sz)
                        else:
                            try:
                                size = r.read_number()
                                r.skip(size)
                            except Exception:
                                break
        elif pid == kEncodedHeader:
            pass  # encoded header — we skip, cannot parse without decompression
        else:
            try:
                size = r.read_number()
                r.skip(size)
            except Exception:
                break

    return pack_sizes, unpack_sizes


def scan_7z(path: Path, policy: dict) -> FormatResult:
    t0     = time.perf_counter()
    result = FormatResult(path=str(path), fmt="7z")

    try:
        data = path.read_bytes()
    except OSError as e:
        result.add_flag(ThreatLevel.NONE, "IO_ERROR", str(e))
        return result

    file_size = len(data)

    if not data.startswith(SIGNATURE):
        result.add_flag(ThreatLevel.NONE, "INVALID_7Z", "Bad 7z signature")
        return result

    if file_size < HEADER_SIZE:
        result.add_flag(ThreatLevel.NONE, "INVALID_7Z", "File too small for 7z header")
        return result

    # Parse the start header
    next_hdr_offset = struct.unpack_from("<Q", data, 12)[0]
    next_hdr_size   = struct.unpack_from("<Q", data, 20)[0]

    hdr_start = HEADER_SIZE + next_hdr_offset
    hdr_end   = hdr_start + next_hdr_size

    if hdr_end > file_size:
        result.add_flag(ThreatLevel.MEDIUM, "TRUNCATED_HEADER",
            f"7z end header at {hdr_start}+{next_hdr_size} exceeds file size {file_size}")
        result.scan_time_ms = (time.perf_counter() - t0) * 1000
        return result

    header_data = data[hdr_start:hdr_end]

    # Best-effort size extraction
    try:
        pack_sizes, unpack_sizes = _extract_sizes(header_data)
    except Exception as e:
        result.add_flag(ThreatLevel.LOW, "PARSE_ERROR",
            f"Could not fully parse 7z header: {e}. Using file size as lower bound.")
        pack_sizes, unpack_sizes = [], []

    total_pack   = sum(pack_sizes)   if pack_sizes   else file_size
    total_unpack = sum(unpack_sizes) if unpack_sizes else 0

    result.total_compressed   = total_pack
    result.total_uncompressed = total_unpack
    result.details["pack_streams"]   = len(pack_sizes)
    result.details["unpack_streams"] = len(unpack_sizes)
    result.details["header_size"]    = next_hdr_size

    if total_pack > 0 and total_unpack > 0:
        result.overall_ratio = total_unpack / total_pack

        if result.overall_ratio > policy["max_ratio"]:
            result.add_flag(ThreatLevel.CRITICAL, "RATIO_EXCEEDED",
                f"7z ratio {result.overall_ratio:.1f}:1 exceeds limit {policy['max_ratio']}:1")

        if total_unpack > policy["max_uncompressed"]:
            result.add_flag(ThreatLevel.CRITICAL, "SIZE_EXCEEDED",
                f"Declared unpack size {fmt_bytes(total_unpack)} exceeds limit "
                f"{fmt_bytes(policy['max_uncompressed'])}")

        if not result.is_threat and result.overall_ratio > 10:
            lv = ThreatLevel.MEDIUM if result.overall_ratio > 50 else ThreatLevel.LOW
            result.add_flag(lv, "HIGH_RATIO", f"Overall ratio {result.overall_ratio:.1f}:1")
    else:
        result.details["note"] = "Could not extract stream sizes — encoded/encrypted header"

    result.scan_time_ms = (time.perf_counter() - t0) * 1000
    return result
