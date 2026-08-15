"""
base.py — Shared types and utilities for all format scanners.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class ThreatLevel(IntEnum):
    NONE     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

    def __str__(self):
        return self.name


@dataclass
class ThreatFlag:
    level: ThreatLevel
    code: str
    description: str


@dataclass
class FormatResult:
    path:               str
    fmt:                str          # "zip", "gzip", "tar", "7z", etc.
    is_threat:          bool         = False
    threat_level:       ThreatLevel  = ThreatLevel.NONE
    total_compressed:   int          = 0
    total_uncompressed: int          = 0
    overall_ratio:      float        = 0.0
    entry_count:        int          = 0
    has_overlaps:       bool         = False
    scan_time_ms:       float        = 0.0
    flags:              list[ThreatFlag] = field(default_factory=list)
    details:            dict         = field(default_factory=dict)

    def add_flag(self, level: ThreatLevel, code: str, desc: str):
        self.flags.append(ThreatFlag(level, code, desc))
        if level > self.threat_level:
            self.threat_level = level
        self.is_threat = self.threat_level > ThreatLevel.NONE

    def to_dict(self) -> dict:
        return {
            "path":               self.path,
            "format":             self.fmt,
            "is_threat":          self.is_threat,
            "threat_level":       str(self.threat_level),
            "total_compressed":   self.total_compressed,
            "total_uncompressed": self.total_uncompressed,
            "overall_ratio":      round(self.overall_ratio, 4),
            "entry_count":        self.entry_count,
            "has_overlaps":       self.has_overlaps,
            "scan_time_ms":       round(self.scan_time_ms, 2),
            "flags": [
                {"level": str(f.level), "code": f.code, "description": f.description}
                for f in self.flags
            ],
            "details": self.details,
        }

    def summary(self) -> str:
        lines = [
            f"  Format     : {self.fmt.upper()}",
            f"  File       : {self.path}",
            f"  Threat     : {self.threat_level}",
            f"  Compressed : {fmt_bytes(self.total_compressed)}",
            f"  Expanded   : {fmt_bytes(self.total_uncompressed)}",
            f"  Ratio      : {self.overall_ratio:.2f} : 1",
            f"  Entries    : {self.entry_count}",
            f"  Scan time  : {self.scan_time_ms:.2f} ms",
        ]
        for f in self.flags:
            lines.append(f"  [{f.level}] {f.code}: {f.description}")
        return "\n".join(lines) + "\n"


def fmt_bytes(n: int) -> str:
    for unit, threshold in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= threshold:
            return f"{n/threshold:.2f} {unit}"
    return f"{n} bytes"


# Magic byte signatures
MAGIC = {
    b"\x50\x4b\x03\x04":           "zip",
    b"\x50\x4b\x05\x06":           "zip",   # empty zip
    b"\x1f\x8b":                   "gzip",
    b"BZh":                        "bzip2",
    b"\x37\x7a\xbc\xaf\x27\x1c":  "7z",
    b"\xfd\x37\x7a\x58\x5a\x00":  "xz",
    b"Rar!\x1a\x07\x00":          "rar4",
    b"Rar!\x1a\x07\x01\x00":      "rar5",
    b"\x28\xb5\x2f\xfd":          "zstd",
}

TAR_MAGIC_OFFSET = 257   # "ustar" lives at byte 257 in a TAR block

# Extensions that map to a format regardless of magic
EXT_MAP = {
    ".tar":   "tar",
    ".gz":    "gzip",
    ".tgz":   "tar.gz",
    ".bz2":   "bzip2",
    ".tbz2":  "tar.bzip2",
    ".7z":    "7z",
    ".xz":    "xz",
    ".rar":   "rar",
    ".zst":   "zstd",
    ".zstd":  "zstd",
    ".pt":    "pytorch",
    ".pth":   "pytorch",
    ".zip":   "zip",
    ".jar":   "zip",
    ".war":   "zip",
    ".apk":   "zip",
    ".docx":  "zip",
    ".xlsx":  "zip",
    ".pptx":  "zip",
}


def detect_format(path: Path) -> str:
    """Detect archive format by magic bytes first, extension as fallback."""
    try:
        data = path.read_bytes()[:16]
    except OSError:
        return "unknown"

    for magic, fmt in MAGIC.items():
        if data.startswith(magic):
            return fmt

    # TAR: check "ustar" at offset 257
    try:
        raw = path.open("rb").read(512)
        if len(raw) >= 262 and raw[257:262] in (b"ustar", b"ustar"):
            return "tar"
    except OSError:
        pass

    # Extension fallback
    suffix = path.suffix.lower()
    if suffix in EXT_MAP:
        return EXT_MAP[suffix]

    # Handle compound extensions like .tar.gz
    suffixes = "".join(path.suffixes[-2:]).lower()
    if ".tar.gz" in suffixes or ".tgz" in suffixes:
        return "tar.gz"
    if ".tar.bz2" in suffixes or ".tbz2" in suffixes:
        return "tar.bzip2"
    if ".tar.xz" in suffixes:
        return "tar.xz"

    return "unknown"
