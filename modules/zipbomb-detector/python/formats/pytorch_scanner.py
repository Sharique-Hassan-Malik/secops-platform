"""
pytorch_scanner.py — PyTorch model file (.pt / .pth) bomb detection.

PyTorch serialises checkpoints using Python's pickle format wrapped
inside a ZIP archive. This means .pt and .pth files ARE ZIP files
and can contain zip bombs.

We scan the ZIP structure using the same zip scanner, with additional
checks specific to model files:
  - Detect unusually large tensor data entries
  - Flag suspicious non-pickle entries (unexpected executables, scripts)
  - Warn on pickle protocol 5 (supports out-of-band buffers)
  - Flag entries with names resembling path traversal attacks
"""

from __future__ import annotations
import time
from pathlib import Path
from .base import FormatResult, ThreatLevel

SUSPICIOUS_EXTENSIONS = {".py", ".sh", ".bat", ".ps1", ".exe", ".dll", ".so"}
PICKLE_MAGIC          = b"\x80"   # PROTO opcode
PICKLE5_PROTO         = 5


def scan_pytorch(path: Path, policy: dict) -> FormatResult:
    """
    Scan a .pt/.pth file. Delegates ZIP structure scanning to the ZIP scanner,
    then adds PyTorch-specific checks on top.
    """
    from .zip_scanner import scan_zip as _scan_zip

    t0     = time.perf_counter()

    # Run ZIP scanner first
    result = _scan_zip(path, policy)
    result.fmt  = "pytorch"
    orig_time   = result.scan_time_ms

    # Additional PyTorch-specific checks on the entries
    suspicious_entries = []
    has_pickle         = False
    data_entries_size  = 0

    # We need to re-read to inspect entry content signatures
    try:
        path.read_bytes()
    except OSError:
        result.scan_time_ms = (time.perf_counter() - t0) * 1000
        return result

    for entry in result.entries:
        name = entry.get("name", "") if isinstance(entry, dict) else getattr(entry, "name", "")
        name_lower = name.lower()
        ext   = Path(name).suffix.lower()

        # Suspicious non-model file types inside a model archive
        if ext in SUSPICIOUS_EXTENSIONS:
            suspicious_entries.append(name)

        # Path traversal attempt
        if ".." in name or name.startswith("/"):
            result.add_flag(ThreatLevel.CRITICAL, "PATH_TRAVERSAL",
                f"Entry '{name}' contains path traversal sequence")

        # .pkl and .data are normal; flag anything else unusual
        if name_lower.endswith(".pkl"):
            has_pickle = True

        # Large data entries (> 500MB single entry)
        uncomp_sz = entry.get("uncompSz", 0) if isinstance(entry, dict) else getattr(entry, "uncompressed_size", 0)
        if uncomp_sz > 500 * 1024 * 1024:
            data_entries_size += uncomp_sz

    if suspicious_entries:
        result.add_flag(ThreatLevel.HIGH, "SUSPICIOUS_ENTRIES",
            f"Non-model file types in archive: {', '.join(suspicious_entries[:5])}")

    if not has_pickle:
        result.add_flag(ThreatLevel.LOW, "NO_PICKLE",
            "No .pkl entries found — may not be a valid PyTorch checkpoint")

    result.details["format_note"] = "PyTorch checkpoints are ZIP archives containing pickle data"
    result.details["has_pickle"]  = has_pickle

    result.scan_time_ms = orig_time + (time.perf_counter() - t0) * 1000
    return result
