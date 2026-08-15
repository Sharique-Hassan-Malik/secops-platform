"""
formats — Multi-format archive bomb detection package.

Supported formats:
  zip, jar, war, apk, docx, xlsx, pptx  — ZIP-based
  gzip (.gz)
  bzip2 (.bz2)
  tar (.tar, .tar.gz, .tgz, .tar.bz2, .tbz2, .tar.xz)
  7z (.7z)
  xz (.xz)
  rar (.rar)  — RAR4 and RAR5
  zstd (.zst, .zstd)
  pytorch (.pt, .pth)  — PyTorch checkpoints (ZIP-based)
"""

from .base        import FormatResult, ThreatLevel, ThreatFlag, detect_format, fmt_bytes
from .zip_scanner import scan_zip
from .gzip_scanner import scan_gzip
from .bzip2_scanner import scan_bzip2
from .tar_scanner   import scan_tar
from .sevenz_scanner import scan_7z
from .xz_scanner    import scan_xz
from .rar_scanner   import scan_rar
from .zstd_scanner  import scan_zstd
from .pytorch_scanner import scan_pytorch

ZIP_FORMATS = {"zip", "jar", "war", "apk", "docx", "xlsx", "pptx"}
TAR_FORMATS = {"tar", "tar.gz", "tar.bzip2", "tar.xz"}


def scan_any(path, policy: dict) -> FormatResult:
    """
    Auto-detect archive format and dispatch to the correct scanner.
    Falls back to ZIP detection if extension maps to a ZIP-based format.
    """
    from pathlib import Path
    p   = Path(path)
    fmt = detect_format(p)

    if fmt in ZIP_FORMATS or fmt == "pytorch":
        if fmt == "pytorch":
            return scan_pytorch(p, policy)
        return scan_zip(p, policy)

    dispatch = {
        "gzip":      scan_gzip,
        "bzip2":     scan_bzip2,
        "tar":       scan_tar,
        "tar.gz":    lambda p, pol: _scan_tar_compressed(p, pol, "tar.gz"),
        "tar.bzip2": lambda p, pol: _scan_tar_compressed(p, pol, "tar.bzip2"),
        "tar.xz":    lambda p, pol: _scan_tar_compressed(p, pol, "tar.xz"),
        "7z":        scan_7z,
        "xz":        scan_xz,
        "rar4":      scan_rar,
        "rar5":      scan_rar,
        "rar":       scan_rar,
        "zstd":      scan_zstd,
    }

    scanner = dispatch.get(fmt)
    if scanner:
        return scanner(p, policy)

    # Unknown format — return a minimal result
    result = FormatResult(path=str(p), fmt=fmt or "unknown")
    result.add_flag(ThreatLevel.NONE, "UNSUPPORTED_FORMAT",
        f"Format '{fmt}' is not supported for analysis")
    return result


def _scan_tar_compressed(path, policy: dict, fmt: str) -> FormatResult:
    """
    For .tar.gz / .tar.bz2 / .tar.xz we report based on the compressed
    container stats, noting the TAR is inside.
    """
    p = path
    if fmt == "tar.gz":
        result = scan_gzip(p, policy)
    elif fmt == "tar.bzip2":
        result = scan_bzip2(p, policy)
    else:
        result = scan_xz(p, policy)
    result.fmt = fmt
    result.details["note"] = "Compressed TAR archive — inner TAR not scanned without decompression"
    return result


__all__ = [
    "scan_any", "scan_zip", "scan_gzip", "scan_bzip2", "scan_tar",
    "scan_7z", "scan_xz", "scan_rar", "scan_zstd", "scan_pytorch",
    "FormatResult", "ThreatLevel", "ThreatFlag", "detect_format", "fmt_bytes",
]
