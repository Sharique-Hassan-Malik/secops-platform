#!/usr/bin/env python3
"""
zipbomb_detector.py  —  Multi-Format Archive Bomb Detector (Python 3.10+)

Supported formats: ZIP, GZip, BZip2, TAR, 7z, XZ, RAR, Zstandard,
                   PyTorch (.pt/.pth), and ZIP-based formats (jar, apk, docx…)

Usage:
    python zipbomb_detector.py scan  <file> [--policy strict] [--json]
    python zipbomb_detector.py batch <directory> [--csv report.csv]
    python zipbomb_detector.py info  <file>
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Iterator

from formats import scan_any, detect_format


DEFAULT_POLICY = {
    "max_ratio":         100.0,
    "max_uncompressed":  4 * 1024 ** 3,
    "max_entries":       10_000,
    "max_nesting_depth": 3,
    "check_overlaps":    True,
}

POLICIES = {
    "default":  dict(DEFAULT_POLICY),
    "strict":   {"max_ratio": 50,  "max_uncompressed": 1<<30, "max_entries": 500,    "max_nesting_depth": 2, "check_overlaps": True},
    "paranoid": {"max_ratio": 10,  "max_uncompressed": 1<<28, "max_entries": 100,    "max_nesting_depth": 1, "check_overlaps": True},
    "relaxed":  {"max_ratio": 500, "max_uncompressed": 1<<36, "max_entries": 50_000, "max_nesting_depth": 5, "check_overlaps": True},
}

SCANNABLE_EXTENSIONS = {
    ".zip", ".gz", ".bz2", ".tgz", ".tbz2", ".7z", ".xz",
    ".rar", ".zst", ".zstd", ".tar", ".jar", ".war", ".apk",
    ".docx", ".xlsx", ".pptx", ".pt", ".pth",
}


def scan_file(path: str | Path, policy: dict) -> object:
    return scan_any(path, policy)


def scan_directory(directory: str | Path, policy: dict) -> Iterator:
    for fp in Path(directory).rglob("*"):
        if fp.suffix.lower() in SCANNABLE_EXTENSIONS:
            yield scan_any(fp, policy)


def cli_main() -> int:
    parser = argparse.ArgumentParser(
        prog="zipbomb_detector",
        description="Multi-format archive bomb detector — zero decompression"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="Scan one or more archive files")
    sc.add_argument("files", nargs="+")
    sc.add_argument("--policy", choices=list(POLICIES), default="default")
    sc.add_argument("--json", action="store_true")

    bc = sub.add_parser("batch", help="Scan a directory of archives")
    bc.add_argument("directory")
    bc.add_argument("--policy", choices=list(POLICIES), default="default")
    bc.add_argument("--csv",  default=None)
    bc.add_argument("--json", action="store_true")

    ic = sub.add_parser("info", help="Show format detection and entry table")
    ic.add_argument("file")

    args = parser.parse_args()

    if args.command == "info":
        p = Path(args.file)
        fmt = detect_format(p)
        print(f"  File   : {p}")
        print(f"  Format : {fmt}")
        result = scan_any(p, POLICIES["default"])
        if hasattr(result, "entries") and result.entries:
            print(f"\n  {'Name':<50} {'CompSz':>12} {'UncompSz':>12} {'Ratio':>8}")
            print("  " + "-" * 86)
            for e in result.entries[:50]:
                name  = e.get("name","")[:50] if isinstance(e, dict) else getattr(e,"name","")[:50]
                csz   = e.get("compSz",0)  if isinstance(e, dict) else getattr(e,"compressed_size",0)
                usz   = e.get("uncompSz",0) if isinstance(e, dict) else getattr(e,"uncompressed_size",0)
                ratio = e.get("ratio",0)   if isinstance(e, dict) else getattr(e,"ratio",0)
                print(f"  {name:<50} {csz:>12,} {usz:>12,} {ratio:>7.1f}x")
        return 0

    policy   = POLICIES[args.policy]
    results  = []
    exit_code = 0

    if args.command == "scan":
        for fp in args.files:
            r = scan_any(fp, policy)
            results.append(r)
            print(r.to_json() if args.json else r.summary())
            if r.is_threat: exit_code = 1

    elif args.command == "batch":
        for r in scan_directory(args.directory, policy):
            results.append(r)
            print(r.to_json() if args.json else r.summary())
            if r.is_threat: exit_code = 1

        if args.csv:
            with open(args.csv, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["path","format","threat_level","entry_count",
                             "total_compressed","total_uncompressed",
                             "overall_ratio","has_overlaps","scan_time_ms"])
                for r in results:
                    w.writerow([r.path, r.fmt, r.threat_level, r.entry_count,
                                 r.total_compressed, r.total_uncompressed,
                                 f"{r.overall_ratio:.4f}", r.has_overlaps,
                                 f"{r.scan_time_ms:.2f}"])
            print(f"\nCSV saved: {args.csv}")

    return exit_code


if __name__ == "__main__":
    sys.exit(cli_main())
