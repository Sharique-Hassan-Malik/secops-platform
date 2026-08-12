#!/usr/bin/env python3
"""
test_corpus.py — Safe test corpus generator and runner.

Creates synthetic archives with controlled metadata (small actual payloads,
inflated declared sizes) to validate each detection vector independently.
"""

from __future__ import annotations
import argparse
import os
import struct
import sys
import zlib
from pathlib import Path


class ZipBuilder:
    """Minimal ZIP builder with full metadata control."""

    def __init__(self):
        self._entries: list[dict] = []

    def add_entry(self, *, name: str, data: bytes,
                  compressed_size_override: int | None = None,
                  uncompressed_size_override: int | None = None,
                  method: int = 8) -> "ZipBuilder":
        if method == 8:
            compressed = zlib.compress(data, level=9)[2:-4]
        else:
            compressed = data
            method = 0
        self._entries.append({
            "name":       name.encode("utf-8"),
            "compressed": compressed,
            "comp_sz":    compressed_size_override  if compressed_size_override  is not None else len(compressed),
            "uncomp_sz":  uncompressed_size_override if uncompressed_size_override is not None else len(data),
            "method":     method,
            "crc":        zlib.crc32(data) & 0xFFFFFFFF,
        })
        return self

    def build(self) -> bytes:
        local_parts, cd_parts, offsets = [], [], []
        offset = 0
        for e in self._entries:
            offsets.append(offset)
            fname = e["name"]
            lh = struct.pack("<IHHHHHIIIHH",
                0x04034b50, 20, 0, e["method"], 0, 0,
                e["crc"], e["comp_sz"], e["uncomp_sz"],
                len(fname), 0) + fname + e["compressed"]
            local_parts.append(lh)
            offset += len(lh)
        cd_start = offset
        for i, e in enumerate(self._entries):
            fname = e["name"]
            cd = struct.pack("<IHHHHHHIIIHHHHHII",
                0x02014b50, 20, 20, 0, e["method"], 0, 0,
                e["crc"], e["comp_sz"], e["uncomp_sz"],
                len(fname), 0, 0, 0, 0, 0, offsets[i]) + fname
            cd_parts.append(cd)
        cd_bytes = b"".join(cd_parts)
        eocd = struct.pack("<IHHHHIIH",
            0x06054b50, 0, 0, len(self._entries), len(self._entries),
            len(cd_bytes), cd_start, 0)
        return b"".join(local_parts) + cd_bytes + eocd


def generate_corpus(outdir: Path) -> list[tuple[str, str, bool]]:
    outdir.mkdir(parents=True, exist_ok=True)
    cases = []

    # Clean ZIP
    z = ZipBuilder()
    z.add_entry(name="hello.txt", data=b"Hello, World!\n", method=0)
    (outdir / "clean.zip").write_bytes(z.build())
    cases.append(("clean.zip", "Normal ZIP — should be clean", False))

    # Ratio trigger
    z = ZipBuilder()
    z.add_entry(name="big_declared.txt", data=b"Hello, World!\n",
                uncompressed_size_override=0xFFFFFFFF)
    (outdir / "ratio_trigger.zip").write_bytes(z.build())
    cases.append(("ratio_trigger.zip", "Declared 4GB — triggers RATIO_EXCEEDED", True))

    # Entry flood
    z = ZipBuilder()
    for i in range(600):
        z.add_entry(name=f"file_{i:05d}.txt", data=b"x", method=0)
    (outdir / "entry_flood.zip").write_bytes(z.build())
    cases.append(("entry_flood.zip", "600 entries — triggers ENTRY_FLOOD (strict limit=500)", True))

    # Elevated ratio
    z = ZipBuilder()
    z.add_entry(name="moderate.txt", data=b"A"*100, uncompressed_size_override=5000)
    (outdir / "elevated_ratio.zip").write_bytes(z.build())
    cases.append(("elevated_ratio.zip", "50:1 declared ratio — LOW/MEDIUM flag", True))

    # Clean multi-entry
    z = ZipBuilder()
    for i in range(10):
        z.add_entry(name=f"doc{i}.bin", data=os.urandom(256) + f"entry_{i}".encode(), method=0)
    (outdir / "multi_entry_clean.zip").write_bytes(z.build())
    cases.append(("multi_entry_clean.zip", "10 low-ratio binary entries — clean", False))

    # Zero entries
    z = ZipBuilder()
    for i in range(20):
        z.add_entry(name=f"empty_{i}.txt", data=b"", method=0)
    (outdir / "zero_entries.zip").write_bytes(z.build())
    cases.append(("zero_entries.zip", "20 empty entries — clean", False))

    print(f"Generated {len(cases)} test cases in: {outdir}")
    return cases


def run_tests(outdir: Path) -> int:
    from formats import scan_any

    strict_policy = {
        "max_ratio": 50, "max_uncompressed": 1<<30,
        "max_entries": 500, "max_nesting_depth": 2, "check_overlaps": True
    }

    cases = generate_corpus(outdir)
    passed = failed = 0

    print("\n" + "=" * 70)
    print(f"{'TEST CASE':<35} {'EXPECTED':<10} {'GOT':<10} {'STATUS'}")
    print("=" * 70)

    for fname, desc, should_flag in cases:
        path    = outdir / fname
        result  = scan_any(path, strict_policy)
        flagged = result.is_threat
        ok      = (flagged == should_flag)
        status  = "✓ PASS" if ok else "✗ FAIL"
        exp_str = "THREAT" if should_flag else "CLEAN"
        got_str = "THREAT" if flagged    else "CLEAN"
        print(f"{fname:<35} {exp_str:<10} {got_str:<10} {status}")
        if not ok:
            for f in result.flags:
                print(f"  └ [{f.level}] {f.code}: {f.description}")
        if ok: passed += 1
        else:  failed += 1

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed out of {len(cases)} cases\n")
    return 0 if failed == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Test corpus generator & runner")
    sub    = parser.add_subparsers(dest="cmd", required=True)
    gen    = sub.add_parser("generate")
    gen.add_argument("--outdir", default="./test_zips")
    run    = sub.add_parser("run")
    run.add_argument("--outdir", default="./test_zips")
    args   = parser.parse_args()
    outdir = Path(args.outdir)
    if args.cmd == "generate":
        generate_corpus(outdir); return 0
    return run_tests(outdir)


if __name__ == "__main__":
    sys.exit(main())
