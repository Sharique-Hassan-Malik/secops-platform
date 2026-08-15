"""
Command-line interface for the steganography detector.

Usage examples:
    python -m stegdetect photo.png
    python -m stegdetect --verbose photo.jpg
    python -m stegdetect --channel green photo.png
    python -m stegdetect --windowed photo.png
    python -m stegdetect *.png *.jpg
    python -m stegdetect --json photo.png
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from stegdetect import detector
from stegdetect.report import format_report, format_batch_summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="stegdetect",
        description="Detect steganographic content in images and audio files.",
    )
    p.add_argument("files", nargs="+", metavar="FILE", help="Files to analyze.")
    p.add_argument(
        "--channel",
        choices=["red", "green", "blue", "all"],
        default="all",
        help="Color channel(s) to test. 'all' tests all three. (default: all)",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show per-channel breakdown in the report.",
    )
    p.add_argument(
        "--windowed",
        action="store_true",
        help="Run windowed chi-square analysis to locate partial embeddings.",
    )
    p.add_argument(
        "--window-size",
        type=int,
        default=512,
        metavar="N",
        help="Window size for windowed chi-square (default: 512).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output results as JSON instead of formatted text.",
    )
    p.add_argument(
        "--summary",
        action="store_true",
        help="When analyzing multiple files, print a one-line-per-file summary.",
    )
    return p.parse_args(argv)


def _run_windowed(path: str, window_size: int) -> None:
    from stegdetect.image import chi_square as cq

    results = cq.analyze_windowed(path, channel="green", window_size=window_size)
    if not results:
        print("  (file too small for windowed analysis)")
        return

    max_prob = max(r["stego_probability"] for r in results)
    print(f"  Windowed chi-square (window={window_size}):")
    print(f"  Peak stego probability: {max_prob * 100:.1f}%")
    if max_prob > 0.05:
        peak = max(results, key=lambda r: r["stego_probability"])
        print(f"  Peak at sample {peak['start']}..{peak['end']}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    channels = ["red", "green", "blue"] if args.channel == "all" else [args.channel]
    all_results: list[dict] = []

    for file_str in args.files:
        paths = list(Path().glob(file_str)) if "*" in file_str else [Path(file_str)]
        for path in paths:
            result = detector.detect(str(path), channels=channels)
            all_results.append(result)

            if not args.output_json:
                print(format_report(result, verbose=args.verbose))
                if args.windowed and result.get("file_type") == "image":
                    _run_windowed(str(path), args.window_size)

    if args.output_json:
        print(json.dumps(all_results if len(all_results) > 1 else all_results[0], indent=2))
    elif args.summary and len(all_results) > 1:
        print(format_batch_summary(all_results))

    n_flagged = sum(1 for r in all_results if r.get("verdict") in ("suspicious", "likely_stego"))
    return 0 if n_flagged == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
