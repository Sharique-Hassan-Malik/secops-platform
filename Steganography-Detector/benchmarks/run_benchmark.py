"""
run_benchmark.py — measure detection accuracy vs embedding rate.

Reads the dataset produced by generate_stego.py and runs all three
image detectors (chi-square, RS, SPA) on each file. Reports accuracy,
precision and recall at each embedding rate.

Usage:
    python benchmarks/run_benchmark.py --data-dir benchmarks/data
    python benchmarks/run_benchmark.py --data-dir benchmarks/data --csv results.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from stegdetect.image import chi_square, rs_analysis, spa


def _parse_rate(name: str) -> float:
    """Extract embedding rate from filename like 'img_0001_p050.png'."""
    for part in name.split("_"):
        if part.startswith("p"):
            # Strip file extension if present.
            raw = part.split(".")[0]
            if len(raw) == 4:
                try:
                    return int(raw[1:]) / 100.0
                except ValueError:
                    pass
    return -1.0


def _run_methods(path: Path) -> dict[str, bool]:
    detections: dict[str, bool] = {}
    try:
        result = chi_square.analyze(path, channel="green")
        detections["chi_square"] = bool(result.get("detection", False))
    except Exception:
        detections["chi_square"] = False

    try:
        result = rs_analysis.analyze(path, channel="green")
        detections["rs_analysis"] = bool(result.get("detection", False))
    except Exception:
        detections["rs_analysis"] = False

    try:
        result = spa.analyze_rows_and_cols(path)
        detections["spa"] = bool(result.get("detection", False))
    except Exception:
        detections["spa"] = False

    return detections


def run(data_dir: Path, csv_path: Path | None, verbose: bool) -> None:
    img_dir = data_dir / "images"
    if not img_dir.exists():
        print(f"Image directory not found: {img_dir}")
        print("Run benchmarks/generate_stego.py first.")
        sys.exit(1)

    files = sorted(img_dir.glob("*.png"))
    if not files:
        print("No PNG files found. Run generate_stego.py first.")
        sys.exit(1)

    # Group results by rate x method.
    # true_positive[rate][method] = count detected as stego (ground truth: stego)
    # false_positive[rate][method] = count detected as stego (ground truth: clean)
    tp: dict[float, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    fp: dict[float, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    fn: dict[float, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    tn: dict[float, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    methods = ["chi_square", "rs_analysis", "spa"]
    total = len(files)
    t0 = time.time()

    for idx, path in enumerate(files):
        rate = _parse_rate(path.name)
        if rate < 0:
            continue
        is_stego = rate > 0.0

        detections = _run_methods(path)

        for m in methods:
            detected = detections[m]
            if is_stego and detected:
                tp[rate][m] += 1
            elif is_stego and not detected:
                fn[rate][m] += 1
            elif not is_stego and detected:
                fp[rate][m] += 1
            else:
                tn[rate][m] += 1

        if verbose and (idx + 1) % 20 == 0:
            print(f"  Processed {idx + 1}/{total}  ({time.time() - t0:.1f}s)")

    # Print results table.
    rates = sorted(set(tp.keys()) | set(fp.keys()) | set(fn.keys()) | set(tn.keys()))

    print(f"\n{'Rate':>6}  {'Method':<14}  {'TP':>5}  {'FP':>5}  {'FN':>5}  {'TN':>5}  {'Acc':>6}  {'Rec':>6}  {'Prec':>6}")
    print("-" * 80)

    csv_rows = []
    for rate in rates:
        for m in methods:
            t = tp[rate][m]
            f = fp[rate][m]
            fn_val = fn[rate][m]
            tn_val = tn[rate][m]
            total_m = t + f + fn_val + tn_val
            acc = (t + tn_val) / total_m if total_m > 0 else 0.0
            rec = t / (t + fn_val) if (t + fn_val) > 0 else 0.0
            prec = t / (t + f) if (t + f) > 0 else 0.0
            print(f"{rate:>6.2f}  {m:<14}  {t:>5}  {f:>5}  {fn_val:>5}  {tn_val:>5}  {acc:>5.1%}  {rec:>5.1%}  {prec:>5.1%}")
            csv_rows.append({
                "rate": rate, "method": m, "tp": t, "fp": f,
                "fn": fn_val, "tn": tn_val,
                "accuracy": round(acc, 4), "recall": round(rec, 4), "precision": round(prec, 4),
            })

    elapsed = time.time() - t0
    print(f"\nAnalyzed {total} files in {elapsed:.1f}s  ({total / elapsed:.1f} files/s)")

    if csv_path:
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"Results saved to {csv_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark steganography detection accuracy.")
    parser.add_argument("--data-dir", default="benchmarks/data", metavar="DIR")
    parser.add_argument("--csv", metavar="FILE", help="Save results to a CSV file.")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    run(Path(args.data_dir), Path(args.csv) if args.csv else None, args.verbose)


if __name__ == "__main__":
    main()
