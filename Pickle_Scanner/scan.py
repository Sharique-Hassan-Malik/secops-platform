#!/usr/bin/env python3
"""
Memory-safe pickle scanner.

Scans .pkl, .pickle, .pt and .pth files for dangerous opcodes without
executing any pickle bytecode.  Supports single files, directories (with
optional recursion) and glob patterns.

Usage:
    python scan.py model.pt
    python scan.py checkpoints/ --recursive
    python scan.py "**/*.pkl" --min-severity HIGH
    python scan.py payload.pkl --verbose --strict
    python scan.py model.pt --json
"""

import argparse
import json
import sys
from pathlib import Path

from scanner.opcodes import Severity, ScanResult
from scanner.reporter import print_result, print_summary
from scanner.scanner import scan_file

_PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".joblib"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Memory-safe pickle scanner — static analysis of pickle bytecode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="+", help="Files, directories or glob patterns")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="Recurse into subdirectories")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show INFO-level findings (suppressed by default)")
    p.add_argument("--strict", action="store_true",
                   help="Raise severity for private C-extension modules")
    p.add_argument(
        "--min-severity", default="LOW",
        choices=[s.value for s in Severity],
        help="Only report findings at or above this severity (default: LOW)",
    )
    p.add_argument("--json", action="store_true",
                   help="Output results as JSON instead of terminal text")
    p.add_argument("--no-colour", action="store_true",
                   help="Disable ANSI colour output")
    p.add_argument("--exit-zero", action="store_true",
                   help="Always exit 0 even when dangerous opcodes are found")
    return p.parse_args()


def collect_files(targets: list[str], recursive: bool) -> list[Path]:
    paths: list[Path] = []
    for target in targets:
        p = Path(target)
        if p.is_file():
            paths.append(p)
        elif p.is_dir():
            glob_fn = p.rglob if recursive else p.glob
            for ext in _PICKLE_EXTENSIONS:
                paths.extend(glob_fn(f"*{ext}"))
        else:
            # Treat as glob
            root  = Path(".")
            found = list(root.rglob(target) if "**" in target else root.glob(target))
            paths.extend(f for f in found if f.is_file())

    # Deduplicate preserving order
    seen: set[Path] = set()
    unique = []
    for p in paths:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            unique.append(p)
    return unique


def results_to_json(results: list[ScanResult], min_sev: Severity) -> str:
    out = []
    for r in results:
        findings = []
        for f in r.findings:
            if f.severity >= min_sev:
                findings.append({
                    "opcode":      f.opcode,
                    "offset":      f.offset,
                    "severity":    f.severity.value,
                    "description": f.description,
                    "detail":      f.detail,
                })
        out.append({
            "path":         r.path,
            "safe":         r.safe,
            "error":        r.error,
            "protocol":     r.proto,
            "n_opcodes":    r.n_opcodes,
            "max_severity": r.max_severity.value,
            "findings":     findings,
        })
    return json.dumps(out, indent=2)


def main():
    args = parse_args()
    files = collect_files(args.targets, args.recursive)

    if not files:
        print("No files matched.", file=sys.stderr)
        sys.exit(1)

    min_sev    = Severity[args.min_severity]
    use_colour = None if not args.no_colour else False

    all_results: list[ScanResult] = []
    for path in files:
        results = scan_file(str(path), strict=args.strict)
        all_results.extend(results)

    if args.json:
        print(results_to_json(all_results, min_sev))
    else:
        for r in all_results:
            print_result(r, verbose=args.verbose, use_colour=use_colour)
        if len(all_results) > 1:
            print_summary(all_results, use_colour=use_colour)

    # Exit code: 1 if any result is HIGH or CRITICAL and --exit-zero not set
    if not args.exit_zero:
        from scanner.opcodes import Severity as S
        dangerous = any(
            r.max_severity >= S.HIGH or not r.safe
            for r in all_results
        )
        sys.exit(1 if dangerous else 0)


if __name__ == "__main__":
    main()
