#!/usr/bin/env python3
"""
Python Bytecode Obfuscation Analyzer.

Decompiles .pyc files, detects obfuscation patterns and reconstructs
readable source where possible.

Usage:
    python analyze.py target.pyc
    python analyze.py obfuscated.pyc --decompile
    python analyze.py obfuscated.pyc --disassemble
    python analyze.py build/ --recursive --json
    python analyze.py target.pyc --verbose --min-confidence 0.5
"""

import argparse
import json
import sys
from pathlib import Path

from config import AnalysisResult
from analyzer.pyc_parser import PycParser, PycParseError
from analyzer.disassembler import Disassembler
from analyzer.decompiler import Decompiler
from analyzer.obfuscation import ObfuscationDetector
from analyzer.reporter import Reporter


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Python bytecode obfuscation analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="+", help="Files, directories or glob patterns")
    p.add_argument("-r", "--recursive", action="store_true")
    p.add_argument("-v", "--verbose",   action="store_true",
                   help="Show low-confidence findings and full details")
    p.add_argument("--decompile",       action="store_true",
                   help="Print reconstructed Python source")
    p.add_argument("--disassemble",     action="store_true",
                   help="Print annotated disassembly")
    p.add_argument("--min-confidence",  type=float, default=0.5,
                   metavar="FLOAT", help="Minimum confidence to display (default: 0.5)")
    p.add_argument("--json",            action="store_true",
                   help="Output results as JSON")
    p.add_argument("--no-colour",       action="store_true")
    p.add_argument("--exit-zero",       action="store_true",
                   help="Always exit 0")
    return p.parse_args()


def collect_files(targets: list[str], recursive: bool) -> list[Path]:
    paths: list[Path] = []
    for target in targets:
        p = Path(target)
        if p.is_file():
            paths.append(p)
        elif p.is_dir():
            fn = p.rglob if recursive else p.glob
            paths.extend(fn("*.pyc"))
            paths.extend(fn("*.pyo"))
        else:
            root = Path(".")
            found = list(root.rglob(target) if "**" in target else root.glob(target))
            paths.extend(f for f in found if f.is_file())
    seen: set[Path] = set()
    unique = []
    for p in paths:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            unique.append(p)
    return unique


def analyse_file(path: str) -> tuple[AnalysisResult, object]:
    """
    Returns (AnalysisResult, root_CodeObject_or_None).
    """
    result = AnalysisResult(path=path)
    root_co = None

    try:
        pyc    = PycParser().parse_file(path)
        result.python_version = pyc.python_version
        result.source_file    = getattr(pyc.code, "co_filename", "")
        result.timestamp      = pyc.timestamp
        result.flags          = pyc.flags

        dis  = Disassembler()
        root_co = dis.disassemble(pyc.code)

        ObfuscationDetector().analyse(root_co, result)

    except PycParseError as exc:
        result.error = str(exc)
    except Exception as exc:
        result.error = f"Unexpected error: {exc}"

    return result, root_co


def main():
    args  = parse_args()
    files = collect_files(args.targets, args.recursive)

    if not files:
        print("No .pyc files found.", file=sys.stderr)
        sys.exit(1)

    reporter    = Reporter()
    use_colour  = None if not args.no_colour else False
    all_results = []

    for path in files:
        result, root_co = analyse_file(str(path))
        all_results.append(result)

        if not args.json:
            reporter.print_result(result, verbose=args.verbose, use_colour=use_colour)

            if args.disassemble and root_co is not None:
                reporter.print_disassembly(root_co, use_colour=use_colour)

            if args.decompile and root_co is not None:
                dec = Decompiler()
                print()
                print("── Decompiled source " + "─" * 40)
                print(dec.decompile(root_co))

    if args.json:
        print(reporter.results_to_json(all_results))

    if not args.exit_zero:
        obfuscated = any(r.obfuscated for r in all_results)
        sys.exit(1 if obfuscated else 0)


if __name__ == "__main__":
    main()
