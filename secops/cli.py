"""`secops` — one command across ten security tools.

    secops sensors                              what is here and what it needs
    secops scan uploads/ --recursive            every scanner that claims each file
    secops probe side-channel-aes --traces 500  run one red-team simulator
    secops rules                                the correlation rules
    secops scan uploads/ --ingest               push the results into the SIEM

Every sensor also keeps its own CLI in its own folder, which is what to reach
for when you want that one tool:

    cd modules/zipbomb-detector/python && python zipbomb_detector.py scan x.zip
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import correlate, pipeline, sink
from .core import sensor as registry
from .core.event import Kind, Report, Severity
from .core.render import render_html, render_terminal


def _output_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", metavar="FILE", nargs="?", const="-",
                        help="write JSON (default: stdout)")
    parser.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    parser.add_argument("--min-severity", default="LOW",
                        choices=[s.value for s in Severity],
                        help="hide events below this severity (default: LOW)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-colour", action="store_true")
    parser.add_argument("--ingest", action="store_true",
                        help="also write the results into the SIEM")
    parser.add_argument("--exit-zero", action="store_true",
                        help="always exit 0, whatever is found")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secops",
        description="Scanners, monitors and red-team simulators reporting into one pipeline.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("sensors", help="show every registered sensor")
    listing.add_argument("--kind", choices=[k.value for k in Kind])

    sub.add_parser("rules", help="show the correlation rules")

    scan = sub.add_parser("scan", help="run file scanners over paths")
    scan.add_argument("targets", nargs="+", help="files, directories or globs")
    scan.add_argument("-r", "--recursive", action="store_true")
    scan.add_argument("--only", metavar="SENSOR", action="append",
                      help="limit to this sensor (repeatable)")
    scan.add_argument("--no-correlate", action="store_true",
                      help="report raw sensor events without correlating them")
    _output_flags(scan)

    probe = sub.add_parser("probe", help="run a red-team simulator")
    probe.add_argument("name", help="sensor name")
    probe.add_argument("--target", default="", help="what to point it at")
    probe.add_argument("--traces", type=int, help="side-channel: traces to collect")
    probe.add_argument("--iterations", type=int, help="fuzzer: iterations")
    probe.add_argument("--host", help="fuzzer: target host")
    probe.add_argument("--port", type=int, help="fuzzer: target port")
    probe.add_argument("--protocol", help="fuzzer: http | dns | mqtt")
    probe.add_argument("--model", help="acoustic: trained model path")
    probe.add_argument("--seed", type=int, default=0)
    _output_flags(probe)

    return parser


def _cmd_sensors(args) -> int:
    kind = Kind(args.kind) if args.kind else None
    print()
    for spec in registry.specs(kind):
        absent = registry.missing_requirements(spec)
        state = "ready" if not absent else f"needs {', '.join(absent)}"
        print(f"  {spec.name:26} {spec.kind.value:10} {state}")
        print(f"  {'':26} {spec.title}")
        for line in _wrap(spec.summary, 72):
            print(f"  {'':26} {line}")
        if spec.extensions:
            print(f"  {'':26} handles: {' '.join(sorted(spec.extensions))}")
        print()
    return 0


def _cmd_rules(args) -> int:
    print()
    for name in correlate.rules():
        fn = dict(correlate._RULES)[name]
        doc = (fn.__doc__ or "").strip().split("\n\n")
        print(f"  {name}")
        print(f"    {doc[0].strip()}")
        if len(doc) > 1:
            for line in _wrap(" ".join(doc[1].split()), 74):
                print(f"    {line}")
        print()
    return 0


def _wrap(text: str, width: int) -> list[str]:
    words, lines, line = text.split(), [], []
    for word in words:
        if sum(len(w) + 1 for w in line) + len(word) > width and line:
            lines.append(" ".join(line))
            line = []
        line.append(word)
    if line:
        lines.append(" ".join(line))
    return lines


def _emit(report: Report, args) -> int:
    if getattr(args, "ingest", False):
        usable, reason = sink.available()
        if not usable:
            print(f"  ingest skipped — {reason}", file=sys.stderr)
        else:
            counts = sink.ingest(report)
            print(f"  ingested {counts['detections']} detection(s) and "
                  f"{counts['alerts']} alert(s) into the SIEM")

    wrote_stdout = False
    if getattr(args, "json", None):
        payload = report.to_json()
        if args.json == "-":
            print(payload)
            wrote_stdout = True
        else:
            Path(args.json).write_text(payload, encoding="utf-8")

    if getattr(args, "html", None):
        Path(args.html).write_text(render_html(report), encoding="utf-8")

    if not wrote_stdout:
        shown = report if args.verbose else report.filtered(Severity[args.min_severity])
        render_terminal(shown, colour=False if args.no_colour else None,
                        verbose=args.verbose)
        for path, label in ((getattr(args, "json", None), "JSON"),
                            (getattr(args, "html", None), "HTML")):
            if path and path != "-":
                print(f"  {label} report → {path}")

    return 0 if args.exit_zero else report.exit_code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "sensors":
        return _cmd_sensors(args)
    if args.command == "rules":
        return _cmd_rules(args)

    try:
        if args.command == "scan":
            report = pipeline.scan(
                args.targets,
                recursive=args.recursive,
                only=args.only,
                correlate_events=not args.no_correlate,
            )
            if not report.results:
                print("No files matched, or no scanner claims them.", file=sys.stderr)
                return 2
        else:
            options = {
                key: value
                for key, value in vars(args).items()
                if key in ("traces", "iterations", "host", "port", "protocol",
                           "model", "seed")
                and value is not None
            }
            report = pipeline.observe(
                args.target or args.name, only=[args.name], options=options
            )
    except (KeyError, ValueError) as exc:
        print(f"secops: {exc}", file=sys.stderr)
        return 2

    return _emit(report, args)


if __name__ == "__main__":
    raise SystemExit(main())
