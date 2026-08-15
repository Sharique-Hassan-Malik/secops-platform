"""
Command-line interface for the CAN Bus Intrusion Detection System.

Examples
--------
Split a single log file (first 70% as baseline, rest as test):
    can-ids analyze capture.log

Separate baseline and test files:
    can-ids analyze --baseline normal.log test.log

Save a JSON report:
    can-ids analyze capture.log --json report.json

Tune detector thresholds:
    can-ids analyze capture.log --freq-threshold 4.0 --timing-threshold 5.0

Show baseline profile only:
    can-ids baseline capture.log

Generate a synthetic demo capture:
    can-ids demo --duration 30 --attack all --output demo.log
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from can_ids import __version__
from can_ids.analyzer import CANIntrusion, DetectorConfig
from can_ids.core.baseline import build as build_baseline, split_train_test
from can_ids.parsers import load
from can_ids.report.renderer import render
from can_ids.report.json_report import save as save_json


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="can-ids",
        description="CAN Bus Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", "-V", action="version", version=f"can-ids {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    # ── analyze ──────────────────────────────────────────────────────────────
    analyze = sub.add_parser("analyze", help="Run intrusion detection on a CAN log")
    analyze.add_argument("test", metavar="TEST_LOG", help="Log file to analyze")
    analyze.add_argument(
        "--baseline", "-b", metavar="BASELINE_LOG",
        help="Separate baseline log (if omitted, TEST_LOG is split by --train-ratio)",
    )
    analyze.add_argument(
        "--train-ratio", type=float, default=0.7, metavar="RATIO",
        help="Fraction of TEST_LOG used as baseline when no --baseline given (default: 0.7)",
    )
    analyze.add_argument(
        "--freq-window", type=float, default=1.0, metavar="SEC",
        help="Frequency detector window size in seconds (default: 1.0)",
    )
    analyze.add_argument(
        "--freq-threshold", type=float, default=3.0, metavar="Z",
        help="Frequency detector z-score threshold (default: 3.0)",
    )
    analyze.add_argument(
        "--timing-threshold", type=float, default=4.0, metavar="Z",
        help="Timing detector z-score threshold (default: 4.0)",
    )
    analyze.add_argument(
        "--payload-threshold", type=float, default=4.0, metavar="Z",
        help="Payload detector z-score threshold (default: 4.0)",
    )
    analyze.add_argument(
        "--replay-window", type=int, default=16, metavar="N",
        help="Replay detector sequence window size in frames (default: 16)",
    )
    analyze.add_argument(
        "--json", "-j", metavar="FILE",
        help="Write JSON report to FILE",
    )
    analyze.add_argument(
        "--no-color", action="store_true",
        help="Disable terminal color output",
    )
    analyze.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress terminal output",
    )

    # ── baseline ─────────────────────────────────────────────────────────────
    bl_cmd = sub.add_parser("baseline", help="Show the baseline profile for a log file")
    bl_cmd.add_argument("log", metavar="LOG", help="CAN log file")
    bl_cmd.add_argument("--no-color", action="store_true")

    # ── demo ─────────────────────────────────────────────────────────────────
    demo_cmd = sub.add_parser("demo", help="Generate a synthetic CAN capture and run IDS on it")
    demo_cmd.add_argument(
        "--duration", type=float, default=20.0, metavar="SEC",
        help="Capture duration in seconds (default: 20)",
    )
    demo_cmd.add_argument(
        "--attack", choices=["none", "flood", "replay", "unknown", "payload", "all"],
        default="all", metavar="TYPE",
        help="Attack type to inject: flood, replay, unknown, payload or all (default: all)",
    )
    demo_cmd.add_argument(
        "--output", "-o", metavar="FILE",
        help="Save generated log to FILE in candump format",
    )
    demo_cmd.add_argument(
        "--json", "-j", metavar="FILE",
        help="Write JSON report to FILE",
    )
    demo_cmd.add_argument("--no-color", action="store_true")

    return p


def cmd_analyze(args: argparse.Namespace) -> int:
    console = Console(no_color=args.no_color)

    for path in ([args.baseline] if args.baseline else []) + [args.test]:
        if path and not Path(path).exists():
            console.print(f"[red]error:[/red] file not found: {path}")
            return 1

    cfg = DetectorConfig(
        freq_window_sec=args.freq_window,
        freq_threshold=args.freq_threshold,
        timing_threshold=args.timing_threshold,
        payload_threshold=args.payload_threshold,
        replay_window_size=args.replay_window,
    )
    ids = CANIntrusion(cfg)

    if args.baseline:
        baseline = ids.build_baseline(args.baseline)
        result = ids.detect(args.test, baseline)
    else:
        result = ids.analyze_split(args.test, train_ratio=args.train_ratio)

    if not args.quiet:
        render(result, console)
        console.print(f"\n[dim]Analysis completed in {result.analysis_time * 1000:.1f} ms[/dim]")

    if args.json:
        save_json(result, args.json)
        if not args.quiet:
            console.print(f"JSON report saved → {args.json}")

    return 1 if result.critical_count > 0 else 0


def cmd_baseline(args: argparse.Namespace) -> int:
    console = Console(no_color=args.no_color)
    if not Path(args.log).exists():
        console.print(f"[red]error:[/red] file not found: {args.log}")
        return 1

    from can_ids.report.renderer import _baseline_table, _summary
    from can_ids.analyzer import AnalysisResult

    frames = load(args.log)
    baseline = build_baseline(frames)

    # Wrap in a minimal result for the renderer
    result = AnalysisResult(
        baseline=baseline,
        alerts=[],
        test_frame_count=0,
        analysis_time=0.0,
        source=Path(args.log).name,
    )
    _summary(result, console)
    _baseline_table(result, console)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from can_ids.parsers.generator import (
        generate_normal,
        inject_frequency_flood,
        inject_replay,
        inject_unknown_id,
        inject_payload_spoof,
        frames_to_candump,
    )

    console = Console(no_color=args.no_color)
    dur = args.duration
    mid = dur * 0.6      # attacks start at 60% through the capture

    console.print(f"[cyan]Generating {dur:.0f}s synthetic CAN capture…[/cyan]")
    frames = generate_normal(duration_sec=dur, seed=42)

    base_ts = frames[0].timestamp if frames else 1_600_000_000.0

    attack = args.attack
    if attack in ("flood", "all"):
        frames = inject_frequency_flood(
            frames, target_id=0x0C0, flood_start=base_ts + mid,
            flood_duration=0.5, multiplier=10, seed=1,
        )
        console.print("  [yellow]+ frequency flood injected on ID 0C0[/yellow]")

    if attack in ("replay", "all"):
        frames = inject_replay(
            frames, replay_start=base_ts + mid + 1.0, replay_delay=0.8, window=20,
        )
        console.print("  [yellow]+ replay attack injected (20-frame window)[/yellow]")

    if attack in ("unknown", "all"):
        frames = inject_unknown_id(
            frames, inject_at=base_ts + mid + 2.0, unknown_id=0x666, count=8,
        )
        console.print("  [yellow]+ unknown ID 0x666 injected (8 frames)[/yellow]")

    if attack in ("payload", "all"):
        frames = inject_payload_spoof(
            frames, target_id=0x0C0, spoof_at=base_ts + mid + 3.0,
            spoofed_data=bytes([0xFF, 0xFF]),   # RPM = 65535 — physically impossible
        )
        console.print("  [yellow]+ payload spoof injected on ID 0C0 (RPM=65535)[/yellow]")

    if args.output:
        Path(args.output).write_text(frames_to_candump(frames), encoding="utf-8")
        console.print(f"  Log saved → {args.output}")

    console.print()

    # Run IDS on the synthetic capture
    train_count = int(len(frames) * 0.6)
    train_frames = [f for f in frames if f.timestamp < base_ts + mid]
    test_frames  = [f for f in frames if f.timestamp >= base_ts + mid]

    ids = CANIntrusion()
    baseline = ids.build_baseline_from_frames(train_frames)
    result = ids.detect_frames(test_frames, baseline, source="synthetic-demo")

    render(result, console)

    if args.json:
        save_json(result, args.json)
        console.print(f"\nJSON report saved → {args.json}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "baseline":
        return cmd_baseline(args)
    if args.command == "demo":
        return cmd_demo(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
