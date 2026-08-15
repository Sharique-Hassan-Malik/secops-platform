"""
Rich terminal renderer for CAN IDS analysis results.

Produces:
  - Summary banner with baseline stats and alert counts
  - Baseline profile table (per-ID IAT mean/std and message rate)
  - Alert table grouped and color-coded by severity
  - Per-detector summary
"""

from __future__ import annotations

from typing import Dict, List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from can_ids.analyzer import AnalysisResult
from can_ids.core.alert import Alert

_SEV_COLOR = {
    "critical": "bold bright_red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim white",
    "info":     "dim",
}

_DET_COLOR = {
    "frequency":  "bright_cyan",
    "timing":     "magenta",
    "replay":     "bright_yellow",
    "payload":    "bright_green",
    "unknown_id": "bright_red",
}


def render(result: AnalysisResult, console: Console | None = None) -> None:
    if console is None:
        console = Console()

    _summary(result, console)
    _baseline_table(result, console)
    _alert_table(result, console)
    _detector_summary(result, console)


def _summary(result: AnalysisResult, console: Console) -> None:
    bl = result.baseline
    alerts = result.alerts
    sev = result.by_severity

    lines = [
        f"[bold]Source:[/bold]          {result.source or '—'}",
        f"[bold]Baseline frames:[/bold] {bl.total_frames:,}  over {bl.duration:.2f} s",
        f"[bold]Baseline IDs:[/bold]    {len(bl.profiles)}",
        f"[bold]Test frames:[/bold]     {result.test_frame_count:,}",
        f"[bold]Total alerts:[/bold]    {len(alerts)}",
        f"  [bold bright_red]Critical[/bold bright_red] {len(sev.get('critical', []))}  "
        f"[red]High[/red] {len(sev.get('high', []))}  "
        f"[yellow]Medium[/yellow] {len(sev.get('medium', []))}  "
        f"[dim]Low[/dim] {len(sev.get('low', []))}",
        f"[bold]Analysis time:[/bold]   {result.analysis_time * 1000:.1f} ms",
    ]

    color = "bright_red" if result.critical_count > 0 else "yellow" if result.high_count > 0 else "green"
    console.print(Panel(
        "\n".join(lines),
        title="[bold bright_cyan]CAN Bus Intrusion Detection System[/bold bright_cyan]",
        border_style=color,
    ))


def _baseline_table(result: AnalysisResult, console: Console) -> None:
    profiles = sorted(result.baseline.profiles.values(), key=lambda p: p.can_id)
    if not profiles:
        return

    tbl = Table(
        title="Baseline Profile",
        box=box.SIMPLE_HEAD,
        title_style="bold bright_cyan",
        show_lines=False,
    )
    tbl.add_column("ID",          style="yellow",      width=8)
    tbl.add_column("Frames",      justify="right",     width=9)
    tbl.add_column("Rate (msg/s)",justify="right",     width=12)
    tbl.add_column("IAT mean (ms)",justify="right",    width=14)
    tbl.add_column("IAT std (ms)", justify="right",    width=13)
    tbl.add_column("DLC",          justify="center",   width=5)

    for p in profiles:
        dlc = (max(p.byte_stats.keys()) + 1) if p.byte_stats else 0
        tbl.add_row(
            f"{p.can_id:03X}" if p.can_id <= 0x7FF else f"{p.can_id:08X}",
            f"{p.count:,}",
            f"{p.mean_rate:.1f}",
            f"{p.iat_mean * 1000:.2f}" if p.iat_count > 0 else "—",
            f"{p.iat_std * 1000:.2f}" if p.iat_count > 1 else "—",
            str(dlc),
        )

    console.print(tbl)


def _alert_table(result: AnalysisResult, console: Console) -> None:
    alerts = result.alerts
    if not alerts:
        console.print(Panel(
            "[bold green]No anomalies detected.[/bold green]",
            title="Alerts", border_style="green",
        ))
        return

    tbl = Table(
        title=f"Alerts  ({len(alerts)} total)",
        box=box.SIMPLE_HEAD,
        title_style="bold bright_red",
        show_lines=False,
    )
    tbl.add_column("Timestamp",  style="dim",        width=14)
    tbl.add_column("ID",         style="yellow",     width=8)
    tbl.add_column("Severity",   justify="center",   width=10)
    tbl.add_column("Detector",   style="cyan",       width=12)
    tbl.add_column("Message",    min_width=40)

    for a in alerts:
        sev_text = Text(a.severity.upper(), style=_SEV_COLOR.get(a.severity, "white"))
        det_text = Text(a.detector, style=_DET_COLOR.get(a.detector, "white"))
        tbl.add_row(
            f"{a.timestamp:.3f}",
            a.id_str,
            sev_text,
            det_text,
            a.message,
        )

    console.print(tbl)


def _detector_summary(result: AnalysisResult, console: Console) -> None:
    from collections import Counter
    counts: Counter = Counter(a.detector for a in result.alerts)
    if not counts:
        return

    tbl = Table(
        title="Detector Summary",
        box=box.SIMPLE_HEAD,
        title_style="bold cyan",
        show_lines=False,
    )
    tbl.add_column("Detector",   style="cyan",  min_width=14)
    tbl.add_column("Alerts",     justify="right", width=8)

    for det in ("frequency", "timing", "replay", "payload", "unknown_id"):
        n = counts.get(det, 0)
        tbl.add_row(
            Text(det, style=_DET_COLOR.get(det, "white")),
            str(n) if n else Text("0", style="dim"),
        )

    console.print(tbl)
