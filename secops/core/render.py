"""One output format for ten sensors.

Per-sensor reporters — coloured tables, an HTML page, a JSON dump, a bare print
— are not merely untidy: an analyst comparing a stego finding against a bytecode
finding then reads two severity vocabularies in two layouts, and a correlation
between them is invisible because nothing renders it.

Severity never travels as colour alone. Every level carries a distinct glyph
and its written name, which is what keeps the output readable for a
colour-blind analyst, in a printed incident report, and in a CI log that has
stripped the ANSI codes.
"""

from __future__ import annotations

import html
import sys
from typing import Any, Sequence

from .event import Alert, Report, SensorResult, Severity

# Status hexes are fixed by the palette; INFO and LOW are not status states, so
# they take muted ink and a sequential blue step rather than impersonating one.
_SEV_LIGHT = {
    Severity.INFO: "#52514e",
    Severity.LOW: "#1c5cab",
    Severity.MEDIUM: "#fab219",
    Severity.HIGH: "#ec835a",
    Severity.CRITICAL: "#d03b3b",
}
_GLYPH = {
    Severity.INFO: "i",
    Severity.LOW: "▪",
    Severity.MEDIUM: "▲",
    Severity.HIGH: "◆",
    Severity.CRITICAL: "✖",
}
_ANSI = {
    Severity.INFO: "\033[2m",
    Severity.LOW: "\033[34m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[38;5;209m",
    Severity.CRITICAL: "\033[31;1m",
}

# Eight categorical slots in the fixed order that clears every adjacent-pair
# gate in both themes. Never cycled; a ninth series means faceting instead.
_SERIES = 8
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"


def _tag(severity: Severity, colour: bool) -> str:
    text = f"{_GLYPH[severity]} {severity.value:<8}"
    return f"{_ANSI[severity]}{text}{_RESET}" if colour else text


def render_terminal(report: Report, *, colour: bool | None = None,
                    verbose: bool = False, stream: Any = None) -> None:
    out = stream or sys.stdout
    if colour is None:
        colour = hasattr(out, "isatty") and out.isatty()

    def emit(line: str = "") -> None:
        print(line, file=out)

    emit()
    if report.target:
        emit(f"{_BOLD if colour else ''}── {report.target}{_RESET if colour else ''}")

    for result in report.results:
        _render_result(result, emit, colour, verbose, report.target)

    if report.alerts:
        emit()
        emit(f"  {_BOLD if colour else ''}correlated alerts{_RESET if colour else ''}")
        for alert in report.alerts:
            emit(f"    {_tag(alert.severity, colour)} {alert.rule}  [{alert.entity}]")
            for line in _wrap(alert.description, 82):
                emit(f"{'':>15}{line}")
            emit(f"{'':>15}{_DIM if colour else ''}sensors: "
                 f"{', '.join(alert.sensors)}{_RESET if colour else ''}")

    _render_summary(report, emit, colour)


def _render_result(result: SensorResult, emit: Any, colour: bool, verbose: bool,
                   report_target: str = "") -> None:
    emit()
    # Name the target on the row when a run covers more than one, otherwise
    # a multi-file scan is a list of identical-looking sensor headers.
    where = f"  {result.target}" if result.target and result.target != report_target else ""
    emit(f"  {result.sensor}  {_DIM if colour else ''}({result.kind.value})"
         f"{_RESET if colour else ''}{where}")

    if result.skipped:
        emit(f"    skipped — {result.skipped}")
        return
    if result.error:
        emit(f"    ERROR — {result.error}")
        return

    for key, value in result.metrics.items():
        if key in ("charts", "traceback"):
            continue
        emit(f"    {key:<22} {_fmt(value)}")

    events = result.events if verbose else [
        e for e in result.events if e.severity >= Severity.LOW
    ]
    if not events:
        note = "nothing observed" if not result.events else "nothing at or above LOW"
        emit(f"    {_tag(Severity.INFO, colour)} {note}")
        return

    for event in sorted(events, key=lambda e: (-e.severity.rank, e.title))[:40]:
        emit(f"    {_tag(event.severity, colour)} {event.title}"
             f"{'  ' + event.entity if event.entity != result.target else ''}")
        if event.message:
            for line in _wrap(event.message, 82):
                emit(f"{'':>15}{line}")
    if len(events) > 40:
        emit(f"{'':>15}… {len(events) - 40} more")


def _render_summary(report: Report, emit: Any, colour: bool) -> None:
    counts = {s: n for s, n in report.counts().items() if n}
    emit()
    emit(f"  {'─' * 60}")
    worst = report.max_severity
    emit(f"  worst     {_tag(worst, colour)}")
    parts = " ".join(f"{_GLYPH[s]} {s.value.lower()} {n}"
                     for s, n in sorted(counts.items(), key=lambda kv: -kv[0].rank))
    emit(f"  events    {len(report.events)}   {parts}")
    emit(f"  alerts    {len(report.alerts)}")
    if report.errors:
        emit(f"  errors    {len(report.errors)} sensor(s) failed to run")
    emit()


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, (list, tuple)):
        return f"{len(value)} item(s)"
    if isinstance(value, dict):
        return ", ".join(f"{k}={_fmt(v)}" for k, v in list(value.items())[:4])
    return str(value)


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


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def svg_bars(values: dict[str, float], *, width: int = 560, height: int = 190,
             label: str = "") -> str:
    """A horizontal bar per category. Bars start at a shared baseline, are
    4px-rounded at the data end only, and every bar is labelled — the count is
    beside the bar, so nothing depends on reading a length against an axis."""
    if not values:
        return ""
    rows = list(values.items())[:_SERIES]
    top, left, right = 12, 150, 56
    row_h = max(18, (height - top - 20) // max(len(rows), 1))
    plot_w = width - left - right
    biggest = max(v for _, v in rows) or 1

    body = ""
    for index, (name, value) in enumerate(rows):
        y = top + index * row_h
        bar_w = max(2.0, plot_w * value / biggest)
        colour = f"var(--series-{index + 1})"
        body += (
            f'<text x="{left - 10}" y="{y + row_h / 2 + 4:.0f}" text-anchor="end" '
            f'font-size="11" fill="var(--text-secondary)">{html.escape(name)}</text>'
            f'<rect x="{left}" y="{y + 3:.0f}" width="{bar_w:.1f}" '
            f'height="{row_h - 8}" rx="4" fill="{colour}"/>'
            f'<text x="{left + bar_w + 8:.1f}" y="{y + row_h / 2 + 4:.0f}" '
            f'font-size="11" fill="var(--text-secondary)">{value:g}</text>'
        )
    caption = (
        f'<text x="{left}" y="{height - 4}" font-size="10" fill="var(--text-muted)">'
        f"{html.escape(label)}</text>" if label else ""
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width:{width}px" '
        f'role="img" xmlns="http://www.w3.org/2000/svg">{body}{caption}</svg>'
    )


_CSS = """
:root {
  color-scheme: light;
  --surface-0:#f4f3f1; --surface-1:#fcfcfb; --border:#dedcd6;
  --text-primary:#0b0b0b; --text-secondary:#52514e; --text-muted:#77756f;
  --series-1:#2a78d6; --series-2:#eb6834; --series-3:#1baf7a; --series-4:#eda100;
  --series-5:#e87ba4; --series-6:#008300; --series-7:#4a3aa7; --series-8:#e34948;
  --sev-info:#52514e; --sev-low:#1c5cab; --sev-medium:#fab219;
  --sev-high:#ec835a; --sev-critical:#d03b3b;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --surface-0:#121211; --surface-1:#1a1a19; --border:#333330;
    --text-primary:#fff; --text-secondary:#c3c2b7; --text-muted:#918f86;
    --series-1:#3987e5; --series-2:#d95926; --series-3:#199e70; --series-4:#c98500;
    --series-5:#d55181; --series-6:#008300; --series-7:#9085e9; --series-8:#e66767;
    --sev-info:#c3c2b7; --sev-low:#6da7ec;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --surface-0:#121211; --surface-1:#1a1a19; --border:#333330;
  --text-primary:#fff; --text-secondary:#c3c2b7; --text-muted:#918f86;
  --series-1:#3987e5; --series-2:#d95926; --series-3:#199e70; --series-4:#c98500;
  --series-5:#d55181; --series-6:#008300; --series-7:#9085e9; --series-8:#e66767;
  --sev-info:#c3c2b7; --sev-low:#6da7ec;
}
* { box-sizing: border-box; }
body { margin:0; padding:32px 24px; background:var(--surface-0); color:var(--text-primary);
       font:15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:1080px; margin:0 auto; }
h1 { font-size:1.35rem; margin:0 0 4px; }
h2 { font-size:1rem; margin:30px 0 10px; font-weight:600; }
.sub { color:var(--text-secondary); font-size:.85rem; margin:0 0 24px; }
.cards { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:12px; }
.card { background:var(--surface-1); border:1px solid var(--border); border-radius:10px;
        padding:14px 20px; min-width:120px; }
.card .k { font-size:.7rem; letter-spacing:.07em; text-transform:uppercase; color:var(--text-muted); }
.card .v { font-size:1.5rem; font-weight:650; margin-top:3px; }
.panel { background:var(--surface-1); border:1px solid var(--border); border-radius:10px;
         padding:4px 0; overflow-x:auto; margin-bottom:10px; }
table { width:100%; border-collapse:collapse; font-size:.85rem; min-width:640px; }
th { text-align:left; padding:10px 16px; font-size:.7rem; font-weight:600; letter-spacing:.07em;
     text-transform:uppercase; color:var(--text-muted); }
td { padding:9px 16px; border-top:1px solid var(--border); vertical-align:top; }
td.ent { color:var(--text-secondary); font-family:ui-monospace,Menlo,monospace;
         font-size:.78rem; word-break:break-all; }
.sev { font-weight:600; white-space:nowrap; }
.glyph { display:inline-block; width:1.1em; }
.meta { display:flex; gap:20px; flex-wrap:wrap; font-size:.8rem; color:var(--text-secondary);
        padding:10px 16px; }
.meta b { color:var(--text-primary); font-weight:600; }
.empty { padding:14px 16px; color:var(--text-secondary); font-size:.85rem; }
.alert { padding:12px 16px; border-top:1px solid var(--border); }
.alert:first-child { border-top:none; }
.alert .rule { font-weight:650; }
.alert .why { color:var(--text-secondary); font-size:.85rem; margin-top:3px; }
.alert .from { color:var(--text-muted); font-size:.75rem; margin-top:5px; }
.chart { padding:12px 16px; }
"""


def _sev_html(severity: Severity) -> str:
    return (f'<span class="sev" style="color:var(--sev-{severity.value.lower()})">'
            f'<span class="glyph">{_GLYPH[severity]}</span>{severity.value}</span>')


def render_html(report: Report, *, title: str = "Security operations report") -> str:
    counts = {s: n for s, n in report.counts().items() if n}
    worst = report.max_severity

    cards = [("Worst", f'<span style="color:var(--sev-{worst.value.lower()})">'
                       f"{_GLYPH[worst]} {worst.value}</span>"),
             ("Events", str(len(report.events))),
             ("Alerts", str(len(report.alerts))),
             ("Sensors", str(len(report.results)))]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
        if counts.get(sev):
            cards.append((sev.value.title(),
                          f'<span style="color:var(--sev-{sev.value.lower()})">'
                          f"{counts[sev]}</span>"))

    card_html = "".join(
        f'<div class="card"><div class="k">{html.escape(k)}</div><div class="v">{v}</div></div>'
        for k, v in cards
    )

    per_sensor = {}
    for result in report.results:
        if result.events:
            per_sensor[result.sensor] = len(result.events)
    chart = svg_bars(per_sensor, label="events by sensor") if per_sensor else ""

    alerts_html = ""
    if report.alerts:
        rows = "".join(
            f'<div class="alert"><div class="rule">{_sev_html(a.severity)} &nbsp;'
            f"{html.escape(a.rule)} &nbsp;<span class='ent'>{html.escape(a.entity)}</span></div>"
            f'<div class="why">{html.escape(a.description)}</div>'
            f'<div class="from">sensors: {html.escape(", ".join(a.sensors))} · '
            f"{len(a.events)} event(s)</div></div>"
            for a in report.alerts
        )
        alerts_html = f"<h2>Correlated alerts</h2><div class='panel'>{rows}</div>"

    sections = "".join(_render_sensor_html(r) for r in report.results)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>{html.escape(title)}</h1>
<p class="sub">{html.escape(report.target or "multiple targets")}
 &nbsp;·&nbsp; {html.escape(report.timestamp)}</p>
<div class="cards">{card_html}</div>
{f'<div class="panel"><div class="chart">{chart}</div></div>' if chart else ''}
{alerts_html}
{sections}
</main>
</body>
</html>
"""


def _render_sensor_html(result: SensorResult) -> str:
    head = (f"<h2>{html.escape(result.sensor)} "
            f'<span style="color:var(--text-muted);font-weight:400">'
            f"· {result.kind.value}</span></h2>")

    if result.skipped:
        return head + f'<div class="panel"><div class="empty">Skipped — {html.escape(result.skipped)}</div></div>'
    if result.error:
        return head + f'<div class="panel"><div class="empty">Error — {html.escape(result.error)}</div></div>'

    blocks = []
    scalars = {k: v for k, v in result.metrics.items() if k not in ("charts", "traceback")}
    if scalars:
        blocks.append('<div class="meta">' + "".join(
            f"<span>{html.escape(str(k))} <b>{html.escape(_fmt(v))}</b></span>"
            for k, v in scalars.items()) + "</div>")

    if result.events:
        rows = "".join(
            "<tr>"
            f"<td>{_sev_html(e.severity)}</td>"
            f"<td>{html.escape(e.category.value)}</td>"
            f"<td><b>{html.escape(e.title)}</b></td>"
            f'<td class="ent">{html.escape(e.entity)}</td>'
            f"<td>{html.escape(e.message)}</td>"
            "</tr>"
            for e in sorted(result.events, key=lambda e: (-e.severity.rank, e.title))[:200]
        )
        blocks.append("<table><thead><tr><th>Severity</th><th>Category</th><th>Event</th>"
                      f"<th>Entity</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>")
    else:
        blocks.append('<div class="empty">Nothing observed.</div>')

    return head + '<div class="panel">' + "".join(blocks) + "</div>"


def events_table_text(events: Sequence) -> str:
    """Plain-text table — the accessible fallback the colour rules require."""
    lines = [f"{'SEVERITY':<10} {'SENSOR':<24} {'ENTITY':<30} TITLE"]
    for event in sorted(events, key=lambda e: -e.severity.rank):
        lines.append(f"{event.severity.value:<10} {event.sensor[:23]:<24} "
                     f"{event.entity[:29]:<30} {event.title}")
    return "\n".join(lines)
