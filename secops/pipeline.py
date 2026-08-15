"""Run sensors over targets, correlate what they saw, hand back one report.

A sensor that cannot run here is *skipped and says why*. "Scanned, clean" and
"could not scan" are different answers, and a security tool that blurs them is
worse than one that refuses to start.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from . import correlate
from .core import sensor as registry
from .core.event import Kind, Report, SensorResult


def collect_files(targets: Iterable[str], recursive: bool = False) -> list[Path]:
    """Expand files, directories and globs into a deduplicated file list."""
    found: list[Path] = []
    for target in targets:
        path = Path(target)
        if path.is_file():
            found.append(path)
        elif path.is_dir():
            walk = path.rglob("*") if recursive else path.glob("*")
            found.extend(p for p in walk if p.is_file())
        else:
            root = Path(".")
            matches = root.rglob(target) if "**" in target else root.glob(target)
            found.extend(m for m in matches if m.is_file())

    seen: set[Path] = set()
    unique: list[Path] = []
    for path in found:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def _skipped(spec, target: str, reason: str) -> SensorResult:
    return SensorResult(sensor=spec.name, kind=spec.kind, target=target, skipped=reason)


def run_sensor(spec, target: Any, options: dict[str, Any] | None = None) -> SensorResult:
    absent = registry.missing_requirements(spec)
    if absent:
        return _skipped(spec, str(target), f"needs {', '.join(absent)}")
    try:
        instance = registry.load(spec.name)
    except registry.SensorUnavailable as exc:
        return _skipped(spec, str(target), str(exc))
    return instance.execute(
        lambda: instance.observe(target, **(options or {})), target=str(target)
    )


def scan(
    targets: Iterable[str],
    *,
    recursive: bool = False,
    only: list[str] | None = None,
    options: dict[str, Any] | None = None,
    correlate_events: bool = True,
) -> Report:
    """Run every scanner that claims each file, then correlate across them."""
    paths = collect_files(targets, recursive)
    report = Report(target=str(paths[0]) if len(paths) == 1 else f"{len(paths)} files")

    for path in paths:
        for spec in registry.specs(Kind.SCANNER, only):
            if not spec.handles(path):
                continue
            report.add(run_sensor(spec, path, options))

    if correlate_events:
        report.alerts = correlate.correlate(report.events)
    return report


def observe(
    target: Any,
    *,
    only: list[str] | None = None,
    kind: Kind | None = None,
    options: dict[str, Any] | None = None,
    correlate_events: bool = True,
) -> Report:
    """Run monitors (or a named set of sensors) over one target."""
    report = Report(target=str(target))
    for spec in registry.specs(kind, only):
        report.add(run_sensor(spec, target, options))
    if correlate_events:
        report.alerts = correlate.correlate(report.events)
    return report
