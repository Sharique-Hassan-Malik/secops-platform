"""Joins browser fingerprint analysis to the platform as a monitor.

Fingerprinting is reconnaissance, and its severity is measured in bits: a
fingerprint carrying 20 bits of entropy singles a visitor out of a million.
So the events here are graded by how identifying the surface actually is,
measured over a corpus, rather than by a rule that says "canvas fingerprinting
is bad".

Individual visitors are emitted as their own events keyed by IP, so a highly
identifying visitor can correlate with anything else seen from that origin —
which is the `recon-then-exploit` pattern.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE.parents[1]):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from analysis.entropy import entropy_summary  # noqa: E402
from secops.core.event import Category, Event, SensorResult, Severity  # noqa: E402
from secops.core.sensor import Sensor, spec  # noqa: E402

# Bits of entropy in the whole surface. 33 bits singles out one person on
# Earth; 20 singles one out of a million.
_UNIQUE_BITS = 33.0
_IDENTIFYING_BITS = 20.0


def _severity(bits: float) -> Severity:
    if bits >= _UNIQUE_BITS:
        return Severity.HIGH
    if bits >= _IDENTIFYING_BITS:
        return Severity.MEDIUM
    if bits >= 10:
        return Severity.LOW
    return Severity.INFO


class FingerprintSensor(Sensor):
    def observe(self, target: Any, **options: Any) -> SensorResult:
        rows = _rows(target)
        result = self.result(str(options.get("label", "fingerprint corpus")))
        if not rows:
            result.skipped = "no fingerprint rows supplied"
            return result

        summary = entropy_summary(rows)
        total = float(summary["total_bits"])

        result.emit(
            Event(
                sensor=self.name,
                category=Category.RECON,
                severity=_severity(total),
                title="fingerprint_surface_entropy",
                message=(
                    f"{total:.1f} bits across {summary['n_fingerprints']} fingerprints — "
                    f"an anonymity set of about "
                    f"{summary['anonymity_set_upper']:,.0f}. "
                    f"33 bits identifies one person on Earth."
                ),
                entity=str(options.get("label", "fingerprint corpus")),
                score=min(total / _UNIQUE_BITS, 1.0),
                fields={"group_totals": summary["group_totals"]},
            )
        )

        # The features doing the identifying — the ones worth removing first.
        for feature in summary["features"][:5]:
            if feature["entropy_bits"] < 1.0:
                continue
            result.emit(
                Event(
                    sensor=self.name,
                    category=Category.RECON,
                    severity=Severity.LOW,
                    title=f"identifying_feature:{feature['feature']}",
                    message=(
                        f"{feature['entropy_bits']:.2f} bits from "
                        f"{feature['n_unique']} distinct values "
                        f"({feature['coverage']:.0%} coverage)."
                    ),
                    entity=str(options.get("label", "fingerprint corpus")),
                    score=feature["entropy_bits"] / max(total, 1e-9),
                    fields={"group": feature["group"]},
                )
            )

        # Per-visitor events, so an origin can correlate with other sensors.
        for row in rows:
            source = str(row.get("source_ip") or row.get("ip") or "")
            if not source:
                continue
            result.emit(
                Event(
                    sensor=self.name,
                    category=Category.RECON,
                    severity=_severity(total),
                    title="visitor_fingerprinted",
                    message=f"Fingerprint captured from {source}.",
                    entity=source,
                    fields={"user_agent": str(row.get("user_agent", ""))[:120]},
                )
            )

        result.metrics.update({
            "fingerprints": summary["n_fingerprints"],
            "total_bits": total,
            "anonymity_set": summary["anonymity_set_upper"],
        })
        return result


def _rows(target: Any) -> list[dict]:
    """Accept a list of fingerprint dicts, or a path to a JSON array of them."""
    if isinstance(target, list):
        return [r for r in target if isinstance(r, dict)]
    if isinstance(target, dict):
        return [target]
    path = Path(str(target))
    if path.is_file() and path.suffix.lower() == ".json":
        import json

        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, list) else [loaded]
    return []


SENSOR = FingerprintSensor(spec("browser-fingerprinting"))
