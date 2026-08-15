"""Joins the steganography detector to the platform as a scanner.

Four statistical tests run over the same image and they disagree often — that
is the point of running four. Each test that fires becomes its own event
carrying its own confidence, and the aggregate verdict is reported as a metric
rather than collapsing the tests into one number that hides the disagreement.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE.parents[1]):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from secops.core.event import Category, Event, SensorResult, Severity  # noqa: E402
from secops.core.sensor import Sensor, spec  # noqa: E402
from stegdetect.detector import detect  # noqa: E402

_VERDICT_SEVERITY = {
    "likely_stego": Severity.HIGH,
    "suspicious": Severity.MEDIUM,
    "clean": Severity.INFO,
}


class SteganographySensor(Sensor):
    def observe(self, target: Any, **options: Any) -> SensorResult:
        path = Path(str(target))
        result = self.result(str(path))

        report = detect(path, channels=options.get("channels"))

        for name, method in report.get("methods", {}).items():
            if not method.get("detection"):
                continue
            result.emit(
                Event(
                    sensor=self.name,
                    category=Category.EVASION,
                    severity=Severity.MEDIUM,
                    title=f"stego_{name}",
                    message=_describe(name, method),
                    entity=str(path),
                    score=_confidence(method),
                    fields={k: v for k, v in method.items() if k != "detection"},
                )
            )

        verdict = report.get("verdict", "clean")
        if verdict != "clean":
            result.emit(
                Event(
                    sensor=self.name,
                    category=Category.EXFILTRATION,
                    severity=_VERDICT_SEVERITY[verdict],
                    title=f"hidden_payload_{verdict}",
                    message=(
                        f"{report['n_detected']} of {report['n_methods']} independent "
                        f"tests indicate embedded data."
                    ),
                    entity=str(path),
                    score=report.get("score"),
                    fields={"detections": report.get("detections", [])},
                )
            )

        result.metrics.update({
            "file_type": report.get("file_type", "?"),
            "tests_run": report.get("n_methods", 0),
            "tests_fired": report.get("n_detected", 0),
            "verdict": verdict,
        })
        return result


def _describe(name: str, method: dict) -> str:
    for key in ("message", "detail", "description"):
        if method.get(key):
            return str(method[key])
    numbers = ", ".join(
        f"{k}={v:.4g}" for k, v in method.items()
        if isinstance(v, (int, float)) and k != "detection"
    )
    return f"{name} test fired" + (f" ({numbers})" if numbers else "")


def _confidence(method: dict) -> float | None:
    for key in ("confidence", "score", "p_value"):
        if isinstance(method.get(key), (int, float)):
            return float(method[key])
    return None


SENSOR = SteganographySensor(spec("steganography-detector"))
