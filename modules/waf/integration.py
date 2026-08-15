"""Joins the web application firewall to the platform as a monitor.

The WAF's two halves disagree on purpose — a rule engine that knows exactly
what SQL injection looks like, and a classifier that recognises requests
unlike anything legitimate. Both verdicts are emitted, because a request only
the classifier objects to is a different operational decision from one that
tripped a signature.

The entity is the source IP, so a WAF event can correlate with reconnaissance
seen by another sensor against the same origin.
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
from waf.rules.engine import RuleEngine  # noqa: E402


def _severity(score: int) -> Severity:
    if score >= 15:
        return Severity.CRITICAL
    if score >= 10:
        return Severity.HIGH
    if score >= 5:
        return Severity.MEDIUM
    return Severity.LOW


class WafSensor(Sensor):
    def __init__(self, sensor_spec) -> None:
        super().__init__(sensor_spec)
        self.engine = RuleEngine()
        self._classifier = None

    def _classify(self, request: dict) -> float | None:
        """Model score, if a trained model is available. Absent is not zero."""
        if self._classifier is False:
            return None
        if self._classifier is None:
            try:
                from waf.ml.classifier import RequestClassifier

                self._classifier = RequestClassifier()
            except Exception:  # noqa: BLE001 — unavailable model is not an error
                self._classifier = False
                return None
        try:
            return float(self._classifier.score(request))
        except Exception:  # noqa: BLE001
            return None

    def observe(self, target: Any, **options: Any) -> SensorResult:
        requests = target if isinstance(target, list) else [target]
        result = self.result(str(options.get("label", "http requests")))

        inspected = 0
        blocked = 0
        for request in requests:
            if not isinstance(request, dict):
                continue
            inspected += 1
            verdict = self.engine.inspect(request)
            source = str(request.get("source_ip") or request.get("remote_addr") or "unknown")

            if verdict.matches:
                blocked += 1
                result.emit(
                    Event(
                        sensor=self.name,
                        category=Category.EXPLOIT,
                        severity=_severity(verdict.score),
                        title=verdict.primary_category or "rule_match",
                        message="; ".join(m.message for m in verdict.matches[:3]),
                        entity=source,
                        score=float(verdict.score),
                        fields={
                            "path": request.get("path", ""),
                            "method": request.get("method", ""),
                            "rules": [m.rule_id for m in verdict.matches][:8],
                        },
                    )
                )

            model_score = self._classify(request)
            if model_score is not None and model_score >= 0.8 and not verdict.matches:
                result.emit(
                    Event(
                        sensor=self.name,
                        category=Category.EXPLOIT,
                        severity=Severity.MEDIUM,
                        title="anomalous_request",
                        message=(
                            f"No signature matched, but the classifier scores this "
                            f"{model_score:.2f} — unlike legitimate traffic."
                        ),
                        entity=source,
                        score=model_score,
                        fields={"path": request.get("path", "")},
                    )
                )

        result.metrics.update({"requests": inspected, "rule_hits": blocked})
        return result


SENSOR = WafSensor(spec("waf"))
