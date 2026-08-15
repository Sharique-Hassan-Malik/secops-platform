"""Joins acoustic keystroke recovery to the platform as a simulator.

A red-team sensor. It answers one question — how much of what someone typed
comes back from the sound of the keyboard — and the answer is the severity.
Character accuracy is the score, because "recovered 8% of keystrokes" and
"recovered 80%" are different findings about the same microphone permission.
Without a reference text there is nothing to score against, so the model's own
confidence is reported instead — labelled as confidence, never as accuracy.

The trained model and captured audio are supplied by the caller; without them
the sensor skips and says so rather than reporting a clean result.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE / "host", _HERE.parents[1]):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from secops.core.event import Category, Event, SensorResult, Severity  # noqa: E402
from secops.core.sensor import Sensor, spec  # noqa: E402


def _severity(accuracy: float) -> Severity:
    if accuracy >= 0.60:
        return Severity.CRITICAL
    if accuracy >= 0.35:
        return Severity.HIGH
    if accuracy >= 0.15:
        return Severity.MEDIUM
    return Severity.LOW


class AcousticSensor(Sensor):
    def observe(self, target: Any, **options: Any) -> SensorResult:
        result = self.result(str(target or "keystroke audio"))

        model_path = options.get("model")
        if not model_path or not Path(str(model_path)).exists():
            result.skipped = (
                "needs a trained keystroke model — pass model=<path>; "
                "train one with `python host/train.py`"
            )
            return result

        try:
            from offline import classify_recording
        except ImportError as exc:
            result.skipped = f"inference pipeline unavailable ({exc})"
            return result

        recovered = classify_recording(str(target), str(model_path))
        if not recovered:
            result.skipped = "no keystroke onsets found in the audio"
            return result

        text = "".join(character for character, _ in recovered)
        mean_confidence = sum(c for _, c in recovered) / len(recovered)

        truth = str(options.get("truth", ""))
        if truth:
            accuracy = sum(1 for a, b in zip(text, truth) if a == b) / len(truth)
        else:
            # No reference text: the model's own confidence is the only measure
            # available, and it is reported as such rather than as accuracy.
            accuracy = mean_confidence

        result.emit(
            Event(
                sensor=self.name,
                category=Category.SIDE_CHANNEL,
                severity=_severity(accuracy),
                title="keystrokes_recovered",
                message=(
                    f"{len(recovered)} keystrokes recovered from audio; "
                    + (f"{accuracy:.0%} character accuracy against the reference."
                       if truth else
                       f"mean model confidence {mean_confidence:.0%} (no reference "
                       f"text supplied, so this is confidence, not accuracy).")
                ),
                entity=str(target),
                score=accuracy,
                fields={
                    "keystrokes": len(recovered),
                    "recovered_text": text[:120],
                    "mean_confidence": round(mean_confidence, 4),
                    "scored_against_reference": bool(truth),
                },
            )
        )
        result.metrics.update({
            "keystrokes": len(recovered),
            "mean_confidence": round(mean_confidence, 4),
            "measure": "accuracy" if truth else "confidence",
        })
        return result


SENSOR = AcousticSensor(spec("acoustic-keylogger"))
