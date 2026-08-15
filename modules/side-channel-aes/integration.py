"""Joins the AES power side channel to the platform as a simulator.

This is a red-team sensor: it does not detect anything, it *demonstrates* what
a power trace gives away. Its events are severity-graded by how much of the key
came back, and the masked device is run alongside the vulnerable one so the
countermeasure is measured rather than asserted.

Running it beside the monitoring sensors is what makes
`simulated-attack-went-undetected` meaningful — a successful key recovery that
nothing else in the stack noticed is a gap in coverage.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE.parents[1]):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import numpy as np  # noqa: E402

from attack.cpa import attack  # noqa: E402
from secops.core.event import Category, Event, SensorResult, Severity  # noqa: E402
from secops.core.sensor import Sensor, spec  # noqa: E402
from sim.device import MaskedDevice, VulnerableDevice  # noqa: E402


def _severity(recovered: int) -> Severity:
    if recovered == 16:
        return Severity.CRITICAL
    if recovered >= 8:
        return Severity.HIGH
    if recovered >= 2:
        return Severity.MEDIUM
    return Severity.INFO


class SideChannelSensor(Sensor):
    def observe(self, target: Any, **options: Any) -> SensorResult:
        traces = int(options.get("traces", 400))
        seed = int(options.get("seed", 0))
        result = self.result(str(target or "simulated AES device"))

        rng = np.random.default_rng(seed)
        key = bytes(rng.integers(0, 256, 16, dtype=np.uint8))

        for label, device_cls in (("unprotected", VulnerableDevice),
                                  ("masked", MaskedDevice)):
            # Each device gets its own generator seeded identically, so the
            # masked and unprotected runs see the same plaintexts and the
            # comparison is about the countermeasure, not the inputs.
            device = device_cls(key=key, rng=np.random.default_rng(seed + 1))
            plaintexts, power = device.collect(traces)
            recovered, correlations = attack(plaintexts, power)
            correct = sum(1 for a, b in zip(recovered, key) if a == b)

            severity = _severity(correct)
            if label == "masked" and correct < 8:
                # The countermeasure working is worth recording, not alerting.
                severity = Severity.INFO

            result.emit(
                Event(
                    sensor=self.name,
                    category=Category.SIDE_CHANNEL,
                    severity=severity,
                    title=f"cpa_{label}",
                    message=(
                        f"{correct}/16 key bytes recovered from {traces} power traces "
                        f"against the {label} device "
                        f"(peak correlation {float(correlations.max()):.3f})."
                    ),
                    entity=f"aes-device:{label}",
                    score=correct / 16,
                    fields={
                        "traces": traces,
                        "bytes_recovered": correct,
                        "peak_correlation": round(float(correlations.max()), 4),
                    },
                )
            )
            result.metrics[f"{label}_bytes_recovered"] = correct

        result.metrics["traces"] = traces
        return result


SENSOR = SideChannelSensor(spec("side-channel-aes"))
