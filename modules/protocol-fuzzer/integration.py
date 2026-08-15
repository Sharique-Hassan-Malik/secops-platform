"""Joins the protocol fuzzer to the platform as a simulator.

Red-team, and it needs a target: fuzzing requires something listening, so
without `host`/`port` the sensor skips rather than pretending. Severity comes
from the crash kind, because the kinds are not equally serious — a 5xx is a
bug, a connection that stops accepting anything is an outage.

Crashes are deduplicated by the engine, so each event is a distinct signature
rather than the thousandth repeat of one bug.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _path in (_HERE, _HERE.parents[1]):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from fuzzer_config import CrashKind, FuzzerConfig, FuzzTarget, Protocol  # noqa: E402
from fuzzer.engine import FuzzEngine  # noqa: E402
from secops.core.event import Category, Event, SensorResult, Severity  # noqa: E402
from secops.core.sensor import Sensor, spec  # noqa: E402

_SEVERITY = {
    CrashKind.CONNECTION_REFUSED: Severity.CRITICAL,   # the service stopped serving
    CrashKind.UNEXPECTED_CLOSE: Severity.HIGH,
    CrashKind.TIMEOUT: Severity.HIGH,
    CrashKind.EXCEPTION: Severity.HIGH,
    CrashKind.SERVER_ERROR: Severity.MEDIUM,           # handled badly, still handled
    CrashKind.MALFORMED_RESPONSE: Severity.MEDIUM,
}

_CATEGORY = {
    CrashKind.CONNECTION_REFUSED: Category.AVAILABILITY,
    CrashKind.TIMEOUT: Category.AVAILABILITY,
    CrashKind.UNEXPECTED_CLOSE: Category.AVAILABILITY,
}


def _generator(protocol: Protocol):
    if protocol is Protocol.DNS:
        from protocols.dns_gen import DNSGenerator

        return DNSGenerator()
    if protocol is Protocol.MQTT:
        from protocols.mqtt_gen import MQTTGenerator

        return MQTTGenerator()
    from protocols.http_gen import HTTPGenerator

    return HTTPGenerator()


class ProtocolFuzzerSensor(Sensor):
    def observe(self, target: Any, **options: Any) -> SensorResult:
        host = options.get("host")
        port = options.get("port")
        result = self.result(str(target or f"{host}:{port}"))

        if not host or not port:
            result.skipped = (
                "needs something to fuzz — pass host=<addr> port=<n> "
                "(and protocol=http|dns|mqtt)"
            )
            return result

        protocol = Protocol(str(options.get("protocol", "http")).lower())
        fuzz_target = FuzzTarget(host=str(host), port=int(port), protocol=protocol)
        config = FuzzerConfig(
            iterations=int(options.get("iterations", 200)),
            seed=int(options.get("seed", 0)),
            crash_dir=str(options.get("crash_dir", "./.crashes")),
            corpus_dir=str(options.get("corpus_dir", "./.corpus")),
        )

        engine = FuzzEngine(fuzz_target, config, _generator(protocol))
        session = engine.run()

        for crash in session.crashes:
            result.emit(
                Event(
                    sensor=self.name,
                    category=_CATEGORY.get(crash.kind, Category.EXPLOIT),
                    severity=_SEVERITY.get(crash.kind, Severity.MEDIUM),
                    title=f"fuzz_{crash.kind.value.lower()}",
                    message=(
                        f"{crash.detail or crash.kind.value} at iteration "
                        f"{crash.iteration} via {crash.mutation} mutation."
                    ),
                    entity=f"{host}:{port}",
                    fields={
                        "protocol": protocol.value,
                        "mutation": crash.mutation,
                        "iteration": crash.iteration,
                        "payload_prefix": crash.payload[:48].hex(),
                    },
                )
            )

        result.metrics.update({
            "protocol": protocol.value,
            "iterations": session.iterations,
            "sent": session.sent,
            "unique_crashes": session.unique_crashes,
        })
        return result


SENSOR = ProtocolFuzzerSensor(spec("protocol-fuzzer"))
