"""What a sensor has to implement, and the registry of the ones that exist.

The manifest is static data. Reading it imports nothing, so `secops sensors`
and a scan of a zip file both work on a host with no numpy, no scipy and no
FastAPI — and a sensor whose dependencies are missing is listed as such rather
than taking the process down on import.

Loading is by file path: each module folder under `modules/` is its own source
root, so it goes on `sys.path` and its `integration.py` is imported under a
unique key. That is the same import path the sensor gets when run standalone
from its own directory.
"""

from __future__ import annotations

import importlib.util
import sys
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .event import Category, Kind, SensorResult

MODULES_ROOT = Path(__file__).resolve().parents[2] / "modules"


@dataclass(frozen=True)
class SensorSpec:
    name: str
    kind: Kind
    title: str
    summary: str
    categories: tuple[Category, ...] = ()
    requires: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()

    @property
    def folder(self) -> str:
        return self.name

    def handles(self, path: Path) -> bool:
        """Whether this scanner claims a file. No extensions means any file."""
        if not self.extensions:
            return True
        return path.suffix.lower() in self.extensions


MANIFEST: tuple[SensorSpec, ...] = (
    SensorSpec(
        name="zipbomb-detector",
        kind=Kind.SCANNER,
        title="Archive bomb detector",
        summary="Reads archive metadata to find compression ratios and nesting "
                "depth that would exhaust a host on extraction — without extracting.",
        categories=(Category.AVAILABILITY, Category.MALWARE),
        extensions=(".zip", ".gz", ".bz2", ".xz", ".tar", ".jar", ".apk", ".docx", ".xlsx"),
    ),
    SensorSpec(
        name="steganography-detector",
        kind=Kind.SCANNER,
        title="Steganography detector",
        summary="Chi-square, RS analysis, sample-pair and DCT tests for payloads "
                "hidden in image least-significant bits.",
        categories=(Category.EVASION, Category.EXFILTRATION),
        requires=("numpy", "PIL"),
        extensions=(".png", ".bmp", ".jpg", ".jpeg", ".gif", ".tiff"),
    ),
    SensorSpec(
        name="bytecode-analyzer",
        kind=Kind.SCANNER,
        title="Python bytecode analyzer",
        summary="Disassembles .pyc without importing it, reconstructs control "
                "flow and flags obfuscation and dangerous call patterns.",
        categories=(Category.MALWARE, Category.EVASION),
        extensions=(".pyc", ".pyo"),
    ),
    SensorSpec(
        name="can-ids",
        kind=Kind.MONITOR,
        title="CAN bus intrusion detection",
        summary="Timing, entropy and message-sequence analysis over a CAN "
                "capture, for injection, flooding and replay.",
        categories=(Category.INTRUSION,),
        extensions=(".log", ".csv", ".asc", ".blf"),
    ),
    SensorSpec(
        name="browser-fingerprinting",
        kind=Kind.MONITOR,
        title="Browser fingerprint analysis",
        summary="Measures how identifying a browser fingerprint is, in bits of "
                "entropy, and how stably it tracks across visits.",
        categories=(Category.RECON,),
        requires=("numpy",),
    ),
    SensorSpec(
        name="waf",
        kind=Kind.MONITOR,
        title="Web application firewall",
        summary="Rule engine plus a learned classifier over HTTP requests, for "
                "injection, traversal and scanner traffic.",
        categories=(Category.EXPLOIT, Category.RECON),
        requires=("numpy",),
    ),
    SensorSpec(
        name="protocol-fuzzer",
        kind=Kind.SIMULATOR,
        title="Protocol fuzzer",
        summary="Generates malformed HTTP, DNS and MQTT and reports what the "
                "target did with it — crashes, hangs, protocol violations.",
        categories=(Category.EXPLOIT, Category.AVAILABILITY),
    ),
    SensorSpec(
        name="acoustic-keylogger",
        kind=Kind.SIMULATOR,
        title="Acoustic keystroke recovery",
        summary="Recovers typed characters from keystroke audio — the attack a "
                "microphone permission actually buys.",
        categories=(Category.SIDE_CHANNEL, Category.EXFILTRATION),
        requires=("numpy",),
    ),
    SensorSpec(
        name="side-channel-aes",
        kind=Kind.SIMULATOR,
        title="AES power side channel",
        summary="Correlation power analysis against a simulated AES device, "
                "with and without masking, recovering the key byte by byte.",
        categories=(Category.SIDE_CHANNEL,),
        requires=("numpy",),
    ),
)

_BY_NAME = {spec.name: spec for spec in MANIFEST}
_LOADED: dict[str, "Sensor"] = {}


class SensorUnavailable(RuntimeError):
    """The sensor cannot run here — usually a missing dependency."""


class Sensor(ABC):
    """Base for everything in the manifest."""

    def __init__(self, spec: SensorSpec) -> None:
        self.spec = spec

    @property
    def name(self) -> str:
        return self.spec.name

    def result(self, target: str = "") -> SensorResult:
        return SensorResult(sensor=self.spec.name, kind=self.spec.kind, target=target)

    def execute(self, call: Callable[[], SensorResult], target: str = "") -> SensorResult:
        """Run *call*, timing it and turning a crash into a reported error.

        One sensor failing must not cost the operator the other nine. A scan
        that dies on the third file of forty is worse than useless, because it
        looks like it finished.
        """
        started = time.perf_counter()
        try:
            result = call()
        except Exception as exc:  # noqa: BLE001 — deliberate: report, never abort
            result = self.result(target)
            result.error = f"{type(exc).__name__}: {exc}"
            result.metrics["traceback"] = traceback.format_exc(limit=6)
        result.elapsed = time.perf_counter() - started
        return result

    @abstractmethod
    def observe(self, target: Any, **options: Any) -> SensorResult:
        """Look at *target* and emit events."""


def specs(kind: Kind | None = None, names: list[str] | None = None) -> list[SensorSpec]:
    found = list(MANIFEST)
    if kind is not None:
        found = [s for s in found if s.kind is kind]
    if names:
        wanted = {n.strip() for n in names}
        unknown = wanted - set(_BY_NAME)
        if unknown:
            raise KeyError(
                f"unknown sensor(s): {', '.join(sorted(unknown))}. "
                f"Known: {', '.join(sorted(_BY_NAME))}"
            )
        found = [s for s in found if s.name in wanted]
    return found


def spec(name: str) -> SensorSpec:
    try:
        return _BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"unknown sensor {name!r}") from exc


def missing_requirements(spec_: SensorSpec) -> list[str]:
    return [r for r in spec_.requires if importlib.util.find_spec(r) is None]


def available(spec_: SensorSpec) -> bool:
    return not missing_requirements(spec_)


def sensor_path(name: str) -> Path:
    """Where a sensor lives, so one can find a sibling without hardcoding."""
    return MODULES_ROOT / spec(name).folder


def load(name: str) -> Sensor:
    if name in _LOADED:
        return _LOADED[name]

    spec_ = spec(name)
    absent = missing_requirements(spec_)
    if absent:
        raise SensorUnavailable(
            f"{name} needs {', '.join(absent)} — "
            f"install with `pip install -r modules/{name}/requirements.txt`"
        )

    folder = MODULES_ROOT / spec_.folder
    entry = folder / "integration.py"
    if not entry.is_file():
        raise SensorUnavailable(f"{name} has no integration.py at {entry}")

    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

    unique = f"secops._sensors.{name.replace('-', '_')}"
    file_spec = importlib.util.spec_from_file_location(unique, entry)
    if file_spec is None or file_spec.loader is None:
        raise SensorUnavailable(f"could not load {entry}")
    imported = importlib.util.module_from_spec(file_spec)
    sys.modules[unique] = imported
    file_spec.loader.exec_module(imported)

    instance = getattr(imported, "SENSOR", None)
    if instance is None:
        raise SensorUnavailable(f"{entry} defines no SENSOR")
    _LOADED[name] = instance
    return instance
