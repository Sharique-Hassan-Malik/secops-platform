"""Cross-sensor tests — what is only true because these ten are one platform.

Each sensor's own behaviour is tested inside its own folder. What is tested
here is the contract between them: that the manifest matches what is on disk,
that every sensor reports in the shared vocabulary, that correlation fires only
when it should, and that a sensor still runs from its own directory.
"""

from __future__ import annotations

import json
import os
import pickle
import py_compile
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from secops import correlate, pipeline, sink  # noqa: E402
from secops.core import sensor as registry  # noqa: E402
from secops.core.event import (  # noqa: E402
    Alert, Category, Event, Kind, Report, SensorResult, Severity,
)
from secops.core.render import render_html, render_terminal  # noqa: E402


@pytest.fixture(scope="session")
def artifacts(tmp_path_factory) -> Path:
    """A directory with one hostile artifact per file scanner."""
    root = tmp_path_factory.mktemp("artifacts")

    with zipfile.ZipFile(root / "bomb.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.bin", b"\0" * (64 * 1024 * 1024))
    with zipfile.ZipFile(root / "ok.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("notes.txt", b"nothing to see here")

    source = root / "sneaky.py"
    source.write_text(
        "import base64\n"
        "def go():\n"
        "    exec(base64.b64decode('cHJpbnQoMSk='))\n"
    )
    py_compile.compile(str(source), cfile=str(root / "sneaky.pyc"), doraise=True)
    source.unlink()

    return root


def _event(sensor: str, category: Category, severity: Severity,
           entity: str, title: str = "t", timestamp: str = "2026-08-15T10:00:00Z") -> Event:
    return Event(sensor=sensor, category=category, severity=severity,
                 title=title, entity=entity, timestamp=timestamp)


class TestManifest:
    def test_every_sensor_has_a_folder_readme_and_integration(self):
        for spec in registry.MANIFEST:
            folder = registry.MODULES_ROOT / spec.folder
            assert folder.is_dir(), f"{spec.name} has no folder"
            assert (folder / "README.md").is_file(), f"{spec.name} has no README"
            assert (folder / "integration.py").is_file(), f"{spec.name} has no integration.py"

    def test_the_siem_is_present_even_though_it_is_not_a_sensor(self):
        assert (registry.MODULES_ROOT / "siem").is_dir()

    def test_names_are_unique(self):
        names = [s.name for s in registry.MANIFEST]
        assert len(names) == len(set(names))

    def test_no_two_modules_claim_the_same_top_level_module_name(self):
        """The collision that only appears once they share a process.

        Three of these shipped a top-level `config.py`; whichever imported
        first won `sys.modules["config"]` and the others silently got the wrong
        settings.
        """
        seen: dict[str, str] = {}
        for module in sorted(p for p in registry.MODULES_ROOT.iterdir() if p.is_dir()):
            for entry in module.glob("*.py"):
                if entry.stem in ("integration", "__init__"):
                    continue
                assert entry.stem not in seen, (
                    f"{module.name}/{entry.name} collides with "
                    f"{seen[entry.stem]} on the top-level name {entry.stem!r}"
                )
                seen[entry.stem] = f"{module.name}/{entry.name}"

    def test_unknown_sensor_is_a_clear_error(self):
        with pytest.raises(KeyError, match="unknown sensor"):
            registry.spec("nope")


class TestLoading:
    @pytest.mark.parametrize("spec", registry.MANIFEST, ids=lambda s: s.name)
    def test_sensor_loads_and_is_a_sensor(self, spec):
        if registry.missing_requirements(spec):
            pytest.skip(f"{spec.name} needs {registry.missing_requirements(spec)}")
        instance = registry.load(spec.name)
        assert isinstance(instance, registry.Sensor)
        assert instance.spec.name == spec.name

    def test_reading_the_manifest_imports_nothing(self):
        before = set(sys.modules)
        registry.specs()
        leaked = {m for m in set(sys.modules) - before if m.startswith("secops._sensors")}
        assert not leaked


class TestScanning:
    def test_archive_bomb_is_critical(self, artifacts):
        report = pipeline.scan([str(artifacts / "bomb.zip")])
        assert report.max_severity is Severity.CRITICAL
        assert report.exit_code == 1

    def test_benign_archive_is_quiet(self, artifacts):
        report = pipeline.scan([str(artifacts / "ok.zip")])
        assert report.max_severity < Severity.MEDIUM

    def test_obfuscated_bytecode_is_flagged(self, artifacts):
        report = pipeline.scan([str(artifacts / "sneaky.pyc")])
        titles = {e.title for e in report.events}
        assert "EXEC_EVAL_USE" in titles

    def test_every_event_carries_provenance(self, artifacts):
        report = pipeline.scan([str(artifacts)])
        assert report.events
        for event in report.events:
            assert event.sensor
            assert event.entity

    def test_scanners_only_see_files_they_claim(self, artifacts):
        report = pipeline.scan([str(artifacts / "sneaky.pyc")])
        assert {r.sensor for r in report.results} == {"bytecode-analyzer"}

    def test_a_directory_scan_covers_every_artifact(self, artifacts):
        report = pipeline.scan([str(artifacts)])
        assert {r.sensor for r in report.results} >= {"zipbomb-detector", "bytecode-analyzer"}


class TestCorrelation:
    def test_two_sensors_on_one_entity_escalate(self):
        events = [
            _event("waf", Category.EXPLOIT, Severity.HIGH, "198.51.100.7"),
            _event("browser-fingerprinting", Category.RECON, Severity.MEDIUM, "198.51.100.7"),
        ]
        alerts = correlate.correlate(events)
        rules = {a.rule for a in alerts}
        assert "multi-sensor-agreement" in rules
        agreement = next(a for a in alerts if a.rule == "multi-sensor-agreement")
        assert agreement.severity is Severity.CRITICAL

    def test_one_sensor_alone_does_not_correlate(self):
        events = [
            _event("waf", Category.EXPLOIT, Severity.HIGH, "198.51.100.7", "a"),
            _event("waf", Category.RECON, Severity.HIGH, "198.51.100.7", "b"),
        ]
        assert not [a for a in correlate.correlate(events)
                    if a.rule == "multi-sensor-agreement"]

    def test_evasion_plus_hostile_needs_two_sensors(self):
        same = [
            _event("bytecode-analyzer", Category.EVASION, Severity.HIGH, "x.pyc", "a"),
            _event("bytecode-analyzer", Category.MALWARE, Severity.HIGH, "x.pyc", "b"),
        ]
        assert not [a for a in correlate.correlate(same)
                    if a.rule == "hidden-payload-in-hostile-artifact"]

        different = [
            _event("steganography-detector", Category.EVASION, Severity.HIGH, "x.zip", "a"),
            _event("zipbomb-detector", Category.AVAILABILITY, Severity.HIGH, "x.zip", "b"),
        ]
        fired = [a for a in correlate.correlate(different)
                 if a.rule == "hidden-payload-in-hostile-artifact"]
        assert fired and fired[0].severity is Severity.CRITICAL

    def test_recon_must_precede_exploit(self):
        after = [
            _event("waf", Category.EXPLOIT, Severity.HIGH, "203.0.113.4", "x",
                   "2026-08-15T10:00:00Z"),
            _event("browser-fingerprinting", Category.RECON, Severity.MEDIUM, "203.0.113.4",
                   "y", "2026-08-15T11:00:00Z"),
        ]
        assert not [a for a in correlate.correlate(after) if a.rule == "recon-then-exploit"]

    def test_volume_alone_can_raise_an_alert(self):
        events = [
            _event("can-ids", Category.INTRUSION, Severity.MEDIUM, "CAN:2C4", f"f{i}")
            for i in range(12)
        ]
        fired = [a for a in correlate.correlate(events) if a.rule == "sustained-intrusion"]
        assert fired

    def test_every_alert_names_the_events_it_fired_on(self):
        events = [
            _event("waf", Category.EXPLOIT, Severity.HIGH, "198.51.100.7"),
            _event("browser-fingerprinting", Category.RECON, Severity.MEDIUM, "198.51.100.7"),
        ]
        for alert in correlate.correlate(events):
            assert alert.events
            assert alert.sensors


class TestReport:
    def _report(self, *severities: Severity) -> Report:
        report = Report(target="synthetic")
        result = SensorResult(sensor="test", kind=Kind.SCANNER, target="synthetic")
        for index, severity in enumerate(severities):
            result.emit(Event(sensor="test", category=Category.AUDIT,
                              severity=severity, title=f"e{index}", entity="synthetic"))
        report.add(result)
        return report

    def test_worst_wins_not_the_average(self):
        report = self._report(*([Severity.INFO] * 9), Severity.CRITICAL)
        assert report.max_severity is Severity.CRITICAL

    def test_a_failed_sensor_never_looks_clean(self):
        report = self._report(Severity.INFO)
        report.results[0].error = "unreadable"
        assert report.exit_code == 2

    def test_severity_parses_every_spelling_the_sensors_use(self):
        for text, expected in (("warn", Severity.MEDIUM), ("critical", Severity.CRITICAL),
                               ("ERROR", Severity.HIGH), ("clean", Severity.INFO)):
            assert Severity.parse(text) is expected

    def test_json_round_trips(self, artifacts):
        report = pipeline.scan([str(artifacts / "bomb.zip")])
        data = json.loads(report.to_json())
        assert data["results"][0]["events"]
        assert data["max_severity"] == "CRITICAL"


class TestRendering:
    def test_html_is_self_contained(self, artifacts):
        """No resource the page would have to fetch to render.

        `xmlns="http://www.w3.org/2000/svg"` is a namespace identifier, not a
        URL anything loads — so the check is for actual resource references.
        """
        page = render_html(pipeline.scan([str(artifacts)]))
        for forbidden in ('src="http', "src='http", 'href="http', "href='http",
                          "url(http", "@import", "<script", "<iframe"):
            assert forbidden not in page, f"report would fetch: {forbidden}"

    def test_html_defines_both_themes(self, artifacts):
        page = render_html(pipeline.scan([str(artifacts)]))
        assert "prefers-color-scheme: dark" in page
        assert '[data-theme="dark"]' in page

    def test_severity_is_never_colour_alone(self, artifacts):
        page = render_html(pipeline.scan([str(artifacts)]))
        assert "CRITICAL" in page and "✖" in page

    def test_terminal_output_survives_no_colour(self, artifacts, capsys):
        render_terminal(pipeline.scan([str(artifacts)]), colour=False)
        out = capsys.readouterr().out
        assert "\033[" not in out
        assert "CRITICAL" in out


class TestSiemSink:
    def test_ingest_writes_detections_and_alerts(self, artifacts, tmp_path, monkeypatch):
        usable, reason = sink.available()
        if not usable:
            pytest.skip(reason)

        monkeypatch.chdir(tmp_path)          # the SIEM writes ./siem.db
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'siem.db'}")

        report = pipeline.scan([str(artifacts)])
        counts = sink.ingest(report)
        assert counts["detections"] == len(report.events)
        assert counts["alerts"] == len(report.alerts)


class TestStandalone:
    """Each sensor runs from its own folder — the reason for the layout."""

    HELP = {
        "zipbomb-detector": ([sys.executable, "zipbomb_detector.py", "--help"], "python"),
        "bytecode-analyzer": ([sys.executable, "analyze.py", "--help"], ""),
        "steganography-detector": ([sys.executable, "-m", "stegdetect", "--help"], ""),
        "protocol-fuzzer": ([sys.executable, "fuzz.py", "--help"], ""),
    }

    @pytest.mark.parametrize("name", sorted(HELP))
    def test_cli_runs_from_its_own_folder(self, name):
        spec = registry.spec(name)
        if registry.missing_requirements(spec):
            pytest.skip(f"{name} needs {registry.missing_requirements(spec)}")
        command, subdir = self.HELP[name]
        cwd = registry.MODULES_ROOT / name / subdir if subdir else registry.MODULES_ROOT / name
        completed = subprocess.run(command, cwd=cwd, capture_output=True,
                                   text=True, timeout=180)
        assert completed.returncode == 0, completed.stderr

    def test_zipbomb_detector_needs_nothing_installed(self, artifacts):
        """Run it from its own folder with an empty PYTHONPATH."""
        completed = subprocess.run(
            [sys.executable, "zipbomb_detector.py", "scan", str(artifacts / "bomb.zip")],
            cwd=registry.MODULES_ROOT / "zipbomb-detector" / "python",
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONPATH": ""},
        )
        assert completed.returncode in (0, 1), completed.stderr
        assert "bomb.zip" in completed.stdout


class TestCli:
    def test_sensors_listing_covers_the_manifest(self, capsys):
        from secops import cli

        assert cli.main(["sensors"]) == 0
        out = capsys.readouterr().out
        for spec in registry.MANIFEST:
            assert spec.name in out

    def test_rules_listing_explains_each_rule(self, capsys):
        from secops import cli

        assert cli.main(["rules"]) == 0
        out = capsys.readouterr().out
        for name in correlate.rules():
            assert name in out
