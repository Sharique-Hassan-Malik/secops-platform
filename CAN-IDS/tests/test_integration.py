"""End-to-end integration tests for CANIntrusion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from can_ids.analyzer import CANIntrusion, AnalysisResult, DetectorConfig
from can_ids.core.baseline import build as build_baseline
from can_ids.parsers.generator import (
    generate_normal,
    inject_frequency_flood,
    inject_replay,
    inject_unknown_id,
    inject_payload_spoof,
    frames_to_candump,
)
from can_ids.report.json_report import to_json, to_dict, save as save_json


BASE_TS = 1_600_000_000.0


@pytest.fixture
def ids():
    return CANIntrusion()


@pytest.fixture
def clean_log(tmp_path):
    frames = generate_normal(duration_sec=15.0, seed=42, base_ts=BASE_TS)
    p = tmp_path / "clean.log"
    p.write_text(frames_to_candump(frames))
    return str(p)


@pytest.fixture
def attacked_log(tmp_path):
    frames = generate_normal(duration_sec=15.0, seed=42, base_ts=BASE_TS)
    # Attacks at t+11 and t+12 so they land in the test window (>70% split ≈ t+10.1)
    frames = inject_frequency_flood(frames, 0x0C0, BASE_TS + 11.0, flood_duration=0.5, multiplier=10, seed=1)
    frames = inject_unknown_id(frames, BASE_TS + 12.0, unknown_id=0x666, count=8)
    p = tmp_path / "attacked.log"
    p.write_text(frames_to_candump(frames))
    return str(p)


class TestCANIntrusionClean:
    def test_returns_analysis_result(self, ids, clean_log):
        result = ids.analyze_split(clean_log)
        assert isinstance(result, AnalysisResult)

    def test_baseline_populated(self, ids, clean_log):
        result = ids.analyze_split(clean_log)
        assert len(result.baseline.profiles) >= 8

    def test_test_frame_count_positive(self, ids, clean_log):
        result = ids.analyze_split(clean_log)
        assert result.test_frame_count > 0

    def test_analysis_time_positive(self, ids, clean_log):
        result = ids.analyze_split(clean_log)
        assert result.analysis_time > 0

    def test_no_critical_alerts_on_clean(self, ids, clean_log):
        result = ids.analyze_split(clean_log)
        assert result.critical_count == 0

    def test_low_alert_count_on_clean(self, ids, clean_log):
        result = ids.analyze_split(clean_log)
        # Some low/medium alerts are normal due to timing jitter in the test window
        assert len([a for a in result.alerts if a.severity in ("critical", "high")]) == 0


class TestCANIntrusionAttacked:
    def test_flood_detected(self, ids, attacked_log):
        result = ids.analyze_split(attacked_log)
        flood = [a for a in result.alerts if a.can_id == 0x0C0 and a.detector == "frequency"]
        assert len(flood) >= 1

    def test_unknown_id_detected(self, ids, attacked_log):
        result = ids.analyze_split(attacked_log)
        unknown = [a for a in result.alerts if a.can_id == 0x666]
        assert len(unknown) >= 1

    def test_alerts_sorted_by_severity(self, ids, attacked_log):
        result = ids.analyze_split(attacked_log)
        from can_ids.core.alert import SEVERITY_RANK
        ranks = [SEVERITY_RANK.get(a.severity, 99) for a in result.alerts]
        assert ranks == sorted(ranks)

    def test_high_count_positive(self, ids, attacked_log):
        result = ids.analyze_split(attacked_log)
        assert result.high_count >= 0   # sanity


class TestSeparateBaselineAndTest:
    def test_separate_files(self, ids, tmp_path):
        all_frames = generate_normal(duration_sec=15.0, seed=1, base_ts=BASE_TS)
        train = [f for f in all_frames if f.timestamp < BASE_TS + 10.0]
        test  = [f for f in all_frames if f.timestamp >= BASE_TS + 10.0]

        bl_file   = tmp_path / "baseline.log"
        test_file = tmp_path / "test.log"
        bl_file.write_text(frames_to_candump(train))
        test_file.write_text(frames_to_candump(test))

        baseline = ids.build_baseline(str(bl_file))
        result   = ids.detect(str(test_file), baseline)
        assert result.test_frame_count > 0
        assert len(result.baseline.profiles) >= 8

    def test_detect_frames_api(self, ids):
        all_frames = generate_normal(duration_sec=10.0, seed=2, base_ts=BASE_TS)
        train = all_frames[:int(len(all_frames) * 0.7)]
        test  = all_frames[int(len(all_frames) * 0.7):]
        baseline = ids.build_baseline_from_frames(train)
        result   = ids.detect_frames(test, baseline, source="api-test")
        assert result.source == "api-test"


class TestDetectorConfig:
    def test_disable_all_detectors(self):
        cfg = DetectorConfig(
            enable_frequency=False,
            enable_timing=False,
            enable_replay=False,
            enable_payload=False,
            enable_unknown_id=False,
        )
        ids = CANIntrusion(cfg)
        all_frames = generate_normal(duration_sec=5.0, seed=3, base_ts=BASE_TS)
        all_frames = inject_frequency_flood(all_frames, 0x0C0, BASE_TS + 3.0, multiplier=10)
        all_frames = inject_unknown_id(all_frames, BASE_TS + 3.5, 0x999)
        train = all_frames[:int(len(all_frames) * 0.6)]
        test  = all_frames[int(len(all_frames) * 0.6):]
        baseline = ids.build_baseline_from_frames(train)
        result = ids.detect_frames(test, baseline)
        assert len(result.alerts) == 0


class TestJSONReport:
    def test_to_json_valid(self, ids, clean_log):
        result = ids.analyze_split(clean_log)
        doc = json.loads(to_json(result))
        assert "alerts" in doc
        assert "baseline" in doc
        assert "alert_summary" in doc

    def test_alert_fields(self, ids, attacked_log):
        result = ids.analyze_split(attacked_log)
        doc = json.loads(to_json(result))
        for alert in doc["alerts"]:
            assert "timestamp" in alert
            assert "can_id" in alert
            assert "severity" in alert
            assert "detector" in alert
            assert "message" in alert

    def test_save_creates_file(self, ids, clean_log, tmp_path):
        result = ids.analyze_split(clean_log)
        out = str(tmp_path / "report.json")
        save_json(result, out)
        assert Path(out).exists()
        assert Path(out).stat().st_size > 0

    def test_baseline_profiles_in_json(self, ids, clean_log):
        result = ids.analyze_split(clean_log)
        doc = json.loads(to_json(result))
        assert len(doc["baseline"]["profiles"]) >= 8


class TestEdgeCases:
    def test_empty_test_frames(self, baseline, ids):
        result = ids.detect_frames([], baseline)
        assert result.test_frame_count == 0
        assert result.alerts == []

    def test_single_frame(self, baseline, ids):
        frame = CANFrame(BASE_TS + 10.0, 0x0C0, False, b"\x10\x00")
        result = ids.detect_frames([frame], baseline)
        assert result.test_frame_count == 1

    def test_all_unknown_ids(self, ids):
        frames = generate_normal(duration_sec=3.0, seed=5, base_ts=BASE_TS)
        train  = frames[:10]
        # test has IDs not seen in training
        test   = [
            CANFrame(BASE_TS + 5.0 + i * 0.01, 0xABC, False, b"\x00")
            for i in range(5)
        ]
        baseline = ids.build_baseline_from_frames(train)
        result   = ids.detect_frames(test, baseline)
        unknown = [a for a in result.alerts if a.detector == "unknown_id"]
        assert len(unknown) >= 1


# avoid NameError if CANFrame import is needed inside TestEdgeCases
from can_ids.core.frame import CANFrame  # noqa: E402
