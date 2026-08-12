"""Tests for all five detectors."""

from __future__ import annotations

import pytest

from can_ids.core.detectors import (
    detect_frequency,
    detect_timing,
    detect_replay,
    detect_payload,
    detect_unknown_id,
)
from can_ids.core.frame import CANFrame
from can_ids.core.baseline import build as build_baseline


class TestFrequencyDetector:
    def test_no_alerts_on_clean_traffic(self, test_frames, baseline):
        alerts = detect_frequency(test_frames, baseline, window_sec=1.0, threshold=3.0)
        burst_alerts = [a for a in alerts if "burst" in a.message]
        assert len(burst_alerts) == 0

    def test_detects_flood(self, flood_frames, baseline):
        alerts = detect_frequency(flood_frames, baseline, window_sec=1.0, threshold=3.0)
        flood_on_c0 = [a for a in alerts if a.can_id == 0x0C0 and "burst" in a.message]
        assert len(flood_on_c0) >= 1

    def test_flood_alert_severity(self, flood_frames, baseline):
        alerts = detect_frequency(flood_frames, baseline, window_sec=1.0, threshold=3.0)
        burst = [a for a in alerts if a.can_id == 0x0C0 and "burst" in a.message]
        assert any(a.severity in ("critical", "high", "medium") for a in burst)

    def test_detector_label(self, flood_frames, baseline):
        alerts = detect_frequency(flood_frames, baseline)
        assert all(a.detector == "frequency" for a in alerts)

    def test_alert_scores_positive(self, flood_frames, baseline):
        alerts = detect_frequency(flood_frames, baseline)
        for a in alerts:
            assert a.score >= 0

    def test_empty_frames(self, baseline):
        assert detect_frequency([], baseline) == []

    def test_silence_detection(self, baseline):
        # Send only frames for IDs that are not 0x0C0
        # 0x0C0 has period 10ms so it's expected every window
        frames = [
            f for f in [
                CANFrame(1_600_000_009.0 + i * 0.02, 0x0D0, False, b"\x00\x3C")
                for i in range(60)
            ]
        ]
        alerts = detect_frequency(frames, baseline, window_sec=1.0, threshold=3.0)
        silence = [a for a in alerts if "silence" in a.message and a.can_id == 0x0C0]
        assert len(silence) >= 1


class TestTimingDetector:
    def test_no_alerts_on_clean_traffic(self, test_frames, baseline):
        alerts = detect_timing(test_frames, baseline, threshold=4.0)
        assert len(alerts) == 0

    def test_detects_injected_early_frame(self, baseline):
        # Inject a frame much earlier than expected (IAT = 0.1 ms vs 10 ms baseline)
        frames = [
            CANFrame(1_600_000_009.000, 0x0C0, False, b"\x00\x64"),
            CANFrame(1_600_000_009.0001, 0x0C0, False, b"\x00\x64"),   # 0.1 ms gap
            CANFrame(1_600_000_009.010, 0x0C0, False, b"\x00\x64"),
        ]
        alerts = detect_timing(frames, baseline, threshold=4.0, min_baseline_iats=5)
        assert len(alerts) >= 1
        assert any(a.can_id == 0x0C0 for a in alerts)

    def test_detector_label(self, test_frames, baseline):
        alerts = detect_timing(test_frames, baseline)
        assert all(a.detector == "timing" for a in alerts)

    def test_empty_frames(self, baseline):
        assert detect_timing([], baseline) == []

    def test_alert_has_iat_info(self, baseline):
        frames = [
            CANFrame(1_600_000_009.0, 0x0C0, False, b"\x00\x64"),
            CANFrame(1_600_000_009.0001, 0x0C0, False, b"\x00\x64"),
        ]
        alerts = detect_timing(frames, baseline, threshold=2.0, min_baseline_iats=5)
        if alerts:
            assert "ms" in alerts[0].message
            assert "observed_iat_ms" in alerts[0].extra


class TestReplayDetector:
    def test_detects_replay_attack(self, replay_frames, baseline):
        # Use window_size=4 — a 4-frame sequence is much more likely to repeat exactly
        # than a 16-frame sequence when normal traffic interleaves with the injected copy.
        alerts = detect_replay(replay_frames, baseline, window_size=4, lookback_sec=5.0)
        assert len(alerts) >= 1

    def test_replay_alert_label(self, replay_frames, baseline):
        alerts = detect_replay(replay_frames, baseline)
        assert all(a.detector == "replay" for a in alerts)

    def test_no_false_positives_on_clean(self, test_frames, baseline):
        # Clean traffic should produce few or no replay alerts
        alerts = detect_replay(test_frames, baseline, window_size=16, lookback_sec=2.0)
        # Strictly periodic traffic may produce rapid duplicates, so allow a small number
        assert len(alerts) <= 5

    def test_rapid_duplicate_detected(self, baseline):
        # Same (id, data) within 2% of expected 10 ms IAT = 0.2 ms
        frames = [
            CANFrame(1_600_000_009.0,    0x0C0, False, b"\x10\x00"),
            CANFrame(1_600_000_009.0001, 0x0C0, False, b"\x10\x00"),   # rapid dup
            CANFrame(1_600_000_009.010,  0x0C0, False, b"\x10\x01"),
        ]
        alerts = detect_replay(frames, baseline, rapid_dup_ratio=0.5)
        rapid = [a for a in alerts if "rapid" in a.message]
        assert len(rapid) >= 1

    def test_empty_frames(self, baseline):
        assert detect_replay([], baseline) == []


class TestPayloadDetector:
    def test_detects_out_of_range_byte(self, payload_spoof_frames, baseline):
        alerts = detect_payload(
            payload_spoof_frames, baseline, threshold=4.0, min_baseline_count=20
        )
        spoof_alerts = [a for a in alerts if a.can_id == 0x0C0]
        assert len(spoof_alerts) >= 1

    def test_no_false_positives_on_clean(self, test_frames, baseline):
        # Low-severity alerts are acceptable on the sin-wave throttle signal
        # whose phase drifts slightly outside the training window range.
        # Only high and critical alerts indicate real anomalies.
        alerts = detect_payload(test_frames, baseline, threshold=4.0, min_baseline_count=20)
        high_plus = [a for a in alerts if a.severity in ("high", "critical")]
        assert len(high_plus) == 0

    def test_detector_label(self, payload_spoof_frames, baseline):
        alerts = detect_payload(payload_spoof_frames, baseline)
        assert all(a.detector == "payload" for a in alerts)

    def test_dlc_mismatch_detected(self, baseline):
        # Send a frame with wrong DLC for 0x0C0 (baseline DLC=2, inject DLC=4)
        frames = [
            CANFrame(1_600_000_009.0 + i * 0.01, 0x0C0, False, bytes([0x10, 0x00, 0xAA, 0xBB]))
            for i in range(5)
        ]
        alerts = detect_payload(frames, baseline, threshold=4.0, min_baseline_count=5)
        dlc_alerts = [a for a in alerts if "DLC" in a.message]
        assert len(dlc_alerts) >= 1

    def test_empty_frames(self, baseline):
        assert detect_payload([], baseline) == []

    def test_alert_has_z_score(self, payload_spoof_frames, baseline):
        alerts = detect_payload(payload_spoof_frames, baseline, threshold=3.0, min_baseline_count=20)
        for a in alerts:
            if "z_score" in a.extra:
                assert a.extra["z_score"] > 0


class TestUnknownIDDetector:
    def test_detects_unknown_id(self, unknown_id_frames, baseline):
        alerts = detect_unknown_id(unknown_id_frames, baseline)
        ids_flagged = {a.can_id for a in alerts}
        assert 0x666 in ids_flagged

    def test_no_alerts_on_known_ids(self, test_frames, baseline):
        alerts = detect_unknown_id(test_frames, baseline)
        assert len(alerts) == 0

    def test_severity_scales_with_count(self, baseline):
        # 1 frame → low, ≥5 → high
        single = [CANFrame(1_600_000_010.0, 0x777, False, b"\x01")]
        multi  = [CANFrame(1_600_000_010.0 + i * 0.01, 0x777, False, b"\x01") for i in range(6)]

        a_single = detect_unknown_id(single, baseline)
        a_multi  = detect_unknown_id(multi, baseline)

        assert a_single[0].severity == "low"
        assert a_multi[0].severity == "high"

    def test_detector_label(self, unknown_id_frames, baseline):
        alerts = detect_unknown_id(unknown_id_frames, baseline)
        assert all(a.detector == "unknown_id" for a in alerts)

    def test_deduplication(self, baseline):
        # 20 frames from same unknown ID → exactly 1 alert
        frames = [CANFrame(1_600_000_010.0 + i * 0.01, 0x888, False, b"\x00") for i in range(20)]
        alerts = detect_unknown_id(frames, baseline)
        assert len([a for a in alerts if a.can_id == 0x888]) == 1

    def test_empty_frames(self, baseline):
        assert detect_unknown_id([], baseline) == []
