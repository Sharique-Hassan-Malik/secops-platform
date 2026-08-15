"""Tests for core.frame and core.baseline."""

from __future__ import annotations

import pytest

from can_ids.core.frame import CANFrame, payload_key, byte_values, pack_uint
from can_ids.core.baseline import build as build_baseline, split_train_test, IDProfile, ByteStats


class TestCANFrame:
    def test_dlc(self):
        f = CANFrame(0.0, 0x100, False, bytes([0xAA, 0xBB]))
        assert f.dlc == 2

    def test_id_str_standard(self):
        f = CANFrame(0.0, 0x1A0, False, b"")
        assert f.id_str == "1A0"

    def test_id_str_extended(self):
        f = CANFrame(0.0, 0x1FFFFFFF, True, b"")
        assert f.id_str == "1FFFFFFF"

    def test_data_hex(self):
        f = CANFrame(0.0, 0x100, False, bytes([0xDE, 0xAD]))
        assert f.data_hex == "DEAD"

    def test_empty_payload(self):
        f = CANFrame(0.0, 0x100, False, b"")
        assert f.dlc == 0
        assert f.data_hex == ""

    def test_frozen_immutable(self):
        f = CANFrame(0.0, 0x100, False, b"\x01")
        with pytest.raises((AttributeError, TypeError)):
            f.can_id = 0x200  # type: ignore

    def test_ordering(self):
        f1 = CANFrame(1.0, 0x100, False, b"")
        f2 = CANFrame(2.0, 0x100, False, b"")
        assert f1 < f2

    def test_payload_key(self):
        f = CANFrame(0.0, 0x1A0, False, bytes([1, 2, 3]))
        assert payload_key(f) == (0x1A0, bytes([1, 2, 3]))

    def test_byte_values(self):
        f = CANFrame(0.0, 0x100, False, bytes([10, 20, 30]))
        assert byte_values(f) == [10, 20, 30]

    def test_pack_uint_big(self):
        data = bytes([0x01, 0x00])
        assert pack_uint(data, 0, 2, big_endian=True) == 256

    def test_pack_uint_little(self):
        data = bytes([0x01, 0x00])
        assert pack_uint(data, 0, 2, big_endian=False) == 1

    def test_pack_uint_out_of_range(self):
        assert pack_uint(bytes([0x01]), 0, 2) is None


class TestByteStats:
    def test_single_update(self):
        bs = ByteStats()
        bs.update(100)
        assert bs.count == 1
        assert bs.mean == 100.0
        assert bs.variance == 0.0
        assert 100 in bs.observed

    def test_multiple_updates(self):
        bs = ByteStats()
        for v in [10, 20, 30]:
            bs.update(v)
        assert bs.count == 3
        assert abs(bs.mean - 20.0) < 1e-9

    def test_std_uniform(self):
        bs = ByteStats()
        for _ in range(100):
            bs.update(128)
        assert bs.std == 0.0

    def test_observed_set(self):
        bs = ByteStats()
        for v in [1, 2, 2, 3, 1]:
            bs.update(v)
        assert bs.observed == {1, 2, 3}


class TestIDProfile:
    def _frames(self, can_id: int, count: int, period: float = 0.01) -> list:
        return [
            CANFrame(i * period, can_id, False, bytes([i % 256, 0]))
            for i in range(count)
        ]

    def test_ingest_count(self):
        profile = IDProfile(can_id=0x100)
        for f in self._frames(0x100, 50):
            profile.ingest(f)
        assert profile.count == 50

    def test_iat_mean(self):
        profile = IDProfile(can_id=0x100)
        for f in self._frames(0x100, 50, period=0.01):
            profile.ingest(f)
        assert abs(profile.iat_mean - 0.01) < 1e-4

    def test_mean_rate(self):
        profile = IDProfile(can_id=0x100)
        for f in self._frames(0x100, 100, period=0.01):
            profile.ingest(f)
        # 100 frames over ~1 second → ~100 msg/s
        assert 90.0 < profile.mean_rate < 110.0

    def test_byte_stats_populated(self):
        profile = IDProfile(can_id=0x100)
        for f in self._frames(0x100, 10):
            profile.ingest(f)
        assert 0 in profile.byte_stats

    def test_byte_zscore_same_value(self):
        profile = IDProfile(can_id=0x100)
        for _ in range(50):
            profile.ingest(CANFrame(0.0, 0x100, False, bytes([128, 0])))
            profile.ingest(CANFrame(0.001, 0x100, False, bytes([128, 0])))
        z = profile.byte_zscore(0, 128)
        assert z == 0.0

    def test_byte_zscore_outlier(self):
        profile = IDProfile(can_id=0x100)
        for i in range(100):
            profile.ingest(CANFrame(i * 0.01, 0x100, False, bytes([128, 0])))
        z = profile.byte_zscore(0, 255)
        assert z == float("inf") or z > 5.0


class TestBuildBaseline:
    def test_empty(self):
        bl = build_baseline([])
        assert bl.total_frames == 0
        assert len(bl.profiles) == 0

    def test_single_id(self):
        frames = [CANFrame(i * 0.01, 0x100, False, bytes([i % 256])) for i in range(50)]
        bl = build_baseline(frames)
        assert 0x100 in bl.profiles
        assert bl.profiles[0x100].count == 50

    def test_multiple_ids(self):
        frames = (
            [CANFrame(i * 0.01, 0x100, False, b"\x01") for i in range(20)] +
            [CANFrame(i * 0.02, 0x200, False, b"\x02") for i in range(15)]
        )
        frames.sort(key=lambda f: f.timestamp)
        bl = build_baseline(frames)
        assert len(bl.profiles) == 2
        assert bl.total_frames == 35

    def test_known_ids(self, normal_frames):
        bl = build_baseline(normal_frames)
        expected = {0x0C0, 0x0D0, 0x0E0, 0x0F0, 0x100, 0x110, 0x120, 0x130}
        assert expected.issubset(bl.known_ids)

    def test_duration(self):
        frames = [CANFrame(float(i), 0x100, False, b"") for i in range(5)]
        bl = build_baseline(frames)
        assert abs(bl.duration - 4.0) < 1e-9

    def test_split_train_test_ratio(self, normal_frames):
        train, test = split_train_test(normal_frames, train_ratio=0.7)
        total = len(train) + len(test)
        assert total == len(normal_frames)
        assert abs(len(train) / total - 0.7) < 0.01

    def test_split_temporal_order(self, normal_frames):
        train, test = split_train_test(normal_frames)
        if train and test:
            assert train[-1].timestamp <= test[0].timestamp
