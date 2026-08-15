"""Tests for candump, CSV parsers and the synthetic generator."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from can_ids.parsers.candump import parse_line, parse_lines, parse_file
from can_ids.parsers.csv_parser import parse_file as csv_parse_file
from can_ids.parsers.generator import (
    generate_normal,
    inject_frequency_flood,
    inject_replay,
    inject_unknown_id,
    inject_payload_spoof,
    frames_to_candump,
    _DEFAULT_ECUS,
)
from can_ids.parsers import load
from can_ids.core.frame import CANFrame


class TestCandumpParser:
    def test_standard_line(self):
        f = parse_line("(1609459200.000100) vcan0 1A0#DEADBEEF")
        assert f is not None
        assert f.can_id == 0x1A0
        assert f.timestamp == pytest.approx(1609459200.0001)
        assert f.data == bytes.fromhex("DEADBEEF")
        assert f.extended is False

    def test_no_interface(self):
        f = parse_line("(1609459200.000100) 1A0#DEADBEEF")
        assert f is not None
        assert f.can_id == 0x1A0

    def test_no_parentheses(self):
        f = parse_line("1609459200.000100 vcan0 1A0#11")
        assert f is not None
        assert f.can_id == 0x1A0

    def test_extended_id(self):
        f = parse_line("(1609459200.000100) vcan0 1FFFFFFF#AABB")
        assert f is not None
        assert f.extended is True
        assert f.can_id == 0x1FFFFFFF

    def test_remote_frame(self):
        f = parse_line("(1609459200.0) vcan0 123#R")
        assert f is not None
        assert f.data == b""

    def test_empty_payload(self):
        f = parse_line("(1609459200.0) vcan0 200#")
        assert f is not None
        assert f.data == b""

    def test_error_frame_skipped(self):
        # Error frame: ID has bit 29 set (0x20000004)
        f = parse_line("(1609459200.0) vcan0 20000004#0000000000000000")
        assert f is None

    def test_comment_skipped(self):
        assert parse_line("# this is a comment") is None

    def test_blank_line_skipped(self):
        assert parse_line("") is None
        assert parse_line("   ") is None

    def test_invalid_line(self):
        assert parse_line("garbage data here") is None

    def test_payload_too_long(self):
        f = parse_line("(1.0) vcan0 100#0102030405060708090A")
        assert f is None

    def test_parse_lines(self):
        lines = [
            "(1.0) vcan0 1A0#DEAD",
            "# comment",
            "(1.01) vcan0 1B0#BEEF",
            "",
        ]
        frames = parse_lines(iter(lines))
        assert len(frames) == 2
        assert frames[0].can_id == 0x1A0

    def test_parse_file(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("(1.0) vcan0 1A0#DEAD\n(1.01) vcan0 1B0#BEEF\n")
        frames = parse_file(str(log))
        assert len(frames) == 2

    def test_parse_file_sorted(self, tmp_path):
        log = tmp_path / "unsorted.log"
        log.write_text("(2.0) vcan0 1A0#01\n(1.0) vcan0 1B0#02\n")
        frames = parse_file(str(log))
        assert frames[0].timestamp < frames[1].timestamp


class TestCSVParser:
    def _write_csv(self, tmp_path, content: str) -> str:
        p = tmp_path / "test.csv"
        p.write_text(textwrap.dedent(content))
        return str(p)

    def test_standard_headers(self, tmp_path):
        path = self._write_csv(tmp_path, """\
            timestamp,can_id,data
            1.0,1A0,DEADBEEF
            1.01,1B0,AABB
        """)
        frames = csv_parse_file(path)
        assert len(frames) == 2
        assert frames[0].can_id == 0x1A0
        assert frames[0].data == bytes.fromhex("DEADBEEF")

    def test_alias_headers(self, tmp_path):
        path = self._write_csv(tmp_path, """\
            time,arbitration_id,payload
            1.0,0x1A0,DE AD BE EF
        """)
        frames = csv_parse_file(path)
        assert len(frames) == 1
        assert frames[0].data == bytes.fromhex("DEADBEEF")

    def test_hex_with_colons(self, tmp_path):
        path = self._write_csv(tmp_path, """\
            timestamp,can_id,data
            1.0,100,DE:AD:BE:EF
        """)
        frames = csv_parse_file(path)
        assert frames[0].data == bytes.fromhex("DEADBEEF")

    def test_empty_data(self, tmp_path):
        path = self._write_csv(tmp_path, """\
            timestamp,can_id,data
            1.0,100,
        """)
        frames = csv_parse_file(path)
        assert frames[0].data == b""

    def test_sorted_output(self, tmp_path):
        path = self._write_csv(tmp_path, """\
            timestamp,can_id,data
            2.0,100,AA
            1.0,200,BB
        """)
        frames = csv_parse_file(path)
        assert frames[0].timestamp < frames[1].timestamp


class TestAutoLoad:
    def test_log_extension(self, tmp_path):
        p = tmp_path / "x.log"
        p.write_text("(1.0) vcan0 1A0#DEAD\n")
        frames = load(str(p))
        assert len(frames) == 1

    def test_csv_extension(self, tmp_path):
        p = tmp_path / "x.csv"
        p.write_text("timestamp,can_id,data\n1.0,1A0,DEAD\n")
        frames = load(str(p))
        assert len(frames) == 1


class TestGenerator:
    def test_generates_frames(self):
        frames = generate_normal(duration_sec=5.0, seed=0)
        assert len(frames) > 0

    def test_all_ecus_represented(self):
        frames = generate_normal(duration_sec=5.0, seed=0)
        ids_seen = {f.can_id for f in frames}
        for ecu in _DEFAULT_ECUS:
            assert ecu.can_id in ids_seen

    def test_frames_sorted_by_timestamp(self):
        frames = generate_normal(duration_sec=5.0, seed=0)
        ts = [f.timestamp for f in frames]
        assert ts == sorted(ts)

    def test_deterministic_with_seed(self):
        a = generate_normal(duration_sec=3.0, seed=99)
        b = generate_normal(duration_sec=3.0, seed=99)
        assert len(a) == len(b)
        assert all(f1 == f2 for f1, f2 in zip(a, b))

    def test_flood_increases_count(self):
        normal = generate_normal(duration_sec=5.0, seed=0)
        flooded = inject_frequency_flood(
            normal, target_id=0x0C0, flood_start=normal[0].timestamp + 2.0,
            flood_duration=0.5, multiplier=10,
        )
        normal_c0 = sum(1 for f in normal if f.can_id == 0x0C0)
        flood_c0  = sum(1 for f in flooded if f.can_id == 0x0C0)
        assert flood_c0 > normal_c0

    def test_replay_increases_count(self):
        normal = generate_normal(duration_sec=5.0, seed=0)
        replayed = inject_replay(normal, replay_start=normal[0].timestamp + 2.0, window=10)
        assert len(replayed) == len(normal) + 10

    def test_unknown_id_present(self):
        normal = generate_normal(duration_sec=5.0, seed=0)
        injected = inject_unknown_id(normal, inject_at=normal[0].timestamp + 2.0, unknown_id=0x999)
        assert any(f.can_id == 0x999 for f in injected)

    def test_candump_export_parseable(self):
        frames = generate_normal(duration_sec=2.0, seed=0)
        log = frames_to_candump(frames)
        from can_ids.parsers.candump import parse_lines
        parsed = parse_lines(iter(log.splitlines()))
        assert len(parsed) == len(frames)
