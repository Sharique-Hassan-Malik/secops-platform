"""Shared fixtures for the CAN IDS test suite."""

from __future__ import annotations

import random
from typing import List

import pytest

from can_ids.core.frame import CANFrame
from can_ids.core.baseline import build as build_baseline, Baseline
from can_ids.parsers.generator import (
    generate_normal,
    inject_frequency_flood,
    inject_replay,
    inject_unknown_id,
    inject_payload_spoof,
    _DEFAULT_ECUS,
)


BASE_TS = 1_600_000_000.0
DURATION = 15.0


@pytest.fixture(scope="session")
def normal_frames() -> List[CANFrame]:
    """15 s of clean synthetic traffic, seed=0."""
    return generate_normal(duration_sec=DURATION, seed=0, base_ts=BASE_TS)


@pytest.fixture(scope="session")
def baseline(normal_frames) -> Baseline:
    """Baseline built from the first 60% of normal_frames."""
    train = [f for f in normal_frames if f.timestamp < BASE_TS + DURATION * 0.6]
    return build_baseline(train)


@pytest.fixture(scope="session")
def test_frames(normal_frames) -> List[CANFrame]:
    """Last 40% of normal traffic — no attacks."""
    return [f for f in normal_frames if f.timestamp >= BASE_TS + DURATION * 0.6]


@pytest.fixture(scope="session")
def flood_frames(normal_frames) -> List[CANFrame]:
    """Test frames with a frequency flood injected at t=BASE_TS+9."""
    frames = inject_frequency_flood(
        normal_frames, target_id=0x0C0,
        flood_start=BASE_TS + 9.0, flood_duration=0.5,
        multiplier=15, seed=7,
    )
    return [f for f in frames if f.timestamp >= BASE_TS + DURATION * 0.6]


@pytest.fixture(scope="session")
def replay_frames(normal_frames) -> List[CANFrame]:
    """Test frames with a replay attack injected."""
    frames = inject_replay(
        normal_frames, replay_start=BASE_TS + 9.0,
        replay_delay=0.5, window=20,
    )
    return [f for f in frames if f.timestamp >= BASE_TS + DURATION * 0.6]


@pytest.fixture(scope="session")
def unknown_id_frames(normal_frames) -> List[CANFrame]:
    """Test frames with unknown ID 0x666 injected."""
    frames = inject_unknown_id(
        normal_frames, inject_at=BASE_TS + 9.5,
        unknown_id=0x666, count=10,
    )
    return [f for f in frames if f.timestamp >= BASE_TS + DURATION * 0.6]


@pytest.fixture(scope="session")
def payload_spoof_frames(normal_frames) -> List[CANFrame]:
    """Test frames with an out-of-range RPM payload injected."""
    frames = inject_payload_spoof(
        normal_frames, target_id=0x0C0,
        spoof_at=BASE_TS + 9.2,
        spoofed_data=bytes([0xFF, 0xFF]),
    )
    return [f for f in frames if f.timestamp >= BASE_TS + DURATION * 0.6]
