"""
Synthetic CAN traffic generator.

Generates realistic CAN bus captures for testing and demonstration.
Models a simplified vehicle CAN network with periodic ECU messages.

Simulated ECUs and their message schedules:
  0x0C0  Engine RPM        — 10 ms period,  2-byte value 0–8000 rpm
  0x0D0  Vehicle speed     — 20 ms period,  2-byte value 0–300 km/h
  0x0E0  Throttle position — 10 ms period,  1-byte 0–100%
  0x0F0  Coolant temp      — 1000 ms period, 1-byte 0–255 (raw sensor)
  0x100  Brake pressure    — 10 ms period,  2-byte 0–4096 (ADC units)
  0x110  Steering angle    — 20 ms period,  2-byte signed -540 to +540 deg
  0x120  Transmission gear — 100 ms period, 1-byte 0–8
  0x130  Battery voltage   — 500 ms period, 2-byte mV (10000–16000)
  0x7DF  OBD-II query      — sporadic

Attack injections (optional):
  - Frequency flood: burst a target ID at 10× normal rate
  - Replay: replay a window of frames after a delay
  - Unknown ID: inject frames from a new ID
  - Payload spoof: inject a frame with an out-of-range byte value
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from can_ids.core.frame import CANFrame


@dataclass
class ECUSpec:
    can_id: int
    period_ms: float          # nominal period in milliseconds
    dlc: int                  # data length in bytes
    jitter_pct: float = 2.0  # timing jitter as percentage of period


_DEFAULT_ECUS: List[ECUSpec] = [
    ECUSpec(0x0C0, 10.0,   2),
    ECUSpec(0x0D0, 20.0,   2),
    ECUSpec(0x0E0, 10.0,   1),
    ECUSpec(0x0F0, 1000.0, 1),
    ECUSpec(0x100, 10.0,   2),
    ECUSpec(0x110, 20.0,   2),
    ECUSpec(0x120, 100.0,  1),
    ECUSpec(0x130, 500.0,  2),
]


def generate_normal(
    duration_sec: float = 10.0,
    ecus: Optional[List[ECUSpec]] = None,
    seed: Optional[int] = None,
    base_ts: float = 1_600_000_000.0,
) -> List[CANFrame]:
    """
    Generate a normal (attack-free) CAN capture.

    Parameters
    ----------
    duration_sec : capture duration in seconds
    ecus         : list of ECU specifications (defaults to _DEFAULT_ECUS)
    seed         : RNG seed for reproducibility
    base_ts      : starting Unix timestamp
    """
    rng = random.Random(seed)
    if ecus is None:
        ecus = _DEFAULT_ECUS

    frames: List[CANFrame] = []

    for ecu in ecus:
        period_s = ecu.period_ms / 1000.0
        jitter_s = period_s * ecu.jitter_pct / 100.0
        t = base_ts + rng.uniform(0, period_s)
        while t < base_ts + duration_sec:
            data = _generate_payload(ecu.can_id, ecu.dlc, t - base_ts, rng)
            frames.append(CANFrame(
                timestamp=t,
                can_id=ecu.can_id,
                extended=False,
                data=data,
            ))
            t += period_s + rng.uniform(-jitter_s, jitter_s)

    frames.sort(key=lambda f: f.timestamp)
    return frames


def inject_frequency_flood(
    frames: List[CANFrame],
    target_id: int,
    flood_start: float,
    flood_duration: float = 0.5,
    multiplier: int = 10,
    seed: Optional[int] = None,
) -> List[CANFrame]:
    """
    Inject a burst of frames with `target_id` between `flood_start` and
    `flood_start + flood_duration`, at `multiplier` times the normal rate.
    """
    rng = random.Random(seed)
    # find nominal period for target_id
    ecu = next((e for e in _DEFAULT_ECUS if e.can_id == target_id), None)
    period_s = (ecu.period_ms / 1000.0 / multiplier) if ecu else 0.001

    injected: List[CANFrame] = list(frames)
    t = flood_start
    while t < flood_start + flood_duration:
        data = bytes([rng.randint(0, 255) for _ in range(2)])
        injected.append(CANFrame(timestamp=t, can_id=target_id, extended=False, data=data))
        t += period_s

    injected.sort(key=lambda f: f.timestamp)
    return injected


def inject_replay(
    frames: List[CANFrame],
    replay_start: float,
    replay_delay: float = 1.0,
    window: int = 20,
) -> List[CANFrame]:
    """
    Take `window` frames starting at `replay_start` and re-inject them
    shifted forward by `replay_delay` seconds.
    """
    source = [f for f in frames if f.timestamp >= replay_start][:window]
    if not source:
        return frames

    shift = replay_delay
    replayed = [
        CANFrame(
            timestamp=f.timestamp + shift,
            can_id=f.can_id,
            extended=f.extended,
            data=f.data,
        )
        for f in source
    ]

    result = list(frames) + replayed
    result.sort(key=lambda f: f.timestamp)
    return result


def inject_unknown_id(
    frames: List[CANFrame],
    inject_at: float,
    unknown_id: int = 0x666,
    count: int = 10,
    period_ms: float = 20.0,
) -> List[CANFrame]:
    """Inject `count` frames from a CAN ID not in the baseline."""
    injected = list(frames)
    t = inject_at
    for _ in range(count):
        injected.append(CANFrame(
            timestamp=t,
            can_id=unknown_id,
            extended=False,
            data=bytes([0xDE, 0xAD, 0xBE, 0xEF]),
        ))
        t += period_ms / 1000.0
    injected.sort(key=lambda f: f.timestamp)
    return injected


def inject_payload_spoof(
    frames: List[CANFrame],
    target_id: int,
    spoof_at: float,
    spoofed_data: bytes,
) -> List[CANFrame]:
    """Insert a single frame with an out-of-range payload."""
    result = list(frames) + [
        CANFrame(timestamp=spoof_at, can_id=target_id, extended=False, data=spoofed_data)
    ]
    result.sort(key=lambda f: f.timestamp)
    return result


def frames_to_candump(frames: List[CANFrame], interface: str = "vcan0") -> str:
    """Serialise frames to candump log format for export or testing."""
    lines: List[str] = []
    for f in frames:
        id_str = f"{f.can_id:08X}" if f.extended else f"{f.can_id:03X}"
        lines.append(f"({f.timestamp:.6f}) {interface} {id_str}#{f.data_hex}")
    return "\n".join(lines)


def _generate_payload(can_id: int, dlc: int, t_rel: float, rng: random.Random) -> bytes:
    """Generate a plausible payload for a given ID and relative timestamp."""
    if can_id == 0x0C0:      # RPM 0–8000 with slow sweep
        rpm = int(1000 + 3000 * (0.5 + 0.5 * math.sin(t_rel * 0.5)))
        rpm += rng.randint(-50, 50)
        return _clamp_u16(rpm)
    if can_id == 0x0D0:      # speed 0–120 km/h
        speed = int(60 + 30 * math.sin(t_rel * 0.2))
        speed += rng.randint(-2, 2)
        return _clamp_u16(speed)
    if can_id == 0x0E0:      # throttle 0–100%
        throttle = int(30 + 20 * math.sin(t_rel * 0.3))
        return bytes([max(0, min(100, throttle + rng.randint(-2, 2)))])
    if can_id == 0x0F0:      # coolant temp raw 80–130 (normal operating)
        return bytes([max(0, min(255, 95 + rng.randint(-3, 3)))])
    if can_id == 0x100:      # brake pressure
        pressure = 512 + rng.randint(-20, 20)
        return _clamp_u16(pressure)
    if can_id == 0x110:      # steering angle
        angle = int(100 * math.sin(t_rel * 0.15))
        angle += rng.randint(-5, 5)
        return (angle & 0xFFFF).to_bytes(2, "big")
    if can_id == 0x120:      # gear 1–4 mostly
        return bytes([rng.choice([1, 2, 2, 3, 3, 3, 4, 4])])
    if can_id == 0x130:      # battery voltage ~12.6 V
        mv = 12600 + rng.randint(-100, 100)
        return _clamp_u16(mv)
    return bytes([rng.randint(0, 255) for _ in range(dlc)])


def _clamp_u16(v: int) -> bytes:
    return max(0, min(65535, v)).to_bytes(2, "big")
