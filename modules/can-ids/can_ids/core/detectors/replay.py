"""
Replay attack detector.

A replay attack records a sequence of legitimate frames and retransmits
them later to fool the ECU.  Two detection strategies are combined:

1. **Content-hash window**: hash the sequence of (ID, data) tuples in a
   sliding window.  If the same hash appears again within a configurable
   look-back period, the sequence has been replayed.

2. **Rapid duplicate**: a specific (ID, data) pair that last appeared
   significantly less time ago than its baseline IAT is suspicious.
   Injecting a copy of a recent frame is the simplest replay form.

Both strategies emit alerts with the replayed CAN ID, the timestamp of
the re-occurrence and the minimum interval between identical frames.
"""

from __future__ import annotations

import hashlib
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from can_ids.core.alert import Alert
from can_ids.core.baseline import Baseline
from can_ids.core.frame import CANFrame, payload_key


def detect(
    frames: List[CANFrame],
    baseline: Baseline,
    window_size: int = 16,
    lookback_sec: float = 5.0,
    rapid_dup_ratio: float = 0.2,
) -> List[Alert]:
    """
    Parameters
    ----------
    frames           : test frames sorted by timestamp
    baseline         : learned profile
    window_size      : number of frames in the sequence hash window
    lookback_sec     : how far back to search for a duplicate sequence hash
    rapid_dup_ratio  : flag (id, data) duplicate if its IAT is less than
                       rapid_dup_ratio × baseline mean IAT
    """
    if not frames:
        return []

    alerts: List[Alert] = []

    # Strategy 1: sequence hash
    _sequence_hash_detect(frames, lookback_sec, window_size, alerts)

    # Strategy 2: rapid duplicate
    _rapid_duplicate_detect(frames, baseline, rapid_dup_ratio, alerts)

    return alerts


def _sequence_hash_detect(
    frames: List[CANFrame],
    lookback_sec: float,
    window_size: int,
    alerts: List[Alert],
) -> None:
    """
    Slide a window of `window_size` frames and hash each window as a
    sequence of (id, data) tuples.  Emit an alert if the same hash
    appeared within the last `lookback_sec` seconds.
    """
    if len(frames) < window_size:
        return

    # (hash → timestamp of first occurrence)
    hash_seen: Dict[str, float] = {}
    seen_pairs: set = set()         # avoid duplicate alerts per sequence hash

    window: Deque[CANFrame] = deque()

    for frame in frames:
        window.append(frame)
        if len(window) > window_size:
            window.popleft()

        if len(window) < window_size:
            continue

        seq_hash = _window_hash(window)
        cur_ts = frame.timestamp

        if seq_hash in hash_seen:
            prev_ts = hash_seen[seq_hash]
            gap = cur_ts - prev_ts
            if gap <= lookback_sec and seq_hash not in seen_pairs:
                seen_pairs.add(seq_hash)
                # report the can_id of the last frame in the replayed window
                alerts.append(Alert(
                    timestamp=cur_ts,
                    can_id=frame.can_id,
                    detector="replay",
                    severity="high",
                    message=(
                        f"ID {frame.can_id:03X}: frame sequence replay detected — "
                        f"window of {window_size} frames repeated "
                        f"{gap * 1000:.1f} ms after first occurrence"
                    ),
                    score=gap,
                    frame_data=frame.data,
                    extra={
                        "window_size": window_size,
                        "gap_ms": round(gap * 1000, 2),
                        "first_seen_ts": prev_ts,
                    },
                ))
        else:
            hash_seen[seq_hash] = cur_ts


def _rapid_duplicate_detect(
    frames: List[CANFrame],
    baseline: Baseline,
    rapid_dup_ratio: float,
    alerts: List[Alert],
) -> None:
    """
    Track the last time each (ID, data) pair was seen.  If it reappears
    in less than `rapid_dup_ratio × baseline_iat`, flag it as a rapid duplicate.
    """
    last_seen: Dict[Tuple[int, bytes], float] = {}
    seen_alerts: set = set()

    for frame in frames:
        key = payload_key(frame)
        cur_ts = frame.timestamp

        if key in last_seen:
            gap = cur_ts - last_seen[key]
            profile = baseline.get(frame.can_id)
            if profile and profile.iat_mean > 0:
                threshold = profile.iat_mean * rapid_dup_ratio
                if gap < threshold and key not in seen_alerts:
                    seen_alerts.add(key)
                    alerts.append(Alert(
                        timestamp=cur_ts,
                        can_id=frame.can_id,
                        detector="replay",
                        severity="medium",
                        message=(
                            f"ID {frame.can_id:03X}: rapid payload duplicate — "
                            f"same (ID, data) appeared {gap * 1000:.2f} ms ago "
                            f"(baseline IAT {profile.iat_mean * 1000:.2f} ms)"
                        ),
                        score=gap,
                        frame_data=frame.data,
                        extra={
                            "gap_ms": round(gap * 1000, 2),
                            "baseline_iat_ms": round(profile.iat_mean * 1000, 2),
                            "ratio": round(gap / profile.iat_mean, 4) if profile.iat_mean else 0,
                        },
                    ))

        last_seen[key] = cur_ts


def _window_hash(window: Deque[CANFrame]) -> str:
    h = hashlib.sha1()
    for f in window:
        h.update(f.can_id.to_bytes(4, "big"))
        h.update(f.data)
    return h.hexdigest()
