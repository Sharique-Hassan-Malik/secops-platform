"""
Feature preparation for ML classification.

Converts fingerprint ORM rows (or dicts) into a numerical feature matrix.
Categorical features are label-encoded; continuous features are kept as-is.
Missing values are imputed with -1 (a sentinel outside all natural ranges).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import numpy as np

# Features used for ML — a subset of ALL_FEATURES that are well-populated
# and carry high entropy. User-agent is excluded (too high cardinality for
# simple classification; use canvas/webgl hashes instead).
ML_FEATURES = [
    "canvas_hash",
    "webgl_unmasked_renderer",
    "webgl_vendor",
    "webgl_extensions_count",
    "webgl_image_hash",
    "audio_hash",
    "font_count",
    "timezone",
    "timezone_offset",
    "platform",
    "language",
    "hardware_concurrency",
    "device_memory_gb",
    "screen_width",
    "screen_height",
    "screen_depth",
    "pixel_ratio",
    "max_touch_points",
    "clock_resolution",
    "audio_input_count",
    "audio_output_count",
    "video_input_count",
]

# Features that are treated as categorical (hashed to integer)
CATEGORICAL = {
    "canvas_hash",
    "webgl_unmasked_renderer",
    "webgl_vendor",
    "webgl_image_hash",
    "audio_hash",
    "timezone",
    "platform",
    "language",
}


def _encode(value: Any, feature: str) -> float:
    if value is None:
        return -1.0
    if feature in CATEGORICAL:
        # Stable integer encoding via hash
        s = str(value).strip()
        if not s:
            return -1.0
        h = int(hashlib.md5(s.encode()).hexdigest()[:8], 16)
        return float(h % 100_000)
    try:
        return float(value)
    except (ValueError, TypeError):
        s = str(value).strip()
        if not s:
            return -1.0
        h = int(hashlib.md5(s.encode()).hexdigest()[:8], 16)
        return float(h % 100_000)


def extract_features(row: dict) -> list[float]:
    """Convert a single fingerprint dict to a feature vector of len(ML_FEATURES)."""
    return [_encode(row.get(f), f) for f in ML_FEATURES]


def build_matrix(rows: list[dict]) -> np.ndarray:
    """Convert a list of fingerprint dicts to an (N, D) float matrix."""
    return np.array([extract_features(r) for r in rows], dtype=np.float64)
