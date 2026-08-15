"""
Shannon entropy analysis for browser fingerprint features.

For each feature, entropy H = -Σ p(x) log2 p(x) across the observed value
distribution measures how many bits of identifying information that feature
contributes. A feature with entropy H bits reduces the anonymity set by a
factor of 2^H.

Features are grouped into categories matching the collector modules:
canvas, webgl, audio, fonts, timing and network.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

import numpy as np


# Columns extracted from the Fingerprint ORM model, grouped by source
FEATURE_GROUPS: dict[str, list[str]] = {
    "canvas": [
        "canvas_hash",
    ],
    "webgl": [
        "webgl_unmasked_renderer",
        "webgl_vendor",
        "webgl_renderer",
        "webgl_version",
        "webgl_extensions_count",
        "webgl_image_hash",
    ],
    "audio": [
        "audio_hash",
        "audio_sample_sum",
    ],
    "fonts": [
        "font_count",
        "fonts_detected",
    ],
    "timing": [
        "timezone",
        "timezone_offset",
        "platform",
        "language",
        "languages",
        "hardware_concurrency",
        "device_memory_gb",
        "screen_width",
        "screen_height",
        "screen_depth",
        "pixel_ratio",
        "max_touch_points",
        "clock_resolution",
        "math_timing_hash",
        "user_agent",
    ],
    "network": [
        "connection_type",
        "effective_type",
        "audio_input_count",
        "audio_output_count",
        "video_input_count",
        "ice_types",
    ],
}

ALL_FEATURES = [f for group in FEATURE_GROUPS.values() for f in group]


@dataclass
class FeatureEntropy:
    feature:          str
    group:            str
    entropy_bits:     float
    n_unique_values:  int
    n_samples:        int
    most_common:      list[tuple[str, int]]   # top 5 (value, count)
    coverage:         float                    # fraction of rows with non-null value


def compute_entropy(values: list) -> float:
    """Shannon entropy in bits for a list of discrete values."""
    non_null = [v for v in values if v is not None and str(v).strip() != ""]
    if not non_null:
        return 0.0
    counts = Counter(str(v) for v in non_null)
    n      = sum(counts.values())
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyse_features(rows: list[dict]) -> list[FeatureEntropy]:
    """
    Compute entropy for every feature column across a list of fingerprint dicts.
    Rows should be dictionaries with keys matching ALL_FEATURES.
    """
    n = len(rows)
    if n == 0:
        return []

    results = []
    for group, features in FEATURE_GROUPS.items():
        for feature in features:
            values   = [r.get(feature) for r in rows]
            non_null = [v for v in values if v is not None and str(v).strip() != ""]
            coverage = len(non_null) / n if n else 0.0
            entropy  = compute_entropy(values)
            counts   = Counter(str(v) for v in non_null)
            n_unique = len(counts)
            top5     = counts.most_common(5)

            results.append(FeatureEntropy(
                feature=feature,
                group=group,
                entropy_bits=round(entropy, 4),
                n_unique_values=n_unique,
                n_samples=n,
                most_common=top5,
                coverage=round(coverage, 4),
            ))

    return sorted(results, key=lambda x: x.entropy_bits, reverse=True)


def entropy_summary(rows: list[dict]) -> dict:
    """
    High-level summary:
    - Per-feature entropy sorted descending
    - Per-group total entropy (sum of feature entropies within group)
    - Estimated anonymity set size = 2^(sum of top-N independent feature entropies)
    """
    features = analyse_features(rows)

    group_totals: dict[str, float] = {}
    for fe in features:
        group_totals[fe.group] = group_totals.get(fe.group, 0.0) + fe.entropy_bits

    # Anonymity set estimate using all features (assuming independence — upper bound)
    total_bits = sum(fe.entropy_bits for fe in features)

    return {
        "n_fingerprints":      len(rows),
        "total_bits":          round(total_bits, 2),
        "anonymity_set_upper": round(2 ** total_bits, 0) if total_bits < 50 else float("inf"),
        "group_totals":        {k: round(v, 3) for k, v in sorted(group_totals.items(), key=lambda x: -x[1])},
        "features": [
            {
                "feature":         fe.feature,
                "group":           fe.group,
                "entropy_bits":    fe.entropy_bits,
                "n_unique":        fe.n_unique_values,
                "coverage":        fe.coverage,
                "top_values":      [{"value": str(v)[:80], "count": c} for v, c in fe.most_common],
            }
            for fe in features
        ],
    }
