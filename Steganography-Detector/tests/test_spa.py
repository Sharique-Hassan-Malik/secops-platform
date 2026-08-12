"""
Tests for the Sample Pair Analysis module.

Uses smooth spatially-correlated images where SPA has meaningful power.
"""

import io
import unittest

import numpy as np
from PIL import Image
from scipy.ndimage import gaussian_filter

from stegdetect.image.spa import analyze, analyze_rows_and_cols, _spa_counts


def _smooth_image(size: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    raw = rng.normal(128, 50, (size, size))
    blurred = gaussian_filter(raw, sigma=6)
    lo, hi = blurred.min(), blurred.max()
    arr = (blurred - lo) / (hi - lo + 1e-12) * 215 + 20
    return np.clip(arr, 0, 255).astype(np.uint8)


def _to_buf(arr: np.ndarray) -> io.BytesIO:
    img = Image.fromarray(np.stack([arr] * 3, axis=-1), mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def _embed(base: np.ndarray, rate: float, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    flat = base.flatten().astype(np.int32)
    n = int(len(flat) * rate)
    idx = rng.choice(len(flat), size=n, replace=False)
    bits = rng.integers(0, 2, size=n, dtype=np.int32)
    flat[idx] = (flat[idx] & ~1) | bits
    return flat.reshape(base.shape).astype(np.uint8)


class TestSpaCounts(unittest.TestCase):
    def test_perfectly_embedded_raises_w(self):
        # On a smooth image, full embedding should raise W above X.
        base = _smooth_image(256, seed=0).flatten().astype(np.int32)
        rng = np.random.default_rng(0)
        bits = rng.integers(0, 2, size=len(base), dtype=np.int32)
        stego = (base & ~1) | bits
        W, X, _ = _spa_counts(stego)
        # W > X is the expected direction on smooth embedded content.
        self.assertGreater(W, X)

    def test_counts_non_negative(self):
        samples = np.arange(256, dtype=np.int32)
        W, X, total = _spa_counts(samples)
        self.assertGreaterEqual(W, 0)
        self.assertGreaterEqual(X, 0)
        self.assertEqual(total, len(samples) - 1)


class TestSpaAnalyze(unittest.TestCase):
    def setUp(self):
        self.clean = _smooth_image(512, seed=3)

    def test_result_keys(self):
        result = analyze(_to_buf(self.clean), channel="green")
        for key in ("W", "X", "asymmetry", "estimated_rate", "detection"):
            self.assertIn(key, result)

    def test_clean_not_detected(self):
        result = analyze(_to_buf(self.clean), channel="green")
        self.assertFalse(result["detection"])

    def test_high_rate_detected(self):
        embedded = _embed(self.clean, 0.9)
        result = analyze(_to_buf(embedded), channel="green")
        self.assertTrue(result["detection"])

    def test_asymmetry_increases_with_embedding(self):
        prev = None
        for rate in (0.0, 0.1, 0.25, 0.5, 1.0):
            arr = _embed(self.clean, rate)
            result = analyze(_to_buf(arr), channel="green")
            if prev is not None:
                self.assertGreaterEqual(result["asymmetry"], prev - 0.02)
            prev = result["asymmetry"]

    def test_rows_and_cols_returns_keys(self):
        embedded = _embed(self.clean, 0.8)
        result = analyze_rows_and_cols(_to_buf(embedded))
        for key in ("W", "X", "asymmetry", "estimated_rate", "detection"):
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
