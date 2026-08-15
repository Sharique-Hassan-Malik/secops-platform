"""
Tests for the RS analysis module.

Uses spatially-correlated images with strong texture (sigma=5 blur with
amplitude=80) where the clean RS ratio is reliably above 0.7 and fully
embedded RS ratio is reliably near 0.
"""

import io
import unittest

import numpy as np
from PIL import Image
from scipy.ndimage import gaussian_filter

from stegdetect.image.rs_analysis import analyze, _count_rs_vectorized, _MASK


def _rs_image(size: int, seed: int) -> np.ndarray:
    """Natural-texture image with reliably high RS ratio when clean."""
    rng = np.random.default_rng(seed)
    raw = rng.normal(0, 1, (size, size))
    arr = np.clip(gaussian_filter(raw, sigma=5) * 80 + 128, 0, 255)
    return arr.astype(np.uint8)


def _to_buf(arr: np.ndarray) -> io.BytesIO:
    img = Image.fromarray(np.stack([arr] * 3, axis=-1), mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def _embed(base: np.ndarray, rate: float, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    flat = base.flatten().astype(np.int32)
    n = int(len(flat) * rate)
    idx = rng.choice(len(flat), size=n, replace=False)
    bits = rng.integers(0, 2, size=n, dtype=np.int32)
    flat[idx] = (flat[idx] & ~1) | bits
    return flat.reshape(base.shape).astype(np.uint8)


class TestRSCounts(unittest.TestCase):
    def test_vectorized_counts_nonnegative(self):
        rng = np.random.default_rng(5)
        flat = rng.integers(0, 256, size=10_000, dtype=np.int32)
        R, S = _count_rs_vectorized(flat, _MASK, group_size=4, inverse=False)
        self.assertGreaterEqual(R, 0)
        self.assertGreaterEqual(S, 0)
        self.assertLessEqual(R + S, len(flat) // 4)

    def test_clean_smooth_rm_greater_than_sm(self):
        base = _rs_image(512, seed=11).flatten().astype(np.int32)
        R, S = _count_rs_vectorized(base, _MASK, group_size=4, inverse=False)
        self.assertGreater(R, S)


class TestRSAnalyze(unittest.TestCase):
    def setUp(self):
        self.clean = _rs_image(512, seed=99)

    def test_result_keys(self):
        result = analyze(_to_buf(self.clean), channel="green")
        for key in ("RM", "SM", "RN", "SN", "rs_ratio", "estimated_rate", "detection"):
            self.assertIn(key, result)

    def test_clean_not_detected(self):
        # Clean image has rs_ratio ~ 0.8 which is well above the detection threshold.
        result = analyze(_to_buf(self.clean), channel="green")
        self.assertFalse(result["detection"])

    def test_rs_ratio_decreases_with_embedding(self):
        prev = None
        for rate in (0.0, 0.1, 0.25, 0.5, 1.0):
            arr = _embed(self.clean, rate)
            result = analyze(_to_buf(arr), channel="green")
            if prev is not None:
                # Allow small tolerance for numerical variation.
                self.assertLessEqual(result["rs_ratio"], prev + 0.03)
            prev = result["rs_ratio"]

    def test_full_embedding_detected(self):
        fully_embedded = _embed(self.clean, 1.0)
        result = analyze(_to_buf(fully_embedded), channel="green")
        self.assertTrue(result["detection"])


if __name__ == "__main__":
    unittest.main()
