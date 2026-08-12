"""
Tests for the chi-square attack module.

The chi-square statistic tests work with explicitly constructed histograms
rather than image files because the statistic only cares about the value
frequency distribution, not the image structure.
"""

import io
import unittest

import numpy as np
from PIL import Image
from scipy.ndimage import gaussian_filter

from stegdetect.image.chi_square import (
    _chi_square_statistic,
    analyze,
    analyze_windowed,
)


def _smooth_image(size: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    raw = rng.normal(0, 1, (size, size))
    arr = np.clip(gaussian_filter(raw, sigma=5) * 80 + 128, 0, 255).astype(np.uint8)
    return arr


def _embed(base: np.ndarray, rate: float, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    flat = base.flatten().astype(np.int32)
    n = int(len(flat) * rate)
    idx = rng.choice(len(flat), size=n, replace=False)
    bits = rng.integers(0, 2, size=n, dtype=np.int32)
    flat[idx] = (flat[idx] & ~1) | bits
    return flat.reshape(base.shape).astype(np.uint8)


def _to_png_buf(arr: np.ndarray) -> io.BytesIO:
    img = Image.fromarray(np.stack([arr] * 3, axis=-1), mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


class TestChiSquareStatistic(unittest.TestCase):
    def test_equalized_pairs_high_stego_prob(self):
        """Perfectly equalized (2k, 2k+1) pairs = the stego histogram signature."""
        arr = []
        for k in range(20, 80):
            arr.extend([2 * k] * 500)
            arr.extend([2 * k + 1] * 500)
        equalized = np.array(arr, dtype=np.uint8)
        result = _chi_square_statistic(equalized)
        self.assertGreater(result["stego_probability"], 0.99)

    def test_unequalized_pairs_low_stego_prob(self):
        """Strongly unequal pairs = clean natural image signature."""
        rng = np.random.default_rng(0)
        arr = []
        for k in range(20, 80):
            n_even = int(rng.integers(200, 800))
            n_odd = int(rng.integers(10, 100))   # much fewer odd values
            arr.extend([2 * k] * n_even)
            arr.extend([2 * k + 1] * n_odd)
        unequal = np.array(arr, dtype=np.uint8)
        result = _chi_square_statistic(unequal)
        self.assertLess(result["stego_probability"], 0.01)

    def test_empty_array_returns_zero(self):
        result = _chi_square_statistic(np.array([], dtype=np.uint8))
        self.assertEqual(result["stego_probability"], 0.0)


class TestAnalyzeFromFile(unittest.TestCase):
    def setUp(self):
        self.clean = _smooth_image(512, seed=1)
        self.stego = _embed(self.clean, 1.0, seed=2)

    def test_clean_image_not_detected(self):
        result = analyze(_to_png_buf(self.clean), channel="green")
        self.assertIn("detection", result)
        self.assertFalse(result["detection"])

    def test_stego_image_detected(self):
        result = analyze(_to_png_buf(self.stego), channel="green")
        self.assertTrue(result["detection"])

    def test_result_keys(self):
        result = analyze(_to_png_buf(self.clean), channel="red")
        for key in ("chi2", "df", "stego_probability", "detection", "channel"):
            self.assertIn(key, result)

    def test_windowed_returns_list(self):
        results = analyze_windowed(
            _to_png_buf(self.stego), channel="green", window_size=2048, step=1024
        )
        self.assertIsInstance(results, list)
        for item in results:
            self.assertIn("start", item)
            self.assertIn("end", item)
            self.assertGreaterEqual(item["stego_probability"], 0.0)
            self.assertLessEqual(item["stego_probability"], 1.0)


if __name__ == "__main__":
    unittest.main()
