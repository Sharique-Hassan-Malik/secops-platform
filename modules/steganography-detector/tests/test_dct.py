"""
Tests for the DCT coefficient analysis module.

DCT-domain steganography is JPEG-specific. These tests verify correct
behavior when given a non-JPEG file and verify that the coefficient
extraction and chi-square logic work on known synthetic data.
"""

import io
import unittest

import numpy as np
from PIL import Image

from stegdetect.image.dct_analysis import _dct_coefficients, _chi_square_dct, analyze


def _make_jpeg(arr: np.ndarray, quality: int = 85) -> io.BytesIO:
    img = Image.fromarray(arr.astype(np.uint8), mode="L")
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    return buf


def _make_png(arr: np.ndarray) -> io.BytesIO:
    img = Image.fromarray(arr.astype(np.uint8), mode="L")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


class TestDCTCoefficients(unittest.TestCase):
    def test_coefficient_count(self):
        # 64x64 image -> 64 blocks of 8x8 -> 64 * 63 = 4032 AC coefficients.
        arr = np.zeros((64, 64), dtype=np.uint8)
        coeffs = _dct_coefficients(arr.astype(float))
        self.assertEqual(len(coeffs), 64 * 63)

    def test_nonzero_coefficients(self):
        rng = np.random.default_rng(10)
        arr = rng.integers(0, 256, size=(128, 128), dtype=np.uint8)
        coeffs = _dct_coefficients(arr.astype(float))
        self.assertTrue(np.any(coeffs != 0))


class TestChiSquareDCT(unittest.TestCase):
    def test_equalized_coefficients_high_stego_prob(self):
        # Construct a coefficient distribution that has perfectly equalized pairs.
        rng = np.random.default_rng(17)
        coeffs = np.array([], dtype=float)
        for k in range(-60, 60, 2):
            n = rng.integers(50, 200)
            coeffs = np.append(coeffs, [k] * n)
            coeffs = np.append(coeffs, [k + 1] * n)
        rng.shuffle(coeffs)
        result = _chi_square_dct(coeffs.astype(int))
        self.assertGreater(result["stego_probability"], 0.3)

    def test_result_keys(self):
        coeffs = np.arange(-64, 64, dtype=float)
        result = _chi_square_dct(coeffs.astype(int))
        for key in ("chi2", "df", "stego_probability"):
            self.assertIn(key, result)


class TestAnalyzeFunction(unittest.TestCase):
    def test_non_jpeg_returns_error(self):
        arr = np.zeros((64, 64), dtype=np.uint8)
        buf = _make_png(arr)
        # BytesIO does not have a .suffix attribute; analyze() checks suffix,
        # so we pass a fake path string. But for BufferedIO we check the error path.
        # Create a temporary file to test non-JPEG rejection.
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            img = Image.fromarray(arr, mode="L")
            img.save(f.name)
            fname = f.name
        try:
            result = analyze(fname)
            self.assertIn("error", result)
            self.assertFalse(result["detection"])
        finally:
            os.unlink(fname)

    def test_jpeg_analysis_returns_keys(self):
        import tempfile, os
        rng = np.random.default_rng(55)
        arr = rng.integers(0, 256, (256, 256), dtype=np.uint8)
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            Image.fromarray(arr, mode="L").save(f.name, format="JPEG", quality=85)
            fname = f.name
        try:
            result = analyze(fname, calibrate=False)
            for key in ("chi2", "df", "stego_probability", "detection", "n_coefficients"):
                self.assertIn(key, result)
        finally:
            os.unlink(fname)


if __name__ == "__main__":
    unittest.main()
