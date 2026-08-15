"""
DCT-domain chi-square analysis for JPEG steganography detection.

Reference:
    Westfeld, A. (2001). F5 — A Steganographic Algorithm. Proceedings of the
    4th International Workshop on Information Hiding.

    Fridrich, J., Goljan, M., and Hogea, D. (2002). Steganalysis of JPEG Images:
    Breaking the F5 Algorithm. Proceedings of the 5th International Workshop on
    Information Hiding.

Tools like JSteg and F5 embed data by modifying DCT AC coefficients of 8x8
JPEG blocks. This produces the same pair-equalization artifact as spatial LSB
embedding, but in the DCT domain. The calibration step (slight crop and re-save)
constructs a reference histogram that approximates the pre-embedding DCT
statistics, enabling a more sensitive detection for low embedding rates.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Union

import numpy as np
from PIL import Image
from scipy.fft import dctn
from scipy.stats import chi2 as chi2_dist


def _dct_coefficients(image_array: np.ndarray) -> np.ndarray:
    """Compute 8x8 block DCT coefficients for a single-channel image array.

    Returns a flattened array of all AC coefficients (DC coefficient at position
    (0,0) of each block is excluded because tools avoid modifying it).
    """
    h, w = image_array.shape
    # Trim to multiple of 8
    h8 = (h // 8) * 8
    w8 = (w // 8) * 8
    arr = image_array[:h8, :w8].astype(float)

    coeffs = []
    for r in range(0, h8, 8):
        for c in range(0, w8, 8):
            block = arr[r : r + 8, c : c + 8]
            dct_block = dctn(block, norm="ortho")
            # Flatten and skip the DC component at index [0, 0]
            flat = dct_block.flatten()
            coeffs.append(flat[1:])  # 63 AC coefficients per block

    return np.concatenate(coeffs)


def _quantize(coeffs: np.ndarray, step: float = 1.0) -> np.ndarray:
    """Round coefficients to simulate JPEG quantization."""
    return np.round(coeffs / step).astype(int)


def _chi_square_dct(coeffs: np.ndarray) -> dict:
    """Chi-square test on DCT coefficient histogram pairs."""
    # Focus on the central range where steganography is applied (-127 to 127 typically).
    cmin, cmax = -127, 127
    bins = np.arange(cmin, cmax + 2)
    counts, _ = np.histogram(coeffs, bins=bins)
    counts = counts.astype(float)

    # Pair (2k, 2k+1) — same idea as spatial chi-square.
    # The range starts at -127 which is odd; align to even-start pairs.
    if cmin % 2 != 0:
        counts = counts[1:]  # start from -126 (even)

    n_pairs = len(counts) // 2
    pairs = counts[: n_pairs * 2].reshape(n_pairs, 2)
    totals = pairs.sum(axis=1)
    valid = totals > 0

    if valid.sum() <= 1:
        return {"chi2": 0.0, "df": 0, "stego_probability": 0.0}

    exp = (totals[valid] / 2.0)[:, None].repeat(2, axis=1)
    obs = pairs[valid]
    chi2_stat = float(np.sum((obs - exp) ** 2 / exp))
    df = int(valid.sum()) - 1
    stego_prob = float(chi2_dist.sf(chi2_stat, df=df))

    return {"chi2": chi2_stat, "df": df, "stego_probability": stego_prob}


def _calibrated_chi_square(original_path: Path) -> dict:
    """Calibrated chi-square test using a re-compressed reference.

    The image is cropped by 4 pixels from top-left and re-saved at the same
    JPEG quality. This breaks any steganographic alignment while preserving the
    natural DCT statistics. The chi-square is computed on the difference between
    the original and reference coefficient histograms.
    """
    img = Image.open(original_path)
    if img.mode != "L":
        img = img.convert("L")

    arr = np.array(img, dtype=float)

    # Determine original JPEG quality if available; default to 75.
    quality = 75
    try:
        quantization = img.quantization  # type: ignore[attr-defined]
        if quantization:
            # Estimate quality from luminance quantization table (table 0).
            q_table = list(quantization.get(0, {}).values())
            if q_table:
                avg_q = np.mean(q_table)
                # Rough inversion of the JPEG quality formula.
                if avg_q <= 8:
                    quality = 100
                elif avg_q <= 100:
                    quality = int(np.clip(100 - avg_q, 1, 95))
    except Exception:
        pass

    # Reference: crop 4 pixels and re-compress.
    ref_arr = arr[4:, 4:]
    ref_img = Image.fromarray(ref_arr.astype(np.uint8), mode="L")
    buf = io.BytesIO()
    ref_img.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    ref_img = Image.open(buf).convert("L")
    ref_arr = np.array(ref_img, dtype=float)

    orig_coeffs = _dct_coefficients(arr)
    ref_coeffs = _dct_coefficients(ref_arr)

    orig_result = _chi_square_dct(orig_coeffs)
    ref_result = _chi_square_dct(ref_coeffs)

    # The calibrated score is the excess stego probability over the reference.
    calibrated_prob = float(
        np.clip(orig_result["stego_probability"] - ref_result["stego_probability"], 0.0, 1.0)
    )

    return {
        "chi2_original": orig_result["chi2"],
        "chi2_reference": ref_result["chi2"],
        "stego_probability_original": orig_result["stego_probability"],
        "stego_probability_reference": ref_result["stego_probability"],
        "stego_probability": calibrated_prob,
        "detection": calibrated_prob > 0.02,
    }


def analyze(path: Union[str, Path], calibrate: bool = True) -> dict:
    """Analyze a JPEG image for DCT-domain steganography.

    Args:
        path:      Path to a JPEG image file.
        calibrate: If True, use the calibrated chi-square variant. This reduces
                   false positives on clean images at the cost of slightly lower
                   sensitivity at very low embedding rates.

    Returns:
        Dictionary with detection result and intermediate statistics.
        Returns an error entry if the file is not JPEG.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix not in (".jpg", ".jpeg"):
        return {"error": "DCT analysis requires a JPEG file", "detection": False}

    img = Image.open(path)
    arr = np.array(img.convert("L"), dtype=float)
    coeffs = _dct_coefficients(arr)

    uncalibrated = _chi_square_dct(coeffs)

    if calibrate:
        result = _calibrated_chi_square(path)
    else:
        result = {
            "stego_probability": uncalibrated["stego_probability"],
            "detection": uncalibrated["stego_probability"] > 0.05,
        }

    result["chi2"] = uncalibrated["chi2"]
    result["df"] = uncalibrated["df"]
    result["n_coefficients"] = len(coeffs)
    result["calibrated"] = calibrate
    return result
