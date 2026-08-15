"""
Chi-square attack for spatial-domain LSB steganography detection.

Reference:
    Westfeld, A. and Pfitzmann, A. (2000). Attacks on Steganographic Systems.
    Proceedings of the 3rd International Workshop on Information Hiding.

The attack exploits a statistical artifact of LSB replacement: embedding data
equalizes the occurrence counts of each (2k, 2k+1) value pair in the pixel
histogram. A chi-square test measures how far the histogram is from that
equalized state.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import numpy as np
from PIL import Image
from scipy.stats import chi2 as chi2_dist


def _load_channel(path: Union[str, Path], channel: str) -> np.ndarray:
    img = Image.open(path)
    mode = img.mode

    if mode in ("RGB", "RGBA"):
        img = img.convert("RGB")
        arr = np.array(img, dtype=np.uint8)
        ch = {"red": 0, "green": 1, "blue": 2}.get(channel, 1)
        return arr[:, :, ch].flatten()

    if mode == "P":
        img = img.convert("RGB")
        arr = np.array(img, dtype=np.uint8)
        ch = {"red": 0, "green": 1, "blue": 2}.get(channel, 1)
        return arr[:, :, ch].flatten()

    return np.array(img.convert("L"), dtype=np.uint8).flatten()


def _chi_square_statistic(samples: np.ndarray) -> dict:
    counts = np.bincount(samples, minlength=256).astype(float)
    pairs = counts.reshape(128, 2)
    totals = pairs.sum(axis=1)

    valid = totals > 0
    n_valid = int(valid.sum())
    if n_valid <= 1:
        return {"chi2": 0.0, "df": 0, "stego_probability": 0.0}

    exp = (totals[valid] / 2.0)[:, None].repeat(2, axis=1)
    obs = pairs[valid]
    chi2_stat = float(np.sum((obs - exp) ** 2 / exp))
    df = n_valid - 1

    # H0: pairs are equalized (consistent with LSB embedding).
    # A natural image deviates strongly from H0 -> large chi2 -> small sf.
    # A stego image matches H0 -> small chi2 -> sf close to 1.
    stego_prob = float(chi2_dist.sf(chi2_stat, df=df))

    return {"chi2": chi2_stat, "df": df, "stego_probability": stego_prob}


def analyze(path: Union[str, Path], channel: str = "green") -> dict:
    """Run the chi-square attack on one channel of an image.

    Args:
        path:    Path to the image file.
        channel: Which channel to analyze: 'red', 'green', or 'blue'.

    Returns:
        Dictionary with keys:
            chi2             -- chi-square statistic
            df               -- degrees of freedom
            stego_probability -- 0..1, values near 1 indicate steganography
            detection        -- True if stego_probability > 0.05
            channel          -- channel analyzed
    """
    pixels = _load_channel(path, channel)
    result = _chi_square_statistic(pixels)
    result["channel"] = channel
    result["detection"] = result["stego_probability"] > 0.05
    return result


def analyze_windowed(
    path: Union[str, Path],
    channel: str = "green",
    window_size: int = 512,
    step: int = 256,
) -> list[dict]:
    """Sliding-window chi-square analysis.

    Partial LSB embedding hides data in only a fraction of the image.
    A global chi-square test may miss this if the stego region is small.
    Sliding the window over the pixel stream locates the stego region.

    Returns:
        List of dicts, each with keys: start, end, stego_probability.
    """
    pixels = _load_channel(path, channel)
    results: list[dict] = []
    pos = 0
    while pos + window_size <= len(pixels):
        stat = _chi_square_statistic(pixels[pos : pos + window_size])
        results.append(
            {
                "start": pos,
                "end": pos + window_size,
                "stego_probability": stat["stego_probability"],
            }
        )
        pos += step
    return results
