"""
Palette-based steganography detection for GIF and palette PNG images.

Tools like Steganos and early palette steganography schemes embed data by:
  1. Reordering palette entries in a non-luminance-sorted order (index-order encoding).
  2. Embedding in the LSBs of palette color components.
  3. Introducing duplicate or near-duplicate colors.

This module applies three checks:
  - Palette ordering entropy: a naturally-quantized palette tends to be ordered
    by luminance or color proximity. Unusual orderings raise suspicion.
  - Duplicate palette entries: legitimate quantization rarely produces exact
    duplicate colors; their presence suggests palette manipulation.
  - LSB frequency in palette components: checks whether palette RGB values
    show the same pair-equalization artifact as spatial LSB embedding.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import numpy as np
from PIL import Image
from scipy.stats import chi2 as chi2_dist


def _palette_luminance(palette_rgb: np.ndarray) -> np.ndarray:
    """Rec. 601 luma for each palette entry."""
    return (
        0.299 * palette_rgb[:, 0]
        + 0.587 * palette_rgb[:, 1]
        + 0.114 * palette_rgb[:, 2]
    )


def _ordering_score(palette_rgb: np.ndarray) -> float:
    """Measure how close the palette ordering is to luminance-sorted order.

    Returns a value in [0, 1]; values near 1 indicate luminance-sorted order
    (typical of natural quantization); values near 0 indicate random or
    deliberately scrambled order.
    """
    luma = _palette_luminance(palette_rgb)
    n = len(luma)
    if n <= 1:
        return 1.0

    # Kendall's tau between index order and sorted-luma order.
    rank_luma = np.argsort(np.argsort(luma))
    rank_index = np.arange(n)

    concordant = 0
    discordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            sign_idx = np.sign(rank_index[j] - rank_index[i])
            sign_luma = np.sign(rank_luma[j] - rank_luma[i])
            if sign_idx * sign_luma > 0:
                concordant += 1
            elif sign_idx * sign_luma < 0:
                discordant += 1

    total = concordant + discordant
    tau = (concordant - discordant) / total if total > 0 else 0.0
    return float((tau + 1.0) / 2.0)


def _duplicate_count(palette_rgb: np.ndarray) -> int:
    """Count exact duplicate palette entries."""
    unique_rows = {tuple(row) for row in palette_rgb}
    return len(palette_rgb) - len(unique_rows)


def _palette_lsb_chi_square(palette_rgb: np.ndarray) -> float:
    """Chi-square test on LSBs of palette component values.

    The palette is small, so the test has limited power. A near-zero return
    value indicates the palette components are not LSB-equalized.
    """
    flat = palette_rgb.flatten()
    counts = np.bincount(flat, minlength=256).astype(float)
    pairs = counts.reshape(128, 2)
    totals = pairs.sum(axis=1)
    valid = totals > 0

    if valid.sum() <= 1:
        return 0.0

    exp = (totals[valid] / 2.0)[:, None].repeat(2, axis=1)
    obs = pairs[valid]
    chi2_stat = float(np.sum((obs - exp) ** 2 / exp))
    df = int(valid.sum()) - 1
    return float(chi2_dist.sf(chi2_stat, df=df))


def analyze(path: Union[str, Path]) -> dict:
    """Analyze a palette image for palette-based steganography.

    Args:
        path: Path to a GIF or palette-mode PNG file.

    Returns:
        Dictionary with keys:
            is_palette_image    -- False if the image is not a palette mode
            n_colors            -- number of palette entries
            ordering_score      -- luminance-ordering score, 0..1 (low = suspicious)
            duplicates          -- number of duplicate palette entries
            lsb_chi_prob        -- chi-square probability on palette LSBs (high = suspicious)
            detection           -- True if any indicator crosses its threshold
    """
    path = Path(path)
    img = Image.open(path)

    if img.mode != "P":
        return {"is_palette_image": False, "detection": False}

    raw_palette = img.getpalette()  # flat list: R0,G0,B0,R1,G1,B1,...
    if raw_palette is None:
        return {"is_palette_image": False, "detection": False}

    n_colors = len(raw_palette) // 3
    palette_rgb = np.array(raw_palette, dtype=np.uint8)[: n_colors * 3].reshape(n_colors, 3)

    # Only look at entries that are actually used.
    used_indices = set(img.getdata())
    used_mask = np.array([i in used_indices for i in range(n_colors)])
    used_palette = palette_rgb[used_mask]

    if len(used_palette) < 2:
        return {
            "is_palette_image": True,
            "n_colors": n_colors,
            "ordering_score": 1.0,
            "duplicates": 0,
            "lsb_chi_prob": 0.0,
            "detection": False,
        }

    ordering = _ordering_score(used_palette)
    duplicates = _duplicate_count(used_palette)
    lsb_prob = _palette_lsb_chi_square(used_palette)

    # Detection thresholds: low ordering score or any duplicates are suspicious.
    suspicious_ordering = ordering < 0.4
    suspicious_duplicates = duplicates > 0
    suspicious_lsb = lsb_prob > 0.2

    detection = suspicious_ordering or suspicious_duplicates or suspicious_lsb

    return {
        "is_palette_image": True,
        "n_colors": n_colors,
        "n_used_colors": int(len(used_palette)),
        "ordering_score": float(ordering),
        "duplicates": int(duplicates),
        "lsb_chi_prob": float(lsb_prob),
        "suspicious_ordering": suspicious_ordering,
        "suspicious_duplicates": suspicious_duplicates,
        "suspicious_lsb": suspicious_lsb,
        "detection": detection,
    }
