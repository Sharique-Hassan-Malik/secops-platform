"""
Sample Pair Analysis (SPA) for LSB steganography detection.

Reference:
    Dumitrescu, S., Wu, X., and Wang, Z. (2003). Detection of LSB Steganography
    via Sample Pair Analysis. IEEE Transactions on Signal Processing, 51(7).

SPA examines pairs of adjacent pixels and exploits how LSB embedding alters
the joint distribution of value pairs. Two counts W and X are derived from
the orientation of near-valued pairs relative to parity. For smooth natural
images W ≈ X in clean content. LSB embedding on smooth content creates new
same-to-adjacent transitions concentrated in the W direction, raising the
(W-X)/(W+X) asymmetry measurably. The asymmetry is used to estimate the
embedding rate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import numpy as np
from PIL import Image


def _load_channel(path: Union[str, Path], channel: str) -> np.ndarray:
    img = Image.open(path)
    if img.mode in ("RGB", "RGBA", "P"):
        img = img.convert("RGB")
        arr = np.array(img, dtype=np.int32)
        ch = {"red": 0, "green": 1, "blue": 2}.get(channel, 1)
        return arr.flatten()[ch::3] if arr.ndim == 1 else arr[:, :, ch].flatten()
    return np.array(img.convert("L"), dtype=np.int32).flatten()


def _load_channel(path: Union[str, Path], channel: str) -> np.ndarray:
    img = Image.open(path)
    if img.mode in ("RGB", "RGBA", "P"):
        img = img.convert("RGB")
        arr = np.array(img, dtype=np.int32)
        ch = {"red": 0, "green": 1, "blue": 2}.get(channel, 1)
        return arr[:, :, ch].flatten()
    return np.array(img.convert("L"), dtype=np.int32).flatten()


def _spa_counts(samples: np.ndarray) -> tuple[int, int, int]:
    """Compute W and X pair counts from a 1D sample sequence.

    W counts pairs where an even pixel is followed by the next value up OR
    an odd pixel is followed by the next value down.
    X counts the opposite orientation.

    LSB embedding on smooth content converts zero-difference adjacent pairs
    into ±1 transitions concentrated in the W direction (even->odd for
    increasing gradients) raising W above X.
    """
    a = samples[:-1]
    b = samples[1:]
    diff = b - a

    W = int(
        np.sum(((a % 2 == 0) & (diff == 1)))
        + np.sum(((a % 2 != 0) & (diff == -1)))
    )
    X = int(
        np.sum(((a % 2 == 0) & (diff == -1)))
        + np.sum(((a % 2 != 0) & (diff == 1)))
    )
    return W, X, len(a)


def _asymmetry(W: int, X: int) -> float:
    """(W-X)/(W+X) in [-1, 1]. Values well above 0 indicate embedding."""
    denom = W + X
    return float((W - X) / denom) if denom > 0 else 0.0


def analyze(path: Union[str, Path], channel: str = "green") -> dict:
    """Run SPA on one channel of an image.

    Args:
        path:    Path to the image file.
        channel: Channel to analyze: 'red', 'green', or 'blue'.

    Returns:
        Dictionary with keys:
            W               -- normalized W count
            X               -- normalized X count
            asymmetry       -- (W-X)/(W+X); positive and large indicates embedding
            estimated_rate  -- estimated LSB embedding rate in [0, 1]
            detection       -- True if asymmetry > 0.05
    """
    samples = _load_channel(path, channel)
    W, X, total = _spa_counts(samples)
    asym = _asymmetry(W, X)

    # Full LSB embedding on smooth content yields asym ≈ 0.2-0.3.
    # Normalize to [0, 1] with 0.25 as the reference full-embedding asymmetry.
    rate = float(np.clip(asym / 0.25, 0.0, 1.0))

    return {
        "W": float(W / max(total, 1)),
        "X": float(X / max(total, 1)),
        "asymmetry": float(asym),
        "estimated_rate": rate,
        "detection": asym > 0.05,
    }


def analyze_rows_and_cols(path: Union[str, Path]) -> dict:
    """Run SPA on horizontal and vertical scan orders and average the estimates.

    Averaging over two scan directions reduces variance on images where
    the dominant gradient direction aligns with one scan axis.
    """
    img = Image.open(path)
    if img.mode in ("RGB", "RGBA", "P"):
        img = img.convert("RGB")
        plane = np.array(img, dtype=np.int32)[:, :, 1]
    else:
        plane = np.array(img.convert("L"), dtype=np.int32)

    W_h, X_h, n_h = _spa_counts(plane.flatten())
    W_v, X_v, n_v = _spa_counts(plane.T.flatten())

    W_total = W_h + W_v
    X_total = X_h + X_v
    asym = _asymmetry(W_total, X_total)
    rate = float(np.clip(asym / 0.25, 0.0, 1.0))
    total = n_h + n_v

    return {
        "W": float(W_total / max(total, 1)),
        "X": float(X_total / max(total, 1)),
        "asymmetry": float(asym),
        "estimated_rate": rate,
        "detection": asym > 0.05,
    }
