"""
Chi-square attack for audio LSB steganography detection.

The same statistical artifact exploited in spatial image analysis appears in
audio files when LSB replacement is used on PCM samples. This module applies
the chi-square test to 16-bit and 8-bit WAV audio.

Reference:
    Westfeld, A. and Pfitzmann, A. (2000). Attacks on Steganographic Systems.
    Proceedings of the 3rd International Workshop on Information Hiding.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import numpy as np
from scipy.stats import chi2 as chi2_dist

try:
    import soundfile as sf
    _HAVE_SF = True
except ImportError:
    _HAVE_SF = False

try:
    from scipy.io import wavfile as _wavfile
    _HAVE_SCIPY_WAV = True
except ImportError:
    _HAVE_SCIPY_WAV = False


def _load_audio(path: Union[str, Path], channel: str = "left") -> np.ndarray:
    """Load audio samples from a WAV file and return them as uint8 or uint16 integers."""
    path = Path(path)

    if _HAVE_SF:
        data, _sr = sf.read(str(path), dtype="int16", always_2d=True)
    elif _HAVE_SCIPY_WAV:
        _sr, data = _wavfile.read(str(path))
        if data.ndim == 1:
            data = data[:, None]
        if data.dtype == np.float32 or data.dtype == np.float64:
            data = (data * 32767).astype(np.int16)
        elif data.dtype == np.uint8:
            data = data.astype(np.int16) - 128
        data = data.astype(np.int16)
    else:
        raise ImportError("Install soundfile or scipy to analyze audio files.")

    ch_idx = 0 if channel in ("left", "mono", "0") else 1
    if data.shape[1] == 1:
        ch_idx = 0
    samples = data[:, min(ch_idx, data.shape[1] - 1)]
    return samples


def _to_uint16(samples: np.ndarray) -> np.ndarray:
    """Map signed int16 samples to uint16 for histogram analysis."""
    return (samples.astype(np.int32) + 32768).astype(np.uint16)


def _chi_square_statistic_16bit(samples_u16: np.ndarray) -> dict:
    """Chi-square test on 16-bit sample value pairs."""
    counts = np.bincount(samples_u16, minlength=65536).astype(float)
    pairs = counts.reshape(32768, 2)
    totals = pairs.sum(axis=1)

    valid = totals > 0
    n_valid = int(valid.sum())
    if n_valid <= 1:
        return {"chi2": 0.0, "df": 0, "stego_probability": 0.0}

    exp = (totals[valid] / 2.0)[:, None].repeat(2, axis=1)
    obs = pairs[valid]
    chi2_stat = float(np.sum((obs - exp) ** 2 / exp))
    df = n_valid - 1
    stego_prob = float(chi2_dist.sf(chi2_stat, df=df))
    return {"chi2": chi2_stat, "df": df, "stego_probability": stego_prob}


def _chi_square_statistic_8bit(samples: np.ndarray) -> dict:
    """Chi-square test on 8-bit (byte-level) sample pairs."""
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
    stego_prob = float(chi2_dist.sf(chi2_stat, df=df))
    return {"chi2": chi2_stat, "df": df, "stego_probability": stego_prob}


def analyze(
    path: Union[str, Path],
    channel: str = "left",
    mode: str = "16bit",
) -> dict:
    """Run the chi-square attack on an audio file.

    Args:
        path:    Path to a WAV audio file.
        channel: Which channel: 'left' (or '0') or 'right' (or '1').
        mode:    '16bit' analyzes 16-bit sample pairs directly.
                 '8bit'  splits each sample into two bytes and tests each byte.

    Returns:
        Dictionary with keys:
            chi2             -- chi-square statistic
            df               -- degrees of freedom
            stego_probability -- values near 1 indicate steganography
            detection        -- True if stego_probability > 0.05
            n_samples        -- number of samples analyzed
            channel          -- channel analyzed
    """
    samples = _load_audio(path, channel)

    if mode == "16bit":
        samples_u16 = _to_uint16(samples)
        result = _chi_square_statistic_16bit(samples_u16)
    else:
        # Analyze the LSByte and MSByte separately; report the max probability.
        u16 = _to_uint16(samples)
        lo_bytes = (u16 & 0xFF).astype(np.uint8)
        hi_bytes = ((u16 >> 8) & 0xFF).astype(np.uint8)
        r_lo = _chi_square_statistic_8bit(lo_bytes)
        r_hi = _chi_square_statistic_8bit(hi_bytes)
        # The LSByte is where embedding happens; report its result.
        result = r_lo
        result["hi_byte_stego_prob"] = r_hi["stego_probability"]

    result["n_samples"] = int(len(samples))
    result["channel"] = channel
    result["mode"] = mode
    result["detection"] = result["stego_probability"] > 0.05
    return result
