"""
Sample Pair Analysis for audio LSB steganography detection.

Applies the SPA framework to audio sample pairs. The same parity-orientation
statistics that distinguish LSB-embedded image pixels from clean ones also
apply to PCM audio samples, because LSB replacement has the same effect on
any integer-valued signal regardless of whether it represents color intensity
or sound pressure.

Reference:
    Dumitrescu, S., Wu, X., and Wang, Z. (2003). Detection of LSB Steganography
    via Sample Pair Analysis. IEEE Transactions on Signal Processing, 51(7).
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import numpy as np

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
    path = Path(path)
    if _HAVE_SF:
        data, _ = sf.read(str(path), dtype="int16", always_2d=True)
    elif _HAVE_SCIPY_WAV:
        _, data = _wavfile.read(str(path))
        if data.ndim == 1:
            data = data[:, None]
        if data.dtype in (np.float32, np.float64):
            data = (data * 32767).astype(np.int16)
        data = data.astype(np.int16)
    else:
        raise ImportError("Install soundfile or scipy to analyze audio files.")

    ch_idx = 0 if channel in ("left", "mono", "0") else 1
    return data[:, min(ch_idx, data.shape[1] - 1)].astype(np.int32)


def _spa_counts(samples: np.ndarray) -> tuple[int, int]:
    """Compute W and X pair counts from consecutive audio samples."""
    a = samples[:-1]
    b = samples[1:]
    diff = b - a

    W = int(
        np.sum((a % 2 == 0) & (diff == 1))
        + np.sum((a % 2 != 0) & (diff == -1))
    )
    X = int(
        np.sum((a % 2 == 0) & (diff == -1))
        + np.sum((a % 2 != 0) & (diff == 1))
    )
    return W, X


def analyze(path: Union[str, Path], channel: str = "left") -> dict:
    """Run SPA on an audio channel.

    Args:
        path:    Path to a WAV file.
        channel: Channel to analyze: 'left' or 'right'.

    Returns:
        Dictionary with keys:
            W               -- normalized W count
            X               -- normalized X count
            estimated_rate  -- estimated LSB embedding rate in [0, 1]
            detection       -- True if estimated_rate > 0.05
            n_samples       -- number of samples analyzed
    """
    samples = _load_audio(path, channel)
    W, X = _spa_counts(samples)
    total = max(len(samples) - 1, 1)

    W_n = W / total
    X_n = X / total

    denom = W_n + X_n
    if denom < 1e-12:
        rate = 0.0
    else:
        raw = 1.0 - (W_n - X_n) / denom
        rate = float(np.clip((raw - 0.5) * 2.0, 0.0, 1.0))

    return {
        "W": float(W_n),
        "X": float(X_n),
        "estimated_rate": rate,
        "detection": rate > 0.05,
        "n_samples": int(len(samples)),
        "channel": channel,
    }
