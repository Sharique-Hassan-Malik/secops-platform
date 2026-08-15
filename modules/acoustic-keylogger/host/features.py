"""
features.py — MFCC feature extraction for keystroke audio.

Pipeline per keystroke window (50 ms at 8 kHz = 400 samples):
  1. Pre-emphasis filter:   s'[n] = s[n] - α·s[n-1]    (α = 0.97)
  2. Hamming window
  3. Zero-pad to next power of 2 for FFT
  4. Power spectrum:        |FFT(windowed)|²
  5. Mel filterbank:        26 triangular filters, 0–4000 Hz
  6. Log:                   log(mel_energies + epsilon)
  7. DCT:                   first 13 coefficients → MFCCs
  8. Delta coefficients:    Δ and ΔΔ over a 3-frame context window
                            (frame the 400-sample window into 25 ms / 10 ms frames)
  9. Statistics:            mean and std of each coefficient across frames
                            → final feature vector of length 13×3×2 = 78 dims

No external audio library is used. NumPy and SciPy only.
"""

from __future__ import annotations

import numpy as np
from scipy.fft import fft
from scipy.signal import get_window

# ── Configuration ──────────────────────────────────────────────────────────────
SAMPLE_RATE    = 8000      # Hz
N_MFCC        = 13        # number of cepstral coefficients
N_MEL         = 26        # number of mel filterbank channels
F_MIN         = 80.0      # Hz — lower mel filterbank edge
F_MAX         = 4000.0    # Hz — upper mel filterbank edge (= Nyquist)
PRE_EMPHASIS  = 0.97      # pre-emphasis coefficient
FRAME_LEN_MS  = 25.0      # ms — FFT frame length
FRAME_STEP_MS = 10.0      # ms — frame hop
DELTA_WIDTH   = 2         # ±context frames for delta computation


def _hz_to_mel(hz: float) -> float:
    return 2595.0 * np.log10(1.0 + hz / 700.0)


def _mel_to_hz(mel: float) -> float:
    return 700.0 * (10.0 ** (mel / 2595.0) - 1.0)


def _mel_filterbank(n_fft: int, sr: int, n_mel: int,
                    f_min: float, f_max: float) -> np.ndarray:
    """
    Build a mel filterbank matrix of shape (n_mel, n_fft // 2 + 1).
    Each row is a triangular filter on the linear frequency axis.
    """
    mel_min  = _hz_to_mel(f_min)
    mel_max  = _hz_to_mel(f_max)
    mel_pts  = np.linspace(mel_min, mel_max, n_mel + 2)
    hz_pts   = np.array([_mel_to_hz(m) for m in mel_pts])
    bin_pts  = np.floor((n_fft + 1) * hz_pts / sr).astype(int)

    n_bins   = n_fft // 2 + 1
    fb       = np.zeros((n_mel, n_bins), dtype=np.float32)

    for m in range(1, n_mel + 1):
        lo, ctr, hi = bin_pts[m - 1], bin_pts[m], bin_pts[m + 1]
        for k in range(lo, ctr):
            if ctr != lo:
                fb[m - 1, k] = (k - lo) / (ctr - lo)
        for k in range(ctr, hi):
            if hi != ctr:
                fb[m - 1, k] = (hi - k) / (hi - ctr)

    return fb


def _dct_matrix(n_in: int, n_out: int) -> np.ndarray:
    """
    Orthonormal DCT-II matrix of shape (n_out, n_in).
    Applied to log mel energies to produce MFCCs.
    """
    i = np.arange(n_in, dtype=np.float64)
    j = np.arange(n_out, dtype=np.float64).reshape(-1, 1)
    D = np.cos(np.pi / n_in * (i + 0.5) * j)
    D[0]  *= 1.0 / np.sqrt(n_in)
    D[1:] *= np.sqrt(2.0 / n_in)
    return D.astype(np.float32)


def _delta(coeffs: np.ndarray, width: int = DELTA_WIDTH) -> np.ndarray:
    """
    Compute delta (first derivative) of a (T, D) coefficient matrix.
    Uses the regression formula over ±width context frames.
    """
    T, D = coeffs.shape
    denom = 2.0 * sum(t ** 2 for t in range(1, width + 1))
    delta = np.zeros_like(coeffs)
    for t in range(T):
        for w in range(1, width + 1):
            t_fwd = min(t + w, T - 1)
            t_bwd = max(t - w, 0)
            delta[t] += w * (coeffs[t_fwd] - coeffs[t_bwd])
    delta /= denom
    return delta


class MFCCExtractor:
    """
    Stateless MFCC extractor. Build once and call extract() for each keystroke.
    Pre-builds the mel filterbank and DCT matrix for efficiency.
    """

    def __init__(self, sample_rate: int = SAMPLE_RATE) -> None:
        self._sr          = sample_rate
        self._frame_len   = int(round(FRAME_LEN_MS  * sample_rate / 1000))
        self._frame_step  = int(round(FRAME_STEP_MS * sample_rate / 1000))
        self._n_fft       = 1
        while self._n_fft < self._frame_len:
            self._n_fft <<= 1   # next power of 2

        self._window = get_window("hamming", self._frame_len, fftbins=True
                                  ).astype(np.float32)
        self._fb     = _mel_filterbank(self._n_fft, sample_rate, N_MEL, F_MIN, F_MAX)
        self._dct    = _dct_matrix(N_MEL, N_MFCC)

    def extract(self, samples: np.ndarray) -> np.ndarray:
        """
        Extract the feature vector from a 1-D int16 sample array.

        Returns a 1-D float32 vector of length N_MFCC × 3 × 2 = 78.
        """
        sig = samples.astype(np.float32)

        # ── Pre-emphasis ──────────────────────────────────────────────────────
        sig[1:] -= PRE_EMPHASIS * sig[:-1]

        # ── Frame the signal ──────────────────────────────────────────────────
        n_frames = 1 + max(0, (len(sig) - self._frame_len) // self._frame_step)
        frames   = np.zeros((n_frames, self._frame_len), dtype=np.float32)
        for i in range(n_frames):
            start = i * self._frame_step
            end   = start + self._frame_len
            chunk = sig[start:min(end, len(sig))]
            frames[i, :len(chunk)] = chunk

        # ── Hamming window ────────────────────────────────────────────────────
        frames *= self._window

        # ── Power spectrum ────────────────────────────────────────────────────
        spec = np.abs(fft(frames, n=self._n_fft, axis=1)
                      )[:, :self._n_fft // 2 + 1] ** 2

        # ── Mel filterbank ────────────────────────────────────────────────────
        mel_e = np.dot(spec, self._fb.T)   # (n_frames, N_MEL)

        # ── Log compression ───────────────────────────────────────────────────
        log_mel = np.log(mel_e + 1e-8)

        # ── DCT → MFCCs ───────────────────────────────────────────────────────
        mfcc = np.dot(log_mel, self._dct.T)   # (n_frames, N_MFCC)

        # ── Delta and delta-delta ─────────────────────────────────────────────
        d1   = _delta(mfcc, DELTA_WIDTH)
        d2   = _delta(d1,   DELTA_WIDTH)

        # ── Aggregate statistics across frames ────────────────────────────────
        # Stack [MFCC | Δ | ΔΔ] → (n_frames, N_MFCC×3) then take mean and std.
        all_coef = np.concatenate([mfcc, d1, d2], axis=1)  # (T, 39)
        feat_mean = np.mean(all_coef, axis=0)               # (39,)
        feat_std  = np.std(all_coef,  axis=0) + 1e-8        # (39,)
        feature   = np.concatenate([feat_mean, feat_std])   # (78,)

        return feature.astype(np.float32)
