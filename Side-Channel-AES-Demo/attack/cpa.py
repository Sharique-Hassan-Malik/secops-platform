"""Correlation Power Analysis (CPA) — Brier et al., CHES 2004.

Attack model
------------
Target operation: intermediate = SBOX[plaintext[b] XOR key[b]]
Leakage model:    power ~ HW(intermediate) + noise

For each key byte position b:
  1. Build a (N, 256) hypothesis matrix H where H[n, kh] = HW(SBOX[pt_n[b] XOR kh]).
  2. Compute Pearson correlation between each column of H and each column of
     the trace matrix T (shape N × TRACE_LEN) → correlation matrix (256, TRACE_LEN).
  3. For each key hypothesis kh, take the maximum absolute correlation over time.
  4. The hypothesis with the highest peak correlation is the recovered key byte.

The correct hypothesis matches the true intermediate values and therefore
produces the highest correlation with the observed power signal.
"""

from __future__ import annotations

import numpy as np

from aes.constants import SBOX

# Precompute Hamming weights for all 256 byte values
_HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)
_SBOX_NP = np.frombuffer(SBOX, dtype=np.uint8)


def _hypothesis_matrix(plaintexts: np.ndarray, byte_idx: int) -> np.ndarray:
    """Build (N, 256) hypothesis matrix for one key byte position.

    H[n, kh] = HW(SBOX[plaintexts[n, byte_idx] XOR kh])
    """
    pt_col = plaintexts[:, byte_idx].astype(np.uint8)        # (N,)
    all_kh = np.arange(256, dtype=np.uint8)
    xor_table = pt_col[:, None] ^ all_kh[None, :]            # (N, 256) — all XOR combos
    intermediates = _SBOX_NP[xor_table]                       # (N, 256) — S-box lookup
    return _HW[intermediates]                                  # (N, 256) — Hamming weights


def _pearson_matrix(h: np.ndarray, traces: np.ndarray) -> np.ndarray:
    """Compute Pearson correlation between each pair of columns in h and traces.

    Parameters
    ----------
    h:      (N, 256) hypothesis matrix
    traces: (N, T)   power trace matrix

    Returns
    -------
    corr: (256, T) Pearson correlation matrix
    """
    n = h.shape[0]
    h_c    = h      - h.mean(axis=0, keepdims=True)          # centre columns
    t_c    = traces - traces.mean(axis=0, keepdims=True)
    num    = h_c.T @ t_c                                      # (256, T)
    h_std  = np.sqrt((h_c ** 2).sum(axis=0))                 # (256,)
    t_std  = np.sqrt((t_c ** 2).sum(axis=0))                 # (T,)
    denom  = np.outer(h_std, t_std)                           # (256, T)
    with np.errstate(divide="ignore", invalid="ignore"):
        corr = np.where(denom != 0.0, num / denom, 0.0)
    return corr


def attack(
    plaintexts: np.ndarray,
    traces: np.ndarray,
) -> tuple[bytes, np.ndarray]:
    """Run CPA against all 16 key bytes.

    Returns
    -------
    recovered_key : bytes (16)
    max_corr      : (16,) peak absolute correlation for the best hypothesis per byte
    """
    key_bytes = []
    max_corrs = np.zeros(16)
    for b in range(16):
        h    = _hypothesis_matrix(plaintexts, b)
        corr = _pearson_matrix(h, traces)
        peak = np.abs(corr).max(axis=1)                       # (256,) — best time per hyp
        best = int(peak.argmax())
        key_bytes.append(best)
        max_corrs[b] = peak[best]
    return bytes(key_bytes), max_corrs


def attack_byte(
    plaintexts: np.ndarray,
    traces: np.ndarray,
    byte_idx: int,
) -> np.ndarray:
    """Return the full (256, T) correlation matrix for one key byte (for visualisation)."""
    h = _hypothesis_matrix(plaintexts, byte_idx)
    return _pearson_matrix(h, traces)


def convergence_curve(
    plaintexts: np.ndarray,
    traces: np.ndarray,
    true_key: bytes,
    byte_idx: int = 0,
    step: int = 50,
) -> tuple[np.ndarray, np.ndarray]:
    """Track the rank of the true key byte as the trace count grows.

    Rank 0 means the correct hypothesis has the highest peak correlation.

    Returns
    -------
    counts : (M,) trace counts at which rank was evaluated
    ranks  : (M,) rank of the true key byte at each count
    """
    n      = len(plaintexts)
    counts = np.arange(step, n + 1, step)
    ranks  = np.zeros(len(counts), dtype=np.int32)
    for idx, cnt in enumerate(counts):
        h    = _hypothesis_matrix(plaintexts[:cnt], byte_idx)
        corr = _pearson_matrix(h, traces[:cnt])
        peak = np.abs(corr).max(axis=1)
        true_peak = peak[true_key[byte_idx]]
        ranks[idx] = int((peak > true_peak).sum())
    return counts, ranks
