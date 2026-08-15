"""Simulated power-trace devices.

Each device wraps an AES-128 encryption and emits a synthetic power trace
using the Hamming-weight leakage model.  No physical hardware is needed.

Trace layout (200 samples):

    Time:  0──19  20  25  30 … 95  96──199
                  │   │   │     │
                  └───┴───┴─────┘
            Round-1 SubBytes (16 bytes, one leaky sample per byte, spaced 5 apart)
            All other samples: Gaussian noise only

Three models:

    VulnerableDevice  — direct HW leakage; CPA recovers the key in ~300 traces.
    MaskedDevice      — XOR mask applied to S-box output each trace; CPA fails.
    ShuffledDevice    — S-box operations execute in random order; CPA fails.
"""

from __future__ import annotations
import os

import numpy as np

from aes.constants import SBOX
from aes.core import encrypt, key_schedule

TRACE_LEN   = 200
LEAKY_START = 20   # time index of byte-0 leakage
LEAKY_STEP  = 5    # spacing between successive byte leakages
NOISE_STD   = 0.5  # default Gaussian noise standard deviation


def _hw(x: int) -> int:
    return bin(x).count("1")


class VulnerableDevice:
    """Standard AES-128 with Hamming-weight leakage at round-1 SubBytes."""

    def __init__(
        self,
        key: bytes,
        noise_std: float = NOISE_STD,
        rng: np.random.Generator | None = None,
    ) -> None:
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        self._key      = key
        self._noise_std = noise_std
        self._rng      = rng or np.random.default_rng()
        self._rk       = key_schedule(key)

    def encrypt_trace(self, plaintext: bytes) -> tuple[bytes, np.ndarray]:
        """Return (ciphertext, power_trace) for one plaintext."""
        trace = self._rng.normal(0.0, self._noise_std, TRACE_LEN)
        for i in range(16):
            intermediate = SBOX[plaintext[i] ^ self._key[i]]
            trace[LEAKY_START + i * LEAKY_STEP] += _hw(intermediate)
        return encrypt(plaintext, self._key), trace

    def collect(self, n: int) -> tuple[np.ndarray, np.ndarray]:
        """Return (plaintexts, traces) for n random encryptions."""
        plaintexts = np.zeros((n, 16), dtype=np.uint8)
        traces     = np.zeros((n, TRACE_LEN), dtype=np.float64)
        for i in range(n):
            pt = os.urandom(16)
            _, tr = self.encrypt_trace(pt)
            plaintexts[i] = list(pt)
            traces[i]     = tr
        return plaintexts, traces


class MaskedDevice:
    """AES-128 with Boolean masking on round-1 S-box outputs.

    A fresh 16-byte mask is drawn per encryption.  The observable intermediate
    is SBOX[pt ^ key] XOR mask, whose Hamming weight is statistically
    independent of SBOX[pt ^ key] for a uniformly random mask.
    """

    def __init__(
        self,
        key: bytes,
        noise_std: float = NOISE_STD,
        rng: np.random.Generator | None = None,
    ) -> None:
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        self._key       = key
        self._noise_std  = noise_std
        self._rng        = rng or np.random.default_rng()

    def encrypt_trace(self, plaintext: bytes) -> tuple[bytes, np.ndarray]:
        trace = self._rng.normal(0.0, self._noise_std, TRACE_LEN)
        masks = os.urandom(16)
        for i in range(16):
            # Mask hides the true S-box output from the power side channel
            intermediate = SBOX[plaintext[i] ^ self._key[i]] ^ masks[i]
            trace[LEAKY_START + i * LEAKY_STEP] += _hw(intermediate)
        return encrypt(plaintext, self._key), trace

    def collect(self, n: int) -> tuple[np.ndarray, np.ndarray]:
        plaintexts = np.zeros((n, 16), dtype=np.uint8)
        traces     = np.zeros((n, TRACE_LEN), dtype=np.float64)
        for i in range(n):
            pt = os.urandom(16)
            _, tr = self.encrypt_trace(pt)
            plaintexts[i] = list(pt)
            traces[i]     = tr
        return plaintexts, traces


class ShuffledDevice:
    """AES-128 with randomised S-box execution order.

    A random permutation of the 16 SubBytes operations is chosen per encryption.
    Byte i leaks at time LEAKY_START + perm[i] * LEAKY_STEP instead of the
    expected LEAKY_START + i * LEAKY_STEP.  CPA correlates at fixed time
    positions and sees a mixture of leakages from different key bytes, reducing
    effective SNR by a factor of 16 and preventing convergence.
    """

    def __init__(
        self,
        key: bytes,
        noise_std: float = NOISE_STD,
        rng: np.random.Generator | None = None,
    ) -> None:
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        self._key       = key
        self._noise_std  = noise_std
        self._rng        = rng or np.random.default_rng()

    def encrypt_trace(self, plaintext: bytes) -> tuple[bytes, np.ndarray]:
        trace = self._rng.normal(0.0, self._noise_std, TRACE_LEN)
        perm = self._rng.permutation(16)
        for slot, byte_idx in enumerate(perm):
            intermediate = SBOX[plaintext[byte_idx] ^ self._key[byte_idx]]
            trace[LEAKY_START + slot * LEAKY_STEP] += _hw(intermediate)
        return encrypt(plaintext, self._key), trace

    def collect(self, n: int) -> tuple[np.ndarray, np.ndarray]:
        plaintexts = np.zeros((n, 16), dtype=np.uint8)
        traces     = np.zeros((n, TRACE_LEN), dtype=np.float64)
        for i in range(n):
            pt = os.urandom(16)
            _, tr = self.encrypt_trace(pt)
            plaintexts[i] = list(pt)
            traces[i]     = tr
        return plaintexts, traces
