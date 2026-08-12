"""Verify that masking and shuffling prevent CPA from recovering the key."""

import numpy as np

from sim.device import MaskedDevice, ShuffledDevice
from attack.cpa import attack

_KEY     = bytes.fromhex("deadbeef0102030405060708cafebabe")
_N       = 500
_MAX_RATE = 0.5   # any defence should leave fewer than half the bytes exposed


def _byte_success_rate(device_cls, seed: int = 10) -> float:
    rng      = np.random.default_rng(seed)
    device   = device_cls(_KEY, rng=rng)
    pts, trs = device.collect(_N)
    recovered, _ = attack(pts, trs)
    return sum(r == t for r, t in zip(recovered, _KEY)) / 16.0


def test_masked_breaks_cpa():
    rate = _byte_success_rate(MaskedDevice)
    assert rate < _MAX_RATE, (
        f"Masked device leaked too many bytes: {rate * 16:.0f}/16 recovered"
    )


def test_shuffled_breaks_cpa():
    rate = _byte_success_rate(ShuffledDevice)
    assert rate < _MAX_RATE, (
        f"Shuffled device leaked too many bytes: {rate * 16:.0f}/16 recovered"
    )


def test_masked_peak_correlation_is_low():
    rng      = np.random.default_rng(11)
    device   = MaskedDevice(_KEY, rng=rng)
    pts, trs = device.collect(_N)
    _, max_corrs = attack(pts, trs)
    assert float(max_corrs.mean()) < 0.3


def test_shuffled_peak_correlation_is_low():
    rng      = np.random.default_rng(12)
    device   = ShuffledDevice(_KEY, rng=rng)
    pts, trs = device.collect(_N)
    _, max_corrs = attack(pts, trs)
    assert float(max_corrs.mean()) < 0.3
