"""CPA recovers the full key from a vulnerable device."""

import numpy as np
import pytest

from sim.device import VulnerableDevice
from attack.cpa import attack, attack_byte, convergence_curve

_KEY = bytes.fromhex("deadbeef0102030405060708cafebabe")


def test_cpa_recovers_full_key():
    rng    = np.random.default_rng(0)
    device = VulnerableDevice(_KEY, noise_std=0.5, rng=rng)
    pts, trs = device.collect(500)
    recovered, _ = attack(pts, trs)
    assert recovered == _KEY


def test_cpa_peak_correlation_above_threshold():
    rng    = np.random.default_rng(1)
    device = VulnerableDevice(_KEY, noise_std=0.5, rng=rng)
    pts, trs = device.collect(500)
    _, max_corrs = attack(pts, trs)
    assert float(max_corrs.mean()) > 0.4


def test_attack_byte_shape():
    rng    = np.random.default_rng(2)
    device = VulnerableDevice(_KEY, rng=rng)
    pts, trs = device.collect(200)
    corr = attack_byte(pts, trs, byte_idx=0)
    assert corr.shape == (256, trs.shape[1])


def test_convergence_curve_rank_reaches_zero():
    rng    = np.random.default_rng(3)
    device = VulnerableDevice(_KEY, noise_std=0.5, rng=rng)
    pts, trs = device.collect(500)
    counts, ranks = convergence_curve(pts, trs, _KEY, byte_idx=0, step=50)
    assert int(ranks[-1]) == 0   # rank-0 with full trace set
