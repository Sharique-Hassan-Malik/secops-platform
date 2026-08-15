#!/usr/bin/env python3
"""AES-128 side-channel attack demo.

Runs Correlation Power Analysis against three simulated devices:

    1. Vulnerable AES  — direct Hamming-weight leakage
    2. Masked AES      — Boolean mask applied to S-box output
    3. Shuffled AES    — random S-box execution order

Usage
-----
    python demo.py                       # 500 traces, no plots
    python demo.py --traces 1000 --plot  # more traces + matplotlib output
    python demo.py --traces 200 --seed 7
"""

from __future__ import annotations
import argparse
import sys

import numpy as np

from sim.device import VulnerableDevice, MaskedDevice, ShuffledDevice, LEAKY_START, LEAKY_STEP
from attack.cpa import attack, attack_byte, convergence_curve

_BANNER = """\
Side-Channel Attack Demo — AES-128 Correlation Power Analysis
=============================================================
Target:  Round-1 SubBytes — HW(SBOX[plaintext XOR key])
Attack:  Correlation Power Analysis (CPA)
"""


def _fmt(key: bytes) -> str:
    return " ".join(f"{b:02x}" for b in key)


def _leaky_times() -> list[int]:
    return [LEAKY_START + i * LEAKY_STEP for i in range(16)]


def run_scenario(
    label: str,
    device_cls: type,
    key: bytes,
    n: int,
    plot: bool,
    conv_curves: dict,
) -> tuple[bytes, np.ndarray]:
    print(f"{label}")
    rng    = np.random.default_rng(42)
    device = device_cls(key, rng=rng)

    print(f"  Collecting {n} traces ...", end=" ", flush=True)
    plaintexts, traces = device.collect(n)
    print("done")

    print("  Running CPA ...", end=" ", flush=True)
    recovered, max_corrs = attack(plaintexts, traces)
    print("done")

    correct = sum(r == t for r, t in zip(recovered, key))
    print(f"  Recovered:     {_fmt(recovered)}")
    print(f"  True key:      {_fmt(key)}")
    print(f"  Bytes correct: {correct}/16   Mean peak |r|: {max_corrs.mean():.3f}")

    if plot:
        counts, ranks = convergence_curve(plaintexts, traces, key, byte_idx=0, step=max(n // 10, 50))
        conv_curves[label] = (counts, ranks)

    return recovered, max_corrs


def main() -> None:
    parser = argparse.ArgumentParser(description="AES side-channel demo")
    parser.add_argument("-n", "--traces", type=int, default=500,
                        help="number of traces per device (default 500)")
    parser.add_argument("--plot", action="store_true",
                        help="display matplotlib figures")
    parser.add_argument("--seed", type=int, default=0,
                        help="seed for the target key (default 0)")
    args = parser.parse_args()

    key_rng = np.random.default_rng(args.seed)
    key     = bytes(key_rng.integers(0, 256, 16, dtype=np.uint8))

    print(_BANNER)
    print(f"Target key:  {_fmt(key)}")
    print(f"Traces:      {args.traces} per device\n")

    scenarios: list[tuple[str, type]] = [
        ("[1/3] Vulnerable AES", VulnerableDevice),
        ("[2/3] Masked AES    ", MaskedDevice),
        ("[3/3] Shuffled AES  ", ShuffledDevice),
    ]

    all_max_corrs: dict[str, np.ndarray] = {}
    conv_curves:   dict[str, tuple]      = {}

    for label, cls in scenarios:
        _, mc = run_scenario(label, cls, key, args.traces, args.plot, conv_curves)
        all_max_corrs[label.strip()] = mc
        print()

    print("Summary — mean peak |r| across 16 key bytes")
    print("-" * 44)
    for lbl, mc in all_max_corrs.items():
        bar_len = int(mc.mean() * 40)
        bar     = "█" * bar_len
        print(f"  {lbl:<20} {mc.mean():.3f}  {bar}")
    print()

    if args.plot:
        try:
            from analysis.plot import (
                plot_traces,
                plot_correlation,
                plot_convergence,
                plot_protection_comparison,
            )
        except RuntimeError as exc:
            print(f"Plot skipped: {exc}", file=sys.stderr)
            return

        # Sample traces from the vulnerable device
        vuln = VulnerableDevice(key, rng=np.random.default_rng(99))
        pts_v, trs_v = vuln.collect(args.traces)
        plot_traces(trs_v, n=10, leaky_indices=_leaky_times(), title="Vulnerable AES — power traces")

        # Full correlation matrix for key byte 0
        corr = attack_byte(pts_v, trs_v, byte_idx=0)
        plot_correlation(corr, true_key_byte=key[0], byte_idx=0)

        if conv_curves:
            plot_convergence(conv_curves)

        plot_protection_comparison(all_max_corrs)


if __name__ == "__main__":
    main()
