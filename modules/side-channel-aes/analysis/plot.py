"""Visualisation utilities for traces, correlation matrices and convergence curves.

All functions require matplotlib.  Import errors are deferred to call time
so that the rest of the project works without it.
"""

from __future__ import annotations

import numpy as np

try:
    import matplotlib.pyplot as plt
    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False

_MPL_MSG = "matplotlib is not installed — run: pip install matplotlib"


def _require_mpl() -> None:
    if not _HAS_MPL:
        raise RuntimeError(_MPL_MSG)


def plot_traces(
    traces: np.ndarray,
    n: int = 10,
    leaky_indices: list[int] | None = None,
    title: str = "Power Traces",
) -> None:
    """Overlay the first n traces and mark leaky time positions."""
    _require_mpl()
    fig, ax = plt.subplots(figsize=(13, 4))
    for i in range(min(n, len(traces))):
        ax.plot(traces[i], alpha=0.55, linewidth=0.8)
    if leaky_indices:
        for t in leaky_indices:
            ax.axvline(t, color="red", linewidth=0.7, alpha=0.4)
    ax.set_xlabel("Time sample")
    ax.set_ylabel("Power (a.u.)")
    ax.set_title(title)
    plt.tight_layout()
    plt.show()


def plot_correlation(
    corr: np.ndarray,
    true_key_byte: int,
    byte_idx: int,
) -> None:
    """Heatmap of the (256, T) correlation matrix plus a peak-correlation bar chart."""
    _require_mpl()
    fig, axes = plt.subplots(2, 1, figsize=(13, 7))

    im = axes[0].imshow(
        np.abs(corr),
        aspect="auto",
        cmap="hot",
        vmin=0.0,
        vmax=max(np.abs(corr).max(), 1e-6),
    )
    axes[0].set_ylabel("Key hypothesis")
    axes[0].set_xlabel("Time sample")
    axes[0].set_title(f"Correlation heatmap — key byte {byte_idx}")
    fig.colorbar(im, ax=axes[0], label="|Pearson r|")

    peak = np.abs(corr).max(axis=1)
    axes[1].bar(range(256), peak, color="steelblue", width=1.0, alpha=0.75)
    axes[1].axvline(
        true_key_byte,
        color="crimson",
        linewidth=1.5,
        label=f"True key byte: 0x{true_key_byte:02x}",
    )
    axes[1].set_xlabel("Key hypothesis")
    axes[1].set_ylabel("Peak |r|")
    axes[1].set_title("Peak correlation per hypothesis")
    axes[1].legend()
    plt.tight_layout()
    plt.show()


def plot_convergence(
    curves: dict[str, tuple[np.ndarray, np.ndarray]],
) -> None:
    """Key rank vs number of traces for one or more device types."""
    _require_mpl()
    fig, ax = plt.subplots(figsize=(10, 5))
    for label, (counts, ranks) in curves.items():
        ax.plot(counts, ranks, marker="o", markersize=4, label=label)
    ax.axhline(0, color="forestgreen", linestyle="--", linewidth=1.2, label="Rank 0 (recovered)")
    ax.set_xlabel("Number of traces")
    ax.set_ylabel("Rank of correct key byte 0")
    ax.set_title("CPA convergence — byte 0")
    ax.set_ylim(-5, 260)
    ax.legend()
    plt.tight_layout()
    plt.show()


def plot_protection_comparison(results: dict[str, np.ndarray]) -> None:
    """Bar chart comparing mean peak |r| across 16 bytes for each device type."""
    _require_mpl()
    labels = list(results.keys())
    means  = [v.mean() for v in results.values()]
    colors = ["tomato", "steelblue", "seagreen"]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(labels, means, color=colors[: len(labels)])
    ax.axhline(0.2, color="darkorange", linestyle="--", linewidth=1.2, label="Threshold 0.2")
    ax.set_ylabel("Mean peak |r| across 16 key bytes")
    ax.set_title("CPA effectiveness by protection level")
    ax.legend()
    plt.tight_layout()
    plt.show()
