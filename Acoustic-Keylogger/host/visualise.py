"""
visualise.py — plot waveform and spectrogram for collected keystroke samples.

Useful for diagnosing onset detection issues and verifying that the captured
window correctly centres on the keystroke transient.

Usage
-----
    # Plot 5 random samples for key 'a'
    python visualise.py --key a --n 5

    # Live plot: show each keystroke as it arrives
    python visualise.py --port /dev/ttyACM0 --live
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import matplotlib.gridspec as gridspec
import matplotlib.pyplot as plt
import numpy as np

SAMPLE_RATE = 8000
PRE_MS      = 10.0   # ms before onset marked by vertical line


def plot_keystroke(samples: np.ndarray, title: str = "") -> None:
    """Plot waveform and spectrogram for one keystroke window."""
    t = np.arange(len(samples)) / SAMPLE_RATE * 1000.0  # ms

    fig = plt.figure(figsize=(10, 5))
    gs  = gridspec.GridSpec(2, 1, hspace=0.45)

    # ── Waveform ──────────────────────────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0])
    ax1.plot(t, samples, color="#0077BB", lw=0.7)
    ax1.axvline(PRE_MS, color="#EE3377", lw=1.2, ls="--", label="onset")
    ax1.set_xlabel("Time (ms)")
    ax1.set_ylabel("Amplitude (ADC counts)")
    ax1.set_title(title or "Keystroke waveform")
    ax1.legend(fontsize=8)
    ax1.grid(True, color="#DDDDDD", lw=0.5)

    # ── Spectrogram ───────────────────────────────────────────────────────────
    ax2 = fig.add_subplot(gs[1])
    ax2.specgram(samples.astype(float), NFFT=64, Fs=SAMPLE_RATE,
                 noverlap=32, cmap="inferno")
    ax2.axvline(PRE_MS / 1000.0, color="#33BBEE", lw=1.2, ls="--", label="onset")
    ax2.set_xlabel("Time (s)")
    ax2.set_ylabel("Frequency (Hz)")
    ax2.set_title("Spectrogram")
    ax2.legend(fontsize=8)

    plt.show()


def plot_from_files(key: str, n: int, raw_dir: Path) -> None:
    key_dir = raw_dir / key
    files   = sorted(key_dir.glob("*.npy"))
    if not files:
        print(f"No samples found for key '{key}' in {key_dir}")
        return

    chosen = random.sample(files, min(n, len(files)))
    for f in chosen:
        samples = np.load(f)
        plot_keystroke(samples, title=f"Key '{key}' — {f.name}")


def live_plot(port: str, baud: int) -> None:
    """Display each arriving keystroke in a live plot window."""
    from transport import AcousticTransport, Keystroke
    import time

    plt.ion()
    fig = plt.figure(figsize=(10, 5))
    gs  = gridspec.GridSpec(2, 1, hspace=0.45)
    ax1 = fig.add_subplot(gs[0])
    ax2 = fig.add_subplot(gs[1])

    def on_keystroke(ks: Keystroke) -> None:
        samples = ks.samples
        t       = np.arange(len(samples)) / SAMPLE_RATE * 1000.0

        ax1.cla()
        ax1.plot(t, samples, color="#0077BB", lw=0.7)
        ax1.axvline(PRE_MS, color="#EE3377", lw=1.2, ls="--")
        ax1.set_xlabel("Time (ms)")
        ax1.set_ylabel("Amplitude")
        ax1.set_title(f"Keystroke (label={ks.label})")
        ax1.grid(True, color="#DDDDDD", lw=0.5)

        ax2.cla()
        ax2.specgram(samples.astype(float), NFFT=64, Fs=SAMPLE_RATE,
                     noverlap=32, cmap="inferno")
        ax2.set_xlabel("Time (s)")
        ax2.set_ylabel("Frequency (Hz)")

        fig.canvas.draw()
        fig.canvas.flush_events()

    with AcousticTransport(port, baud) as t:
        t.identify()
        t.on_keystroke(on_keystroke)
        t.start()
        print("Live plot active. Press keys near the microphone. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(0.05)
        except KeyboardInterrupt:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Keystroke waveform visualiser")
    parser.add_argument("--key",     default="",
                        help="Key character to visualise from saved data")
    parser.add_argument("--n",       type=int, default=3,
                        help="Number of samples to plot (default 3)")
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--live",    action="store_true",
                        help="Live streaming plot (requires --port)")
    parser.add_argument("--port",    default="")
    parser.add_argument("--baud",    type=int, default=500_000)
    args = parser.parse_args()

    if args.live:
        if not args.port:
            print("--port required for --live mode")
            return
        live_plot(args.port, args.baud)
    elif args.key:
        plot_from_files(args.key, args.n, Path(args.raw_dir))
    else:
        print("Specify --key <char> to plot saved samples or --live for streaming.")


if __name__ == "__main__":
    main()
