"""
collect.py — guided keystroke data collection session.

Streams keystroke audio windows from the Arduino, labels each capture
with the key being pressed and saves raw samples to disk.

Usage
-----
    python collect.py --port /dev/ttyACM0 --keys "asdfghjkl" --reps 30

For each key in --keys the script prompts you to hold that key and
press it --reps times. Each labelled keystroke window is saved to
  data/raw/<key>/<timestamp>.npy

The raw .npy files contain the int16 sample array (WINDOW_SAMPLES long).
Run extract.py afterwards to compute MFCC features.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

from transport import AcousticTransport, Keystroke


def collect(port: str, baud: int, keys: str, reps: int,
            out_dir: Path) -> None:

    out_dir.mkdir(parents=True, exist_ok=True)

    with AcousticTransport(port, baud) as t:
        rate = t.identify()
        print(f"Firmware ready — sample rate: {rate} Hz")

        t.start()

        for key_idx, key_char in enumerate(keys):
            label = key_idx + 1   # label 0 = unlabelled; keys start at 1
            key_dir = out_dir / key_char
            key_dir.mkdir(exist_ok=True)

            # Count existing files so we can resume interrupted sessions.
            existing = len(list(key_dir.glob("*.npy")))
            needed   = reps - existing
            if needed <= 0:
                print(f"  Key '{key_char}' already has {existing} samples — skipping.")
                continue

            print(f"\n── Key '{key_char}' (label {label}) ──────────────────────────")
            print(f"  Press '{key_char}' {needed} times. Press Enter when ready…")
            input()

            t.set_label(label)
            captured  = 0
            collected: list[np.ndarray] = []

            # Collect via callback with a simple event.
            import threading
            event = threading.Event()

            def on_ks(ks: Keystroke) -> None:
                nonlocal captured
                if ks.label != label:
                    return
                collected.append(ks.samples.copy())
                captured += 1
                sys.stdout.write(f"\r  Captured {captured}/{needed}")
                sys.stdout.flush()
                if captured >= needed:
                    event.set()

            t.on_keystroke(on_ks)
            event.wait(timeout=reps * 3.0)   # generous timeout
            t.set_label(0)

            print()
            # Save collected samples.
            for i, samples in enumerate(collected):
                fname = key_dir / f"{int(time.time() * 1000)}_{i:04d}.npy"
                np.save(fname, samples)
            print(f"  Saved {len(collected)} samples for '{key_char}'.")

    print("\nCollection complete.")
    _print_summary(out_dir, keys)


def _print_summary(out_dir: Path, keys: str) -> None:
    print("\nDataset summary:")
    for key_char in keys:
        key_dir = out_dir / key_char
        n = len(list(key_dir.glob("*.npy"))) if key_dir.exists() else 0
        print(f"  '{key_char}' : {n} samples")


def main() -> None:
    parser = argparse.ArgumentParser(description="Keystroke acoustic data collection")
    parser.add_argument("--port",    required=True)
    parser.add_argument("--baud",    type=int, default=500_000)
    parser.add_argument("--keys",    default="asdf",
                        help="Keys to collect, e.g. 'asdfghjkl'")
    parser.add_argument("--reps",    type=int, default=30,
                        help="Repetitions per key (default 30)")
    parser.add_argument("--out-dir", default="data/raw",
                        help="Output directory for raw .npy files")
    args = parser.parse_args()

    collect(
        port    = args.port,
        baud    = args.baud,
        keys    = args.keys,
        reps    = args.reps,
        out_dir = Path(args.out_dir),
    )


if __name__ == "__main__":
    main()
