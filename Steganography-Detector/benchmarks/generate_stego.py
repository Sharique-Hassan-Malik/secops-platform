"""
generate_stego.py — generate test image and audio sets for benchmarking.

Produces a directory of clean and LSB-embedded files at multiple embedding
rates. No external steganography tool is required — the embedder is
implemented here from scratch.

Usage:
    python benchmarks/generate_stego.py --out-dir benchmarks/data
    python benchmarks/generate_stego.py --out-dir benchmarks/data --n 50 --size 256
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import numpy as np
from PIL import Image


# --------------------------------------------------------------------------- #
# LSB embedder (images)                                                        #
# --------------------------------------------------------------------------- #

def embed_image_lsb(image_array: np.ndarray, rate: float, seed: int = 0) -> np.ndarray:
    """Replace a fraction of pixel LSBs with random bits.

    Args:
        image_array: uint8 array of shape (H, W) or (H, W, C).
        rate:        Fraction of pixels (or pixel-channels) to overwrite.
        seed:        RNG seed for reproducibility.

    Returns:
        Modified uint8 array of the same shape.
    """
    rng = np.random.default_rng(seed)
    flat = image_array.flatten().astype(np.int32)
    n_embed = int(len(flat) * rate)
    if n_embed == 0:
        return image_array.copy()

    indices = rng.choice(len(flat), size=n_embed, replace=False)
    bits = rng.integers(0, 2, size=n_embed, dtype=np.int32)
    flat[indices] = (flat[indices] & ~1) | bits
    return flat.reshape(image_array.shape).astype(np.uint8)


def _make_natural_image(size: int, seed: int) -> np.ndarray:
    """Generate a pseudo-natural grayscale image using filtered noise."""
    rng = np.random.default_rng(seed)
    base = rng.standard_normal((size, size))
    # Apply a simple box blur to create spatial correlation (natural images
    # are not white noise).
    for _ in range(4):
        base[1:] = (base[1:] + base[:-1]) / 2
        base[:, 1:] = (base[:, 1:] + base[:, :-1]) / 2
    # Normalize to [20, 235] to avoid histogram clipping artifacts.
    lo, hi = base.min(), base.max()
    base = (base - lo) / (hi - lo + 1e-12)
    return (base * 215 + 20).astype(np.uint8)


# --------------------------------------------------------------------------- #
# LSB embedder (WAV audio)                                                     #
# --------------------------------------------------------------------------- #

def _write_wav(path: Path, samples: np.ndarray, sample_rate: int = 44100) -> None:
    """Write a mono 16-bit PCM WAV file."""
    n = len(samples)
    data_bytes = samples.astype(np.int16).tobytes()
    with open(path, "wb") as f:
        # RIFF header
        f.write(b"RIFF")
        f.write(struct.pack("<I", 36 + len(data_bytes)))
        f.write(b"WAVE")
        # fmt chunk
        f.write(b"fmt ")
        f.write(struct.pack("<IHHIIHH", 16, 1, 1, sample_rate, sample_rate * 2, 2, 16))
        # data chunk
        f.write(b"data")
        f.write(struct.pack("<I", len(data_bytes)))
        f.write(data_bytes)


def embed_audio_lsb(samples: np.ndarray, rate: float, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    flat = samples.astype(np.int32)
    n_embed = int(len(flat) * rate)
    if n_embed == 0:
        return samples.copy().astype(np.int16)
    idx = rng.choice(len(flat), size=n_embed, replace=False)
    bits = rng.integers(0, 2, size=n_embed, dtype=np.int32)
    flat[idx] = (flat[idx] & ~1) | bits
    return flat.astype(np.int16)


def _make_natural_audio(n_samples: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    t = np.linspace(0, 4, n_samples)
    sig = (
        0.4 * np.sin(2 * np.pi * 440 * t)
        + 0.2 * np.sin(2 * np.pi * 880 * t)
        + 0.1 * rng.standard_normal(n_samples)
    )
    sig = sig / np.max(np.abs(sig)) * 0.9
    return (sig * 32767).astype(np.int16)


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #

RATES = [0.0, 0.1, 0.25, 0.5, 0.75, 1.0]


def generate(out_dir: Path, n: int, size: int, audio_samples: int, verbose: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    img_dir = out_dir / "images"
    aud_dir = out_dir / "audio"
    img_dir.mkdir(exist_ok=True)
    aud_dir.mkdir(exist_ok=True)

    for i in range(n):
        base_img = _make_natural_image(size, seed=i * 1000)
        base_aud = _make_natural_audio(audio_samples, seed=i * 1000 + 1)

        for rate in RATES:
            label = f"p{int(rate * 100):03d}"

            # PNG image
            stego_img = embed_image_lsb(base_img, rate, seed=i)
            img_rgb = np.stack([stego_img] * 3, axis=-1)
            fname = img_dir / f"img_{i:04d}_{label}.png"
            Image.fromarray(img_rgb, mode="RGB").save(fname)

            # JPEG image (same content, re-encoded)
            jpg_fname = img_dir / f"img_{i:04d}_{label}.jpg"
            Image.fromarray(img_rgb, mode="RGB").save(jpg_fname, format="JPEG", quality=90)

            # WAV audio
            stego_aud = embed_audio_lsb(base_aud, rate, seed=i)
            aud_fname = aud_dir / f"aud_{i:04d}_{label}.wav"
            _write_wav(aud_fname, stego_aud)

            if verbose:
                print(f"  {fname.name}  {jpg_fname.name}  {aud_fname.name}")

    print(f"\nGenerated {n} samples x {len(RATES)} embedding rates")
    print(f"Images -> {img_dir}")
    print(f"Audio  -> {aud_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate clean and stego test files for benchmarking."
    )
    parser.add_argument("--out-dir", default="benchmarks/data", metavar="DIR")
    parser.add_argument("--n", type=int, default=20, metavar="N", help="Samples per rate (default: 20)")
    parser.add_argument("--size", type=int, default=256, metavar="PX", help="Image size in pixels (default: 256)")
    parser.add_argument("--audio-samples", type=int, default=44100 * 2, metavar="N")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    generate(Path(args.out_dir), args.n, args.size, args.audio_samples, args.verbose)


if __name__ == "__main__":
    main()
