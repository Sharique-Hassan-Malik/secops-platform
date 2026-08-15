"""
extract.py — batch MFCC feature extraction from collected raw samples.

Reads all .npy files under data/raw/<key>/ and writes:
  data/features/X.npy   — float32 feature matrix (N_samples × 78)
  data/features/y.npy   — int32 label vector     (N_samples,)
  data/features/keys.txt — label-to-key mapping (one key per line, 1-indexed)

Usage
-----
    python extract.py [--raw-dir data/raw] [--feat-dir data/features]
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np

from features import MFCCExtractor


def extract_all(raw_dir: Path, feat_dir: Path) -> None:
    feat_dir.mkdir(parents=True, exist_ok=True)
    extractor = MFCCExtractor()

    key_dirs = sorted([d for d in raw_dir.iterdir() if d.is_dir()])
    if not key_dirs:
        print(f"No subdirectories found in {raw_dir}")
        return

    keys      = [d.name for d in key_dirs]
    X_list:   list[np.ndarray] = []
    y_list:   list[int]        = []

    for label, key_dir in enumerate(key_dirs, start=1):
        files = sorted(key_dir.glob("*.npy"))
        print(f"  Key '{key_dir.name}' (label {label}): {len(files)} samples", end="")
        for f in files:
            samples = np.load(f)
            feat    = extractor.extract(samples)
            X_list.append(feat)
            y_list.append(label)
        print(f" → {len(files)} feature vectors extracted")

    X = np.stack(X_list, axis=0).astype(np.float32)
    y = np.array(y_list,  dtype=np.int32)

    np.save(feat_dir / "X.npy", X)
    np.save(feat_dir / "y.npy", y)
    (feat_dir / "keys.txt").write_text("\n".join(keys))

    print(f"\nFeature matrix: {X.shape}  Label vector: {y.shape}")
    print(f"Saved to {feat_dir}/")


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch MFCC feature extraction")
    parser.add_argument("--raw-dir",  default="data/raw")
    parser.add_argument("--feat-dir", default="data/features")
    args = parser.parse_args()

    extract_all(Path(args.raw_dir), Path(args.feat_dir))


if __name__ == "__main__":
    main()
