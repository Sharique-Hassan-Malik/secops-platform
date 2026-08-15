"""
train.py — train and evaluate a keystroke classifier on extracted MFCC features.

Model: SVM with RBF kernel — strong baseline for small tabular datasets.
Pipeline:
  StandardScaler → PCA (optional dimensionality reduction) → SVC (RBF)

Cross-validation: stratified 5-fold.
Outputs:
  data/features/model.pkl   — trained sklearn pipeline (joblib)
  data/features/report.txt  — classification report + confusion matrix

Usage
-----
    python train.py [--feat-dir data/features] [--pca 40]
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.decomposition import PCA
from sklearn.metrics import (ConfusionMatrixDisplay, classification_report,
                             confusion_matrix)
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


def train(feat_dir: Path, n_pca: int) -> None:
    X = np.load(feat_dir / "X.npy")
    y = np.load(feat_dir / "y.npy")
    keys = (feat_dir / "keys.txt").read_text().splitlines()

    print(f"Loaded {X.shape[0]} samples × {X.shape[1]} features, {len(keys)} classes.")

    # ── Build pipeline ────────────────────────────────────────────────────────
    steps = [("scaler", StandardScaler())]
    if n_pca and n_pca < X.shape[1]:
        steps.append(("pca", PCA(n_components=n_pca, whiten=True)))
    steps.append(("svc", SVC(kernel="rbf", C=10.0, gamma="scale",
                              decision_function_shape="ovr", probability=True)))
    pipe = Pipeline(steps)

    # ── Stratified 5-fold cross-validation ────────────────────────────────────
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    print("Running 5-fold cross-validation…")
    y_pred = cross_val_predict(pipe, X, y, cv=cv)

    # Map numeric labels back to key characters for the report.
    label_names = [keys[i - 1] for i in sorted(set(y))]
    report = classification_report(y, y_pred, target_names=label_names)
    cm     = confusion_matrix(y, y_pred)

    print("\n── Classification Report ──────────────────────────────────────")
    print(report)

    # ── Fit final model on all data ───────────────────────────────────────────
    pipe.fit(X, y)
    model_path = feat_dir / "model.pkl"
    joblib.dump({"pipeline": pipe, "keys": keys}, model_path)
    print(f"Model saved to {model_path}")

    # ── Save text report ──────────────────────────────────────────────────────
    report_path = feat_dir / "report.txt"
    with open(report_path, "w") as f:
        f.write("Classification Report\n")
        f.write("=" * 60 + "\n")
        f.write(report + "\n\n")
        f.write("Confusion Matrix\n")
        f.write("=" * 60 + "\n")
        f.write("Rows = true label, columns = predicted label\n")
        f.write("Keys: " + ", ".join(label_names) + "\n\n")
        for row in cm:
            f.write("  " + "  ".join(f"{v:4d}" for v in row) + "\n")
    print(f"Report saved to {report_path}")

    # ── Print confusion matrix to terminal ────────────────────────────────────
    print("\nConfusion matrix (rows=true, cols=predicted):")
    header = "      " + "  ".join(f"{k:>4}" for k in label_names)
    print(header)
    for key, row in zip(label_names, cm):
        print(f"  {key:>3} " + "  ".join(f"{v:4d}" for v in row))


def main() -> None:
    parser = argparse.ArgumentParser(description="Train keystroke classifier")
    parser.add_argument("--feat-dir", default="data/features")
    parser.add_argument("--pca",      type=int, default=40,
                        help="PCA components (0 = skip PCA, default 40)")
    args = parser.parse_args()

    train(Path(args.feat_dir), args.pca)


if __name__ == "__main__":
    main()
