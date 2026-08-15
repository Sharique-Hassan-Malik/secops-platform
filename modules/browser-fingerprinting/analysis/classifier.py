"""
Browser fingerprint classifier.

Given a labelled set of fingerprints (browser family + OS derived from the
user-agent string), train a RandomForest and evaluate its ability to
distinguish browser/OS combinations using only the non-UA fingerprint signals.

This demonstrates the core privacy concern: an adversary can identify your
browser and OS without reading the User-Agent header by combining canvas,
WebGL, audio and timing signals alone.
"""

from __future__ import annotations

import pickle
import re
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from .features import build_matrix, ML_FEATURES


def _parse_browser_os(user_agent: str | None) -> str:
    """Derive a coarse 'Browser/OS' label from a UA string."""
    if not user_agent:
        return "Unknown/Unknown"
    ua = user_agent.lower()

    # OS — iOS must be checked before macOS (iPhone UA contains "Mac OS X")
    if "windows nt" in ua:
        os_lbl = "Windows"
    elif "iphone" in ua or "ipad" in ua:
        os_lbl = "iOS"
    elif "android" in ua:
        os_lbl = "Android"
    elif "mac os x" in ua or "macintosh" in ua:
        os_lbl = "macOS"
    elif "linux" in ua:
        os_lbl = "Linux"
    else:
        os_lbl = "Other"

    # Browser (order matters — Edge and Chrome both contain "chrome")
    if "edg/" in ua or "edge/" in ua:
        br_lbl = "Edge"
    elif "opr/" in ua or "opera" in ua:
        br_lbl = "Opera"
    elif "firefox/" in ua:
        br_lbl = "Firefox"
    elif "safari/" in ua and "chrome" not in ua:
        br_lbl = "Safari"
    elif "chrome/" in ua:
        br_lbl = "Chrome"
    else:
        br_lbl = "Other"

    return f"{br_lbl}/{os_lbl}"


class FingerprintClassifier:
    """
    Predicts browser/OS label from non-UA fingerprint signals.
    """

    def __init__(self):
        self.model    = RandomForestClassifier(
            n_estimators=200, max_depth=12, min_samples_leaf=2,
            class_weight="balanced", n_jobs=-1, random_state=42,
        )
        self.scaler   = StandardScaler()
        self.encoder  = LabelEncoder()
        self._fitted  = False

    def fit(self, rows: list[dict]) -> "FingerprintClassifier":
        labels = [_parse_browser_os(r.get("user_agent")) for r in rows]
        X      = build_matrix(rows)
        y      = self.encoder.fit_transform(labels)
        X      = self.scaler.fit_transform(X)
        self.model.fit(X, y)
        self._fitted = True
        return self

    def predict(self, row: dict) -> tuple[str, dict[str, float]]:
        """Returns (predicted_label, {label: probability})."""
        self._check_fitted()
        from .features import extract_features
        x      = np.array([extract_features(row)], dtype=np.float64)
        x      = self.scaler.transform(x)
        idx    = int(self.model.predict(x)[0])
        probas = self.model.predict_proba(x)[0]
        label  = self.encoder.inverse_transform([idx])[0]
        prob_map = {
            self.encoder.inverse_transform([i])[0]: round(float(p), 4)
            for i, p in enumerate(probas)
        }
        return label, prob_map

    def evaluate(self, rows: list[dict]) -> dict:
        self._check_fitted()
        labels = [_parse_browser_os(r.get("user_agent")) for r in rows]
        X      = build_matrix(rows)
        y_true = self.encoder.transform(labels)
        X      = self.scaler.transform(X)
        y_pred = self.model.predict(X)
        report = classification_report(
            y_true, y_pred,
            target_names=self.encoder.classes_,
            output_dict=True,
        )
        cm = confusion_matrix(y_true, y_pred)
        return {
            "classification_report": report,
            "confusion_matrix":      cm.tolist(),
            "classes":               list(self.encoder.classes_),
            "feature_importances":   self._importances(),
        }

    def feature_importances(self) -> list[dict]:
        """Returns feature importance dicts sorted descending — public alias for _importances."""
        return self._importances()

    def _importances(self) -> list[dict]:
        imp = self.model.feature_importances_
        return sorted(
            [{"feature": f, "importance": round(float(v), 5)} for f, v in zip(ML_FEATURES, imp)],
            key=lambda x: x["importance"],
            reverse=True,
        )

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({
                "model":   self.model,
                "scaler":  self.scaler,
                "encoder": self.encoder,
            }, f)

    @classmethod
    def load(cls, path: str | Path) -> "FingerprintClassifier":
        with open(path, "rb") as f:
            state = pickle.load(f)
        obj          = cls.__new__(cls)
        obj.model    = state["model"]
        obj.scaler   = state["scaler"]
        obj.encoder  = state["encoder"]
        obj._fitted  = True
        return obj

    def _check_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError("Classifier has not been trained. Call fit() first.")
