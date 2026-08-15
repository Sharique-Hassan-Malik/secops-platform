import pytest
from sklearn.model_selection import train_test_split

from analysis.classifier import FingerprintClassifier, _parse_browser_os
from analysis.features import build_matrix, extract_features, ML_FEATURES
from scripts.generate_synthetic import generate


# ── _parse_browser_os ─────────────────────────────────────────────────────────

class TestParseBrowserOS:
    def test_chrome_windows(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        assert _parse_browser_os(ua) == "Chrome/Windows"

    def test_firefox_linux(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
        assert _parse_browser_os(ua) == "Firefox/Linux"

    def test_safari_macos(self):
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        assert _parse_browser_os(ua) == "Safari/macOS"

    def test_safari_ios(self):
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
        assert _parse_browser_os(ua) == "Safari/iOS"

    def test_edge_windows(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        assert _parse_browser_os(ua) == "Edge/Windows"

    def test_opera_windows(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 OPR/106.0.0.0"
        assert _parse_browser_os(ua) == "Opera/Windows"

    def test_chrome_android(self):
        ua = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36"
        assert _parse_browser_os(ua) == "Chrome/Android"

    def test_none_returns_unknown(self):
        assert _parse_browser_os(None) == "Unknown/Unknown"

    def test_empty_string_returns_unknown(self):
        assert _parse_browser_os("") == "Unknown/Unknown"


# ── extract_features / build_matrix ─────────────────────────────────────────

class TestFeatureExtraction:
    @pytest.fixture(scope="class")
    def rows(self):
        return generate(n=100, seed=2)

    def test_vector_length(self, rows):
        v = extract_features(rows[0])
        assert len(v) == len(ML_FEATURES)

    def test_all_floats(self, rows):
        v = extract_features(rows[0])
        assert all(isinstance(x, float) for x in v)

    def test_matrix_shape(self, rows):
        M = build_matrix(rows)
        assert M.shape == (len(rows), len(ML_FEATURES))

    def test_matrix_dtype(self, rows):
        import numpy as np
        M = build_matrix(rows)
        assert M.dtype == np.float64

    def test_none_values_give_sentinel(self):
        row = {f: None for f in ML_FEATURES}
        v   = extract_features(row)
        assert all(x == -1.0 for x in v)

    def test_categorical_encoding_stable(self):
        row = {"canvas_hash": "abc123", "webgl_unmasked_renderer": None}
        v1  = extract_features(row)
        v2  = extract_features(row)
        assert v1 == v2

    def test_different_canvas_hashes_give_different_values(self):
        r1 = {"canvas_hash": "aaa"}
        r2 = {"canvas_hash": "bbb"}
        assert extract_features(r1)[ML_FEATURES.index("canvas_hash")] != \
               extract_features(r2)[ML_FEATURES.index("canvas_hash")]

    def test_screen_width_encoded_as_float(self):
        row = {"screen_width": 1920}
        v   = extract_features(row)
        idx = ML_FEATURES.index("screen_width")
        assert v[idx] == 1920.0


# ── FingerprintClassifier ─────────────────────────────────────────────────────

class TestFingerprintClassifier:
    @pytest.fixture(scope="class")
    def dataset(self):
        return generate(n=600, seed=3)

    @pytest.fixture(scope="class")
    def trained_clf(self, dataset):
        train, _ = train_test_split(dataset, test_size=0.3, random_state=0)
        clf = FingerprintClassifier()
        clf.fit(train)
        return clf

    def test_fit_does_not_raise(self, dataset):
        train, _ = train_test_split(dataset, test_size=0.3, random_state=1)
        FingerprintClassifier().fit(train)

    def test_predict_returns_string_and_dict(self, trained_clf, dataset):
        label, probs = trained_clf.predict(dataset[0])
        assert isinstance(label, str)
        assert isinstance(probs, dict)
        assert len(probs) > 0

    def test_predict_probabilities_sum_to_one(self, trained_clf, dataset):
        _, probs = trained_clf.predict(dataset[0])
        assert abs(sum(probs.values()) - 1.0) < 1e-4

    def test_predicted_label_in_probs(self, trained_clf, dataset):
        label, probs = trained_clf.predict(dataset[0])
        assert label in probs

    def test_unfitted_raises(self):
        clf = FingerprintClassifier()
        with pytest.raises(RuntimeError):
            clf.predict({"canvas_hash": "x"})

    def test_evaluate_returns_required_keys(self, trained_clf, dataset):
        _, test = train_test_split(dataset, test_size=0.3, random_state=0)
        result  = trained_clf.evaluate(test)
        for key in ("classification_report", "confusion_matrix", "classes", "feature_importances"):
            assert key in result

    def test_feature_importances_sum_approx_one(self, trained_clf):
        fi  = trained_clf.feature_importances()
        total = sum(x["importance"] for x in fi)
        assert abs(total - 1.0) < 1e-4

    def test_feature_importances_sorted_descending(self, trained_clf):
        fi   = trained_clf.feature_importances()
        imps = [x["importance"] for x in fi]
        assert imps == sorted(imps, reverse=True)

    def test_save_load_round_trip(self, trained_clf, dataset, tmp_path):
        path = tmp_path / "clf.pkl"
        trained_clf.save(path)
        loaded = FingerprintClassifier.load(path)
        orig_label,   _ = trained_clf.predict(dataset[0])
        loaded_label, _ = loaded.predict(dataset[0])
        assert orig_label == loaded_label

    def test_accuracy_above_threshold(self, dataset):
        # With 10 distinct Browser/OS combos and strong signals, RF should exceed 80%
        train, test = train_test_split(dataset, test_size=0.2, random_state=42, stratify=[
            _parse_browser_os(r.get("user_agent")) for r in dataset
        ])
        clf    = FingerprintClassifier()
        clf.fit(train)
        result = clf.evaluate(test)
        acc    = result["classification_report"]["accuracy"]
        assert acc >= 0.80, f"Expected ≥ 80% accuracy, got {acc:.4f}"

    def test_classes_cover_expected_browsers(self, trained_clf):
        classes = set(trained_clf.encoder.classes_)
        # at least Chrome and Safari should appear in 600 synthetic samples
        assert any("Chrome" in c for c in classes)
        assert any("Safari" in c for c in classes)
