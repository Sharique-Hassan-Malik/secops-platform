import math
import pytest

from analysis.entropy import compute_entropy, analyse_features, entropy_summary, FEATURE_GROUPS, ALL_FEATURES
from scripts.generate_synthetic import generate


# ── compute_entropy ──────────────────────────────────────────────────────────

class TestComputeEntropy:
    def test_uniform_two_values(self):
        values = ["A"] * 50 + ["B"] * 50
        # p(A) = p(B) = 0.5  →  H = 1.0 bit
        assert abs(compute_entropy(values) - 1.0) < 1e-9

    def test_uniform_four_values(self):
        values = ["A"] * 25 + ["B"] * 25 + ["C"] * 25 + ["D"] * 25
        assert abs(compute_entropy(values) - 2.0) < 1e-9

    def test_all_same_value_zero_entropy(self):
        assert compute_entropy(["X"] * 100) == pytest.approx(0.0)

    def test_all_unique_max_entropy(self):
        n      = 32
        values = [str(i) for i in range(n)]
        assert abs(compute_entropy(values) - math.log2(n)) < 1e-9

    def test_empty_list_returns_zero(self):
        assert compute_entropy([]) == 0.0

    def test_all_none_returns_zero(self):
        assert compute_entropy([None, None, None]) == 0.0

    def test_mixed_none_ignored(self):
        values = ["A", "B", None, None, "A", "B"]
        # should be same as ["A","A","B","B"]
        assert abs(compute_entropy(values) - 1.0) < 1e-9

    def test_single_value_returns_zero(self):
        assert compute_entropy(["only_one"]) == pytest.approx(0.0)

    def test_skewed_distribution_less_than_max(self):
        values = ["A"] * 90 + ["B"] * 10
        h = compute_entropy(values)
        assert 0 < h < 1.0

    def test_numeric_values_treated_as_strings(self):
        values = [1, 2, 1, 2, 1, 2]
        assert abs(compute_entropy(values) - 1.0) < 1e-9


# ── analyse_features ─────────────────────────────────────────────────────────

class TestAnalyseFeatures:
    @pytest.fixture(scope="class")
    def rows(self):
        return generate(n=200, seed=0)

    def test_returns_one_result_per_feature(self, rows):
        results = analyse_features(rows)
        assert len(results) == len(ALL_FEATURES)

    def test_sorted_descending_by_entropy(self, rows):
        results = analyse_features(rows)
        bits    = [r.entropy_bits for r in results]
        assert bits == sorted(bits, reverse=True)

    def test_group_labels_match_feature_groups(self, rows):
        results   = analyse_features(rows)
        feat_to_group = {f: g for g, fs in FEATURE_GROUPS.items() for f in fs}
        for r in results:
            assert r.group == feat_to_group[r.feature]

    def test_entropy_non_negative(self, rows):
        for r in analyse_features(rows):
            assert r.entropy_bits >= 0.0

    def test_coverage_in_unit_interval(self, rows):
        for r in analyse_features(rows):
            assert 0.0 <= r.coverage <= 1.0

    def test_n_unique_positive_for_populated_features(self, rows):
        for r in analyse_features(rows):
            if r.coverage > 0:
                assert r.n_unique_values >= 1

    def test_most_common_length_at_most_five(self, rows):
        for r in analyse_features(rows):
            assert len(r.most_common) <= 5

    def test_empty_rows_returns_empty(self):
        assert analyse_features([]) == []

    def test_canvas_hash_has_high_entropy(self, rows):
        results = analyse_features(rows)
        by_name = {r.feature: r for r in results}
        # Canvas hash groups several browser/OS combos — should have > 1 bit
        assert by_name["canvas_hash"].entropy_bits > 1.0

    def test_screen_width_has_nonzero_entropy(self, rows):
        results = analyse_features(rows)
        by_name = {r.feature: r for r in results}
        assert by_name["screen_width"].entropy_bits > 0.0


# ── entropy_summary ───────────────────────────────────────────────────────────

class TestEntropySummary:
    @pytest.fixture(scope="class")
    def summary(self):
        rows = generate(n=300, seed=1)
        return entropy_summary(rows)

    def test_n_fingerprints_matches(self, summary):
        assert summary["n_fingerprints"] == 300

    def test_total_bits_positive(self, summary):
        assert summary["total_bits"] > 0.0

    def test_group_totals_keys(self, summary):
        assert set(summary["group_totals"].keys()) == set(FEATURE_GROUPS.keys())

    def test_group_totals_non_negative(self, summary):
        for v in summary["group_totals"].values():
            assert v >= 0.0

    def test_features_list_correct_length(self, summary):
        assert len(summary["features"]) == len(ALL_FEATURES)

    def test_features_sorted_by_entropy_desc(self, summary):
        bits = [f["entropy_bits"] for f in summary["features"]]
        assert bits == sorted(bits, reverse=True)

    def test_feature_dict_has_required_keys(self, summary):
        for f in summary["features"]:
            for key in ("feature", "group", "entropy_bits", "n_unique", "coverage", "top_values"):
                assert key in f

    def test_top_values_length(self, summary):
        for f in summary["features"]:
            assert len(f["top_values"]) <= 5

    def test_anonymity_set_upper_positive(self, summary):
        asu = summary["anonymity_set_upper"]
        assert asu > 0

    def test_empty_rows_graceful(self):
        s = entropy_summary([])
        assert s["n_fingerprints"] == 0
        assert s["total_bits"] == 0.0
        assert s["features"] == []

    def test_all_same_fingerprint_zero_entropy(self):
        rows = [generate(n=1, seed=0)[0]] * 50
        s    = entropy_summary(rows)
        assert s["total_bits"] == pytest.approx(0.0, abs=1e-9)
