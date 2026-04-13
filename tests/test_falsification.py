"""Tests for falsification framework."""

import pytest

from blindspotsec.benchmark.falsification import (
    Verdict,
    run_all_falsification_tests,
    test_blind_spot_existence,
    test_non_triviality,
    test_reproducibility,
    test_systematicity,
)


class TestBlindSpotExistence:
    def test_pass_high_rate(self) -> None:
        result = test_blind_spot_existence(0.25)
        assert result.verdict == Verdict.PASS

    def test_warning_moderate_rate(self) -> None:
        result = test_blind_spot_existence(0.10)
        assert result.verdict == Verdict.WARNING

    def test_fail_low_rate(self) -> None:
        result = test_blind_spot_existence(0.03)
        assert result.verdict == Verdict.FAIL

    def test_exact_threshold(self) -> None:
        result = test_blind_spot_existence(0.05)
        assert result.verdict == Verdict.WARNING  # equal to min, not below


class TestSystematicity:
    def test_pass_many_clusters(self) -> None:
        clusters = {f"CWE-{i}": [f"CVE-{i}-{j}" for j in range(5)] for i in range(5)}
        result = test_systematicity(clusters)
        assert result.verdict == Verdict.PASS

    def test_fail_no_clusters(self) -> None:
        clusters = {"CWE-1": ["CVE-1"], "CWE-2": ["CVE-2"]}
        result = test_systematicity(clusters)
        assert result.verdict == Verdict.FAIL

    def test_warning_borderline(self) -> None:
        clusters = {f"CWE-{i}": [f"CVE-{i}-{j}" for j in range(3)] for i in range(3)}
        result = test_systematicity(clusters)
        assert result.verdict == Verdict.WARNING


class TestNonTriviality:
    def test_pass_mostly_nontrivial(self) -> None:
        result = test_non_triviality(trivial_count=2, total_count=10)
        assert result.verdict == Verdict.PASS

    def test_fail_mostly_trivial(self) -> None:
        result = test_non_triviality(trivial_count=9, total_count=10)
        assert result.verdict == Verdict.FAIL

    def test_zero_division(self) -> None:
        result = test_non_triviality(trivial_count=0, total_count=0)
        assert result.verdict == Verdict.FAIL  # 1.0 > 0.80


class TestReproducibility:
    def test_pass_stable(self) -> None:
        result = test_reproducibility([0.20, 0.21, 0.19])
        assert result.verdict == Verdict.PASS

    def test_fail_unstable(self) -> None:
        result = test_reproducibility([0.05, 0.30, 0.50])
        assert result.verdict == Verdict.FAIL

    def test_skipped_insufficient(self) -> None:
        result = test_reproducibility([0.20])
        assert result.verdict == Verdict.SKIPPED


class TestFullSuite:
    def test_all_pass(self) -> None:
        clusters = {f"CWE-{i}": [f"CVE-{j}" for j in range(5)] for i in range(5)}
        results = run_all_falsification_tests(
            blind_spot_rate=0.25,
            cwe_clusters=clusters,
            trivial_count=2,
            total_blind_spots=10,
            subsample_rates=[0.24, 0.26, 0.25],
        )
        assert all(r.verdict in (Verdict.PASS, Verdict.WARNING) for r in results)

    def test_kill_on_low_rate(self) -> None:
        results = run_all_falsification_tests(
            blind_spot_rate=0.02,
            cwe_clusters={},
            trivial_count=0,
            total_blind_spots=0,
        )
        assert any(r.verdict == Verdict.FAIL for r in results)
