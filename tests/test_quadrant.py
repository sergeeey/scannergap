"""Tests for quadrant analysis — the core methodology."""

import pytest

from blindspotsec.quadrant.analysis import (
    QuadrantResult,
    analyze_blind_spot_patterns,
    build_coverage_matrix,
    classify_quadrants,
)


class TestBuildCoverageMatrix:
    def test_basic_matrix(self) -> None:
        cve_ids = ["CVE-2024-001", "CVE-2024-002", "CVE-2024-003"]
        scanner_results = {
            "semgrep": {"CVE-2024-001", "CVE-2024-002"},
            "bandit": {"CVE-2024-001"},
        }
        df = build_coverage_matrix(cve_ids, scanner_results)

        assert len(df) == 3
        assert df.loc["CVE-2024-001", "semgrep"] == 1
        assert df.loc["CVE-2024-001", "bandit"] == 1
        assert df.loc["CVE-2024-002", "semgrep"] == 1
        assert df.loc["CVE-2024-002", "bandit"] == 0
        assert df.loc["CVE-2024-003", "semgrep"] == 0
        assert df.loc["CVE-2024-003", "bandit"] == 0

    def test_aggregate_columns(self) -> None:
        cve_ids = ["CVE-2024-001", "CVE-2024-002"]
        scanner_results = {
            "semgrep": {"CVE-2024-001"},
            "bandit": {"CVE-2024-001"},
        }
        df = build_coverage_matrix(cve_ids, scanner_results)

        assert df.loc["CVE-2024-001", "any_scanner"] == 1
        assert df.loc["CVE-2024-001", "all_scanners"] == 1
        assert df.loc["CVE-2024-001", "scanner_count"] == 2
        assert df.loc["CVE-2024-002", "any_scanner"] == 0
        assert df.loc["CVE-2024-002", "scanner_count"] == 0

    def test_empty_results(self) -> None:
        df = build_coverage_matrix(["CVE-1"], {"s1": set()})
        assert df.loc["CVE-1", "any_scanner"] == 0


class TestClassifyQuadrants:
    def test_all_quadrants(self) -> None:
        cve_ids = ["CVE-1", "CVE-2", "CVE-3", "CVE-4"]
        scanner_results = {"scanner_a": {"CVE-1", "CVE-3"}}
        matrix = build_coverage_matrix(cve_ids, scanner_results)
        confirmed = {"CVE-1", "CVE-2"}

        result = classify_quadrants(matrix, confirmed, ["scanner_a"])

        assert "CVE-1" in result.q1_detected  # real + detected
        assert "CVE-2" in result.q2_blind_spot  # real + missed
        assert "CVE-3" in result.q3_false_positive  # not real + detected
        assert "CVE-4" in result.q4_true_negative  # not real + missed

    def test_blind_spot_rate(self) -> None:
        result = QuadrantResult(
            q1_detected=["a", "b", "c"],
            q2_blind_spot=["d"],
        )
        assert result.blind_spot_rate == pytest.approx(0.25)

    def test_zero_division(self) -> None:
        result = QuadrantResult()
        assert result.blind_spot_rate == 0.0


class TestBlindSpotPatterns:
    def test_grouping_by_cwe(self) -> None:
        blind_spots = ["CVE-1", "CVE-2", "CVE-3"]
        metadata = {
            "CVE-1": {"cwe_ids": ["CWE-89"]},
            "CVE-2": {"cwe_ids": ["CWE-89"]},
            "CVE-3": {"cwe_ids": ["CWE-79"]},
        }
        patterns = analyze_blind_spot_patterns(blind_spots, metadata)

        assert len(patterns["CWE-89"]) == 2
        assert len(patterns["CWE-79"]) == 1
        # CWE-89 should come first (larger cluster)
        assert list(patterns.keys())[0] == "CWE-89"

    def test_unknown_cwe(self) -> None:
        patterns = analyze_blind_spot_patterns(["CVE-1"], {})
        assert "CWE-UNKNOWN" in patterns
