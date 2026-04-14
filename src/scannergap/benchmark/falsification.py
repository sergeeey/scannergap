"""Falsification testing framework.

Adapted from ARCHCODE's 6-test validation suite.
Each test has a null hypothesis and a kill criterion.
"""

from dataclasses import dataclass
from enum import Enum

import numpy as np
import structlog

log = structlog.get_logger()


class Verdict(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


@dataclass
class FalsificationResult:
    """Result of a single falsification test."""

    test_name: str
    null_hypothesis: str
    kill_criterion: str
    verdict: Verdict
    metric_name: str
    metric_value: float
    threshold: float
    details: str = ""


def check_blind_spot_existence(
    blind_spot_rate: float,
    min_rate: float = 0.05,
) -> FalsificationResult:
    """Test 1: Do blind spots exist in meaningful quantity?

    Null hypothesis: All scanners combined cover >95% of CVEs.
    Kill criterion: blind_spot_rate < min_rate -> blind spots too rare.
    """
    verdict = (
        Verdict.FAIL
        if blind_spot_rate < min_rate
        else (Verdict.WARNING if blind_spot_rate < 0.15 else Verdict.PASS)
    )

    log.info(
        "falsification_blind_spot_existence",
        rate=blind_spot_rate,
        threshold=min_rate,
        verdict=verdict.value,
    )

    return FalsificationResult(
        test_name="blind_spot_existence",
        null_hypothesis="All scanners combined cover >95% of CVEs",
        kill_criterion=f"blind_spot_rate < {min_rate}",
        verdict=verdict,
        metric_name="blind_spot_rate",
        metric_value=round(blind_spot_rate, 4),
        threshold=min_rate,
        details=f"Rate {blind_spot_rate:.1%}: {'sufficient' if verdict != Verdict.FAIL else 'insufficient'} blind spots",
    )


def check_systematicity(
    cwe_clusters: dict[str, list[str]],
    min_clusters: int = 3,
    min_per_cluster: int = 3,
) -> FalsificationResult:
    """Test 2: Do blind spots form systematic categories?

    Null hypothesis: Blind spots are randomly distributed across CWE categories.
    Kill criterion: Fewer than min_clusters categories with >= min_per_cluster CVEs.
    """
    qualifying_clusters = {
        cwe: cves for cwe, cves in cwe_clusters.items() if len(cves) >= min_per_cluster
    }
    count = len(qualifying_clusters)

    verdict = (
        Verdict.FAIL
        if count < min_clusters
        else (Verdict.WARNING if count < min_clusters + 2 else Verdict.PASS)
    )

    log.info(
        "falsification_systematicity",
        qualifying_clusters=count,
        threshold=min_clusters,
        verdict=verdict.value,
        top_clusters={k: len(v) for k, v in list(qualifying_clusters.items())[:5]},
    )

    return FalsificationResult(
        test_name="systematicity",
        null_hypothesis="Blind spots randomly distributed (no systematic pattern)",
        kill_criterion=f"<{min_clusters} categories with >={min_per_cluster} CVEs each",
        verdict=verdict,
        metric_name="qualifying_cluster_count",
        metric_value=float(count),
        threshold=float(min_clusters),
        details=f"{count} categories with >={min_per_cluster} CVEs: {list(qualifying_clusters.keys())[:5]}",
    )


def check_non_triviality(
    trivial_count: int,
    total_count: int,
    max_trivial_rate: float = 0.80,
) -> FalsificationResult:
    """Test 3: Are blind spots non-trivial?

    Null hypothesis: >80% of blind spots fixable by simple regex rules.
    Kill criterion: trivial_rate > max_trivial_rate.
    """
    trivial_rate = trivial_count / total_count if total_count > 0 else 1.0

    verdict = (
        Verdict.FAIL
        if trivial_rate > max_trivial_rate
        else (Verdict.WARNING if trivial_rate > 0.50 else Verdict.PASS)
    )

    return FalsificationResult(
        test_name="non_triviality",
        null_hypothesis=">80% of blind spots are trivially detectable by regex",
        kill_criterion=f"trivial_rate > {max_trivial_rate}",
        verdict=verdict,
        metric_name="trivial_rate",
        metric_value=round(trivial_rate, 4),
        threshold=max_trivial_rate,
        details=f"{trivial_count}/{total_count} blind spots are trivially detectable",
    )


def check_reproducibility(
    subsample_rates: list[float],
    max_cv: float = 0.20,
) -> FalsificationResult:
    """Test 4: Are results reproducible across corpus subsamples?

    Null hypothesis: Results are corpus-dependent artifacts.
    Kill criterion: CV (coefficient of variation) > max_cv.
    """
    if len(subsample_rates) < 2:
        return FalsificationResult(
            test_name="reproducibility",
            null_hypothesis="Results are corpus-dependent artifacts",
            kill_criterion=f"CV > {max_cv}",
            verdict=Verdict.SKIPPED,
            metric_name="cv",
            metric_value=0.0,
            threshold=max_cv,
            details="Need >= 2 subsample runs",
        )

    mean_rate = float(np.mean(subsample_rates))
    std_rate = float(np.std(subsample_rates))
    cv = std_rate / mean_rate if mean_rate > 0 else float("inf")

    verdict = Verdict.FAIL if cv > max_cv else (Verdict.WARNING if cv > 0.10 else Verdict.PASS)

    return FalsificationResult(
        test_name="reproducibility",
        null_hypothesis="Results are corpus-dependent artifacts",
        kill_criterion=f"CV > {max_cv}",
        verdict=verdict,
        metric_name="coefficient_of_variation",
        metric_value=round(cv, 4),
        threshold=max_cv,
        details=f"Mean rate: {mean_rate:.3f}, Std: {std_rate:.3f}, CV: {cv:.3f}",
    )


def run_all_falsification_tests(
    blind_spot_rate: float,
    cwe_clusters: dict[str, list[str]],
    trivial_count: int,
    total_blind_spots: int,
    subsample_rates: list[float] | None = None,
) -> list[FalsificationResult]:
    """Run all 4 falsification tests and return results."""
    results = [
        check_blind_spot_existence(blind_spot_rate),
        check_systematicity(cwe_clusters),
        check_non_triviality(trivial_count, total_blind_spots),
        check_reproducibility(subsample_rates or []),
    ]

    passed = sum(1 for r in results if r.verdict == Verdict.PASS)
    failed = sum(1 for r in results if r.verdict == Verdict.FAIL)
    warnings = sum(1 for r in results if r.verdict == Verdict.WARNING)

    log.info(
        "falsification_suite_complete",
        passed=passed,
        warnings=warnings,
        failed=failed,
        skipped=len(results) - passed - failed - warnings,
        overall="ALIVE" if failed == 0 else "KILL",
    )

    return results
