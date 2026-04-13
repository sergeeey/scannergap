"""Quadrant analysis engine.

Builds a coverage matrix: CVE x Scanner -> found/missed.
Identifies Q2 (blind spots) — vulnerabilities missed by ALL scanners.

Methodology from ARCHCODE:
  ARCHCODE used Q2 = "LSSIM < threshold AND VEP < threshold"
  (structural disruption invisible to sequence predictors).
  BlindSpotSec uses Q2 = "CVE confirmed AND no scanner found it".
"""

from dataclasses import dataclass, field

import pandas as pd
import structlog

log = structlog.get_logger()


@dataclass
class QuadrantResult:
    """Result of quadrant analysis across all scanners."""

    # Q1: Detected by at least one scanner (true positive)
    q1_detected: list[str] = field(default_factory=list)
    # Q2: Missed by ALL scanners despite being a real CVE (BLIND SPOT)
    q2_blind_spot: list[str] = field(default_factory=list)
    # Q3: Flagged by scanner but not a real CVE (false positive)
    q3_false_positive: list[str] = field(default_factory=list)
    # Q4: Not flagged and not a real CVE (true negative)
    q4_true_negative: list[str] = field(default_factory=list)

    @property
    def blind_spot_rate(self) -> float:
        """Fraction of real CVEs missed by all scanners."""
        total_real = len(self.q1_detected) + len(self.q2_blind_spot)
        if total_real == 0:
            return 0.0
        return len(self.q2_blind_spot) / total_real

    def summary(self) -> dict[str, int | float]:
        return {
            "q1_detected": len(self.q1_detected),
            "q2_blind_spot": len(self.q2_blind_spot),
            "q3_false_positive": len(self.q3_false_positive),
            "q4_true_negative": len(self.q4_true_negative),
            "blind_spot_rate": round(self.blind_spot_rate, 4),
        }


def build_coverage_matrix(
    cve_ids: list[str],
    scanner_results: dict[str, set[str]],
) -> pd.DataFrame:
    """Build CVE x Scanner coverage matrix.

    Args:
        cve_ids: List of all CVE IDs in corpus.
        scanner_results: {scanner_name: set of CVE IDs it detected}.

    Returns:
        DataFrame with CVE IDs as index, scanner names as columns,
        1 = detected, 0 = missed.
    """
    matrix_data: dict[str, list[int]] = {}
    for scanner_name, detected_cves in scanner_results.items():
        matrix_data[scanner_name] = [1 if cve_id in detected_cves else 0 for cve_id in cve_ids]

    df = pd.DataFrame(matrix_data, index=cve_ids)
    df.index.name = "cve_id"

    # Add aggregate columns
    scanner_cols = list(scanner_results.keys())
    df["any_scanner"] = (df[scanner_cols].sum(axis=1) > 0).astype(int)
    df["all_scanners"] = (df[scanner_cols].sum(axis=1) == len(scanner_results)).astype(int)
    df["scanner_count"] = df[scanner_cols].sum(axis=1)

    log.info(
        "coverage_matrix_built",
        total_cves=len(cve_ids),
        scanners=scanner_cols,
        detected_by_any=int(df["any_scanner"].sum()),
        detected_by_all=int(df["all_scanners"].sum()),
        missed_by_all=int((df["any_scanner"] == 0).sum()),
    )
    return df


def classify_quadrants(
    coverage_matrix: pd.DataFrame,
    confirmed_cves: set[str],
    scanner_columns: list[str],
) -> QuadrantResult:
    """Classify each CVE into quadrants.

    Args:
        coverage_matrix: Output of build_coverage_matrix().
        confirmed_cves: Set of CVE IDs confirmed as real vulnerabilities.
        scanner_columns: Column names for scanner detection results.

    Returns:
        QuadrantResult with CVEs classified into Q1-Q4.
    """
    result = QuadrantResult()

    for cve_id in coverage_matrix.index:
        is_real = cve_id in confirmed_cves
        detected = coverage_matrix.loc[cve_id, scanner_columns].sum() > 0

        if is_real and detected:
            result.q1_detected.append(cve_id)
        elif is_real and not detected:
            result.q2_blind_spot.append(cve_id)
        elif not is_real and detected:
            result.q3_false_positive.append(cve_id)
        else:
            result.q4_true_negative.append(cve_id)

    log.info("quadrant_classification", **result.summary())
    return result


def analyze_blind_spot_patterns(
    blind_spot_cves: list[str],
    cve_metadata: dict[str, dict],
) -> dict[str, list[str]]:
    """Group blind spot CVEs by CWE category to find systematic patterns.

    Args:
        blind_spot_cves: CVE IDs in Q2 (missed by all).
        cve_metadata: {cve_id: {cwe_ids: [...], description: ..., cvss: ...}}.

    Returns:
        {cwe_category: [cve_ids]} — grouped blind spots, sorted by count desc.
    """
    # WHY: If blind spots cluster by CWE, it reveals systematic scanner limitations
    # (analog of ARCHCODE finding that structural disruptions cluster by mechanism)
    by_cwe: dict[str, list[str]] = {}

    for cve_id in blind_spot_cves:
        meta = cve_metadata.get(cve_id, {})
        cwe_ids = meta.get("cwe_ids", ["CWE-UNKNOWN"])
        for cwe in cwe_ids:
            by_cwe.setdefault(cwe, []).append(cve_id)

    # Sort by count descending — largest clusters are most interesting
    sorted_cwe = dict(sorted(by_cwe.items(), key=lambda x: len(x[1]), reverse=True))

    log.info(
        "blind_spot_patterns",
        total_blind_spots=len(blind_spot_cves),
        cwe_categories=len(sorted_cwe),
        top_3=[(k, len(v)) for k, v in list(sorted_cwe.items())[:3]],
    )
    return sorted_cwe
