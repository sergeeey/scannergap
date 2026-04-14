"""Tests for benchmark report generation."""

from scannergap.benchmark.falsification import FalsificationResult, Verdict
from scannergap.benchmark.report import _render_markdown
from scannergap.quadrant.analysis import QuadrantResult


class TestRenderMarkdown:
    def test_produces_markdown(self) -> None:
        report = {
            "benchmark": "ScannerGap Security Blind Spot Benchmark",
            "version": "0.1.0",
            "generated_at": "2026-04-13T00:00:00Z",
            "corpus": {"total_cves": 20, "confirmed_vulnerabilities": 15},
            "scanners": ["semgrep", "bandit"],
            "quadrant_summary": {
                "q1_detected": 8,
                "q2_blind_spot": 7,
                "q3_false_positive": 3,
                "q4_true_negative": 2,
                "blind_spot_rate": 0.4667,
            },
            "blind_spot_taxonomy": {
                "CWE-94": {"count": 3, "cve_ids": ["CVE-1", "CVE-2", "CVE-3"]},
                "CWE-22": {"count": 2, "cve_ids": ["CVE-4", "CVE-5"]},
            },
            "falsification_tests": [
                {
                    "test": "blind_spot_existence",
                    "verdict": "PASS",
                    "metric": "rate",
                    "value": 0.4667,
                    "threshold": 0.05,
                },
            ],
            "overall_verdict": "ALIVE",
        }

        md = _render_markdown(report)
        assert "# ScannerGap" in md
        assert "## Summary" in md
        assert "## Quadrant Distribution" in md
        assert "## Blind Spot Taxonomy" in md
        assert "## Falsification Tests" in md
        assert "CWE-94" in md
        assert "ALIVE" in md

    def test_quadrant_result_summary(self) -> None:
        qr = QuadrantResult(
            q1_detected=["a", "b"],
            q2_blind_spot=["c", "d", "e"],
        )
        summary = qr.summary()
        assert summary["q1_detected"] == 2
        assert summary["q2_blind_spot"] == 3
        assert summary["blind_spot_rate"] == 0.6

    def test_falsification_result_fields(self) -> None:
        fr = FalsificationResult(
            test_name="test_1",
            null_hypothesis="H0",
            kill_criterion="rate < 0.05",
            verdict=Verdict.PASS,
            metric_name="rate",
            metric_value=0.55,
            threshold=0.05,
        )
        assert fr.verdict == Verdict.PASS
        assert fr.metric_value == 0.55
