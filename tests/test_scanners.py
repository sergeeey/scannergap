"""Tests for scanner base classes."""

from scannergap.scanners.base import Finding, ScanResult


class TestFinding:
    def test_creation(self) -> None:
        finding = Finding(
            scanner="semgrep",
            rule_id="python.lang.security.eval",
            severity="error",
        )
        assert finding.scanner == "semgrep"
        assert finding.cwe_id is None
        assert finding.confidence == "medium"

    def test_with_cwe(self) -> None:
        finding = Finding(
            scanner="bandit",
            rule_id="B608",
            severity="high",
            cwe_id="CWE-89",
            file_path="app.py",
            line_start=42,
            message="SQL injection",
        )
        assert finding.cwe_id == "CWE-89"
        assert finding.line_start == 42


class TestScanResult:
    def test_empty(self) -> None:
        result = ScanResult(scanner="semgrep", target_path="/tmp/test")
        assert result.finding_count == 0
        assert result.detected_cwes == set()
        assert result.error is None

    def test_with_findings(self) -> None:
        findings = [
            Finding(scanner="s", rule_id="r1", severity="high", cwe_id="CWE-89"),
            Finding(scanner="s", rule_id="r2", severity="medium", cwe_id="CWE-79"),
            Finding(scanner="s", rule_id="r3", severity="low"),
        ]
        result = ScanResult(
            scanner="semgrep",
            target_path="/tmp/test",
            findings=findings,
            duration_seconds=1.5,
        )
        assert result.finding_count == 3
        assert result.detected_cwes == {"CWE-89", "CWE-79"}
        assert result.duration_seconds == 1.5

    def test_error_state(self) -> None:
        result = ScanResult(
            scanner="bandit",
            target_path="/tmp/fail",
            error="Scanner timed out",
        )
        assert result.error == "Scanner timed out"
        assert result.finding_count == 0
