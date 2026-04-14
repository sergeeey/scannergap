"""Tests for NVD client data structures."""

from pathlib import Path

from scannergap.corpus.nvd_client import CVERecord, NVD_API_BASE


class TestCVERecord:
    def test_defaults(self) -> None:
        record = CVERecord(cve_id="CVE-2024-0001", description="Test vuln")
        assert record.cve_id == "CVE-2024-0001"
        assert record.cwe_ids == []
        assert record.cvss_score is None
        assert record.references == []
        assert record.github_url is None
        assert record.source_code_path is None
        assert record.patch_url is None

    def test_full_data(self) -> None:
        record = CVERecord(
            cve_id="CVE-2024-0002",
            description="SQL injection in login form",
            cwe_ids=["CWE-89"],
            cvss_score=9.8,
            references=["https://example.com/advisory"],
            github_url="https://github.com/org/repo",
            patch_url="https://github.com/org/repo/commit/abc123",
            source_code_path=Path("/tmp/CVE-2024-0002"),
        )
        assert record.cvss_score == 9.8
        assert "CWE-89" in record.cwe_ids
        assert record.patch_url is not None

    def test_nvd_api_base_url(self) -> None:
        assert NVD_API_BASE.startswith("https://services.nvd.nist.gov")
        assert "cves/2.0" in NVD_API_BASE
