"""NVD (National Vulnerability Database) API client.

Fetches CVE records with associated source code from GitHub.
"""

from dataclasses import dataclass, field
from pathlib import Path

import requests
import structlog

log = structlog.get_logger()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVERecord:
    """A single CVE with metadata and optional source code path."""

    cve_id: str
    description: str
    cwe_ids: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    references: list[str] = field(default_factory=list)
    github_url: str | None = None
    source_code_path: Path | None = None
    patch_url: str | None = None


def fetch_cves(
    keyword: str,
    results_per_page: int = 50,
    start_index: int = 0,
    has_source_code: bool = True,
) -> list[CVERecord]:
    """Fetch CVEs from NVD API matching keyword.

    Args:
        keyword: Search term (e.g., "SQL injection", "buffer overflow").
        results_per_page: Number of results per API call (max 2000).
        start_index: Pagination offset.
        has_source_code: If True, filter to CVEs with GitHub references.

    Returns:
        List of CVERecord objects.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
    }

    log.info("fetching_cves", keyword=keyword, start=start_index)
    resp = requests.get(NVD_API_BASE, params=params, timeout=30)
    resp.raise_for_status()

    data = resp.json()
    records: list[CVERecord] = []

    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

        # Extract CWE IDs
        cwe_ids: list[str] = []
        for weakness in cve_data.get("weaknesses", []):
            for wd in weakness.get("description", []):
                if wd.get("value", "").startswith("CWE-"):
                    cwe_ids.append(wd["value"])

        # Extract references (filter GitHub)
        refs: list[str] = []
        github_url: str | None = None
        patch_url: str | None = None
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            refs.append(url)
            if "github.com" in url:
                if "/commit/" in url or "/pull/" in url:
                    patch_url = url
                elif github_url is None:
                    github_url = url

        if has_source_code and not github_url and not patch_url:
            continue

        # Extract CVSS score
        cvss_score: float | None = None
        metrics = cve_data.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                break

        records.append(
            CVERecord(
                cve_id=cve_id,
                description=desc,
                cwe_ids=cwe_ids,
                cvss_score=cvss_score,
                references=refs,
                github_url=github_url or patch_url,
                patch_url=patch_url,
            )
        )

    log.info("fetched_cves", count=len(records), total=data.get("totalResults", 0))
    return records


def download_source_code(record: CVERecord, output_dir: Path) -> Path | None:
    """Download vulnerable source code from GitHub for a CVE.

    Args:
        record: CVE record with github_url.
        output_dir: Directory to save source code.

    Returns:
        Path to downloaded source, or None if unavailable.
    """
    if not record.patch_url:
        log.warning("no_patch_url", cve_id=record.cve_id)
        return None

    cve_dir = output_dir / record.cve_id
    cve_dir.mkdir(parents=True, exist_ok=True)

    # WHY: We download the patch (diff) rather than full repo to keep corpus manageable
    try:
        patch_resp = requests.get(record.patch_url + ".patch", timeout=30)
        patch_resp.raise_for_status()
        patch_file = cve_dir / "patch.diff"
        patch_file.write_text(patch_resp.text, encoding="utf-8")
        record.source_code_path = cve_dir
        log.info("downloaded_patch", cve_id=record.cve_id, path=str(cve_dir))
        return cve_dir
    except requests.RequestException:
        log.warning("download_failed", cve_id=record.cve_id, url=record.patch_url)
        return None
