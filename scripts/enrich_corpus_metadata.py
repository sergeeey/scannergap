"""Enrich corpus CVEs with metadata from NVD API.

Fetches CWE IDs, CVSS scores, and descriptions for each CVE in corpus.
Saves metadata.json per CVE directory.
"""

import json
import time
from pathlib import Path

import requests
import structlog

log = structlog.get_logger()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve_metadata(cve_id: str) -> dict:
    """Fetch metadata for a single CVE from NVD."""
    try:
        resp = requests.get(NVD_API, params={"cveId": cve_id}, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"cve_id": cve_id, "error": "not_found"}

        cve_data = vulns[0].get("cve", {})

        # Description
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

        # CWE IDs
        cwe_ids = []
        for weakness in cve_data.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # CVSS
        cvss_score = None
        metrics = cve_data.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss_score = metrics[version][0].get("cvssData", {}).get("baseScore")
                break

        return {
            "cve_id": cve_id,
            "description": desc[:500],
            "cwe_ids": cwe_ids if cwe_ids else ["CWE-UNKNOWN"],
            "cvss_score": cvss_score,
        }

    except Exception as e:
        log.warning("nvd_fetch_failed", cve_id=cve_id, error=str(e))
        return {"cve_id": cve_id, "cwe_ids": ["CWE-UNKNOWN"], "error": str(e)}


def enrich_corpus(corpus_dir: Path) -> int:
    """Enrich all CVE dirs in corpus with NVD metadata."""
    cve_dirs = sorted([d for d in corpus_dir.iterdir() if d.is_dir()])
    enriched = 0

    for i, cve_dir in enumerate(cve_dirs):
        meta_file = cve_dir / "metadata.json"

        # Skip if already enriched
        if meta_file.exists():
            existing = json.loads(meta_file.read_text(encoding="utf-8"))
            if existing.get("cwe_ids") and existing["cwe_ids"] != ["CWE-UNKNOWN"]:
                log.info("already_enriched", cve=cve_dir.name)
                enriched += 1
                continue

        meta = fetch_cve_metadata(cve_dir.name)
        meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        status = "ok" if meta.get("cwe_ids", ["CWE-UNKNOWN"]) != ["CWE-UNKNOWN"] else "no_cwe"
        log.info("enriched", cve=cve_dir.name, cwe=meta.get("cwe_ids"), status=status)

        if meta.get("cwe_ids") and meta["cwe_ids"] != ["CWE-UNKNOWN"]:
            enriched += 1

        # NVD rate limit: 5 requests per 30 seconds without API key
        if (i + 1) % 5 == 0:
            log.info("rate_limit_pause", completed=i + 1, total=len(cve_dirs))
            time.sleep(6)

    log.info("enrichment_complete", enriched=enriched, total=len(cve_dirs))
    return enriched


if __name__ == "__main__":
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )
    corpus = Path("corpus/code")
    count = enrich_corpus(corpus)
    print(f"\nEnriched {count}/{len(list(corpus.iterdir()))} CVEs with CWE metadata")
