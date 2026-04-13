"""Corpus expansion script.

Automates: NVD fetch → filter by GitHub patches → download full files → enrich metadata.
Target: scale from 30 to 100+ CVEs while maintaining annotation quality.
"""

import json
import os
import re
import time
from pathlib import Path

import requests
import structlog

log = structlog.get_logger()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_SECONDS = 7  # NVD allows ~5 requests per 30s without API key

# Priority CWE targets (from blind spot clusters)
CWE_TARGETS = [
    "CWE-22",  # Path traversal
    "CWE-78",  # OS command injection
    "CWE-79",  # XSS
    "CWE-89",  # SQL injection
    "CWE-94",  # Code injection
    "CWE-502",  # Deserialization
    "CWE-918",  # SSRF
    "CWE-434",  # Unrestricted upload
    "CWE-287",  # Authentication
    "CWE-862",  # Missing authorization
]

# 120-day date windows (NVD API limit)
DATE_WINDOWS = [
    ("2023-06-01T00:00:00.000", "2023-09-28T00:00:00.000"),
    ("2023-10-01T00:00:00.000", "2024-01-28T00:00:00.000"),
    ("2024-02-01T00:00:00.000", "2024-05-31T00:00:00.000"),
    ("2024-06-01T00:00:00.000", "2024-09-28T00:00:00.000"),
    ("2024-10-01T00:00:00.000", "2025-01-28T00:00:00.000"),
]


def fetch_cves_for_window(cwe_id: str, start: str, end: str, existing_ids: set[str]) -> list[dict]:
    """Fetch CVEs for a CWE + date window, filtering to those with GitHub patches."""
    time.sleep(RATE_LIMIT_SECONDS)
    try:
        resp = requests.get(
            NVD_API,
            params={
                "cweId": cwe_id,
                "pubStartDate": start,
                "pubEndDate": end,
                "resultsPerPage": 50,
            },
            timeout=30,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception:
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        if cve_id in existing_ids:
            continue

        refs = [r["url"] for r in cve.get("references", []) if "github.com" in r["url"]]
        patches = [u for u in refs if "/commit/" in u]
        if not patches:
            continue

        cwes = [
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        ]
        cvss = None
        for v in ["cvssMetricV31", "cvssMetricV30"]:
            if v in cve.get("metrics", {}):
                cvss = cve["metrics"][v][0]["cvssData"]["baseScore"]
                break

        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")

        results.append(
            {
                "cve_id": cve_id,
                "cwe_ids": cwes,
                "cvss_score": cvss,
                "description": desc[:200],
                "patch_url": patches[0],
                "github_refs": refs[:3],
            }
        )

    return results


def download_full_files(cve: dict, fullcode_dir: Path) -> int:
    """Download vulnerable (pre-fix) files from GitHub."""
    patch_url = cve["patch_url"]
    match = re.match(r"https://github.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)", patch_url)
    if not match:
        return 0

    owner, repo, sha = match.groups()
    cve_dir = fullcode_dir / cve["cve_id"]
    cve_dir.mkdir(parents=True, exist_ok=True)

    # Get patch to find changed files
    time.sleep(1)
    try:
        pr = requests.get(patch_url + ".patch", timeout=15, allow_redirects=True)
        if pr.status_code != 200:
            return 0
    except Exception:
        return 0

    changed = re.findall(r"diff --git a/(.+?) b/", pr.text)
    if not changed:
        return 0

    file_count = 0
    for filepath in changed[:5]:
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}~1/{filepath}"
        time.sleep(0.5)
        try:
            r = requests.get(raw_url, timeout=15)
            if r.status_code == 200 and len(r.text) > 20:
                safe = filepath.replace("/", "__")
                if len(safe) > 100:
                    ext = os.path.splitext(filepath)[1] or ".txt"
                    safe = safe[:90] + ext
                (cve_dir / safe).write_text(r.text, encoding="utf-8", errors="replace")
                file_count += 1
        except Exception:
            pass

    # Write metadata
    if file_count > 0:
        meta = {
            "cve_id": cve["cve_id"],
            "cwe_ids": cve.get("cwe_ids", []),
            "cvss_score": cve.get("cvss_score"),
            "description": cve.get("description", ""),
            "patch_url": cve.get("patch_url", ""),
        }
        (cve_dir / "metadata.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    return file_count


def expand_corpus(
    corpus_file: Path,
    fullcode_dir: Path,
    target_total: int = 100,
) -> None:
    """Expand corpus to target_total CVEs."""
    # Load existing
    existing_ids: set[str] = set()
    if corpus_file.exists():
        with open(corpus_file, encoding="utf-8") as f:
            data = json.load(f)
        existing_ids = {c["cve_id"] for c in data.get("cves", [])}
        all_cves = data.get("cves", [])
    else:
        all_cves = []

    # Also check fullcode dirs
    if fullcode_dir.exists():
        for d in fullcode_dir.iterdir():
            if d.is_dir() and d.name.startswith("CVE-"):
                existing_ids.add(d.name)

    current = len(existing_ids)
    needed = target_total - current
    log.info("expansion_start", current=current, target=target_total, needed=needed)

    if needed <= 0:
        log.info("already_at_target")
        return

    new_cves: list[dict] = []

    for start, end in DATE_WINDOWS:
        if len(new_cves) >= needed:
            break
        for cwe in CWE_TARGETS:
            if len(new_cves) >= needed:
                break
            batch = fetch_cves_for_window(cwe, start, end, existing_ids)
            for cve in batch:
                if cve["cve_id"] in existing_ids:
                    continue
                files = download_full_files(cve, fullcode_dir)
                if files > 0:
                    new_cves.append(cve)
                    existing_ids.add(cve["cve_id"])
                    log.info(
                        "added",
                        cve_id=cve["cve_id"],
                        cwe=cve["cwe_ids"][:2],
                        files=files,
                        total=current + len(new_cves),
                    )
                if len(new_cves) >= needed:
                    break

    # Save updated corpus
    all_cves.extend(new_cves)
    with open(corpus_file, "w", encoding="utf-8") as f:
        json.dump({"total": len(all_cves), "cves": all_cves}, f, indent=2, ensure_ascii=False)

    log.info(
        "expansion_complete",
        added=len(new_cves),
        total=len(all_cves),
        target=target_total,
    )


if __name__ == "__main__":
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )

    expand_corpus(
        corpus_file=Path("corpus/pilot_corpus.json"),
        fullcode_dir=Path("corpus/fullcode"),
        target_total=100,
    )
