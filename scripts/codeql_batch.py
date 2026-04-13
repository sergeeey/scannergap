"""Batch CodeQL analysis on corpus CVEs.

Runs CodeQL security-extended queries on all CVEs where CodeQL
has language support (JavaScript, Java, Go, C/C++).
Python requires py launcher on Windows — skipped if unavailable.
"""

import json
import os
import subprocess
from pathlib import Path

import structlog

log = structlog.get_logger()

CODEQL = "C:/Users/serge/codeql-home/codeql/codeql.exe"
DB_DIR = Path("codeql-dbs")
RESULTS_DIR = Path("results/codeql")

# Language detection by file extension
LANG_MAP = {
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".h": "cpp",
}

# Query packs per language
QUERY_PACKS = {
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
    "go": "codeql/go-queries:codeql-suites/go-security-extended.qls",
    "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
}


def detect_language(cve_dir: Path) -> str | None:
    """Detect primary language from file extensions."""
    lang_counts: dict[str, int] = {}
    for f in cve_dir.iterdir():
        ext = f.suffix.lower()
        lang = LANG_MAP.get(ext)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    if not lang_counts:
        return None
    return max(lang_counts, key=lang_counts.get)


def ensure_query_pack(language: str) -> bool:
    """Download query pack if not already available."""
    pack_name = f"codeql/{language}-queries"
    try:
        result = subprocess.run(
            [CODEQL, "pack", "download", pack_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.returncode == 0
    except Exception:
        return False


def run_codeql_on_cve(cve_dir: Path, language: str) -> dict:
    """Create database and run security queries on a single CVE."""
    cve_id = cve_dir.name
    db_path = DB_DIR / cve_id
    sarif_path = RESULTS_DIR / f"{cve_id}.sarif"

    # Create database
    try:
        result = subprocess.run(
            [
                CODEQL,
                "database",
                "create",
                str(db_path),
                "--language",
                language,
                "--source-root",
                str(cve_dir),
                "--overwrite",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return {"cve_id": cve_id, "status": "db_failed", "error": result.stderr[-200:]}
    except subprocess.TimeoutExpired:
        return {"cve_id": cve_id, "status": "db_timeout"}

    # Run analysis
    query_pack = QUERY_PACKS.get(language)
    if not query_pack:
        return {"cve_id": cve_id, "status": "no_queries", "language": language}

    try:
        result = subprocess.run(
            [
                CODEQL,
                "database",
                "analyze",
                str(db_path),
                query_pack,
                "--format=sarifv2.1.0",
                f"--output={sarif_path}",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            return {"cve_id": cve_id, "status": "analyze_failed", "error": result.stderr[-200:]}
    except subprocess.TimeoutExpired:
        return {"cve_id": cve_id, "status": "analyze_timeout"}

    # Parse SARIF results
    try:
        with open(sarif_path, encoding="utf-8") as f:
            sarif = json.load(f)
        findings = sarif["runs"][0]["results"]
        return {
            "cve_id": cve_id,
            "status": "scanned",
            "language": language,
            "findings": len(findings),
            "rules": list({r.get("ruleId", "") for r in findings}),
        }
    except Exception:
        return {"cve_id": cve_id, "status": "parse_failed"}


def run_batch(corpus_dir: Path) -> list[dict]:
    """Run CodeQL on all supported CVEs in corpus."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    cve_dirs = sorted([d for d in corpus_dir.iterdir() if d.is_dir()])

    # Ensure query packs
    for lang in QUERY_PACKS:
        ensure_query_pack(lang)

    for cve_dir in cve_dirs:
        lang = detect_language(cve_dir)
        if not lang:
            continue
        if lang not in QUERY_PACKS:
            continue

        log.info("codeql_scanning", cve=cve_dir.name, language=lang)
        result = run_codeql_on_cve(cve_dir, lang)
        results.append(result)
        log.info("codeql_result", **result)

    return results


if __name__ == "__main__":
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )

    corpus = Path("corpus/fullcode")
    results = run_batch(corpus)

    scanned = [r for r in results if r["status"] == "scanned"]
    found = [r for r in scanned if r["findings"] > 0]
    blind = [r for r in scanned if r["findings"] == 0]

    print(f"\n=== CodeQL Batch Results ===")
    print(f"Scanned: {len(scanned)}, Found: {len(found)}, Blind: {len(blind)}")
    if scanned:
        print(f"Blind rate: {len(blind)*100//len(scanned)}%")

    with open("results/codeql_batch.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "results": results,
                "summary": {
                    "scanned": len(scanned),
                    "found": len(found),
                    "blind": len(blind),
                },
            },
            f,
            indent=2,
        )
    print("Saved to results/codeql_batch.json")
