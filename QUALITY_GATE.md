# ScannerGap Quality Gate

Run these commands before demo, release candidate review, or outreach package changes:

```bash
ruff check --no-cache src/ tests/ scripts/
ruff format --check --no-cache src/ tests/ scripts/
pytest -q --no-cov
python scripts/verify_manifest.py
python scripts/check_claims.py
```

## Local Project Smoke Test

Use this for your own repos or approved read-only pilot repos:

```bash
python scripts/scan_local_project.py /path/to/project --output results/local_projects/project-name
```

If the local Semgrep executable is broken or unavailable, use the Docker runner:

```bash
python scripts/scan_local_project.py /path/to/project --runner docker --output results/local_projects/project-name
```

The generated `summary.md` marks all findings as `REVIEW_CANDIDATE`. Treat them as prompts for manual review, not confirmed vulnerabilities.

## Optional Environment Checks

Semgrep rule validation should run in a clean environment or container:

```bash
semgrep scan --config src/scannergap/detector/rules/ --validate
```

In the current local Windows environment, Semgrep previously failed before validation because of a system X509 store error. Treat Semgrep validation as required for public release, but do not block manual POC packaging on this local machine issue.

## Release Blocking Conditions

- Unsupported benchmark claims in README, docs, or demo collateral.
- Manifest/corpus mismatch for the current checked-out corpus.
- Ruff, format, or tests failing.
- Production benchmark wording while reproducibility remains skipped.
- Any customer code, secrets, or private data committed to examples.
