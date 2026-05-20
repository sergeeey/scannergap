# ScannerGap Reproducibility Status

## Current Status

ScannerGap is currently reproducible as a research MVP and paid audit prototype. It is not yet a production benchmark.

## Reproducible Now

The current checked-out corpus is frozen in `benchmark_manifest.json`.

Run:

```bash
python scripts/verify_manifest.py
```

Expected result:

```text
PASS: manifest matches 131 CVE directories in corpus/fullcode
```

The current quality gate is:

```bash
ruff check --no-cache src/ tests/ scripts/
ruff format --check --no-cache src/ tests/ scripts/
pytest -q --no-cov
python scripts/verify_manifest.py
python scripts/check_claims.py
```

## Historical / Exploratory Artifacts

`results/full_135/benchmark_report_20260413.json` is a historical exploratory artifact. It reports 135 CVEs and Semgrep + Bandit scanner results, but the current checked-out corpus has 131 CVE directories.

Do not use that artifact as a production benchmark claim until its exact corpus manifest is restored.

`results/codeql_batch.json` and `results/codeql_gate.json` are exploratory CodeQL evidence. They are useful for research and demos, but they are not a full CodeQL production benchmark.

## Not Yet Production-Reproducible

The project does not yet have:

- a restored 135-CVE manifest matching the historical artifact;
- a full reproducibility run with `reproducibility: PASS`;
- scanner versions captured in every generated report;
- stable Semgrep validation in this local Windows environment;
- independent external review.

## Release Rule

Public claims must be scoped to the artifact that supports them.

Safe:

> The current checked-out corpus contains 131 CVE directories and can be verified with `benchmark_manifest.json`.

Unsafe:

> ScannerGap has a fully reproducible production benchmark showing a universal 61.5% scanner miss rate.
