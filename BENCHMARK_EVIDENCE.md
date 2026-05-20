# ScannerGap Benchmark Evidence Status

This document is the trust boundary for the current repository state.

## Current Verdict

ScannerGap is a research MVP and founder-led blind-spot audit prototype. It is suitable for scoped demos and manual paid POCs with disclaimers. It is not yet a production benchmark or SaaS/API product.

## Verified Artifacts

| Artifact | Status | Notes |
|---|---|---|
| `benchmark_manifest.json` | Verified present | Frozen manifest for the current checked-out 131-CVE corpus. |
| `corpus/gold_subset.json` | Verified present | 23 annotated CVEs for strict HIT/PARTIAL/MISS review. |
| `results/gold_evaluation.json` | Verified present | Gold subset evaluation artifact. |
| `results/full_135/benchmark_report_20260413.json` | Verified present | Exploratory 135-CVE Semgrep + Bandit report. |
| `results/codeql_batch.json` | Verified present | Exploratory CodeQL subset; includes database failures. |
| `results/codeql_gate.json` | Verified present | Small gate artifact, not full benchmark coverage. |
| `src/scannergap/detector/rules/` | Verified present | 49 Semgrep rule IDs counted by `rg "^  - id:"`. |

## Current Mismatches

| Topic | Current Evidence | Release Impact |
|---|---|---|
| Corpus size | `results/full_135` says 135 CVEs; checked-out `corpus/fullcode` has 131 directories. | Do not claim fully reproducible 135-CVE benchmark until a frozen manifest exists. |
| Scanner count | 135-CVE report lists `semgrep` and `bandit` only. | Do not claim "missed by all three scanners" for the headline result. |
| CodeQL | Separate exploratory artifacts exist; some CodeQL DB creation failed. | Present CodeQL as exploratory evidence only. |
| Reproducibility | Full 135 report marks reproducibility `SKIPPED`. | Do not claim 4/4 production kill-criteria pass. |
| Non-triviality | CLI passes `trivial_count=0` in the benchmark path. | Do not present non-triviality as independently verified without annotation evidence. |

## Safe Public Wording

Use:

> ScannerGap is a benchmark-backed blind-spot audit prototype for finding classes of vulnerabilities that baseline SAST pipelines may miss.

Avoid:

> Unsupported wording that presents ScannerGap as a production substitute for existing scanners.
> Unsupported wording that says 61.5% was missed by Semgrep, Bandit, and CodeQL together.
> Unsupported wording that says all four kill criteria passed for the production benchmark.

## Minimum Release Gate

- `ruff check --no-cache src/ tests/ scripts/`
- `ruff format --check --no-cache src/ tests/ scripts/`
- `pytest -q --no-cov`
- `python scripts/verify_manifest.py`
- `python scripts/check_claims.py`
- Semgrep rule validation in a clean environment or documented container runner.
- Frozen corpus manifest for any headline CVE count.

## Related Docs

- `docs/reproducibility.md`
- `QUALITY_GATE.md`
- `RELEASE_CHECKLIST.md`
- `demo/ciso-demo.md`
- `demo/poc-offer.md`
- `demo/sample-report.md`
