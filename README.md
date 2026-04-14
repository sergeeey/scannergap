# ScannerGap

**Security Blind Spot Benchmark — what your SAST scanners don't see.**

ScannerGap is not a scanner. It's a benchmark that shows where static analysis tools systematically fail on real-world vulnerabilities.

## Key Finding

**56% of real CVEs are invisible to standard SAST scanners** (Semgrep + Bandit), even with maximum configuration. These blind spots cluster into 4 systematic categories and persist across scanner configurations.

| Metric | Value |
|--------|-------|
| Gold subset | 23 annotated CVEs (2023-2025) |
| Blind spot rate | 56% (Baseline A) |
| Systematic clusters | 4 (CWE-22, CWE-94, CWE-502, CWE-918) |
| Non-trivial | 82% require interprocedural/semantic analysis |
| CodeQL verified | 0/104 queries found `new Function(tainted)` |

## Quick Start

```bash
pip install -e ".[dev]"

# Run full pipeline on corpus
scannergap pipeline corpus/fullcode -o results/output

# Run with custom detector rules (catches 30% more blind spots)
semgrep scan --config src/scannergap/detector/rules/ corpus/fullcode/

# Expand corpus to 100+ CVEs
python scripts/expand_corpus.py

# Run gold subset evaluation with strict matching
python scripts/gold_evaluation.py
```

## How It Works

```
CVE Corpus (NVD)          Scanner Execution         Quadrant Analysis
┌─────────────┐          ┌──────────────┐          ┌──────────────┐
│ Fetch CVEs   │──────────│ Semgrep      │──────────│ Q1: Detected │
│ Download code│          │ Bandit       │          │ Q2: BLIND ◄──│── Our target
│ Annotate     │          │ (CodeQL)     │          │ Q3: FP       │
└─────────────┘          └──────────────┘          │ Q4: TN       │
                                                    └──────┬───────┘
                          Falsification                     │
                         ┌──────────────┐                   │
                         │ Kill criteria │◄──────────────────┘
                         │ Taxonomy     │
                         │ Benchmark    │
                         └──────────────┘
```

## Blind Spot Taxonomy

| Type | Detection Requires | Example |
|------|-------------------|---------|
| **Cross-function taint gaps** | Interprocedural taint | mlflow LFI: path crosses 3 function hops |
| **Semantic context blindness** | Business logic understanding | solara: guard exists in sibling function but not target |
| **Non-standard sink patterns** | Expanded sink database | boto3 `endpoint_url` as SSRF sink |
| **Partial mitigation bypass** | Cross-path analysis | Directus: SSRF filter on path A but not path B |

## Custom Detector Rules

17 Semgrep rules targeting patterns that standard scanners miss:

**Python**: boto3 SSRF, unsandboxed Jinja2, zipfile extractall, eval from file data
**JavaScript**: `new Function(tainted)`, child_process template injection, fetch SSRF
**Java**: SnakeYAML unsafe load, URL decode-before-check, Velocity eval
**PHP**: dynamic class instantiation, Twig raw injection, include from POST

```bash
# Run detector on any codebase
semgrep scan --config src/scannergap/detector/rules/ /path/to/code
```

## Project Structure

```
src/scannergap/
├── cli.py                  # CLI: scan, quadrant, benchmark, pipeline
├── corpus/nvd_client.py    # NVD API client
├── scanners/               # Semgrep + Bandit wrappers
├── quadrant/analysis.py    # Coverage matrix + blind spot detection
├── benchmark/              # Falsification tests + report generator
├── detector/rules/         # 17 custom blind spot detection rules
└── taxonomy/               # Blind spot type classification

corpus/
├── gold_subset.json        # 23 annotated CVEs (ground truth)
├── pilot_corpus.json       # 78 CVEs from NVD
└── fullcode/               # Vulnerable source files per CVE

docs/
├── findings.md             # Publishable benchmark report
├── methodology.md          # ARCHCODE transfer methodology
├── scoring_rubric.md       # HIT/PARTIAL/MISS/NOISE definitions
└── roadmap.md              # 30-day MVP plan

scripts/
├── gold_evaluation.py      # Strict matching evaluation
├── codeql_gate.py          # CodeQL decision gate
└── expand_corpus.py        # Scale corpus to 100+ CVEs
```

## Methodology

Transferred from [ARCHCODE](https://github.com/) genomic variant analysis — the same falsification-first framework that found 27 structural variants invisible to all DNA sequence predictors.

Core principle: don't build a better scanner. Find what ALL scanners miss.

## Kill Criteria (all passed)

| Criterion | Threshold | Result |
|-----------|-----------|--------|
| Blind spot rate | >= 15% | **56%** |
| Systematic clusters | >= 3 | **4** |
| Non-trivial | >= 50% | **82%** |
| Reproducibility | 0 diffs | **0/20** |

## License

MIT
