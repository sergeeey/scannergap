<p align="center">
  <img src="docs/assets/logo.svg" alt="ScannerGap" width="120" />
</p>

<h1 align="center">ScannerGap</h1>

<p align="center">
  <strong>Security Blind Spot Benchmark</strong><br>
  <em>What your SAST scanners don't see. We measured it.</em>
</p>

<p align="center">
  <a href="#key-results"><img src="https://img.shields.io/badge/blind_spot_rate-61.5%25-red?style=for-the-badge" alt="Blind Spot Rate" /></a>
  <a href="#results-at-scale"><img src="https://img.shields.io/badge/artifact-135_CVE_exploratory-blue?style=for-the-badge" alt="Exploratory CVE Artifact" /></a>
  <a href="#what-the-detector-catches"><img src="https://img.shields.io/badge/detector_rules-49-green?style=for-the-badge" alt="Detector Rules" /></a>
  <a href="#evidence-status"><img src="https://img.shields.io/badge/status-research_MVP-orange?style=for-the-badge" alt="Research MVP" /></a>
</p>

<p align="center">
  <a href="docs/findings.md">Full Report</a> |
  <a href="BENCHMARK_EVIDENCE.md">Evidence Status</a> |
  <a href="demo/one-pager.md">One-Pager</a> |
  <a href="demo/slides.md">Slides</a> |
  <a href="#quick-start">Quick Start</a>
</p>

---

## The Problem

Most security teams rely on infrastructure scanners (Tenable / Nessus) to find vulnerabilities. These tools scan **deployed systems** --- ports, package versions, configurations. They don't look at **source code**.

Even teams that add static analysis (SAST) have a false sense of security:

```
                        What Tenable/Nessus covers
                        ──────────────────────────
  Code --> CI/CD --> Deploy --> [ Nessus: ports, versions, configs ] --> Production
    |
    |   No automated coverage here.
    |   Injection flaws, SSRF, unsafe deserialization ---
    |   invisible until exploited.
    |
    +-- [ ScannerGap: benchmark method + prototype rules for blind-spot review ]
```

## Key Results

The current evidence base has two layers:

- **Gold subset**: 23 annotated real CVEs evaluated with strict HIT/PARTIAL/MISS scoring against Semgrep and Bandit.
- **Exploratory scale artifact**: a 135-CVE Semgrep + Bandit run in `results/full_135/`.

The 135-CVE artifact is useful research evidence, but it is **not yet a production benchmark claim**: the checked-out corpus currently contains 131 CVE directories, the 135-CVE manifest needs to be frozen, and reproducibility is marked `SKIPPED` in that generated report.

```
Scanner Coverage vs. 135-CVE Exploratory Artifact
=================================================

Semgrep          ████████████░░░░░░░░  36% found
Bandit           ██░░░░░░░░░░░░░░░░░░  10% found
Combined         ████████░░░░░░░░░░░░  38.5% found

                 ░░░░░░░░░░░░ = BLIND (61.5%)
```

> **61.5% of CVEs in the exploratory Semgrep + Bandit artifact were missed by both baseline scanners.**

These aren't theoretical bugs. These are CVEs from the National Vulnerability Database --- exploited in production.

CodeQL evidence exists as a separate exploratory subset/gate (`results/codeql_batch.json`, `results/codeql_gate.json`), not as part of the 135-CVE headline benchmark.

## The 4 Types of Blind Spots

```
+---------------------------+---------------------------+
|                           |                           |
|  Type I: Taint Gaps       |  Type II: Semantic        |
|  ~~~~~~~~~~~~~~~~~~~~~~   |  ~~~~~~~~~~~~~~~~~~~~~~   |
|  Scanner tracks data in   |  Security check exists    |
|  one function but loses   |  in function A, but       |
|  it across calls.         |  function B has none.     |
|                           |  Scanner assumes safe.    |
|  60-80% blind             |  56-78% blind             |
|                           |                           |
+---------------------------+---------------------------+
|                           |                           |
|  Type III: Unknown Sinks  |  Type IV: Partial Bypass  |
|  ~~~~~~~~~~~~~~~~~~~~~~   |  ~~~~~~~~~~~~~~~~~~~~~~   |
|  Scanner flags eval()     |  SSRF filter exists on    |
|  but not boto3(endpoint=) |  /import endpoint but     |
|  or new Function().       |  not on /roles endpoint.  |
|                           |                           |
|  100% blind               |  Case-dependent           |
|                           |                           |
+---------------------------+---------------------------+
```

## Quick Start

```bash
pip install -e ".[dev]"

# Scan your codebase with blind spot detector
# Fully local --- nothing sent externally
semgrep scan --config src/scannergap/detector/rules/ /path/to/your/code

# Or generate a local REVIEW_CANDIDATE summary
python scripts/scan_local_project.py /path/to/your/code --output results/local_projects/example

# If local Semgrep is unavailable, run the same workflow through Docker
python scripts/scan_local_project.py /path/to/your/code --runner docker --output results/local_projects/example

# Run full benchmark pipeline
scannergap pipeline corpus/fullcode -o results/output
```

## What the Detector Catches

49 Semgrep rule IDs across 8 rule files:

```
Python -----+-- boto3 SSRF (endpoint_url)
            +-- Unsandboxed Jinja2 SSTI
            +-- zipfile.extractall (no member check)
            +-- eval() on file-derived data
            +-- requests with f-string URL

JavaScript -+-- new Function(tainted)  * CodeQL also misses this
            +-- child_process template injection
            +-- fetch/axios SSRF via template literal
            +-- innerHTML before sanitize

Java -------+-- SnakeYAML unsafe load (no SafeConstructor)
            +-- URLDecoder.decode before security check
            +-- Velocity template eval on user content
            +-- FreeMarker template from string

PHP --------+-- Dynamic class instantiation from $_REQUEST
            +-- Twig raw() with unsanitized variable
            +-- include/require from $_POST

Ruby -------+-- YAML.load on cookies/params
            +-- Marshal.load on untrusted data
```

Impact is currently a research/prototype claim. Validate findings against your own codebase before treating them as production coverage.

## Results at Scale

```
Metric                    Value
========================  ================
CVEs in exploratory artifact 135 (NVD, 2023-2025)
Checked-out CVE dirs         131 (current repo state)
Blind spot rate              61.5% (Semgrep + Bandit artifact)
Systematic categories     13 CWE clusters
#1 Code injection         29 blind CVEs
#2 SSRF                   25 blind CVEs
#3 Path traversal         24 blind CVEs
#4 Unrestricted upload    17 blind CVEs
#5 XSS                    11 blind CVEs
CodeQL evidence           Separate exploratory subset/gate
Detector impact           Prototype; validate per target
Reproducibility           SKIPPED in full_135 generated report
```

## Evidence Status

Pre-registered criteria exist, but the current public evidence should be read conservatively:

```
 #   Criterion               Threshold    Result      Status
---  ----------------------  -----------  ----------  --------
 1   Blind spot rate         >= 15%       61.5%       PASS
 2   Systematic clusters     >= 3         13          PASS
 3   Non-trivial             >= 50%       see notes    NEEDS MANUAL EVIDENCE
 4   Reproducibility         0 diffs      skipped     NOT PRODUCTION-READY
```

See `BENCHMARK_EVIDENCE.md` for the current trust boundary and release blockers.

Release checks:

```bash
ruff check --no-cache src/ tests/ scripts/
ruff format --check --no-cache src/ tests/ scripts/
pytest -q --no-cov
python scripts/verify_manifest.py
python scripts/check_claims.py
```

## For Security Teams

**This week** --- 5 minutes, zero risk:
```bash
semgrep scan --config src/scannergap/detector/rules/ /path/to/your/code
```
If findings appear --- these are vulnerabilities your pipeline currently marks "clean."

**This month** --- add rules to CI alongside Tenable.

**This quarter** --- map which services have the most cross-function logic. Those are highest risk.

## Project Structure

```
src/scannergap/
  cli.py                  CLI: scan, quadrant, benchmark, pipeline
  corpus/                 NVD API client for CVE collection
  scanners/               Semgrep + Bandit wrappers
  quadrant/               Coverage matrix + blind spot detection
  benchmark/              Falsification tests + report generator
  detector/rules/         custom blind spot detection rule files
  taxonomy/               Blind spot type classification

docs/
  findings.md             Full benchmark report
  methodology.md          How and why this works
  reproducibility.md      What can be reproduced today
  scoring_rubric.md       Strict HIT/PARTIAL/MISS definitions

demo/
  slides.md               7-slide presentation
  demo-script.md          Step-by-step demo with talking points
  one-pager.md            Single page summary for sharing
  ciso-demo.md            Safe CISO demo framing
  poc-offer.md            Scoped paid POC offer
  sample-report.md        Redacted report template
```

## Methodology

Transferred from ARCHCODE genomic variant analysis --- the same falsification-first
framework that found 27 structural DNA variants invisible to all sequence predictors.

Core principle: **don't build another scanner. Map where a selected scanner baseline stops seeing.**

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and guidelines.

## License

Apache 2.0
