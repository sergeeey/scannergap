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
  <a href="#results-at-scale"><img src="https://img.shields.io/badge/CVEs_tested-135-blue?style=for-the-badge" alt="CVEs Tested" /></a>
  <a href="#what-the-detector-catches"><img src="https://img.shields.io/badge/detector_rules-26-green?style=for-the-badge" alt="Detector Rules" /></a>
  <a href="#kill-criteria"><img src="https://img.shields.io/badge/kill_criteria-4%2F4_PASS-brightgreen?style=for-the-badge" alt="Kill Criteria" /></a>
</p>

<p align="center">
  <a href="docs/findings.md">Full Report</a> |
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
    +-- [ ScannerGap: 26 rules that catch what SAST misses ]
```

## Key Results

We tested **135 real CVEs** (NVD, 2023--2025) against 3 leading static analyzers:

```
Scanner Coverage vs. Real CVEs
==============================

Semgrep          ████████████░░░░░░░░  36% found
Bandit           ██░░░░░░░░░░░░░░░░░░  10% found
CodeQL           █████░░░░░░░░░░░░░░░  24% found
All 3 combined   ████████░░░░░░░░░░░░  38.5% found

                 ░░░░░░░░░░░░ = BLIND (61.5%)
```

> **61.5% of real-world CVEs are invisible to all 3 scanners combined.**

These aren't theoretical bugs. These are CVEs from the National Vulnerability Database --- exploited in production.

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

# Run full benchmark pipeline
scannergap pipeline corpus/fullcode -o results/output
```

## What the Detector Catches

26 Semgrep rules across 5 languages:

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

Impact: closes **30%** of identified blind spots with zero configuration.

## Results at Scale

```
Metric                    Value
========================  ================
CVEs tested               135 (NVD, 2023-2025)
Blind spot rate           61.5%
Systematic categories     13 CWE clusters
#1 Code injection         29 blind CVEs
#2 SSRF                   25 blind CVEs
#3 Path traversal         24 blind CVEs
#4 Unrestricted upload    17 blind CVEs
#5 XSS                    11 blind CVEs
CodeQL verified           0/104 queries found new Function(tainted)
Detector impact           +30% coverage
Reproducibility           0 differences across runs
```

## Kill Criteria

Pre-registered before analysis. All passed:

```
 #   Criterion               Threshold    Result      Status
---  ----------------------  -----------  ----------  --------
 1   Blind spot rate         >= 15%       61.5%       PASS
 2   Systematic clusters     >= 3         13          PASS
 3   Non-trivial             >= 50%       82%         PASS
 4   Reproducibility         0 diffs      0/20        PASS
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
  detector/rules/         26 custom blind spot detection rules
  taxonomy/               Blind spot type classification

docs/
  findings.md             Full benchmark report
  methodology.md          How and why this works
  scoring_rubric.md       Strict HIT/PARTIAL/MISS definitions

demo/
  slides.md               7-slide presentation
  demo-script.md          Step-by-step demo with talking points
  one-pager.md            Single page summary for sharing
```

## Methodology

Transferred from ARCHCODE genomic variant analysis --- the same falsification-first
framework that found 27 structural DNA variants invisible to all sequence predictors.

Core principle: **don't build a better scanner. Find what ALL scanners miss.**

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and guidelines.

## License

Apache 2.0
