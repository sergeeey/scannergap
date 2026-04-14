# ScannerGap

**Your code has vulnerabilities that no scanner sees. We measured how many.**

## The Problem

Most security teams rely on infrastructure scanners (Tenable/Nessus) to find vulnerabilities. But these tools scan **deployed systems** — ports, versions, configurations. They don't look at your **source code**.

Even teams that add static analysis (SAST) have a false sense of security. We tested 135 real CVEs against 3 leading static analyzers:

| Scanner | What it missed |
|---------|---------------|
| Semgrep (all rule packs) | 64% of CVEs |
| Bandit | ~90% of CVEs |
| CodeQL (104 security queries) | 76% of CVEs |
| **All 3 combined** | **61.5%** |

These aren't theoretical bugs. These are CVEs from the National Vulnerability Database — real vulnerabilities that were exploited in production.

## Where This Fits

```
                    What Tenable/Nessus covers
                    ─────────────────────────
Code → CI/CD → Deploy → [Nessus: ports, versions, configs] → Production
  ↑
  │  No coverage here.
  │  Logical bugs, injection flaws, SSRF, deserialization —
  │  invisible until exploited.
  │
  └── [ScannerGap: 26 rules that catch what SAST misses]
```

Tenable protects your infrastructure. ScannerGap protects your code.
They're complementary, not competing.

## What ScannerGap Does

1. **Benchmark**: Tests your SAST tools against 135 real CVEs and shows what they miss
2. **Detector**: 26 custom rules that catch vulnerability patterns standard scanners are blind to
3. **Taxonomy**: Classifies WHY scanners miss these bugs (not random — 13 systematic categories)

## Quick Start

```bash
pip install -e ".[dev]"

# Scan your codebase with blind spot detector (fully local, nothing sent externally)
semgrep scan --config src/scannergap/detector/rules/ /path/to/your/code

# Run full benchmark pipeline on CVE corpus
scannergap pipeline corpus/fullcode -o results/output
```

## The 4 Types of Blind Spots

| Type | What happens | Example |
|------|-------------|---------|
| **Cross-function taint** | Scanner tracks data in one function but loses it across calls | User input passes through 3 functions before hitting `send_file()` — each hop looks safe alone |
| **Semantic blindness** | Scanner sees code, not meaning | Security check exists in function A, but sibling function B has no check — scanner assumes both are safe |
| **Non-standard sinks** | Scanner knows `eval()` is dangerous but not `boto3(endpoint_url=...)` | SSRF via cloud SDK configuration parameter — not in any scanner's sink database |
| **Partial bypass** | Scanner sees the fix exists but not that it's missing on another path | SSRF protection on `/import` endpoint but not on `/roles` endpoint |

## What the Detector Catches

26 Semgrep rules across 5 languages:

| Language | Rules | Examples |
|----------|-------|---------|
| Python | 5 | boto3 SSRF, unsandboxed Jinja2, zipfile extractall, eval on file data |
| JavaScript | 4 | `new Function(tainted)`, child_process injection, fetch SSRF |
| Java | 4 | SnakeYAML unsafe load, URL decode-before-check, Velocity eval |
| PHP | 3 | Dynamic class instantiation, Twig raw injection, include from POST |
| Ruby | 2 | YAML.load on cookies, Marshal.load on untrusted data |

These rules close **30% of identified blind spots**. The remaining 70% require next-generation analysis capabilities (interprocedural taint tracking, semantic understanding) that no current SAST tool provides.

## Results at Scale

| Metric | Value |
|--------|-------|
| CVEs tested | 135 (NVD, 2023-2025) |
| Blind spot rate | **61.5%** |
| Systematic categories | 13 CWE clusters |
| Top clusters | Code injection (29), SSRF (25), Path traversal (24) |
| CodeQL verified | 0/104 queries found `new Function(tainted)` |
| Detector impact | +30% coverage over standard scanners |
| Reproducibility | 0 differences across runs |

## For Security Teams

**This week**: Run the 26 rules on your repos. It's free, local, takes 5 minutes.

```bash
semgrep scan --config src/scannergap/detector/rules/ /path/to/your/code
```

If findings appear — these are vulnerabilities your current pipeline marks as "clean".

**This month**: Add rules to CI alongside Tenable.
**This quarter**: Map which services have the most cross-function logic — those are highest risk.

## Project Structure

```
src/scannergap/
├── cli.py                  # CLI: scan, quadrant, benchmark, pipeline
├── corpus/                 # NVD API client for CVE collection
├── scanners/               # Semgrep + Bandit wrappers
├── quadrant/               # Coverage matrix + blind spot detection
├── benchmark/              # Falsification tests + report generator
├── detector/rules/         # 26 custom blind spot detection rules
└── taxonomy/               # Blind spot type classification

docs/
├── findings.md             # Full benchmark report
├── methodology.md          # How and why this works
└── scoring_rubric.md       # Strict HIT/PARTIAL/MISS definitions

demo/
├── slides.md               # 7-slide presentation
├── demo-script.md          # Step-by-step demo with talking points
└── one-pager.md            # Single page summary for sharing
```

## License

MIT
