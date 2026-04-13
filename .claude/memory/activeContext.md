# Active Context — BlindSpotSec

## Current Focus
Project initialization. Setting up BlindSpotSec — a meta-scanner for finding
blind spots in code security scanners (CodeQL, Semgrep, Snyk, Bandit).

## Status
- [x] Project structure created
- [x] Core Python modules scaffolded
- [x] Kill criteria defined (pre-analysis)
- [x] Methodology documented
- [x] 30-day roadmap created
- [ ] NVD API client tested
- [ ] First CVE corpus collected
- [ ] First scanner run completed

## Key Decisions
- New standalone project (not part of ARCHCODE or CCBM)
- Methodology transferred from ARCHCODE, not code
- Start with Semgrep + Bandit (free, easy to install)
- CodeQL + Snyk added later (require setup)
- Kill criteria committed before any analysis

## Architecture
Python 3.11+, Click CLI, structlog, pandas for analysis.
Pipeline: Ingest -> Scan -> Quadrant -> Taxonomy -> Falsify -> Benchmark

## Next Step
Week 1: Set up NVD API client and collect first 100 CVEs.
