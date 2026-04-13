# Active Context — BlindSpotSec

## Current Focus
Gold subset validated. Blind spot signal confirmed at 55% with strict matching.
Now: make claim defendable — reproducibility + targeted cluster expansion.

## Status
- [x] Project structure created
- [x] Core Python modules scaffolded
- [x] Kill criteria defined (pre-analysis)
- [x] Methodology + roadmap documented
- [x] NVD API client working (CWE + date range queries)
- [x] CVE corpus: 78 CVE in pilot, 31 with full code, 20 gold subset annotated
- [x] Scoring rubric: strict HIT/PARTIAL/MISS/NOISE matching
- [x] Gold evaluation: Baseline A 55% blind, Baseline B 65% blind
- [x] Kill criterion 1 PASS (rate 55% >= 15%)
- [x] Kill criterion 3 PASS (non-trivial 82% >= 50%)
- [ ] Kill criterion 2: systematic clusters (borderline — need more CVE per cluster)
- [ ] Kill criterion 4: reproducibility (not tested yet)
- [ ] CodeQL baseline (not added yet)

## Key Results (c8cca4b)
- 11/20 gold CVEs invisible to Semgrep + Bandit with strict matching
- PAT-detectable vulns: 50% found (eval, extractall, execSync)
- IPT/SEM-requiring vulns: 60-80% blind (cross-function taint, semantic context)
- CFG-requiring vulns: 100% blind (platform-specific, config-dependent)
- Blind spot clusters: CWE-22 (3), CWE-94 (2), CWE-918 (2), CWE-502 (2)

## Key Decisions
- New standalone project (not part of ARCHCODE or CCBM)
- Methodology transferred from ARCHCODE, not code
- Start with Semgrep + Bandit; CodeQL later
- Kill criteria committed BEFORE analysis
- Gold subset annotations committed BEFORE re-scanning
- PARTIAL does NOT count as detected (conservative)

## Next Steps
1. Reproducibility: re-run gold_evaluation.py from clean state
2. Targeted cluster expansion: add 3-5 CVE per borderline cluster
3. Decision gate: CodeQL on 5 blind CVEs — does it change the picture?

## Auto-commit log
- [2026-04-13 19:20] `c8cca4b`: feat: gold subset evaluation — 55% blind spot rate on 20 annotated CVEs
- [2026-04-13 17:39] `67255c4`: feat: initialize BlindSpotSec project — security blind spot meta-scanner
