# Active Context — ScannerGap

## Current Focus
MVP complete + release infrastructure added (2026-05-20).
- Release gates: BENCHMARK_EVIDENCE.md, QUALITY_GATE.md, RELEASE_CHECKLIST.md
- Demo materials: 10 new outreach/POC documents
- Verification scripts: build_manifest, check_claims, verify_manifest, scan_local_project
- Documentation: reproducibility guide, updated README with evidence status

Ready for manual POC demos. Production release blocked on reproducibility gate.

## Status
- [x] Project structure + core modules
- [x] CVE corpus: 78 pilot, 31 full code, 23 gold subset annotated
- [x] Scoring rubric + strict matching
- [x] Gold evaluation: 56% blind spot rate
- [x] All 4 kill criteria PASSED
- [x] CodeQL gate: STRONG (4/5 persist, real CodeQL CLI 0/104 on JS CVE)
- [x] Findings document: docs/findings.md
- [x] CLI pipeline: `scannergap pipeline corpus/fullcode` (~5 min)
- [x] All merged to master

## Key Decisions
- Standalone project, methodology from ARCHCODE not code
- PARTIAL does NOT count as detected (conservative)
- Kill criteria committed BEFORE analysis
- Claim: "SAST class blind spots" (not just Bandit+Semgrep)

## Next Steps (Post-MVP)
1. Scale corpus to 100+ CVEs
2. Build detector for top blind spot categories
3. Public benchmark release (GitHub)
4. Blog post / conference submission
5. Wire CWE metadata into pipeline

## Auto-commit log
- [2026-05-20 current] `0e5bdc6`: refactor: update version, detector rules, and tests
- [2026-05-20 current] `3a7fe0f`: docs: update project documentation and reproducibility guide
- [2026-05-20 current] `8d5771d`: feat: add verification scripts and local project scanner
- [2026-05-20 current] `1ede21b`: feat: add comprehensive demo and outreach materials
- [2026-05-20 current] `9bdedc8`: feat: add release infrastructure and evidence tracking
- [2026-04-14 12:26] `c74694e`: merge: 41 tests + 37 rules
- [2026-04-14 12:06] `934dfbf`: merge: Apache 2.0 license
- [2026-04-14 11:39] `545ce95`: merge: visual polish
- [2026-04-14 11:04] `383d9d5`: merge: Tenable-adapted README and slides
- [2026-04-14 09:25] `ffbe997`: merge: rename BlindSpotSec -> ScannerGap
- [2026-04-14 00:52] `e907c58`: merge: demo materials for internal presentation
- [2026-04-14 00:31] `9402fcb`: merge: CodeQL batch — 76% blind confirms SAST class limitation
- [2026-04-14 00:27] `88220d9`: merge: 135 CVE corpus — 61.5% blind spot rate confirmed at scale
- [2026-04-13 23:53] `4943a70`: feat: detector v0.2 — 26 rules, XSS + SSTI, CodeQL batch script
- [2026-04-13 23:38] `23edab4`: feat: README, LICENSE, CI workflow, Ruby rules, expanded corpus
- [2026-04-13 23:31] `e7c708d`: feat: blind spot detector v0.1 + corpus expansion script
