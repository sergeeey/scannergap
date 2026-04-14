# Active Context — ScannerGap

## Current Focus
MVP complete. Benchmark validated, documented, CLI working end-to-end. All merged to master.

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
- [2026-04-13 23:11] merge: findings document, CodeQL verification, CLI pipeline
- [2026-04-13 19:56] `59db94d`: CodeQL decision gate STRONG
- [2026-04-13 19:47] `1350706`: all 4 kill criteria passed — 56% on 23 CVEs
- [2026-04-13 19:20] `c8cca4b`: gold subset evaluation — 55% on 20 CVEs
- [2026-04-13 17:39] `67255c4`: initialize ScannerGap project
