# Changelog

All notable changes to ScannerGap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-20

### Added
- МФО pilot preparation package with comprehensive documentation
  - PROJECT_CONTEXT_AUDIT.md: full codebase audit for AI handoff (12 sections)
  - demo/mfo-discovery-checklist.md: 10 critical questions before pilot launch
  - demo/mfo-pilot-plan.md: 7-day pilot plan with security protocols
- Verification scripts for reproducibility and claims checking
  - scripts/verify_manifest.py: manifest validation against corpus
  - scripts/check_claims.py: public claims verification gate
  - scripts/scan_local_project.py: local project scanner for demos
  - scripts/build_manifest.py: manifest generation from corpus
- Demo and outreach materials (10 new documents)
  - Sample reports, POC offers, discovery scripts
  - CISO demo, public repo sample report
  - First 10 outreach plan, intake questionnaire
- Release infrastructure
  - BENCHMARK_EVIDENCE.md: trust boundary for public claims
  - QUALITY_GATE.md: pre-release verification commands
  - RELEASE_CHECKLIST.md: blocking conditions
  - benchmark_manifest.json: frozen 131-CVE corpus manifest
- Documentation improvements
  - docs/reproducibility.md: reproducibility protocol
  - Updated README with evidence status

### Changed
- Updated detector rules and tests (49 rules total)
- Refined activeContext.md with MVP completion status

### Fixed
- None

## [0.1.0] - 2026-04-14

### Added
- Initial release: benchmark-backed blind-spot audit prototype
- 131 CVE corpus with 23 gold subset annotated
- 49 Semgrep detector rules covering 9 CWE categories
- Quadrant analysis engine (scanner coverage matrix)
- Falsification framework (4 kill criteria)
- CLI pipeline: scan → quadrant → benchmark
- Gold evaluation: 56% blind spot rate confirmed
- CodeQL exploratory integration
