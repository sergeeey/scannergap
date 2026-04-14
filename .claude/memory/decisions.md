# Architectural Decisions — ScannerGap

## ADR-001: Standalone Project
**Date:** 2026-04-13
**Decision:** ScannerGap is a standalone project, not an extension of ARCHCODE or CCBM.
**Why:** Different domain (code security vs genomics), different customers, different publication venue.
Mixing them would dilute both. ARCHCODE methodology transfers conceptually, not as code.

## ADR-002: Methodology-First, Not Tool-First
**Date:** 2026-04-13
**Decision:** Start with quadrant analysis methodology, not with building a scanner.
**Why:** The value is in identifying blind spots (Q2), not in building "yet another scanner."
The benchmark itself is the product — the detector is Phase 2.

## ADR-003: Start with Free Scanners
**Date:** 2026-04-13
**Decision:** MVP uses Semgrep + Bandit. CodeQL and Snyk added in Week 2-3.
**Why:** Semgrep and Bandit are free, open-source, easy to install, no auth tokens needed.
CodeQL requires database creation per project. Snyk requires auth. Don't block MVP on setup.

## ADR-004: Kill Criteria Before Analysis
**Date:** 2026-04-13
**Decision:** Kill criteria committed to git BEFORE any scan results.
**Why:** From ARCHCODE lesson — prevents post-hoc rationalization.
If blind_spot_rate <5%, project dies. No "but we can lower the threshold" excuses.

## ADR-005: CVE-Based Corpus (Not Synthetic)
**Date:** 2026-04-13
**Decision:** Use real CVEs from NVD, not synthetic vulnerable code.
**Why:** Synthetic code tests scanner rules, not scanner blind spots.
Real CVEs represent actual vulnerabilities that existed in production.
Synthetic corpus added later for controlled experiments (labeled SYNTHETIC_).
