# Kill Criteria — ScannerGap
**Created:** 2026-04-13
**Status:** PRE-ANALYSIS (commit BEFORE running any scans)

## Philosophy
From ARCHCODE: define falsification gates BEFORE sunk cost bias kicks in.
If any kill criterion triggers, pivot or terminate. No exceptions.

---

## Criterion 1: Blind Spot Existence
**If:** All scanners combined cover >95% of CVEs in corpus
**By:** Week 2
**Then:** Blind spots are too rare to build a product around. KILL.
**Measurement:** `blind_spot_rate = Q2 / (Q1 + Q2)` from quadrant analysis

## Criterion 2: Blind Spot Systematicity
**If:** Blind spot CVEs do NOT cluster into 3+ CWE categories with 3+ CVEs each
**By:** Week 3
**Then:** Blind spots are random noise, not systematic gaps. PIVOT to different corpus.
**Measurement:** Group Q2 CVEs by CWE. Need 3+ clusters with 3+ CVEs.

## Criterion 3: Non-Triviality
**If:** >80% of blind spots are trivially detectable by adding simple regex rules
**By:** Week 3
**Then:** Existing scanners will fix this quickly. No sustainable moat. PIVOT.
**Measurement:** Manual review of top 20 blind spots. Score: trivial (regex) vs non-trivial (semantic/flow).

## Criterion 4: Reproducibility
**If:** Results vary >20% across different CVE corpus samples
**By:** Week 4
**Then:** Findings are corpus-dependent, not generalizable. RERUN with larger corpus.
**Measurement:** Run on 3 random 50% subsamples. Compare blind_spot_rate variance.

---

## Checkpoints

| Week | Gate | Go/No-Go Decision |
|------|------|--------------------|
| 1 | Corpus >= 100 CVE with source code | If <100: extend collection period |
| 2 | Criterion 1 check | If blind_spot_rate <5%: KILL |
| 3 | Criteria 2+3 check | If random or trivial: PIVOT |
| 4 | Criterion 4 + benchmark draft | If irreproducible: rerun with larger corpus |

## Survival Criteria (all must pass)
1. blind_spot_rate >= 15% (at least 1 in 6 CVEs invisible to all scanners)
2. 3+ systematic blind spot categories with 3+ CVEs each
3. 50%+ of blind spots require semantic/flow analysis (non-trivial)
4. Results stable across corpus subsamples (variance <20%)

## What Happens If Project Survives
- Week 5-8: Build detector for top 3 blind spot categories
- Month 3: Public benchmark release
- Month 4: B2B pilot engagement
