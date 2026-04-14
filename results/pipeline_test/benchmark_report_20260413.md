# ScannerGap Security Blind Spot Benchmark v0.1.0
Generated: 2026-04-13T18:11:00.636226+00:00

## Summary
- Corpus: 38 CVEs
- Confirmed vulnerabilities: 38
- Scanners: semgrep, bandit
- **Overall verdict: KILL**

## Quadrant Distribution
- Q1 (detected by >= 1 scanner): 17
- Q2 (BLIND SPOT — missed by all): 21
- Q3 (false positive): 0
- Q4 (true negative): 0
- **Blind spot rate: 55.3%**

## Blind Spot Taxonomy
- **CWE-UNKNOWN**: 21 CVEs

## Falsification Tests

| Test | Verdict | Metric | Value | Threshold |
|------|---------|--------|-------|-----------|
| blind_spot_existence | PASS | blind_spot_rate | 0.5526 | 0.05 |
| systematicity | FAIL | qualifying_cluster_count | 1.0 | 3.0 |
| non_triviality | PASS | trivial_rate | 0.0 | 0.8 |
| reproducibility | SKIPPED | cv | 0.0 | 0.2 |
