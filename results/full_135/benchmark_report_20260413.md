# ScannerGap Security Blind Spot Benchmark v0.1.0
Generated: 2026-04-13T19:26:42.376319+00:00

## Summary
- Corpus: 135 CVEs
- Confirmed vulnerabilities: 135
- Scanners: semgrep, bandit
- **Overall verdict: ALIVE**

## Quadrant Distribution
- Q1 (detected by >= 1 scanner): 52
- Q2 (BLIND SPOT — missed by all): 83
- Q3 (false positive): 0
- Q4 (true negative): 0
- **Blind spot rate: 61.5%**

## Blind Spot Taxonomy
- **CWE-94**: 29 CVEs
- **CWE-918**: 25 CVEs
- **CWE-22**: 24 CVEs
- **CWE-434**: 17 CVEs
- **CWE-79**: 11 CVEs
- **CWE-502**: 10 CVEs
- **CWE-95**: 10 CVEs
- **CWE-78**: 7 CVEs
- **CWE-287**: 6 CVEs
- **CWE-862**: 6 CVEs
- **CWE-UNKNOWN**: 5 CVEs
- **CWE-1336**: 4 CVEs
- **CWE-89**: 4 CVEs
- **CWE-184**: 2 CVEs
- **CWE-20**: 2 CVEs
- **CWE-23**: 1 CVEs
- **CWE-691**: 1 CVEs
- **CWE-201**: 1 CVEs
- **CWE-281**: 1 CVEs
- **CWE-25**: 1 CVEs
- **CWE-59**: 1 CVEs
- **CWE-620**: 1 CVEs
- **CWE-36**: 1 CVEs
- **CWE-29**: 1 CVEs
- **CWE-74**: 1 CVEs
- **CWE-77**: 1 CVEs
- **CWE-416**: 1 CVEs

## Falsification Tests

| Test | Verdict | Metric | Value | Threshold |
|------|---------|--------|-------|-----------|
| blind_spot_existence | PASS | blind_spot_rate | 0.6148 | 0.05 |
| systematicity | PASS | qualifying_cluster_count | 13.0 | 3.0 |
| non_triviality | PASS | trivial_rate | 0.0 | 0.8 |
| reproducibility | SKIPPED | cv | 0.0 | 0.2 |
