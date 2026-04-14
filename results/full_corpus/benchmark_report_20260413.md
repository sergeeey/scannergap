# ScannerGap Security Blind Spot Benchmark v0.1.0
Generated: 2026-04-13T18:46:14.798260+00:00

## Summary
- Corpus: 56 CVEs
- Confirmed vulnerabilities: 56
- Scanners: semgrep, bandit
- **Overall verdict: ALIVE**

## Quadrant Distribution
- Q1 (detected by >= 1 scanner): 23
- Q2 (BLIND SPOT — missed by all): 33
- Q3 (false positive): 0
- Q4 (true negative): 0
- **Blind spot rate: 58.9%**

## Blind Spot Taxonomy
- **CWE-94**: 12 CVEs
- **CWE-22**: 11 CVEs
- **CWE-918**: 11 CVEs
- **CWE-79**: 8 CVEs
- **CWE-1336**: 4 CVEs
- **CWE-502**: 4 CVEs
- **CWE-78**: 3 CVEs
- **CWE-UNKNOWN**: 2 CVEs
- **CWE-184**: 2 CVEs
- **CWE-89**: 2 CVEs
- **CWE-20**: 1 CVEs
- **CWE-36**: 1 CVEs
- **CWE-29**: 1 CVEs
- **CWE-95**: 1 CVEs
- **CWE-862**: 1 CVEs
- **CWE-74**: 1 CVEs
- **CWE-77**: 1 CVEs
- **CWE-416**: 1 CVEs

## Falsification Tests

| Test | Verdict | Metric | Value | Threshold |
|------|---------|--------|-------|-----------|
| blind_spot_existence | PASS | blind_spot_rate | 0.5893 | 0.05 |
| systematicity | PASS | qualifying_cluster_count | 7.0 | 3.0 |
| non_triviality | PASS | trivial_rate | 0.0 | 0.8 |
| reproducibility | SKIPPED | cv | 0.0 | 0.2 |
