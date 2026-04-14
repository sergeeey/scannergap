# ScannerGap Security Blind Spot Benchmark v0.1.0
Generated: 2026-04-13T18:27:04.255939+00:00

## Summary
- Corpus: 38 CVEs
- Confirmed vulnerabilities: 38
- Scanners: semgrep, bandit
- **Overall verdict: ALIVE**

## Quadrant Distribution
- Q1 (detected by >= 1 scanner): 17
- Q2 (BLIND SPOT — missed by all): 21
- Q3 (false positive): 0
- Q4 (true negative): 0
- **Blind spot rate: 55.3%**

## Blind Spot Taxonomy
- **CWE-918**: 11 CVEs
- **CWE-22**: 8 CVEs
- **CWE-94**: 7 CVEs
- **CWE-502**: 4 CVEs
- **CWE-89**: 2 CVEs
- **CWE-36**: 1 CVEs
- **CWE-29**: 1 CVEs
- **CWE-UNKNOWN**: 1 CVEs
- **CWE-95**: 1 CVEs
- **CWE-862**: 1 CVEs
- **CWE-74**: 1 CVEs
- **CWE-77**: 1 CVEs
- **CWE-78**: 1 CVEs
- **CWE-1336**: 1 CVEs
- **CWE-416**: 1 CVEs

## Falsification Tests

| Test | Verdict | Metric | Value | Threshold |
|------|---------|--------|-------|-----------|
| blind_spot_existence | PASS | blind_spot_rate | 0.5526 | 0.05 |
| systematicity | WARNING | qualifying_cluster_count | 4.0 | 3.0 |
| non_triviality | PASS | trivial_rate | 0.0 | 0.8 |
| reproducibility | SKIPPED | cv | 0.0 | 0.2 |
