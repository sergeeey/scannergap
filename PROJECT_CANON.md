# PROJECT CANON — ScannerGap

## Claim Governance
Adapted from ARCHCODE: every public claim must pass through governance.

### PUBLIC_CANONICAL (what we can say publicly)
- "X% of CVEs in our corpus are invisible to {scanner list}"
- "Blind spots cluster into N systematic categories"
- "Standard SAST scanners share common blind spot patterns"
- Requires: quadrant analysis + falsification suite PASS

### TECHNICAL_FULL_SCOPE (papers, detailed reports)
- Per-scanner coverage breakdown
- Per-CWE blind spot analysis
- Falsification test details + failure modes
- Requires: full pipeline run + reproducibility check

### EXPLORATORY (internal only)
- "This CWE category might be a blind spot" (before validation)
- "Scanner X seems weak on Y" (before statistical significance)
- Requires: 5+ examples, marked as [EXPLORATORY]

### BLOCKED (never claim)
- "Our scanner is better than named commercial or open-source SAST tools"
  (we audit, not compete)
- "These CVEs prove scanners are useless"
  (scanners catch most things — we find the gaps)
- "X% of all code vulnerabilities are undetectable"
  (our corpus != all vulnerabilities)

## Data Provenance
- NVD CVEs: EXPERIMENTAL (real data)
- Scan results: EXPERIMENTAL (real tool output)
- Synthetic test cases: MOCK_SYNTHETIC (must be labeled)
- Manual classifications: HUMAN_ANNOTATED (must note annotator)
