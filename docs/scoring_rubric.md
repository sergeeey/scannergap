# Scoring Rubric — Gold Subset Evaluation

## Purpose
Strict, reproducible criteria for classifying scanner results as
HIT / PARTIAL / MISS / NOISE. Eliminates subjective interpretation.

## Per-CVE Annotation Fields

Each CVE in the gold subset must have these 5 fields filled BEFORE scanning:

| Field | Description | Example |
|-------|-------------|---------|
| `vulnerable_file` | Exact file path from the commit | `src/util/files_util.py` |
| `vulnerable_sink` | Function or line range where the bug lives | `download_model_from_url()` L45-52 |
| `cwe_primary` | Primary CWE from NVD | CWE-22 |
| `detection_requires` | What analysis capability is needed to find this | `taint: user_url -> tarfile.extractall` |
| `match_definition` | What counts as "scanner found THIS CVE" | Finding references tarfile extractall OR path traversal in files_util.py |

## Detection Requirement Categories

| Category | Code | Description | Example |
|----------|------|-------------|---------|
| Pattern match | `PAT` | Regex/AST pattern on dangerous function call | `eval()`, `shell=True`, `extractall()` |
| Local data flow | `LDF` | Taint within one function (source -> sink) | User input -> SQL query in same function |
| Interprocedural taint | `IPT` | Taint across function/file boundaries | Request param -> helper() -> db.execute() |
| Semantic understanding | `SEM` | Requires understanding business logic / intent | Auth check missing in specific context |
| Architectural | `ARCH` | Cross-service or cross-component interaction | Frontend trusts backend response without validation |
| Configuration | `CFG` | Misconfiguration or insecure default | Debug mode enabled, weak crypto params |

## Matching Verdict Definitions

### HIT (scanner correctly identified the vulnerability)
ALL of these must be true:
1. Finding is on the `vulnerable_file` (or a file that directly imports/calls it)
2. Finding references the correct CWE OR a semantically equivalent issue
3. Finding points to code within ±20 lines of `vulnerable_sink`

### PARTIAL (scanner found something related but not precise)
ANY of these:
1. Finding is on `vulnerable_file` but wrong CWE / wrong issue type
2. Finding is on correct CWE but wrong file (different vuln in same project)
3. Finding is generic warning (e.g., B101 assert) that happens to be near the sink

### MISS (scanner did not find the vulnerability)
1. Zero findings on `vulnerable_file` that relate to the CVE
2. OR findings exist but none match the CWE or sink location

### NOISE (scanner finding is irrelevant to CVE evaluation)
1. Finding about code style, not security
2. Finding about a DIFFERENT vulnerability than the CVE under test
3. Finding that would exist in ANY codebase (e.g., `import os` warning)

## Quadrant Classification Rules

For quadrant analysis, only HIT counts as "detected":

| Real CVE? | HIT by >=1 scanner? | Quadrant |
|-----------|---------------------|----------|
| Yes | Yes | Q1 (detected) |
| Yes | No | Q2 (blind spot) |

PARTIAL does NOT count as detected. This is conservative but prevents
inflating detection rates with tangential findings.

## Scanner Configuration Levels

### Baseline A — Default
- Semgrep: `--config auto`
- Bandit: default (no flags)
- Rationale: what a developer gets out of the box

### Baseline B — Tuned
- Semgrep: `--config auto --config r/security-audit --config r/owasp`
- Bandit: `-ll -ii` (low severity, low confidence included)
- Rationale: what a security-conscious team would configure

### Baseline C — Maximum (future)
- CodeQL with security-extended suite
- Semgrep Pro rules (if available)
- Rationale: best available static analysis

## Reproducibility Requirements
- Scanner versions pinned in results metadata
- Exact command recorded per scan
- Results JSON includes: scanner, version, config, command, timestamp
- Gold subset annotations committed BEFORE re-scanning (no post-hoc adjustment)
