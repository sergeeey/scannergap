# ScannerGap Methodology

## Origin: ARCHCODE Transfer

This project transfers the blind spot detection methodology from ARCHCODE
(genomic variant analysis) to code security scanning.

### The Core Insight

ARCHCODE discovered that sequence-based variant predictors (VEP, SpliceAI, CADD)
systematically miss structural disruptions visible only in 3D chromatin analysis.
The key was not building a "better predictor" but finding what ALL predictors miss.

**Same principle applied to security:**
Standard SAST scanners (CodeQL, Semgrep, Snyk, Bandit) operate on pattern matching
and local data flow. They systematically miss vulnerability classes that require:
- Global execution flow understanding
- Cross-service interaction analysis
- State-dependent vulnerability chains
- Semantic intent vs syntactic correctness

### Methodology Transfer Table

| ARCHCODE (Genomics) | ScannerGap (Security) |
|---------------------|-------------------------|
| Sequence predictors (VEP, CADD) | SAST scanners (CodeQL, Semgrep, Snyk, Bandit) |
| 3D structural analysis (LSSIM) | Semantic/flow analysis |
| Variant = mutation in DNA | Vulnerability = CVE in code |
| Pathogenic vs Benign | Exploitable vs Safe |
| Q2 quadrant = structural blind spot | Q2 quadrant = scanner blind spot |
| 27 pearls (HBB) | N security pearls |
| Kill criteria (4 gates) | Kill criteria (4 gates) |
| Per-locus threshold calibration | Per-language/CWE threshold calibration |

## Pipeline (6 Stages)

### Stage 1: Corpus Ingestion
- Fetch CVEs from NVD API (National Vulnerability Database)
- Filter: has GitHub source code, CVSS >= medium, years 2020-2026
- Download vulnerable code + patches
- Target: 100-500 CVEs across Python, JavaScript, Java, C/C++

### Stage 2: Scanner Execution
- Run each scanner on each CVE's vulnerable code
- Record: scanner x CVE -> found (1) or missed (0)
- Normalize findings to CWE IDs for cross-scanner comparison

### Stage 3: Quadrant Analysis
- Build coverage matrix: CVE x Scanner
- Classify into Q1 (detected), Q2 (blind spot), Q3 (false positive), Q4 (true negative)
- Calculate blind_spot_rate = Q2 / (Q1 + Q2)

### Stage 4: Taxonomy
- Group Q2 CVEs by CWE category
- Identify systematic patterns (clusters >= 3 CVEs)
- Hypothesize WHY each category is missed

### Stage 5: Falsification
- Apply kill criteria (see kill_criteria.md)
- Robustness testing: corpus subsampling
- Non-triviality check: could a regex fix it?

### Stage 6: Benchmark + Detector
- Publish reproducible benchmark
- Build detector for top 3 blind spot categories
- Validate detector against held-out corpus

## Key Metrics

| Metric | Formula | Target |
|--------|---------|--------|
| Blind Spot Rate | Q2 / (Q1 + Q2) | >= 15% |
| Category Concentration | max_category_count / total_Q2 | >= 20% |
| Non-Triviality Score | non_trivial_Q2 / total_Q2 | >= 50% |
| Reproducibility | 1 - std(rates) / mean(rates) | >= 80% |

## Hypothesis Classes (To Validate)

1. **Logic Flow Blind Spot** — SAST sees syntax, not intent
2. **Cross-Boundary Blind Spot** — bug spans frontend + backend + DB
3. **State-Dependent Blind Spot** — exploit requires specific call sequence
4. **Architectural Blind Spot** — insecure service interaction pattern
5. **Semantic Blind Spot** — code is syntactically correct but semantically wrong
