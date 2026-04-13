# BlindSpotSec — Security Blind Spot Scanner

## IDENTITY
Project: BlindSpotSec v0.1.0
Domain: Code Security / Meta-Scanner / Benchmark
Goal: Find vulnerability classes that ALL existing SAST scanners systematically miss
Methodology: Transferred from ARCHCODE genomics (blind spot detection via orthogonal analysis)

## STACK
- Python 3.11+, type hints always
- ruff format (double quotes, 100 chars)
- structlog for logging
- pytest for testing (≥80% coverage for business logic)
- Click for CLI

## KEY CONCEPTS
- **Blind Spot**: A vulnerability class that NO standard scanner (CodeQL, Semgrep, Snyk, Bandit) detects
- **Quadrant Analysis**: 2D matrix comparing scanner coverage — Q2 = "missed by ALL" = our target
- **Security Pearl**: A confirmed vulnerability invisible to all standard scanners (analog of ARCHCODE's 27 pearls)
- **Kill Criteria**: Pre-defined falsification gates — if failed, project pivots or dies

## EVIDENCE POLICY
- [VERIFIED] — confirmed with tool (Read, Bash, test output, scanner run)
- [DOCS] — from CVE/NVD/scanner documentation
- [INFERRED] — logical conclusion, state the chain
- [UNKNOWN] — no confirmation

## ARCHITECTURE
```
src/blindspotsec/
├── corpus/        # CVE collection + vulnerable code samples
├── scanners/      # Wrappers: CodeQL, Semgrep, Snyk, Bandit
├── quadrant/      # Coverage matrix + blind spot detection
├── taxonomy/      # Blind spot type classification
├── benchmark/     # Reproducible benchmark framework
└── detector/      # Own blind spot class detector
```

## WORKFLOW
- Falsification-first: define kill criteria BEFORE analysis
- Pre-mortem checkpoints at weeks 1, 2, 3, 4
- Claim governance: PUBLIC (narrow) vs TECHNICAL (broader) vs EXPLORATORY
- No scanner result = [VERIFIED] without independent confirmation

## INTEGRITY
- NO phantom CVE references (verify each CVE ID resolves)
- NO synthetic scan results without SYNTHETIC_ prefix
- NO overclaimed coverage gaps (require ≥3 CVE examples per blind spot class)
- Git-commit kill criteria BEFORE running analysis
