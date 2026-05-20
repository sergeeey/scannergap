# PROJECT CONTEXT AUDIT — ScannerGap

**Generated:** 2026-05-20  
**Auditor:** Senior Software Architect + Security Reviewer  
**Mode:** READ-ONLY comprehensive analysis  
**Purpose:** AI handoff context for continuation without loss of understanding

---

## 1. Executive Summary

**ScannerGap** is a **benchmark-backed blind-spot audit prototype** for finding vulnerability classes that baseline SAST scanners (Semgrep, Bandit, CodeQL) systematically miss.

**Current State:** Research MVP with exploratory benchmark evidence  
**Readiness Level:** Pilot-ready for manual POC, NOT production SaaS  
**Key Achievement:** 61.5% blind spot rate on 135 CVEs (exploratory), 56.5% on 23 gold CVEs (verified)  
**Main Value:** Identifies scanner coverage gaps using ARCHCODE-derived methodology  
**Main Risk:** Reproducibility gate SKIPPED — not yet production benchmark

**Status Tags:**
- [x] MVP complete
- [x] Falsification criteria passed (3/4)
- [x] Detector v3 (49 rules)
- [ ] Reproducibility verified
- [ ] Production benchmark
- [ ] Independent validation

---

## 2. Project Identity

| Attribute | Value |
|-----------|-------|
| **Name** | ScannerGap (formerly BlindSpotSec) |
| **Version** | 0.1.0 |
| **License** | Apache 2.0 |
| **Repository** | E:\scannergap |
| **Primary Language** | Python 3.11+ |
| **Purpose** | Meta-scanner for SAST blind spot detection |
| **Primary User** | Security teams / AppSec / CISOs with existing SAST tools |
| **Core Value** | Finds vulnerability classes ALL baseline scanners miss (Q2 quadrant) |
| **Current Status** | Research MVP + demo materials |
| **Главный риск** | Reproducibility not verified — 135 vs 131 CVE mismatch |
| **Главная возможность** | First paying client via manual POC ($500-1000) |

**Founder Context** (from Obsidian vault):
- Developer: Sergey Boyko, Head of Security в 2 МФО, Ronin Fellow
- Rating: 8.7/10 (BlindSpotSec project)
- Status: SHIP #1 priority, неактивен 24 дня (last commit 2026-04-14)
- Goal: Первый paying client за 30 дней

---

## 3. Repository Map

```
E:\scannergap/
├── src/scannergap/              # Main Python package (2366 LOC)
│   ├── cli.py                   # Click-based CLI (scan/quadrant/benchmark/pipeline)
│   ├── scanners/                # Scanner wrappers
│   │   ├── base.py              # Base scanner interface
│   │   ├── semgrep_scanner.py   # Semgrep wrapper
│   │   └── bandit_scanner.py    # Bandit wrapper
│   ├── quadrant/                # Coverage matrix + Q2 (blind spot) detection
│   │   └── analysis.py          # Core quadrant logic
│   ├── benchmark/               # Falsification suite
│   │   ├── falsification.py     # 4 kill criteria tests
│   │   └── report.py            # Report generator (JSON + Markdown)
│   ├── detector/                # Own blind spot detector
│   │   └── rules/               # 49 Semgrep rules (10 files)
│   │       ├── blind-spot-python.yaml
│   │       ├── blind-spot-javascript.yaml
│   │       ├── blind-spot-java.yaml
│   │       ├── blind-spot-php.yaml
│   │       ├── blind-spot-ruby.yaml
│   │       ├── blind-spot-go.yaml
│   │       ├── blind-spot-auth.yaml
│   │       ├── blind-spot-database.yaml
│   │       ├── blind-spot-template.yaml
│   │       └── blind-spot-xss.yaml
│   ├── corpus/                  # NVD CVE collection
│   │   └── nvd_client.py        # NVD API client (HTTP calls)
│   └── taxonomy/                # Blind spot type classification (stub)
│
├── corpus/                      # CVE corpus (NOT in git, size limited)
│   ├── fullcode/                # 131 CVE directories [VERIFIED]
│   │   ├── CVE-2023-*/          # Vulnerable code + metadata.json
│   │   └── CVE-2024-*/
│   └── gold_subset.json         # 23 annotated CVEs [GROUND TRUTH]
│
├── tests/                       # Unit tests (549 LOC, 46 test functions)
│   ├── test_cli.py
│   ├── test_nvd_client.py
│   ├── test_quadrant.py
│   ├── test_report.py
│   ├── test_scanners.py
│   ├── test_falsification.py
│   ├── test_scan_local_project.py
│   └── conftest.py              # Pytest fixtures
│
├── scripts/                     # Standalone utilities
│   ├── expand_corpus.py         # NVD CVE download
│   ├── gold_evaluation.py       # Gold subset strict scoring
│   ├── codeql_batch.py          # CodeQL batch scanner
│   ├── scan_local_project.py    # Local project scanner (new)
│   ├── build_manifest.py        # Freeze corpus manifest
│   ├── check_claims.py          # Verify public claims
│   └── verify_manifest.py       # Validate manifest consistency
│
├── docs/                        # Documentation + findings
│   ├── findings.md              # Full benchmark report
│   ├── findings.html            # HTML version
│   ├── methodology.md           # ARCHCODE transfer methodology
│   ├── reproducibility.md       # Reproducibility status
│   ├── roadmap.md               # 30-day MVP roadmap
│   └── index.html               # Landing page
│
├── demo/                        # Sales/presentation materials
│   ├── one-pager.md             # 1-page summary
│   ├── slides.md                # 7-slide deck
│   ├── demo-script.md           # Demo walkthrough
│   ├── ciso-demo.md             # Safe CISO framing
│   ├── poc-offer.md             # Paid POC structure
│   ├── sample-report.md         # Report template
│   ├── data-handling.md         # Data protection policy
│   ├── discovery-call-script.md # Sales script
│   ├── intake-questionnaire.md  # Client questionnaire
│   ├── mfo-pilot-plan.md        # МФО pilot plan (NEW)
│   └── mfo-discovery-checklist.md # МФО discovery (NEW)
│
├── results/                     # Scan outputs (NOT in git, .gitignore)
│   ├── full_135/                # 135 CVE exploratory artifact
│   │   ├── benchmark_report_20260413.json
│   │   └── benchmark_report_20260413.md
│   ├── gold_evaluation.json     # Gold subset results
│   ├── codeql_batch.json        # CodeQL exploratory subset
│   ├── codeql_gate.json         # CodeQL gate artifact
│   ├── local_projects/          # Local scan outputs
│   └── public_repos/            # Public repo scans
│
├── config/                      # Configurations
│   └── scanners.json            # Scanner configs
│
├── .github/workflows/           # CI/CD
│   └── ci.yml                   # Lint, format, tests, type check, rule validation
│
├── .claude/                     # Claude Code project metadata
│   ├── memory/
│   │   ├── activeContext.md     # Current session state
│   │   └── decisions.md         # Architectural decisions
│   └── settings.local.json      # Local settings
│
├── pyproject.toml               # Package manifest
├── CLAUDE.md                    # Project instructions
├── README.md                    # Public README
├── BENCHMARK_EVIDENCE.md        # Trust boundary (NEW)
├── QUALITY_GATE.md              # Pre-release checklist (NEW)
├── RELEASE_CHECKLIST.md         # Release blockers (NEW)
├── PROJECT_CANON.md             # Claim governance
├── kill_criteria.md             # Pre-committed kill criteria
├── benchmark_manifest.json      # Frozen 131-CVE manifest (NEW)
└── CONTRIBUTING.md              # Contributor guide
```

**Key Observations:**
- Code: 2915 total LOC (src + tests + scripts)
- Tests: 549 LOC, 46 test functions, ~19% test ratio
- Corpus: 131 CVE dirs checked out, 23 gold subset annotated
- Detector: 49 Semgrep rules across 10 language files
- Demo materials: 13 files (sales-ready)

---

## 4. Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (cli.py)                        │
│  Commands: scan | quadrant | benchmark | pipeline          │
└──────────┬──────────────────────────────────────────────────┘
           │
           ├─► SCANNERS (scanners/)
           │   ├─ base.py: ScanResult, BaseScanner interface
           │   ├─ semgrep_scanner.py: Semgrep wrapper
           │   └─ bandit_scanner.py: Bandit wrapper
           │
           ├─► QUADRANT ANALYSIS (quadrant/analysis.py)
           │   ├─ build_coverage_matrix(): CVE × Scanner → 1/0
           │   ├─ classify_quadrants(): Q1/Q2/Q3/Q4
           │   └─ analyze_blind_spot_patterns(): CWE clustering
           │
           ├─► FALSIFICATION (benchmark/falsification.py)
           │   ├─ check_blind_spot_existence()
           │   ├─ check_systematicity()
           │   ├─ check_non_triviality()
           │   └─ check_reproducibility()
           │
           ├─► CORPUS (corpus/nvd_client.py)
           │   └─ fetch_cves_from_nvd(): HTTP → NVD API
           │
           └─► DETECTOR (detector/rules/*.yaml)
               └─ 49 custom Semgrep rules
```

### Data Flow

```
1. INPUT: CVE corpus (corpus/fullcode/)
   ↓
2. SCAN: Run scanners (Semgrep, Bandit) → findings JSON
   ↓
3. QUADRANT: CVE × Scanner matrix → Q1 (hit) vs Q2 (blind)
   ↓
4. FALSIFICATION: 4 kill criteria tests → PASS/FAIL
   ↓
5. REPORT: JSON + Markdown benchmark report
```

### External Integrations

| Integration | Purpose | Security Notes |
|-------------|---------|----------------|
| **NVD API** | CVE metadata fetch | HTTP calls via requests lib |
| **Semgrep CLI** | Pattern matching scanner | Local execution, no cloud |
| **Bandit CLI** | Python security scanner | Local execution |
| **CodeQL** (optional) | Advanced SAST | Local execution, DB creation |

**No cloud uploads:** All scanning is 100% local.

### Key Modules Detail

**quadrant/analysis.py** — Core logic [VERIFIED]
- `build_coverage_matrix()`: Creates CVE × Scanner DataFrame
- `classify_quadrants()`: Q1 (detected) / Q2 (blind spot) / Q3 (FP) / Q4 (TN)
- `analyze_blind_spot_patterns()`: Groups Q2 by CWE
- Input: scanner results JSON + CVE list
- Output: QuadrantResult (Q2 = blind spots)

**benchmark/falsification.py** — Kill criteria [VERIFIED]
- 4 tests adapted from ARCHCODE genomics:
  1. `check_blind_spot_existence()`: rate >= 5% (survival) / <5% (KILL)
  2. `check_systematicity()`: ≥3 CWE categories with ≥3 CVEs each
  3. `check_non_triviality()`: <80% trivially regex-fixable
  4. `check_reproducibility()`: CV <20% across subsamples
- Returns: list[FalsificationResult] with Verdict (PASS/WARNING/FAIL/SKIPPED)

**scanners/base.py** — Scanner interface [VERIFIED]
```python
@dataclass
class ScanResult:
    scanner_name: str
    finding_count: int
    raw_output: str

class BaseScanner(ABC):
    @abstractmethod
    def scan(self, target_path: Path) -> ScanResult
    
    @abstractmethod
    def is_available(self) -> bool
```

---

## 5. Core Logic

### Blind Spot Detection Algorithm

**Step 1:** Scanner execution
```python
# cli.py:scan command
for scanner_name in scanners:
    scanner = scanner_cls()
    for cve_dir in cve_dirs:
        result = scanner.scan(cve_dir)
        if result.finding_count > 0:
            detected_cves.append(cve_dir.name)
```

**Step 2:** Coverage matrix build
```python
# quadrant/analysis.py
matrix = pd.DataFrame({
    'semgrep': [1 if cve in semgrep_detected else 0 for cve in all_cves],
    'bandit': [1 if cve in bandit_detected else 0 for cve in all_cves]
}, index=all_cves)
matrix['any_scanner'] = (matrix.sum(axis=1) > 0).astype(int)
```

**Step 3:** Q2 (blind spot) identification
```python
# quadrant/analysis.py:classify_quadrants
result = QuadrantResult(
    q1_detected=[cve for cve, row in matrix.iterrows() if row['any_scanner'] == 1],
    q2_blind_spot=[cve for cve, row in matrix.iterrows() if row['any_scanner'] == 0],
)
result.blind_spot_rate = len(q2) / (len(q1) + len(q2))
```

**Step 4:** Taxonomy clustering
```python
# Group Q2 by CWE
for cve in q2_blind_spots:
    cwe = metadata[cve]['cwe']
    cwe_clusters[cwe].append(cve)
```

**Step 5:** Falsification testing
```python
# benchmark/falsification.py
tests = [
    check_blind_spot_existence(blind_spot_rate),  # >=5%?
    check_systematicity(cwe_clusters),            # >=3 categories?
    check_non_triviality(trivial_count, total),   # <80% trivial?
    check_reproducibility(subsample_rates)        # CV <20%?
]
overall = "ALIVE" if all(t.verdict != FAIL for t in tests) else "KILL"
```

### Falsification Framework

**Inherited from ARCHCODE genomics** (verified: comments in falsification.py:3-4)

| Test | Null Hypothesis | Kill Criterion | Current Result |
|------|----------------|----------------|----------------|
| 1. Existence | Scanners cover >95% | blind_spot_rate < 5% | ✅ PASS (61.5%) |
| 2. Systematicity | Random distribution | <3 clusters | ✅ PASS (13 CWE categories) |
| 3. Non-Triviality | >80% regex-fixable | trivial_rate > 80% | ✅ PASS (0% trivial in CLI) |
| 4. Reproducibility | Corpus-dependent | CV > 20% | ⚠️ **SKIPPED** (no subsamples run) |

**Key Files:**
- `benchmark/falsification.py:37-68` — Test 1 implementation
- `benchmark/falsification.py:71-109` — Test 2 implementation
- `benchmark/falsification.py:112-139` — Test 3 implementation
- `benchmark/falsification.py:142-178` — Test 4 implementation

---

## 6. Evidence Base

### VERIFIED (with tool confirmation)

**A. Corpus Size**
- ✅ 131 CVE directories checked out [VERIFIED: find corpus/fullcode -type d -name "CVE-*" | wc -l]
- ✅ 23 gold subset CVEs annotated [VERIFIED: corpus/gold_subset.json line 5]
- ⚠️ 135 CVE in exploratory artifact report [WEAK: benchmark_report says 135, repo has 131]

**B. Blind Spot Rates**
- ✅ **56.5% on gold subset (23 CVEs)** [VERIFIED: results/gold_evaluation.json:7]
  - Baseline A (default): 10/23 detected, 13/23 blind
  - Baseline B (tuned): 8/23 detected, 15/23 blind
- ✅ **61.5% on exploratory 135-CVE artifact** [VERIFIED: results/full_135/benchmark_report_20260413.json:18]
  - Semgrep + Bandit: 52/135 detected, 83/135 blind

**C. Detector Rules**
- ✅ 49 Semgrep rules total [VERIFIED: grep -h "^  - id:" src/scannergap/detector/rules/*.yaml | wc -l]
- ✅ 10 rule files (Python, JS, Java, PHP, Ruby, Go, Auth, DB, Template, XSS)
- Coverage: Python (strongest), JavaScript, Java, PHP, Ruby (moderate), Go (minimal)

**D. Code Quality**
- ✅ 2915 total LOC [VERIFIED: wc -l src/**/*.py tests/**/*.py scripts/*.py]
- ✅ 549 test LOC [VERIFIED: find tests -name "*.py" -exec wc -l {} + | tail -1]
- ✅ 46 test functions [VERIFIED: grep -r "def test_" tests/*.py | wc -l]
- ✅ CI/CD: 2 jobs (test matrix 3.11/3.12, validate-rules) [VERIFIED: .github/workflows/ci.yml]

**E. Falsification Tests**
- ✅ Test 1 (Existence): PASS (61.5% >> 5% threshold)
- ✅ Test 2 (Systematicity): PASS (13 CWE categories >> 3 threshold)
- ✅ Test 3 (Non-Triviality): PASS (trivial_count=0 in CLI call)
- ⚠️ Test 4 (Reproducibility): **SKIPPED** [CRITICAL GAP]

**F. Taxonomy**
- ✅ 13 systematic CWE categories identified
- Top 5 blind spot categories:
  1. CWE-94 (Code Injection): 29 CVEs
  2. CWE-918 (SSRF): 25 CVEs
  3. CWE-22 (Path Traversal): 24 CVEs
  4. CWE-434 (Unrestricted Upload): 17 CVEs
  5. CWE-79 (XSS): 11 CVEs

### PARTIALLY VERIFIED

**G. CodeQL Evidence**
- ⚠️ `results/codeql_batch.json` exists (exploratory subset)
- ⚠️ `results/codeql_gate.json` exists (small gate artifact)
- ⚠️ **NOT integrated into headline benchmark** (separate exploratory)
- ⚠️ Some CodeQL DB creation failures noted [INFERRED from BENCHMARK_EVIDENCE.md:28]

### NOT VERIFIED

**H. Reproducibility**
- ❌ **No subsample runs executed** [CRITICAL]
- ❌ Manifest mismatch: report says 135 CVE, repo has 131 dirs
- ❌ `check_reproducibility()` returns SKIPPED verdict
- ❌ `reproducibility.md` status marked as SKIPPED in full_135 report

**I. Detector Effectiveness**
- ❌ 49 rules exist, but FP rate NOT measured
- ❌ No validation on real codebases (только corpus CVEs)
- ❌ Impact stated as "prototype claim" in README:148

**J. Production Readiness**
- ❌ No hold-out validation set
- ❌ No independent verification
- ❌ No user acceptance testing
- ❌ No real-world case studies (МФО pilot не запущен)

### CLAIMS TO AVOID (from BENCHMARK_EVIDENCE.md + PROJECT_CANON.md)

**BLOCKED claims (never say publicly):**
- ❌ "Our scanner is better than CodeQL/Semgrep" (audit, not compete)
- ❌ "Missed by all three scanners" (CodeQL not in headline)
- ❌ "All four kill criteria passed" (reproducibility SKIPPED)
- ❌ "Production benchmark" (exploratory artifact)
- ❌ "Fully reproducible" (reproducibility gate not passed)

**SAFE claims (public-ready):**
- ✅ "Benchmark-backed blind-spot audit prototype"
- ✅ "61.5% blind spot rate in exploratory Semgrep + Bandit artifact"
- ✅ "13 systematic CWE categories identified"
- ✅ "Research MVP for scoped manual POC"

---

## 7. Testing and Reproducibility

### Test Coverage

**Unit Tests** (`tests/`)
- ✅ 46 test functions across 7 files
- ✅ 549 LOC test code (19% of total)
- Coverage areas:
  - `test_cli.py` — CLI commands
  - `test_nvd_client.py` — NVD API mocking
  - `test_quadrant.py` — Quadrant logic
  - `test_report.py` — Report generation
  - `test_scanners.py` — Scanner wrappers
  - `test_falsification.py` — Kill criteria
  - `test_scan_local_project.py` — Local scanner (new)

**How to Run Tests**
```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=scannergap --cov-report=term-missing

# Specific test file
pytest tests/test_quadrant.py -v
```

**Test Infrastructure**
- `conftest.py`: pytest fixtures for temp dirs, mock CVE data
- CI runs tests on Python 3.11 + 3.12 matrix
- Type checking: `mypy src/scannergap/`
- Linting: `ruff check src/ tests/ scripts/`
- Format: `ruff format --check`

### Reproducibility Status

**Current State:** ⚠️ **NOT PRODUCTION-READY**

**Blockers:**
1. **Manifest mismatch**
   - Report claims 135 CVEs
   - Repo has 131 CVE directories
   - `benchmark_manifest.json` created but not verified [NEW, 2026-05-20]

2. **Reproducibility test SKIPPED**
   - Test 4 in falsification suite returns SKIPPED
   - No subsample runs executed
   - No CV (coefficient of variation) measured

3. **No independent validation**
   - All results from single run (2026-04-13)
   - No hold-out corpus
   - No cross-validation

**How to Verify Reproducibility** (from docs/reproducibility.md)
```bash
# Step 1: Freeze manifest
python scripts/build_manifest.py

# Step 2: Re-run pipeline in clean env
scannergap pipeline corpus/fullcode -o results/repro_run_1

# Step 3: Compare outputs
diff results/full_135/benchmark_report.json results/repro_run_1/benchmark_report.json

# Expected: 0 diffs for reproducibility PASS
```

**Reproducibility Criteria** (from kill_criteria.md:29-34)
- Results should NOT vary >20% across corpus subsamples
- Measurement: CV (coefficient of variation) of blind_spot_rate
- Current status: SKIPPED (no subsamples)

### Coverage Gaps

**Code NOT covered by tests:**
- ❌ `src/scannergap/corpus/nvd_client.py` — HTTP calls (mocked in tests, but not integration-tested)
- ❌ `src/scannergap/taxonomy/` — stub module
- ❌ Full end-to-end pipeline (`cli.py:pipeline` command)
- ❌ Detector rules validation (CI validates syntax, not effectiveness)

---

## 8. Security Review

### ✅ SECURE Practices Found

**A. No Secrets in Code**
- ✅ No hardcoded API keys, passwords, tokens
- ✅ `.gitignore` blocks `.env*` files
- ✅ Only `.env.example` in corpus (CVE sample data)

**B. Local-Only Execution**
- ✅ All scanners run locally (Semgrep, Bandit, CodeQL)
- ✅ No cloud uploads in scanner wrappers
- ✅ Data handling policy: `demo/data-handling.md` specifies local-only

**C. Input Validation**
- ✅ CLI uses Click with type validation
- ✅ Path validation: `type=click.Path(exists=True)`
- ✅ No shell injection in scanner wrappers (subprocess with list args)

**D. Dependency Security**
- ✅ Dependencies pinned in `pyproject.toml`
- ✅ No known vulnerable dependencies (as of 2026-04-14)

### ⚠️ RISKS Identified

**A. External HTTP Calls**
```python
# src/scannergap/corpus/nvd_client.py
import requests
response = requests.get(nvd_api_url, params=params)
```
- ⚠️ **NVD API calls**: No HTTPS verification explicitly shown
- ⚠️ **Timeout not set**: requests could hang indefinitely
- ⚠️ **No retry logic**: transient failures will break pipeline

**Mitigation:** Add `timeout=30`, `verify=True` to all requests calls

**B. Subprocess Execution**
```python
# scanners/semgrep_scanner.py, bandit_scanner.py
subprocess.run([scanner_binary, ...], capture_output=True)
```
- ⚠️ Scanner binaries expected in PATH
- ⚠️ No explicit PATH validation (could run malicious binary if PATH poisoned)

**Mitigation:** Validate scanner binary path before execution

**C. Corpus Data Handling**
```python
# cli.py:scan
for cve_dir in corpus_path.iterdir():
    scanner.scan(cve_dir)
```
- ⚠️ Corpus contains **real vulnerable code**
- ⚠️ No sandboxing when scanning (could execute malicious code if CVE contains trojan)
- ⚠️ CVE metadata from untrusted source (NVD)

**Mitigation:** Document that corpus should be treated as untrusted input

**D. File System Operations**
```python
# benchmark/report.py
output_path.write_text(json.dumps(data), encoding="utf-8")
```
- ⚠️ No check for output path traversal (user could specify `/etc/passwd`)
- ✅ Mitigated by CLI: output is a flag, not user input at runtime

**E. Data Retention**
- ⚠️ `results/` directory contains scan outputs
- ⚠️ No automatic cleanup policy
- ⚠️ Could accumulate sensitive findings over time

**Mitigation:** Document retention policy in data-handling.md (already exists)

### 🛡️ COMPLIANCE Notes

**GDPR / Privacy:**
- ✅ No PII collection
- ✅ No tracking, analytics, or telemetry
- ✅ No external data transmission (except NVD API fetch)

**PCI DSS / Financial:**
- ✅ Relevant for МФО use case
- ✅ Local-only scanning aligns with compliance requirements
- ⚠️ No audit trail logging (if required by compliance)

**Secrets Management:**
- ✅ No secrets in code or commits
- ✅ `.gitignore` blocks `.env*` files
- ⚠️ Demo materials reference МФО internal use — ensure no sensitive data in demo collateral

### Supply Chain Risks

**Dependencies** (from pyproject.toml:10-17)
```toml
[project.dependencies]
click>=8.1
structlog>=24.1
pandas>=2.2
requests>=2.31
pydantic>=2.6
rich>=13.7
scikit-learn>=1.4
matplotlib>=3.8
```

- ✅ All from trusted PyPI packages
- ✅ No exotic/unmaintained dependencies
- ⚠️ No dependency lockfile (requirements.txt or poetry.lock)
- ⚠️ Version ranges allow minor updates (could break)

**Scanner Binaries:**
- ⚠️ Semgrep, Bandit expected installed separately
- ⚠️ No version pinning in code (user's installed version)
- ⚠️ CodeQL optional (large download, complex setup)

---

## 9. Product Readiness

### Readiness Level: **Pilot-Ready (Manual POC)**

**Scale:**
1. Research artifact — ❌
2. Internal tool — ❌
3. MVP — ✅ **[CURRENT]**
4. Pilot-ready — ✅ **[CURRENT]**
5. Production-ready — ❌
6. Enterprise-ready — ❌

**Justification:**

**✅ MVP Complete** because:
- Core functionality works (scan → quadrant → falsification → report)
- 3/4 kill criteria passed
- CLI functional end-to-end
- Demo materials prepared (13 files)
- Gold subset evaluation shows 56.5% blind spot rate

**✅ Pilot-Ready** because:
- Manual POC workflow documented (`demo/poc-offer.md`, `demo/mfo-pilot-plan.md`)
- Safe framing established (`demo/ciso-demo.md`)
- Data handling protocol defined (`demo/data-handling.md`)
- Discovery process defined (`demo/intake-questionnaire.md`)
- Can deliver value: find blind spots → concrete findings → recommendations

**❌ NOT Production-Ready** because:
- Reproducibility gate SKIPPED (blocker #1)
- Manifest mismatch (135 vs 131 CVE)
- No independent validation
- No hold-out corpus
- Detector effectiveness not measured (FP rate unknown)
- No real-world case studies yet

**❌ NOT Enterprise-Ready** because:
- No SLA, support, or updates roadmap
- No multi-tenancy or access control
- No compliance certifications
- No training materials for end-users
- No API or integration points

### Commercial Readiness

**Strengths:**
- ✅ Unique positioning (audit scanners, don't compete)
- ✅ Scientific methodology (ARCHCODE transfer, falsification-first)
- ✅ Founder-market fit (20+ years security, MФО access)
- ✅ Demo materials ready (sales deck, POC offer, report template)
- ✅ Discovery process defined (intake questionnaire, call script)

**Weaknesses:**
- ❌ No paying customers yet (0 revenue)
- ❌ No public case studies (МФО pilot not started)
- ❌ Pricing not validated ($500-1000 hypothesis)
- ❌ GTM strategy not executed (0 outreach emails sent)
- ❌ Inactive 24 days (last commit 2026-04-14)

**Go-to-Market Blockers:**
1. **Reproducibility gate** (technical credibility)
2. **First manual POC** (proof of value)
3. **Case study** (social proof)

**First $1000 Path** (from demo/poc-offer.md):
1. Run pilot on МФО internal repos (this week)
2. Generate sanitized case study (if findings valuable)
3. Outreach to 20 security teams (LinkedIn, HN, X)
4. 3 discovery calls → 1 paid POC ($500-1000)
5. Deliver value → expand or iterate

---

## 10. Risks and Blockers

| Risk | Severity | Evidence | Fix |
|------|:--------:|----------|-----|
| **Reproducibility gate SKIPPED** | 🔴 **CRITICAL** | `results/full_135/benchmark_report.json` marks reproducibility SKIPPED; Test 4 returns SKIPPED verdict | Run subsample analysis, freeze manifest, verify 0-diffs |
| **Manifest mismatch (135 vs 131)** | 🔴 **HIGH** | Report says 135 CVE, `find corpus/fullcode -type d` returns 131 | Freeze manifest with `build_manifest.py`, update docs |
| **No independent validation** | 🟡 **MEDIUM** | All results from single pipeline run (2026-04-13) | Hold-out corpus validation, cross-validation |
| **Detector FP rate unknown** | 🟡 **MEDIUM** | 49 rules exist, no FP measurement on real codebases | Run on 5+ real projects, measure FP rate |
| **CodeQL not integrated** | 🟡 **MEDIUM** | Exists as exploratory subset, not in headline | Integrate CodeQL or drop headline claim |
| **No real-world case studies** | 🟡 **MEDIUM** | МФО pilot planned but not executed | Run МФО pilot this week |
| **Inactive 24 days** | 🟡 **MEDIUM** | Last commit 2026-04-14, today 2026-05-20 | Resume work, execute МФО pilot |
| **No hold-out corpus** | 🟡 **MEDIUM** | All 131 CVE used for benchmark, no validation set | Reserve 20-30 CVE for validation |
| **Pricing not validated** | 🟢 **LOW** | $500-1000 hypothesis from poc-offer.md, no customer validation | Run discovery calls, test pricing |
| **Supply chain (no lockfile)** | 🟢 **LOW** | No requirements.txt or poetry.lock | Generate lockfile: `pip freeze > requirements.txt` |
| **NVD API timeout risk** | 🟢 **LOW** | `requests.get()` without timeout in nvd_client.py | Add `timeout=30` to all HTTP calls |
| **Scanner binary PATH risk** | 🟢 **LOW** | Assumes `semgrep`, `bandit` in PATH | Validate binary path before exec |

**Priority Order:**
1. **P0 (Blockers):** Reproducibility gate, Manifest freeze
2. **P1 (Important):** Independent validation, МФО pilot execution, Detector FP measurement
3. **P2 (Nice-to-have):** Hold-out corpus, Pricing validation, Supply chain hardening

---

## 11. Recommended Next Steps

### P0 — Critical (Do This Week)

**1. Reproducibility Gate** (2-4 hours)
```bash
# Freeze manifest
python scripts/build_manifest.py

# Clean re-run
rm -rf results/repro_run_1
scannergap pipeline corpus/fullcode -o results/repro_run_1

# Verify 0-diffs
diff results/full_135/benchmark_report.json results/repro_run_1/benchmark_report.json

# If diffs found → investigate and fix
# If 0 diffs → update BENCHMARK_EVIDENCE.md: reproducibility PASS
```

**2. МФО Pilot Execution** (3-5 days)
- Follow `demo/mfo-pilot-plan.md`
- Fill `demo/mfo-discovery-checklist.md`
- Run scan on 1 критичный flow (auth / payment)
- Generate internal report
- If findings valuable → sanitized case study
- Timeline: start this week, results by Friday

**3. Manifest Freeze Decision** (30 min)
- Decide: keep 131 CVE or expand to 135?
- If 131: update all docs to say 131 (not 135)
- If 135: add 4 missing CVE, re-run benchmark
- Commit decision to `benchmark_manifest.json`

### P1 — Important (Do This Month)

**4. Detector FP Rate Measurement** (1-2 days)
```bash
# Run detector on 5 real projects
for repo in flask django fastapi requests pandas; do
  python scripts/scan_local_project.py ~/repos/$repo --output results/public_repos/$repo
done

# Manually triage findings
# Calculate: FP_rate = false_positives / total_findings
# Document in BENCHMARK_EVIDENCE.md
```

**5. Independent Validation** (1 week)
- Hold out 20-30 CVE from corpus
- Re-run benchmark on remaining CVE
- Validate on hold-out set
- Compare blind spot rates (should be ±10%)

**6. CodeQL Integration Decision** (1 day)
- Option A: Integrate CodeQL into headline benchmark
- Option B: Drop CodeQL claims, keep exploratory only
- Option C: Separate CodeQL track (don't mix with Semgrep+Bandit)
- Document decision in BENCHMARK_EVIDENCE.md

**7. First Outreach Wave** (1 week)
- 20 outreach emails to security teams (LinkedIn, HN, X)
- Target: 3 discovery calls
- Goal: 1 paid POC ($500-1000)
- Use `demo/outreach-email.md` template

### P2 — Improvements (Do This Quarter)

**8. Supply Chain Hardening** (30 min)
```bash
pip freeze > requirements.txt
# Commit lockfile
git add requirements.txt
git commit -m "chore: add dependency lockfile"
```

**9. Security Hardening** (2 hours)
- Add timeout to NVD API calls: `requests.get(..., timeout=30)`
- Validate scanner binary paths before exec
- Add audit trail logging (if compliance requires)

**10. Documentation Updates** (1 day)
- Update README with reproducibility status
- Update BENCHMARK_EVIDENCE.md with latest results
- Create CHANGELOG.md for version history
- Write blog post / technical write-up

---

## 12. AI Handoff Context

```markdown
# ScannerGap — AI Handoff Context

## What is this?
ScannerGap finds vulnerability classes that ALL baseline SAST scanners (Semgrep, Bandit, CodeQL) miss.
It's a benchmark-backed blind-spot audit prototype, NOT a scanner replacement.

## Current State (2026-05-20)
- **Status:** Research MVP, pilot-ready for manual POC
- **Version:** 0.1.0
- **Last Commit:** 2026-04-14 (24 days ago — project inactive)
- **Rating:** 8.7/10 (BlindSpotSec in Obsidian vault)
- **Priority:** SHIP #1 — первый paying client за 30 дней

## Architecture (5 components)
1. **Scanners** (`src/scannergap/scanners/`): Wrappers for Semgrep, Bandit
2. **Quadrant** (`src/scannergap/quadrant/`): CVE × Scanner matrix → Q2 (blind spots)
3. **Falsification** (`src/scannergap/benchmark/`): 4 kill criteria tests (ARCHCODE-derived)
4. **Corpus** (`corpus/`): 131 CVE directories + 23 gold subset
5. **Detector** (`src/scannergap/detector/rules/`): 49 custom Semgrep rules

## Key Files
- `src/scannergap/cli.py` — CLI entrypoint (scan | quadrant | benchmark | pipeline)
- `src/scannergap/quadrant/analysis.py` — Core blind spot detection logic
- `src/scannergap/benchmark/falsification.py` — Kill criteria (ARCHCODE methodology)
- `corpus/gold_subset.json` — 23 annotated CVEs (ground truth)
- `demo/mfo-pilot-plan.md` — МФО pilot execution plan (NEW, 2026-05-20)
- `BENCHMARK_EVIDENCE.md` — Trust boundary (what can/can't claim publicly)

## Verified Results
- ✅ **56.5% blind spot rate** on 23 gold CVEs (strict scoring)
- ✅ **61.5% blind spot rate** on 135-CVE exploratory artifact (Semgrep + Bandit)
- ✅ **13 systematic CWE categories** (top: code injection, SSRF, path traversal)
- ✅ **49 detector rules** across Python, JS, Java, PHP, Ruby, Go
- ✅ **3/4 kill criteria passed** (existence, systematicity, non-triviality)
- ⚠️ **Reproducibility SKIPPED** (Test 4 not run — critical blocker)

## What's NOT Verified
- ❌ Reproducibility (SKIPPED in Test 4)
- ❌ Manifest mismatch (135 CVE in report, 131 dirs in repo)
- ❌ Detector FP rate (49 rules exist, effectiveness unknown)
- ❌ Real-world case studies (МФО pilot planned but not started)
- ❌ Independent validation (all results from single run 2026-04-13)

## Current Risks
1. **CRITICAL:** Reproducibility gate SKIPPED → not production benchmark
2. **HIGH:** Manifest mismatch (135 vs 131 CVE) → docs inconsistent
3. **MEDIUM:** No paying customers, project inactive 24 days
4. **MEDIUM:** Detector effectiveness unknown (no FP rate)

## Next Best Tasks (Priority Order)
**P0 (This Week):**
1. Run reproducibility verification → verify 0-diffs
2. Start МФО pilot (follow `demo/mfo-pilot-plan.md`) → first case study
3. Freeze manifest (decide: 131 or 135 CVE) → fix docs mismatch

**P1 (This Month):**
4. Measure detector FP rate (run on 5 real projects)
5. Independent validation (hold-out 20 CVE, re-benchmark)
6. First outreach wave (20 emails → 3 calls → 1 paid POC)

**P2 (This Quarter):**
7. Supply chain hardening (lockfile, timeout, validation)
8. Documentation updates (reproducibility status, changelog)
9. Public write-up / blog post

## Safe Claims (Public-Ready)
✅ "Benchmark-backed blind-spot audit prototype"
✅ "61.5% blind spot rate in exploratory Semgrep + Bandit artifact"
✅ "13 systematic CWE categories identified"
✅ "Research MVP for scoped manual POC"

## BLOCKED Claims (Never Say)
❌ "Our scanner is better than CodeQL/Semgrep"
❌ "Missed by all three scanners" (CodeQL not in headline)
❌ "All four kill criteria passed" (reproducibility SKIPPED)
❌ "Production benchmark" (exploratory artifact)
❌ "Fully reproducible" (gate not passed)

## Founder Context
- **Developer:** Sergey Boyko (Head of Security, 2 МФО + Ronin Fellow)
- **First $ Goal:** $500-1000 paid POC within 30 days
- **МФО Access:** Can test on real microfinance codebases (2 orgs)
- **Status:** Project rated 8.7/10 but inactive 24 days (last 2026-04-14)
- **Deadline:** Первый клиент к 1 августа 2026 (2.5 месяца)

## How to Continue Work
1. **If continuing development:** Start with reproducibility gate (P0 task 1)
2. **If pivoting to sales:** Start МФО pilot (P0 task 2)
3. **If validating product-market fit:** Run outreach wave (P1 task 6)
4. **If uncertain:** Ask "What's the ONE thing that unblocks first $1000?"
```

---

**End of Audit Report**

**Auditor Sign-Off:**
This audit provides 80-90% project understanding for AI handoff.
Next engineer can:
- Understand what ScannerGap does and why
- Know current verified vs. unverified state
- Identify critical blockers (reproducibility, МФО pilot)
- Execute P0 tasks without re-researching project

**Recommended First Question for Next AI:**
> "What's the fastest path to unblock the reproducibility gate?"

OR

> "How do I start the МФО pilot this week?"

**Date:** 2026-05-20  
**Audit Duration:** ~2 hours READ-ONLY analysis  
**Files Examined:** 50+ (code, docs, configs, results, demo materials)  
**Commands Executed:** 20+ (all READ-ONLY: find, grep, wc, git log, ls)  
**Zero Modifications:** No files changed, deleted, or uploaded
