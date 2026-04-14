# ScannerGap
## What Your SAST Scanner Doesn't See

---

## Slide 1: The Problem

Your security pipeline looks solid:

```
Code → Semgrep/CodeQL → CI/CD → Production ✓
```

**But what if the scanner is blind to 61% of real vulnerabilities?**

Not because it's bad. Because the entire class of tools
has systematic gaps in what they can detect.

---

## Slide 2: Proof

We tested **135 real CVEs** (2023-2025) against 3 scanners:

| Scanner | Blind Rate |
|---------|-----------|
| Semgrep (all rule packs) | 64% |
| Bandit | ~90% |
| CodeQL (104 security queries) | 76% |
| **All 3 combined** | **61.5%** |

These are not theoretical bugs. These are CVEs from NVD
with GitHub patches. They were exploited in production.

---

## Slide 3: Why?

Scanners work by **pattern matching** and **local data flow**.

Real vulnerabilities increasingly require:

| What's needed | Example | Scanner sees? |
|---------------|---------|:---:|
| Cross-function taint | Path goes through 3 functions before hitting `send_file()` | ✗ |
| Business logic | Guard exists in function A but not sibling function B | ✗ |
| Non-standard sinks | `boto3(endpoint_url=user_input)` = SSRF | ✗ |
| Partial bypass | SSRF filter on /import but not on /roles | ✗ |

**Analogy**: checking every room for fire, but not the hallways between them.

---

## Slide 4: Live Demo

```bash
# 1. What your scanner finds (standard)
semgrep scan --config auto ./example-app
# Result: 12 findings

# 2. What it MISSES (our blind spot rules)
semgrep scan --config scannergap/detector/rules/ ./example-app
# Result: 5 NEW findings your scanner never reported
```

Each new finding is a vulnerability class your current
pipeline gives false confidence on.

---

## Slide 5: The 4 Blind Spot Types

**Type I: Cross-function taint gaps**
Scanner loses track of data across function calls.
→ 60-80% of these bugs are invisible.

**Type II: Semantic context blindness**
Scanner sees the code, not the meaning.
→ A check exists... but in the wrong place.

**Type III: Non-standard sinks**
Scanner knows `eval()` is bad but not `new Function()`.
→ 100% invisible until you add the pattern.

**Type IV: Partial mitigation bypass**
Scanner sees the fix... on a different code path.
→ "Protected" endpoint is actually exposed.

---

## Slide 6: What We Built

**ScannerGap** = Benchmark + Detector

| Component | What it does |
|-----------|-------------|
| Benchmark | 135 CVEs with strict scoring rubric |
| 26 Semgrep rules | Catches patterns standard rules miss |
| Pipeline CLI | `scannergap pipeline ./code` — one command |
| Methodology | Transferred from genomics research (ARCHCODE) |

Detector closes **30% of blind spots** with zero configuration.
Remaining 70% require next-gen analysis (interprocedural + semantic).

---

## Slide 7: For Our Team

**Immediate action** (this week):
→ Run 26 blind spot rules on our repos. Free. Local. 5 minutes.

**If findings appear**:
→ Triage like regular security findings
→ These are the bugs our pipeline currently marks as "clean"

**Longer term**:
→ Add blind spot rules to CI alongside existing scanner
→ Track blind spot coverage as a metric
→ Consider: which of our services have the most cross-function logic?

---

## Questions?

Full report: `docs/findings.md`
Rules: `src/scannergap/detector/rules/`
Run: `semgrep scan --config detector/rules/ /path/to/code`
