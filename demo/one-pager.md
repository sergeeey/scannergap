<h1 align="center">ScannerGap</h1>
<h3 align="center">Security Blind Spot Benchmark</h3>

---

### The Gap

| Layer | Tool | Covers |
|:------|:-----|:-------|
| Infrastructure | Tenable / Nessus | Ports, package CVEs, configs |
| **Code** | **SAST + review** | **Logical bugs still need coverage checks** |

Many logical vulnerabilities still require semantic or cross-function review
beyond baseline pattern checks.

---

### What We Found

```
Exploratory 135-CVE artifact (NVD, 2023-2025)
Semgrep + Bandit baseline
= 61.5% missed by both baseline scanners

Not random --- 13 systematic categories.
```

---

### Why Scanners Miss These

| Blind Spot Type | What Happens | Blind Rate |
|:----------------|:-------------|:----------:|
| Cross-function taint | Data tracked in one function, lost across calls | 60-80% |
| Semantic blindness | Check exists in function A, missing in B | 56-78% |
| Unknown sinks | `boto3(endpoint_url=...)` not in scanner's database | 100% |
| Partial bypass | SSRF filter on path A, missing on path B | varies |

---

### What ScannerGap Does

**49 prototype Semgrep rule IDs** for blind-spot patterns.

Covers Python, JavaScript, Java, PHP, Ruby.

Runs locally. Nothing leaves the machine.

Use as a benchmark-backed audit aid, not as a scanner replacement.

---

### Proposed Action

| Phase | What | Effort |
|:------|:-----|:-------|
| 1. Try | Run prototype rules on our repos | 5 minutes |
| 2. Triage | Review findings | 1-2 hours |
| 3. Integrate | Add to CI alongside Tenable | 1 day |

---

<p align="center">
  <em>ScannerGap helps review where scanner coverage may be thin.</em><br>
  <em>It complements existing SAST and security review.</em>
</p>
