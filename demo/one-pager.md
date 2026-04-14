<h1 align="center">ScannerGap</h1>
<h3 align="center">Security Blind Spot Benchmark</h3>

---

### The Gap

| Layer | Tool | Covers |
|:------|:-----|:-------|
| Infrastructure | Tenable / Nessus | Ports, package CVEs, configs |
| **Code** | **Nothing** | **SQL injection, SSRF, eval, deserialization** |

Every line of code we deploy goes through **zero automated checks**
for logical vulnerabilities.

---

### What We Found

```
135 real CVEs (NVD, 2023-2025)
x 3 scanners (Semgrep + Bandit + CodeQL)
= 61.5% invisible to ALL THREE

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

**26 detection rules** for patterns standard scanners miss.

Covers Python, JavaScript, Java, PHP, Ruby.

Runs locally. Nothing leaves the machine.

**Impact**: closes 30% of blind spots with zero configuration.

---

### Proposed Action

| Phase | What | Effort |
|:------|:-----|:-------|
| 1. Try | Run 26 rules on our repos | 5 minutes |
| 2. Triage | Review findings | 1-2 hours |
| 3. Integrate | Add to CI alongside Tenable | 1 day |

---

<p align="center">
  <em>Tenable covers infrastructure. ScannerGap covers code.</em><br>
  <em>Together = full stack security.</em>
</p>
