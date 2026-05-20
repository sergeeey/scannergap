# ScannerGap
## The Gap Between Tenable and Your Code

---

## Slide 1: What We Cover Today

Tenable/Nessus protects our infrastructure: ports, versions, configs.

**But who protects our source code?**

```
Code → Code Review (manual) → CI/CD → Deploy → Tenable
  ↑                                               ↑
  Nothing automated here              Finds infra vulns here
```

Logical bugs, injection flaws, SSRF, unsafe deserialization
in our code — Tenable can't see them. They're not in its scope.

---

## Slide 2: "We'd catch it in code review"

Would we? The current evidence has an exploratory 135-CVE Semgrep + Bandit artifact, plus separate CodeQL subset evidence:

| Tool | What it missed |
|------|---------------|
| Semgrep (all rule packs) | 64% |
| Bandit (Python SAST) | ~90% |
| CodeQL exploratory subset | scoped separately |
| **Semgrep + Bandit artifact** | **61.5%** |

These are useful baselines, not a production benchmark across every scanner.
The demo point is to identify where scanner coverage needs deeper review.

---

## Slide 3: Why Do They Miss So Much?

Static analyzers work by **pattern matching**: "if you see `eval(X)`, flag it."

Real vulnerabilities are more subtle:

| Pattern | Example | Scanner sees? |
|---------|---------|:---:|
| Data flows through 3 functions | `input → helper() → process() → send_file()` | No |
| Check exists, but in wrong place | `validate()` in function A, missing in function B | No |
| Dangerous API, not in scanner's list | `boto3(endpoint_url=user_input)` = SSRF | No |
| Protection on one path, not another | SSRF filter on /import, missing on /roles | No |

**It's not a bug in the tool. It's a structural limitation of the approach.**

---

## Slide 4: What This Means For Us

Our current security posture:

| Layer | Tool | What it covers |
|-------|------|---------------|
| Infrastructure | Tenable/Nessus | Ports, CVEs in packages, configs |
| Code | **Nothing** | SQL injection, SSRF, eval, deserialization |

Every line of code we deploy goes through **zero automated security checks**
for logical vulnerabilities. Tenable finds known CVEs in dependencies —
not bugs in our own code.

---

## Slide 5: ScannerGap — What I Built

49 prototype rule IDs for vulnerability patterns that baseline scanners may miss.

Works locally, nothing leaves the machine:

```
semgrep scan --config scannergap/detector/rules/ ./our-repo
```

| What it catches | Why standard tools miss it |
|-----------------|--------------------------|
| SSRF via boto3/cloud SDKs | Not in standard sink database |
| Unsafe YAML/template rendering | Looks like normal code |
| `new Function()` injection | Scanners only flag `eval()` |
| Path traversal via zipfile | Scanners flag tarfile but not zipfile |

---

## Slide 6: Live Demo

*[Run semgrep on an open-source fintech project]*

Standard scanner found: N issues
ScannerGap found: M additional issues that were invisible

Each additional finding is a prompt for review, not automatic proof of exploitability.

---

## Slide 7: Proposal

**Phase 1 (this week)** — 5 minutes, zero risk:
- Run prototype rules on our repos, see if anything comes up
- Fully local, no cloud, no API calls

**Phase 2 (if findings appear)** — triage:
- Treat findings like any security finding
- Prioritize by severity and reachability

**Phase 3 (this quarter)** — integrate:
- Add rules to CI/CD alongside existing checks
- Keep existing SAST and infrastructure scanning
- Add focused blind-spot review where coverage is thin

---

## Questions?

One-pager: `demo/one-pager.md`
Full report: `docs/findings.md`
Rules: `src/scannergap/detector/rules/`
