# BlindSpotSec / ScannerGap — CISO Demo Script

## One-line framing

BlindSpotSec is a benchmark-backed blind-spot audit prototype for finding where existing SAST pipelines may systematically miss vulnerability classes.

It is not a scanner replacement.
It is not a certified production benchmark.
It is a focused audit method for identifying scanner coverage gaps.

---

## Problem

Most SAST pipelines answer:

> "Did this scanner find this known rule pattern?"

BlindSpotSec asks a different question:

> "Which classes of real vulnerabilities are systematically invisible to my current scanner stack?"

The focus is not individual bugs, but recurring blind-spot classes.

---

## What the current prototype does

The current ScannerGap prototype:

- runs selected SAST tools over a curated CVE corpus;
- records HIT / PARTIAL / MISS outcomes;
- builds scanner coverage matrices;
- groups misses into blind-spot taxonomy categories;
- produces evidence-backed reports for security teams.

Current benchmark evidence is exploratory and scoped.
The main current artifact covers Semgrep + Bandit.
CodeQL evidence is currently exploratory and separated from the headline claim.

---

## Blind-spot categories

Examples of classes the methodology investigates:

1. Cross-function taint gaps
2. Semantic/context blindness
3. Unknown or framework-specific sinks
4. Partial mitigation bypasses
5. Scanner rule coverage gaps

---

## What I would show in a 10-15 minute demo

1. The problem: scanner coverage is not vulnerability class coverage.
2. One CVE example where standard scanning misses the issue.
3. HIT / PARTIAL / MISS rubric.
4. Coverage matrix.
5. Blind-spot taxonomy.
6. Example recommendation: custom rule, process change, or review checklist.
7. What a paid pilot report would look like.

---

## What I will not claim

I will not claim:

- this does not replace SAST;
- this does not prove every scanner misses every case;
- this is a production SaaS;
- this is a certified 3-scanner benchmark;
- this finds every vulnerability;
- this is a full pentest.

---

## Safe demo wording

"This prototype helps identify likely blind spots in your current SAST pipeline by comparing known vulnerability classes against scanner behavior. The first paid pilot would be a scoped manual audit, not a production SaaS deployment."

---

## Ideal pilot customer

Best fit:

- fintech;
- SaaS company;
- security-conscious engineering team;
- already uses Semgrep / Bandit / CodeQL / Snyk / GitHub Advanced Security;
- wants to know what their scanner stack may be missing.

Not ideal:

- company expecting a full pentest;
- company wanting a production SaaS today;
- company with no existing security process.

---

## Demo close

"Would it be useful if I took one service or one repo from your environment and produced a short scanner blind-spot report showing where your current SAST stack may be under-covering real vulnerability classes?"
