# ScannerGap Sample Public-Repo Report

This sample uses public repositories only. It is designed for demo and outreach
conversations without exposing client code.

## Claims Boundary

This is not a vulnerability disclosure report.

ScannerGap findings are `REVIEW_CANDIDATE` items. They require manual triage before
they can be classified as confirmed vulnerabilities, false positives, safe-by-design
framework behavior, or documentation-only risks.

## Scope

| Repository | Why selected | Scan mode | Result |
|---|---|---|---|
| `fastapi/fastapi` | Popular Python API framework with many docs examples | all areas | 18 raw candidates, 0 runtime candidates |
| `django/django` | Large mature Python web framework with complex internals | runtime-only | 186 raw candidates, 171 runtime candidates |

Scanner command pattern:

```powershell
python scripts\scan_local_project.py <repo-path> --runner docker --output <output-dir> --timeout 900 --report-mode <all|runtime>
```

## Executive Summary

ScannerGap was able to scan large public repositories and produce structured review
queues. The strongest demo result is not the raw candidate count; it is the separation
between runtime code and non-runtime areas such as docs, examples, tests, scripts, and
CI.

FastAPI demonstrates why area filtering is essential: all 18 candidates were in
documentation/tutorial assets, with 0 candidates in the runtime `fastapi/` package.
Django demonstrates a different case: a large framework can produce many runtime
review candidates, but most still require framework-aware manual triage.

## FastAPI Result

Source report:

`results/public_repos/fastapi/summary.md`

Headline:

| Metric | Count |
|---|---:|
| Total raw candidates | 18 |
| Runtime candidates | 0 |
| Non-runtime candidates | 18 |
| Docs candidates | 6 |
| Docs source candidates | 12 |

Rule families:

| Rule family | Count | Interpretation |
|---|---:|---|
| DOM/XSS in docs JS | 6 | Documentation UI review candidates |
| Hardcoded tutorial secrets | 8 | Docs example risk, not production secret leak |
| JWT expiry review | 4 | Hardening prompt, not confirmed vulnerability |

Triage:

`NOT_APPLICABLE_TO_RUNTIME`

Safe wording:

> FastAPI produced 18 review candidates, all outside runtime package code. ScannerGap
> should not claim runtime vulnerabilities here. The value is showing that docs/tutorial
> examples need separate severity and triage handling.

Unsafe wording:

> ScannerGap found 18 vulnerabilities in FastAPI.

## Django Result

Source reports:

- `results/public_repos/django/summary.md`
- `results/public_repos/django_runtime/summary.md`

Headline:

| Metric | Count |
|---|---:|
| Total raw candidates | 186 |
| Runtime candidates | 171 |
| Non-runtime candidates | 15 |

Top runtime rule families:

| Rule family | Count | Triage framing |
|---|---:|---|
| Path traversal review | 71 | Needs source-to-sink context |
| `mark_safe` / safe-marking review | 50 | Often framework-internal, needs escape-before-safe analysis |
| SQL string construction | 34 | Needs identifier-vs-value interpolation review |
| MD5 usage | 10 | Check whether security-sensitive or cache/checksum-only |
| Pickle load | 7 | Ask whether attackers can write backing storage |

Manual triage examples:

| Candidate | Initial classification | Why |
|---|---|---|
| `django/conf/global_settings.py: SECRET_KEY = ""` | `FALSE_POSITIVE` | Empty framework default, not a leaked production secret |
| `django/utils/html.py: mark_safe(...)` | `NEEDS_CONTEXT` / often `SAFE_BY_DESIGN` | Django escapes then marks safe in trusted helper code |
| `django/contrib/postgres/operations.py` dynamic SQL | `NEEDS_CONTEXT` | Uses framework identifier quoting for DDL |
| Cache backend `pickle.loads()` | `NEEDS_CONTEXT` | Review depends on whether attacker can write cache storage |

Safe wording:

> Django produced a large runtime review queue. ScannerGap does not claim these are
> vulnerabilities. The value is prioritizing trust-boundary questions and showing where
> generic SAST rules need framework-aware triage.

Unsafe wording:

> ScannerGap found 171 runtime vulnerabilities in Django.

## What This Demonstrates

ScannerGap is useful as an audit accelerator when the goal is to answer:

- Which findings are in runtime code?
- Which findings are docs/tests/scripts/CI noise?
- Which classes require manual trust-boundary review?
- Which rules need framework-aware suppressions?
- Which findings are review candidates rather than confirmed vulnerabilities?

## What This Does Not Demonstrate

This sample does not prove:

- ScannerGap has high precision.
- ScannerGap finds all vulnerabilities.
- ScannerGap is a production benchmark.
- ScannerGap replaces Semgrep, CodeQL, Snyk, Checkmarx, Fortify, or manual AppSec review.

## Paid POC Framing

The first commercial offer should be a manual audit, not a SaaS claim:

> I can run a focused SAST blind-spot/effectiveness audit on one repository or service.
> The output separates runtime candidates from docs/tests/scripts noise, identifies
> false-positive classes, highlights blind-spot categories, and recommends custom rules
> or review checklist items.

## Deliverable Shape

| Section | Purpose |
|---|---|
| Scope | Repo/service, commit, tools, limitations |
| Runtime candidates | Actionable review queue |
| Non-runtime candidates | Docs/tests/scripts/CI noise and example risks |
| Triage table | `CONFIRMED`, `NEEDS_CONTEXT`, `FALSE_POSITIVE`, `SAFE_BY_DESIGN`, `NOT_APPLICABLE` |
| Blind-spot taxonomy | Classes that current scanner stack may miss or over-report |
| Recommendations | Rule tuning, custom rules, review checklist, process changes |

## Verdict

`audit_mvp_demo_ready_with_disclaimers`

The public-repo evidence is strong enough for CISO/AppSec demo conversations and a
small paid manual POC. It is not enough for a production scanner or benchmark claim.
