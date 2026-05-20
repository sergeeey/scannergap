# First 10 Outreach Plan

Goal: test whether buyers care about SAST noise, runtime-vs-docs separation, and
blind-spot triage enough to take a call or fund a small pilot.

## ICP

Prioritize people who already have SAST and feel its operational pain.

| Target | Why |
|---|---|
| AppSec lead | Owns scanner triage and custom rules |
| DevSecOps lead | Owns CI/SAST integration and developer friction |
| Security engineering manager | Cares about signal/noise and security roadmap |
| CISO in small/mid-size SaaS | Needs evidence for security controls |
| Engineering leader with compliance pressure | Needs practical control validation |

Avoid:

- teams with no SAST;
- teams expecting a full pentest;
- companies asking for production SaaS immediately;
- prospects who only want a free scanner.

## Offer

`Scanner Blind-Spot / SAST Effectiveness Audit`

Scope:

- one repository or service;
- existing SAST output if available;
- local read-only scan where approved;
- manual triage of top candidates;
- runtime vs docs/tests/scripts/CI separation;
- short recommendations.

Deliverable:

- 5-10 page Markdown/PDF report;
- executive summary;
- runtime candidate table;
- non-runtime/noise table;
- blind-spot taxonomy;
- custom rule or review checklist recommendations;
- 30-minute walkthrough.

Price hypothesis:

- `$500-1000` for first external pilot;
- `100k-300k KZT` for local/internal pilot.

## Message 1

Subject: Quick SAST signal/noise review?

Hi [Name],

I am testing BlindSpotSec, a small founder-led audit for teams that already use
SAST but want clearer signal.

The review separates:

- runtime findings from docs/tests/scripts/CI noise;
- review candidates from confirmed issues;
- false-positive classes from blind-spot classes;
- generic scanner output from custom-rule opportunities.

On public repos, this difference is material. For example, FastAPI produced 18 raw
candidates but 0 runtime candidates; Django produced a much larger runtime review
queue that needed framework-aware triage.

This is not a scanner replacement or pentest. It is a short evidence-backed SAST
effectiveness review for one repo/service.

Would a 15-minute walkthrough be useful?

## Message 2

Hi [Name],

Quick follow-up. The output is a short report, not a SaaS deployment:

1. runtime vs non-runtime candidate split;
2. top review candidates;
3. false-positive/noise classes;
4. likely blind spots;
5. custom rule or checklist recommendations.

Best fit is a team that already has Semgrep, CodeQL, Snyk, Checkmarx, Fortify, or
GitHub Advanced Security and wants to know what the scanner output actually means.

Would it make sense to test this on one repo?

## Discovery Questions

1. Which SAST tools do you currently run?
2. How many findings are currently open?
3. Do developers trust the scanner output?
4. Which findings waste the most time?
5. Do you separate runtime findings from docs/tests/examples?
6. Do you maintain custom rules?
7. Do audit/compliance teams ask for evidence that SAST controls are effective?
8. Would a small report on one repo be useful?

## Success Criteria

Outreach is working if:

- 10 targeted messages produce 2+ replies;
- 3 conversations produce 1 serious pilot discussion;
- 1 prospect agrees to share a repo or SAST output;
- 1 prospect pays or agrees to a scoped internal pilot.

If 10 targeted messages produce no replies, adjust positioning before building more features.
