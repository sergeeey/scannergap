# BlindSpotSec Sample Report

This is a redacted sample structure for a first paid POC. Replace example content with client-specific evidence only after scope and data-handling terms are agreed.

## 1. Executive Summary

We reviewed one repository/service to identify where the current SAST pipeline may under-cover known vulnerability classes.

This was a scoped scanner-gap assessment, not a full penetration test and not a guarantee of complete vulnerability discovery.

Example summary:

- Existing scanners cover straightforward local patterns reasonably well.
- Potential blind spots appear in cross-function data flows and framework-specific sinks.
- The highest-value next step is a small review checklist plus one or two custom detection rules for the most critical framework paths.

## 2. Scope

| Item | Value |
|---|---|
| Repository/service | `<redacted>` |
| Languages/frameworks | `<redacted>` |
| SAST tools reviewed | `<redacted>` |
| Critical flows reviewed | `<redacted>` |
| Review dates | `<redacted>` |

## 3. Scanner Coverage Matrix

| Vulnerability class | Existing scanner coverage | Manual review result | Confidence |
|---|---|---|---|
| Cross-function taint | Partial | Needs targeted review | Medium |
| Semantic/context bypass | Low | Potential blind spot | Medium |
| Framework-specific sink | Unknown | Needs custom rule | Low-Medium |
| Partial mitigation bypass | Unknown | Review checklist recommended | Medium |

## 4. Blind-Spot Taxonomy

### Cross-function taint gaps

Data moves across helper functions or service layers before reaching a sensitive sink. Baseline rules may only see one function at a time.

### Semantic/context blindness

A safe-looking guard exists in one code path, but a related path may bypass it.

### Unknown sinks

Framework APIs can become security-sensitive even when they are not classic sinks such as `eval`, `exec`, or raw SQL.

### Partial mitigation bypass

A mitigation exists, but is not consistently applied across all entry points.

## 5. Concrete Examples

### Example 1: Cross-function flow

Evidence:

- Source: `<file/function redacted>`
- Scanner output: `<summary redacted>`
- Manual observation: data crosses multiple functions before the sink.

Recommendation:

- Add targeted review checklist for this flow.
- Consider a custom Semgrep rule or framework-specific test.

### Example 2: Framework-specific sink

Evidence:

- Source: `<file/function redacted>`
- Scanner output: no relevant finding or partial finding.
- Manual observation: API call behavior depends on user-controlled configuration.

Recommendation:

- Add allowlist validation.
- Add a focused detection rule for this API pattern.

## 6. Recommendations

1. Add a review checklist for cross-function data flows into sensitive sinks.
2. Add custom rules for framework-specific sinks used in critical services.
3. Treat partial scanner findings as prompts for manual review, not as proof of coverage.
4. Re-run this review after major framework or routing changes.

## 7. Limitations

- This review is scoped and does not replace a pentest.
- It does not prove the absence of vulnerabilities.
- It focuses on scanner coverage gaps, not general secure-code review.
- Findings depend on provided code, scanner outputs, and agreed scope.

## 8. Next Steps

| Priority | Action | Owner | Timeline |
|---|---|---|---|
| P1 | Review critical flow checklist | Client AppSec | 1 week |
| P1 | Add custom detection rule candidate | BlindSpotSec | 1 week |
| P2 | Expand to adjacent services | Joint | 2-4 weeks |
