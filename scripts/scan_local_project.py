"""Run ScannerGap detector rules against a normal local project.

This is for demos and paid-POC smoke tests. Findings are review candidates,
not confirmed vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_RULES = Path("src/scannergap/detector/rules")


@dataclass(frozen=True)
class LocalFinding:
    rule_id: str
    severity: str
    effective_severity: str
    area: str
    triage_hint: str
    path: str
    line: int
    message: str
    cwe_ids: list[str]


DOC_AREAS = {"docs", "docs_src", "examples", "tutorials"}
NON_RUNTIME_AREAS = DOC_AREAS | {"tests", "ci", "scripts"}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "WARNING": 2, "ERROR": 3}


def normalize_scan_path(path_value: str) -> str:
    path_text = path_value.replace("\\", "/")
    marker = "/scan/target/"
    if marker in path_text:
        return path_text.split(marker, maxsplit=1)[1]
    return path_text.lstrip("/")


def classify_area(path_value: str) -> str:
    rel_path = normalize_scan_path(path_value)
    parts = [part for part in rel_path.split("/") if part]
    if not parts:
        return "runtime"

    first = parts[0].lower()
    second = parts[1].lower() if len(parts) > 1 else ""

    if first in {".github", ".gitlab", ".circleci"}:
        return "ci"
    if first in {"docs", "doc"}:
        return "docs"
    if first in {"docs_src", "doc_src"}:
        return "docs_src"
    if first in {"tests", "test", "__tests__"} or second in {"tests", "__tests__"}:
        return "tests"
    if first in {"examples", "example", "tutorials", "tutorial"}:
        return "examples"
    if first in {"scripts", "script", "tools", "tooling"}:
        return "scripts"
    return "runtime"


def downgrade_severity_for_area(severity: str, area: str) -> str:
    normalized = severity.upper()
    if area in DOC_AREAS:
        return "LOW"
    if area in {"tests", "ci"} and SEVERITY_ORDER.get(normalized, 0) > SEVERITY_ORDER["WARNING"]:
        return "WARNING"
    return normalized


def triage_hint_for_area(area: str) -> str:
    if area in DOC_AREAS:
        return "DOCS_EXAMPLE_RISK"
    if area == "tests":
        return "TEST_CONTEXT"
    if area == "ci":
        return "CI_CONTEXT"
    if area == "scripts":
        return "NEEDS_CONTEXT"
    return "NEEDS_CONTEXT"


def normalize_cwe(value: Any) -> list[str]:
    if not value:
        return []
    raw_values = value if isinstance(value, list) else [value]
    cwes: list[str] = []
    for item in raw_values:
        text = str(item)
        cwe = text.split(":", maxsplit=1)[0].strip()
        if cwe.startswith("CWE-") and cwe not in cwes:
            cwes.append(cwe)
    return cwes


def parse_semgrep_findings(raw: dict[str, Any]) -> list[LocalFinding]:
    findings: list[LocalFinding] = []
    for match in raw.get("results", []):
        extra = match.get("extra", {})
        metadata = extra.get("metadata", {})
        path_value = match.get("path", "")
        severity = extra.get("severity", "INFO").upper()
        area = classify_area(path_value)
        findings.append(
            LocalFinding(
                rule_id=match.get("check_id", ""),
                severity=severity,
                effective_severity=downgrade_severity_for_area(severity, area),
                area=area,
                triage_hint=triage_hint_for_area(area),
                path=path_value,
                line=int(match.get("start", {}).get("line", 0)),
                message=extra.get("message", "").strip(),
                cwe_ids=normalize_cwe(metadata.get("cwe")),
            )
        )
    return findings


def run_local_semgrep(target: Path, rules: Path, timeout: int) -> tuple[dict[str, Any], str, int]:
    command = [
        "semgrep",
        "scan",
        "--config",
        str(rules),
        "--json",
        "--quiet",
        str(target),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    raw = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
    return raw, result.stderr, result.returncode


def run_docker_semgrep(
    target: Path,
    rules: Path,
    timeout: int,
    docker_image: str,
) -> tuple[dict[str, Any], str, int]:
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{target}:/scan/target:ro",
        "-v",
        f"{rules}:/scan/rules:ro",
        docker_image,
        "semgrep",
        "scan",
        "--config",
        "/scan/rules",
        "--json",
        "--quiet",
        "/scan/target",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    raw = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
    return raw, result.stderr, result.returncode


def run_semgrep(
    target: Path,
    rules: Path,
    timeout: int,
    runner: str,
    docker_image: str,
) -> tuple[dict[str, Any], str, int]:
    if runner == "docker":
        return run_docker_semgrep(target, rules, timeout, docker_image)
    return run_local_semgrep(target, rules, timeout)


def filter_findings(findings: list[LocalFinding], report_mode: str) -> list[LocalFinding]:
    if report_mode == "runtime":
        return [finding for finding in findings if finding.area == "runtime"]
    return findings


def render_summary(
    target: Path,
    findings: list[LocalFinding],
    semgrep_exit: int,
    report_mode: str = "all",
) -> str:
    visible_findings = filter_findings(findings, report_mode)
    severity_counts = Counter(f.effective_severity for f in visible_findings)
    area_counts = Counter(f.area for f in findings)
    visible_area_counts = Counter(f.area for f in visible_findings)
    non_runtime_count = sum(count for area, count in area_counts.items() if area in NON_RUNTIME_AREAS)

    lines = [
        "# ScannerGap Local Project Scan",
        "",
        "## Status",
        "",
        "This report lists REVIEW_CANDIDATE findings from prototype ScannerGap Semgrep rules.",
        "It does not confirm exploitability and does not replace SAST, code review, or pentesting.",
        "",
        "## Scope",
        "",
        f"- Target: `{target}`",
        f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Semgrep exit code: `{semgrep_exit}`",
        f"- Report mode: `{report_mode}`",
        f"- Finding count: `{len(visible_findings)}`",
        f"- Total raw candidates: `{len(findings)}`",
        f"- Runtime candidates: `{area_counts.get('runtime', 0)}`",
        f"- Non-runtime candidates: `{non_runtime_count}`",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    for severity, count in sorted(severity_counts.items()):
        lines.append(f"| {severity} | {count} |")
    if not severity_counts:
        lines.append("| none | 0 |")

    lines.extend(["", "## Area Summary", "", "| Area | Visible | Total |", "|---|---:|---:|"])
    all_areas = sorted(set(area_counts) | set(visible_area_counts))
    for area in all_areas:
        lines.append(f"| {area} | {visible_area_counts.get(area, 0)} | {area_counts.get(area, 0)} |")
    if not area_counts:
        lines.append("| none | 0 | 0 |")

    lines.extend(["", "## CWE Summary", "", "| CWE | Count |", "|---|---:|"])
    visible_cwe_counts = Counter(cwe for finding in visible_findings for cwe in finding.cwe_ids)
    for cwe, count in sorted(visible_cwe_counts.items()):
        lines.append(f"| {cwe} | {count} |")
    if not visible_cwe_counts:
        lines.append("| none | 0 |")

    lines.extend(
        [
            "",
            "## Review Candidates",
            "",
            "| Status | Severity | Original | Area | Triage Hint | Rule | Location | CWE | Message |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )

    for finding in visible_findings:
        message = finding.message.replace("|", "\\|").replace("\n", " ")
        cwes = ", ".join(finding.cwe_ids) if finding.cwe_ids else ""
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.append(
            f"| REVIEW_CANDIDATE | {finding.effective_severity} | {finding.severity} | "
            f"{finding.area} | {finding.triage_hint} | `{finding.rule_id}` | "
            f"`{location}` | {cwes} | {message} |"
        )
    if not visible_findings:
        lines.append("| none | - | - | - | - | - | - | - | No review candidates found. |")

    if report_mode == "runtime" and non_runtime_count:
        lines.extend(
            [
                "",
                "## Hidden Non-Runtime Candidates",
                "",
                f"`{non_runtime_count}` candidates were outside runtime areas and hidden by runtime report mode.",
                "Use `--report-mode all` to inspect docs, examples, tests, scripts, and CI candidates.",
            ]
        )

    lines.extend(
        [
            "",
            "## Next Steps",
            "",
            "1. Manually review each candidate in application context.",
            "2. Mark each item as CONFIRMED, PARTIAL, FALSE_POSITIVE, or NEEDS_CONTEXT.",
            "3. Convert repeated true positives into custom rules or review checklist items.",
        ]
    )

    return "\n".join(lines) + "\n"


def write_outputs(
    output_dir: Path,
    raw: dict[str, Any],
    stderr: str,
    target: Path,
    findings: list[LocalFinding],
    semgrep_exit: int,
    report_mode: str,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "semgrep_raw.json").write_text(
        json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (output_dir / "semgrep_stderr.txt").write_text(stderr, encoding="utf-8")
    (output_dir / "summary.md").write_text(
        render_summary(target, findings, semgrep_exit, report_mode),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a normal local project with ScannerGap rules"
    )
    parser.add_argument("target", help="Project directory to scan")
    parser.add_argument("--output", required=True, help="Output directory for raw JSON and summary")
    parser.add_argument("--rules", default=str(DEFAULT_RULES), help="Semgrep rules directory")
    parser.add_argument("--timeout", type=int, default=300, help="Semgrep timeout in seconds")
    parser.add_argument(
        "--report-mode",
        choices=["all", "runtime"],
        default="all",
        help="Use 'runtime' to show only runtime candidates while retaining raw Semgrep JSON",
    )
    parser.add_argument(
        "--runner",
        choices=["local", "docker"],
        default="local",
        help="Run local semgrep executable or semgrep Docker image",
    )
    parser.add_argument(
        "--docker-image",
        default="semgrep/semgrep:latest",
        help="Docker image used when --runner docker is selected",
    )
    args = parser.parse_args()

    target = Path(args.target).resolve()
    rules = Path(args.rules).resolve()
    output = Path(args.output).resolve()

    if not target.exists():
        print(f"FAIL: target does not exist: {target}", file=sys.stderr)
        sys.exit(2)
    if not rules.exists():
        print(f"FAIL: rules directory does not exist: {rules}", file=sys.stderr)
        sys.exit(2)

    try:
        raw, stderr, exit_code = run_semgrep(
            target=target,
            rules=rules,
            timeout=args.timeout,
            runner=args.runner,
            docker_image=args.docker_image,
        )
    except FileNotFoundError:
        executable = "docker" if args.runner == "docker" else "semgrep"
        print(f"FAIL: {executable} executable not found", file=sys.stderr)
        sys.exit(127)
    except subprocess.TimeoutExpired:
        print(f"FAIL: semgrep timed out after {args.timeout}s", file=sys.stderr)
        sys.exit(124)
    except json.JSONDecodeError as exc:
        print(f"FAIL: semgrep returned invalid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    findings = parse_semgrep_findings(raw)
    write_outputs(output, raw, stderr, target, findings, exit_code, args.report_mode)

    print(f"Wrote local scan report to {output}")
    visible_count = len(filter_findings(findings, args.report_mode))
    print(f"Review candidates: {visible_count}")
    if args.report_mode == "runtime":
        print(f"Total raw candidates: {len(findings)}")
    if exit_code not in (0, 1):
        print(f"WARN: semgrep exited with code {exit_code}; inspect semgrep_stderr.txt")


if __name__ == "__main__":
    main()
