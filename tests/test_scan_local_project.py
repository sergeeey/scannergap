"""Tests for local project scan reporting helpers."""

import importlib.util
import sys
from pathlib import Path


def load_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "scan_local_project.py"
    spec = importlib.util.spec_from_file_location("scan_local_project", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["scan_local_project"] = module
    spec.loader.exec_module(module)
    return module


def test_parse_semgrep_findings_extracts_cwe() -> None:
    module = load_module()
    raw = {
        "results": [
            {
                "check_id": "blindspot-python-boto3-ssrf",
                "path": "app.py",
                "start": {"line": 12},
                "extra": {
                    "severity": "WARNING",
                    "message": "endpoint_url may be user controlled",
                    "metadata": {"cwe": ["CWE-918: Server-Side Request Forgery"]},
                },
            }
        ]
    }

    findings = module.parse_semgrep_findings(raw)

    assert len(findings) == 1
    assert findings[0].rule_id == "blindspot-python-boto3-ssrf"
    assert findings[0].severity == "WARNING"
    assert findings[0].effective_severity == "WARNING"
    assert findings[0].area == "runtime"
    assert findings[0].triage_hint == "NEEDS_CONTEXT"
    assert findings[0].cwe_ids == ["CWE-918"]


def test_render_summary_marks_review_candidates() -> None:
    module = load_module()
    finding = module.LocalFinding(
        rule_id="blindspot-js-new-function",
        severity="ERROR",
        effective_severity="ERROR",
        area="runtime",
        triage_hint="NEEDS_CONTEXT",
        path="src/app.js",
        line=42,
        message="new Function called with dynamic input",
        cwe_ids=["CWE-94"],
    )

    summary = module.render_summary(Path("demo"), [finding], 0)

    assert "REVIEW_CANDIDATE" in summary
    assert "does not confirm exploitability" in summary
    assert "CWE-94" in summary
    assert "Area Summary" in summary


def test_docs_examples_are_downgraded_and_classified() -> None:
    module = load_module()
    raw = {
        "results": [
            {
                "check_id": "blindspot-hardcoded-secret-assignment",
                "path": "/scan/target/docs_src/security/tutorial.py",
                "start": {"line": 10},
                "extra": {
                    "severity": "ERROR",
                    "message": "Secret or credential assigned as a string literal.",
                    "metadata": {"cwe": "CWE-798: Hardcoded Credentials"},
                },
            }
        ]
    }

    findings = module.parse_semgrep_findings(raw)

    assert findings[0].severity == "ERROR"
    assert findings[0].effective_severity == "LOW"
    assert findings[0].area == "docs_src"
    assert findings[0].triage_hint == "DOCS_EXAMPLE_RISK"


def test_runtime_report_mode_hides_non_runtime_candidates() -> None:
    module = load_module()
    findings = [
        module.LocalFinding(
            rule_id="runtime-rule",
            severity="ERROR",
            effective_severity="ERROR",
            area="runtime",
            triage_hint="NEEDS_CONTEXT",
            path="src/app.py",
            line=1,
            message="runtime candidate",
            cwe_ids=["CWE-79"],
        ),
        module.LocalFinding(
            rule_id="docs-rule",
            severity="ERROR",
            effective_severity="LOW",
            area="docs",
            triage_hint="DOCS_EXAMPLE_RISK",
            path="docs/tutorial.py",
            line=2,
            message="docs candidate",
            cwe_ids=["CWE-798"],
        ),
    ]

    summary = module.render_summary(Path("demo"), findings, 0, report_mode="runtime")

    assert "Report mode: `runtime`" in summary
    assert "Runtime candidates: `1`" in summary
    assert "Non-runtime candidates: `1`" in summary
    assert "runtime candidate" in summary
    assert "docs candidate" not in summary
    assert "Hidden Non-Runtime Candidates" in summary


def test_run_semgrep_dispatches_to_docker(monkeypatch) -> None:
    module = load_module()
    called = {}

    def fake_docker(target, rules, timeout, docker_image):
        called["args"] = (target, rules, timeout, docker_image)
        return {"results": []}, "", 0

    monkeypatch.setattr(module, "run_docker_semgrep", fake_docker)

    raw, stderr, exit_code = module.run_semgrep(
        target=Path("target"),
        rules=Path("rules"),
        timeout=10,
        runner="docker",
        docker_image="semgrep/semgrep:test",
    )

    assert raw == {"results": []}
    assert stderr == ""
    assert exit_code == 0
    assert called["args"] == (Path("target"), Path("rules"), 10, "semgrep/semgrep:test")
