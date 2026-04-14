"""Benchmark report generator.

Produces a reproducible report with:
- Coverage matrix summary
- Quadrant distribution
- Blind spot taxonomy
- Falsification test results
- Kill criteria status
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import structlog

from scannergap.benchmark.falsification import FalsificationResult, Verdict
from scannergap.quadrant.analysis import QuadrantResult

log = structlog.get_logger()


def generate_report(
    quadrant_result: QuadrantResult,
    falsification_results: list[FalsificationResult],
    cwe_clusters: dict[str, list[str]],
    scanner_names: list[str],
    corpus_size: int,
    output_dir: Path,
) -> Path:
    """Generate full benchmark report as JSON + Markdown.

    Returns:
        Path to the generated JSON report.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")

    report = {
        "benchmark": "ScannerGap Security Blind Spot Benchmark",
        "version": "0.1.0",
        "generated_at": timestamp,
        "corpus": {
            "total_cves": corpus_size,
            "confirmed_vulnerabilities": len(quadrant_result.q1_detected)
            + len(quadrant_result.q2_blind_spot),
        },
        "scanners": scanner_names,
        "quadrant_summary": quadrant_result.summary(),
        "blind_spot_taxonomy": {
            cwe: {
                "count": len(cves),
                "cve_ids": cves[:10],
            }
            for cwe, cves in cwe_clusters.items()
        },
        "falsification_tests": [
            {
                "test": r.test_name,
                "verdict": r.verdict.value,
                "metric": r.metric_name,
                "value": r.metric_value,
                "threshold": r.threshold,
                "details": r.details,
            }
            for r in falsification_results
        ],
        "overall_verdict": "ALIVE"
        if all(r.verdict != Verdict.FAIL for r in falsification_results)
        else "KILL",
    }

    # Write JSON
    json_path = output_dir / f"benchmark_report_{date_str}.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    # Write Markdown summary
    md_path = output_dir / f"benchmark_report_{date_str}.md"
    md_content = _render_markdown(report)
    md_path.write_text(md_content, encoding="utf-8")

    log.info("report_generated", json_path=str(json_path), md_path=str(md_path))
    return json_path


def _render_markdown(report: dict) -> str:
    """Render report dict as Markdown."""
    lines = [
        f"# {report['benchmark']} v{report['version']}",
        f"Generated: {report['generated_at']}",
        "",
        "## Summary",
        f"- Corpus: {report['corpus']['total_cves']} CVEs",
        f"- Confirmed vulnerabilities: {report['corpus']['confirmed_vulnerabilities']}",
        f"- Scanners: {', '.join(report['scanners'])}",
        f"- **Overall verdict: {report['overall_verdict']}**",
        "",
        "## Quadrant Distribution",
        f"- Q1 (detected by >= 1 scanner): {report['quadrant_summary']['q1_detected']}",
        f"- Q2 (BLIND SPOT — missed by all): {report['quadrant_summary']['q2_blind_spot']}",
        f"- Q3 (false positive): {report['quadrant_summary']['q3_false_positive']}",
        f"- Q4 (true negative): {report['quadrant_summary']['q4_true_negative']}",
        f"- **Blind spot rate: {report['quadrant_summary']['blind_spot_rate']:.1%}**",
        "",
        "## Blind Spot Taxonomy",
    ]

    for cwe, data in report["blind_spot_taxonomy"].items():
        lines.append(f"- **{cwe}**: {data['count']} CVEs")

    lines.extend(
        [
            "",
            "## Falsification Tests",
            "",
            "| Test | Verdict | Metric | Value | Threshold |",
            "|------|---------|--------|-------|-----------|",
        ]
    )

    for test in report["falsification_tests"]:
        lines.append(
            f"| {test['test']} | {test['verdict']} | {test['metric']} "
            f"| {test['value']} | {test['threshold']} |"
        )

    return "\n".join(lines) + "\n"
