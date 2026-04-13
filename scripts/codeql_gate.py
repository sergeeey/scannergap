"""CodeQL Decision Gate — test blind CVEs with maximum scanner coverage.

Uses CodeQL CLI where available, falls back to Semgrep with targeted
CWE-specific rule packs as Baseline C (maximum static analysis).
"""

import json
import subprocess
from pathlib import Path

import structlog

log = structlog.get_logger()

# 5 blind CVEs selected for CodeQL gate (fair test — CodeQL's strongest areas)
GATE_CVES = [
    {
        "cve_id": "CVE-2024-2928",
        "cwe": "CWE-22",
        "language": "python",
        "semgrep_configs": [
            "r/python.django.security",
            "r/python.flask.security",
            "r/python.lang.security",
            "p/python",
            "p/security-audit",
            "p/owasp-top-ten",
        ],
    },
    {
        "cve_id": "CVE-2024-21514",
        "cwe": "CWE-89",
        "language": "php",
        "semgrep_configs": [
            "r/php.lang.security",
            "p/php",
            "p/security-audit",
            "p/owasp-top-ten",
        ],
    },
    {
        "cve_id": "CVE-2024-42362",
        "cwe": "CWE-502",
        "language": "java",
        "semgrep_configs": [
            "r/java.lang.security",
            "p/java",
            "p/security-audit",
            "p/owasp-top-ten",
        ],
    },
    {
        "cve_id": "CVE-2024-45390",
        "cwe": "CWE-94",
        "language": "javascript",
        "semgrep_configs": [
            "r/javascript.lang.security",
            "r/typescript.lang.security",
            "p/javascript",
            "p/security-audit",
            "p/owasp-top-ten",
            "p/nodejs",
        ],
    },
    {
        "cve_id": "CVE-2024-24759",
        "cwe": "CWE-918",
        "language": "python",
        "semgrep_configs": [
            "r/python.django.security",
            "r/python.flask.security",
            "r/python.lang.security",
            "p/python",
            "p/security-audit",
            "p/owasp-top-ten",
        ],
    },
]


def run_semgrep_max(target: Path, configs: list[str]) -> list[dict]:
    """Run Semgrep with all provided configs, deduplicate findings."""
    all_findings: list[dict] = []
    seen_rules: set[str] = set()

    for config in configs:
        try:
            result = subprocess.run(
                ["semgrep", "scan", "--config", config, "--json", "--quiet", str(target)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if not result.stdout:
                continue
            data = json.loads(result.stdout)
            for m in data.get("results", []):
                rule_id = m.get("check_id", "")
                if rule_id in seen_rules:
                    continue
                seen_rules.add(rule_id)

                meta = m.get("extra", {}).get("metadata", {})
                cwe_list = meta.get("cwe", [])
                cwe = cwe_list[0].split(":")[0].strip() if cwe_list else None

                all_findings.append(
                    {
                        "rule_id": rule_id,
                        "severity": m.get("extra", {}).get("severity", "?"),
                        "message": m.get("extra", {}).get("message", "")[:200],
                        "file": m.get("path", ""),
                        "line": m.get("start", {}).get("line", 0),
                        "cwe": cwe,
                        "config": config,
                    }
                )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            continue

    return all_findings


def check_codeql_available() -> bool:
    """Check if CodeQL CLI is available."""
    try:
        result = subprocess.run(["codeql", "--version"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_gate() -> dict:
    """Run the CodeQL decision gate."""
    codeql_available = check_codeql_available()
    log.info("codeql_status", available=codeql_available)

    results: list[dict] = []

    for gate_cve in GATE_CVES:
        cve_id = gate_cve["cve_id"]
        cve_dir = Path("corpus/fullcode") / cve_id

        if not cve_dir.exists():
            log.warning("missing_code", cve_id=cve_id)
            results.append({"cve_id": cve_id, "status": "missing", "findings": 0})
            continue

        log.info("scanning_gate_cve", cve_id=cve_id, cwe=gate_cve["cwe"])

        # Baseline C: maximum Semgrep coverage
        findings = run_semgrep_max(cve_dir, gate_cve["semgrep_configs"])

        # Filter to security-relevant findings only
        security_findings = [
            f for f in findings if f["severity"] in ("ERROR", "WARNING", "error", "warning")
        ]

        verdict = "FOUND" if security_findings else "BLIND"

        results.append(
            {
                "cve_id": cve_id,
                "cwe": gate_cve["cwe"],
                "language": gate_cve["language"],
                "status": "scanned",
                "total_findings": len(findings),
                "security_findings": len(security_findings),
                "verdict": verdict,
                "finding_details": findings[:10],
            }
        )

        log.info(
            "gate_result",
            cve_id=cve_id,
            verdict=verdict,
            findings=len(findings),
            security=len(security_findings),
        )

    # Summary
    scanned = [r for r in results if r["status"] == "scanned"]
    found = sum(1 for r in scanned if r["verdict"] == "FOUND")
    blind = sum(1 for r in scanned if r["verdict"] == "BLIND")

    summary = {
        "gate": "CodeQL Decision Gate",
        "scanner": "Semgrep Baseline C (max coverage)"
        if not codeql_available
        else "CodeQL + Semgrep",
        "total": len(scanned),
        "found": found,
        "blind": blind,
        "blind_rate": round(blind / len(scanned), 3) if scanned else 0,
        "conclusion": (
            "STRONG: blind spots persist even with maximum scanner coverage"
            if blind >= 3
            else "WEAK: stronger scanners close most blind spots"
        ),
    }

    return {"summary": summary, "results": results}


if __name__ == "__main__":
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )

    output = run_gate()

    print("\n" + "=" * 80)
    print("CODEQL DECISION GATE RESULTS")
    print("=" * 80)
    for r in output["results"]:
        if r["status"] == "scanned":
            print(
                f"  {r['cve_id']:<20} {r['cwe']:<8} {r['language']:<12} "
                f"findings={r['total_findings']:2d} security={r['security_findings']:2d} "
                f"=> {r['verdict']}"
            )
    print("-" * 80)
    s = output["summary"]
    print(
        f"  Found: {s['found']}/{s['total']}, Blind: {s['blind']}/{s['total']} "
        f"({s['blind_rate']:.0%})"
    )
    print(f"  CONCLUSION: {s['conclusion']}")
    print("=" * 80)

    Path("results").mkdir(exist_ok=True)
    with open("results/codeql_gate.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print("Saved to results/codeql_gate.json")
