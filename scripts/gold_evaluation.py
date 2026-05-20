"""Gold subset evaluation with strict matching rubric.

Runs Baseline A (default) and Baseline B (tuned) scanners,
then applies strict HIT/PARTIAL/MISS matching per scoring_rubric.md.
"""

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import structlog

log = structlog.get_logger()


@dataclass
class ScanFinding:
    rule_id: str
    severity: str
    message: str
    file_path: str
    line: int
    cwe: str | None = None


@dataclass
class EvalResult:
    cve_id: str
    cwe_primary: str
    detection_requires: list[str]
    language: str
    # Per scanner: list of relevant findings
    semgrep_default: list[ScanFinding] = field(default_factory=list)
    semgrep_tuned: list[ScanFinding] = field(default_factory=list)
    bandit_default: list[ScanFinding] = field(default_factory=list)
    bandit_tuned: list[ScanFinding] = field(default_factory=list)
    # Verdicts per rubric
    semgrep_default_verdict: str = "MISS"
    semgrep_tuned_verdict: str = "MISS"
    bandit_default_verdict: str = "MISS"
    bandit_tuned_verdict: str = "MISS"
    # Overall
    any_hit_default: bool = False
    any_hit_tuned: bool = False


def run_semgrep(target: Path, config: str = "auto") -> list[ScanFinding]:
    """Run Semgrep with given config and return findings."""
    cmd = ["semgrep", "scan", "--config", config, "--json", "--quiet", str(target)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if not result.stdout:
            return []
        data = json.loads(result.stdout)
        findings = []
        for m in data.get("results", []):
            meta = m.get("extra", {}).get("metadata", {})
            cwe_list = meta.get("cwe", [])
            cwe = cwe_list[0].split(":")[0].strip() if cwe_list else None
            findings.append(
                ScanFinding(
                    rule_id=m.get("check_id", ""),
                    severity=m.get("extra", {}).get("severity", "?"),
                    message=m.get("extra", {}).get("message", "")[:200],
                    file_path=m.get("path", ""),
                    line=m.get("start", {}).get("line", 0),
                    cwe=cwe,
                )
            )
        return findings
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return []


def run_bandit(target: Path, extra_args: list[str] | None = None) -> list[ScanFinding]:
    """Run Bandit and return findings."""
    cmd = ["bandit", "-r", "-f", "json"] + (extra_args or []) + [str(target)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if not result.stdout:
            return []
        data = json.loads(result.stdout)
        findings = []
        for issue in data.get("results", []):
            findings.append(
                ScanFinding(
                    rule_id=issue.get("test_id", ""),
                    severity=issue.get("issue_severity", "?"),
                    message=issue.get("issue_text", "")[:200],
                    file_path=issue.get("filename", ""),
                    line=issue.get("line_number", 0),
                )
            )
        return findings
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return []


def classify_finding(finding: ScanFinding, gold_entry: dict) -> str:
    """Classify a single finding as HIT, PARTIAL, or NOISE per rubric."""
    vuln_file = gold_entry["vulnerable_file"]
    cwe = gold_entry["cwe_primary"]
    match_def = gold_entry["match_definition"].lower()
    sink = gold_entry["vulnerable_sink"].lower()

    # Check if finding is on the right file (flexible: basename match)
    vuln_basename = Path(vuln_file).name.lower()
    finding_basename = Path(finding.file_path).name.lower()
    # Also check flattened name (corpus uses __ separator)
    finding_flat = finding.file_path.replace("__", "/").lower()

    file_match = (
        vuln_basename in finding_basename
        or vuln_basename in finding_flat
        or finding_basename in vuln_basename
    )

    # Check CWE match
    cwe_match = False
    if finding.cwe and cwe in finding.cwe:
        cwe_match = True

    # Check message relevance
    msg_lower = finding.message.lower()
    rule_lower = finding.rule_id.lower()
    combined = msg_lower + " " + rule_lower

    # Keywords from match_definition and sink
    relevance_keywords = _extract_keywords(match_def, sink, cwe)
    keyword_match = any(kw in combined for kw in relevance_keywords)

    if file_match and (cwe_match or keyword_match):
        return "HIT"
    elif file_match and not cwe_match and not keyword_match:
        return "PARTIAL"
    elif keyword_match and not file_match:
        return "PARTIAL"
    else:
        return "NOISE"


def _extract_keywords(match_def: str, sink: str, cwe: str) -> list[str]:
    """Extract matching keywords from annotation."""
    keywords = []
    # CWE-specific keywords
    cwe_keywords = {
        "CWE-22": [
            "path traversal",
            "traversal",
            "directory traversal",
            "lfi",
            "zipslip",
            "tarslip",
            "extractall",
            "extract",
        ],
        "CWE-89": ["sql injection", "sql", "sqli", "query"],
        "CWE-78": ["command injection", "os command", "exec", "execsync", "shell"],
        "CWE-79": ["xss", "cross-site scripting", "cross site", "innerhtml", "unsanitized html"],
        "CWE-94": [
            "code injection",
            "eval",
            "code execution",
            "rce",
            "template injection",
            "ssti",
            "jinja",
            "twig",
            "velocity",
            "include",
            "new function",
        ],
        "CWE-502": [
            "deserialization",
            "deseriali",
            "yaml.load",
            "pickle",
            "unmarshal",
            "snakeyaml",
            "unsafe",
        ],
        "CWE-918": ["ssrf", "server-side request", "request forgery", "url", "fetch", "endpoint"],
    }
    keywords.extend(cwe_keywords.get(cwe, []))

    # Extract specific function/class names from sink
    for token in re.findall(r"\w+", sink):
        if len(token) > 4 and token.lower() not in ("lines", "function", "line"):
            keywords.append(token.lower())

    return list(set(keywords))


def evaluate_gold_subset(gold_path: Path, fullcode_dir: Path) -> list[EvalResult]:
    """Run full evaluation on gold subset."""
    with open(gold_path, encoding="utf-8") as f:
        gold = json.load(f)

    results: list[EvalResult] = []

    for entry in gold["cves"]:
        cve_id = entry["cve_id"]
        cve_dir = fullcode_dir / cve_id

        if not cve_dir.exists() or not list(cve_dir.iterdir()):
            log.warning("no_code", cve_id=cve_id)
            results.append(
                EvalResult(
                    cve_id=cve_id,
                    cwe_primary=entry["cwe_primary"],
                    detection_requires=entry["detection_requires"],
                    language=entry["language"],
                )
            )
            continue

        log.info("scanning", cve_id=cve_id, language=entry["language"])

        # Baseline A: default configs
        sem_default = run_semgrep(cve_dir, "auto")
        ban_default = run_bandit(cve_dir) if entry["language"] == "python" else []

        # Baseline B: tuned configs
        sem_tuned = run_semgrep(cve_dir, "auto")
        # WHY: Semgrep registry packs loaded via --config r/... for security-audit
        sem_tuned_extra = run_semgrep(cve_dir, "r/security-audit")
        sem_tuned = sem_default + sem_tuned_extra

        ban_tuned = run_bandit(cve_dir, ["-ll", "-ii"]) if entry["language"] == "python" else []

        # Classify each finding
        eval_result = EvalResult(
            cve_id=cve_id,
            cwe_primary=entry["cwe_primary"],
            detection_requires=entry["detection_requires"],
            language=entry["language"],
            semgrep_default=sem_default,
            semgrep_tuned=sem_tuned,
            bandit_default=ban_default,
            bandit_tuned=ban_tuned,
        )

        # Determine verdicts
        for findings, attr in [
            (sem_default, "semgrep_default_verdict"),
            (sem_tuned, "semgrep_tuned_verdict"),
            (ban_default, "bandit_default_verdict"),
            (ban_tuned, "bandit_tuned_verdict"),
        ]:
            verdicts = [classify_finding(f, entry) for f in findings]
            if "HIT" in verdicts:
                setattr(eval_result, attr, "HIT")
            elif "PARTIAL" in verdicts:
                setattr(eval_result, attr, "PARTIAL")
            else:
                setattr(eval_result, attr, "MISS")

        # Overall: any HIT across scanners
        eval_result.any_hit_default = (
            eval_result.semgrep_default_verdict == "HIT"
            or eval_result.bandit_default_verdict == "HIT"
        )
        eval_result.any_hit_tuned = (
            eval_result.semgrep_tuned_verdict == "HIT" or eval_result.bandit_tuned_verdict == "HIT"
        )

        results.append(eval_result)

    return results


def print_results(results: list[EvalResult]) -> dict:
    """Print and return summary."""
    print("\n" + "=" * 110)
    print(
        f"{'CVE':<22} {'CWE':<8} {'Lang':<6} {'Req':<12} "
        f"{'Sem-Def':<10} {'Sem-Tune':<10} {'Ban-Def':<10} {'Ban-Tune':<10} "
        f"{'Default':<8} {'Tuned':<8}"
    )
    print("-" * 110)

    default_hits = 0
    tuned_hits = 0
    by_detection_req: dict[str, dict[str, int]] = {}

    for r in results:
        default_mark = "FOUND" if r.any_hit_default else "BLIND"
        tuned_mark = "FOUND" if r.any_hit_tuned else "BLIND"

        if r.any_hit_default:
            default_hits += 1
        if r.any_hit_tuned:
            tuned_hits += 1

        # Track by detection requirement
        for req in r.detection_requires:
            if req not in by_detection_req:
                by_detection_req[req] = {"total": 0, "default_hit": 0, "tuned_hit": 0}
            by_detection_req[req]["total"] += 1
            if r.any_hit_default:
                by_detection_req[req]["default_hit"] += 1
            if r.any_hit_tuned:
                by_detection_req[req]["tuned_hit"] += 1

        req_str = "+".join(r.detection_requires)
        print(
            f"  {r.cve_id:<20} {r.cwe_primary:<8} {r.language:<6} {req_str:<12} "
            f"{r.semgrep_default_verdict:<10} {r.semgrep_tuned_verdict:<10} "
            f"{r.bandit_default_verdict:<10} {r.bandit_tuned_verdict:<10} "
            f"{default_mark:<8} {tuned_mark:<8}"
        )

    total = len(results)
    default_blind = total - default_hits
    tuned_blind = total - tuned_hits

    print("=" * 110)
    print(
        f"\nBASELINE A (default):  {default_hits}/{total} detected, "
        f"{default_blind}/{total} blind ({default_blind * 100 // total}%)"
    )
    print(
        f"BASELINE B (tuned):    {tuned_hits}/{total} detected, "
        f"{tuned_blind}/{total} blind ({tuned_blind * 100 // total}%)"
    )

    print("\nBlind spot rate by detection requirement:")
    for req, counts in sorted(by_detection_req.items()):
        t = counts["total"]
        dh = counts["default_hit"]
        th = counts["tuned_hit"]
        print(f"  {req:5s}: {t} CVEs, default {t - dh}/{t} blind, " f"tuned {t - th}/{t} blind")

    return {
        "total": total,
        "baseline_a": {
            "detected": default_hits,
            "blind": default_blind,
            "blind_spot_rate": round(default_blind / total, 3),
        },
        "baseline_b": {
            "detected": tuned_hits,
            "blind": tuned_blind,
            "blind_spot_rate": round(tuned_blind / total, 3),
        },
        "by_detection_requirement": by_detection_req,
    }


if __name__ == "__main__":
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )

    gold_path = Path("corpus/gold_subset.json")
    fullcode_dir = Path("corpus/fullcode")

    results = evaluate_gold_subset(gold_path, fullcode_dir)
    summary = print_results(results)

    # Save detailed results
    output = {
        "summary": summary,
        "details": [
            {
                "cve_id": r.cve_id,
                "cwe": r.cwe_primary,
                "language": r.language,
                "detection_requires": r.detection_requires,
                "semgrep_default": {
                    "verdict": r.semgrep_default_verdict,
                    "findings": len(r.semgrep_default),
                },
                "semgrep_tuned": {
                    "verdict": r.semgrep_tuned_verdict,
                    "findings": len(r.semgrep_tuned),
                },
                "bandit_default": {
                    "verdict": r.bandit_default_verdict,
                    "findings": len(r.bandit_default),
                },
                "bandit_tuned": {
                    "verdict": r.bandit_tuned_verdict,
                    "findings": len(r.bandit_tuned),
                },
                "any_hit_default": r.any_hit_default,
                "any_hit_tuned": r.any_hit_tuned,
            }
            for r in results
        ],
    }

    Path("results").mkdir(exist_ok=True)
    with open("results/gold_evaluation.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("\nResults saved to results/gold_evaluation.json")
