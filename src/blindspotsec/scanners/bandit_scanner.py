"""Bandit scanner wrapper (Python-specific SAST)."""

import json
import subprocess
import time
from pathlib import Path

import structlog

from blindspotsec.scanners.base import BaseScanner, Finding, ScanResult

log = structlog.get_logger()

# WHY: Bandit uses its own test IDs (B101, B102...) — we map common ones to CWE
BANDIT_TO_CWE: dict[str, str] = {
    "B101": "CWE-703",  # assert used
    "B102": "CWE-78",  # exec used
    "B103": "CWE-732",  # chmod permissions
    "B104": "CWE-605",  # bind all interfaces
    "B105": "CWE-259",  # hardcoded password
    "B106": "CWE-259",  # hardcoded password (arg)
    "B107": "CWE-259",  # hardcoded password (default)
    "B108": "CWE-377",  # hardcoded tmp dir
    "B110": "CWE-390",  # try-except-pass
    "B112": "CWE-390",  # try-except-continue
    "B201": "CWE-94",  # flask debug
    "B301": "CWE-502",  # pickle
    "B302": "CWE-502",  # marshal
    "B303": "CWE-328",  # insecure hash (md5/sha1)
    "B304": "CWE-327",  # insecure cipher
    "B305": "CWE-327",  # insecure cipher mode
    "B306": "CWE-377",  # mktemp
    "B307": "CWE-78",  # eval
    "B308": "CWE-79",  # mark_safe
    "B311": "CWE-330",  # random
    "B312": "CWE-295",  # telnet
    "B313": "CWE-611",  # xml parse
    "B320": "CWE-611",  # lxml
    "B321": "CWE-319",  # FTP
    "B323": "CWE-295",  # unverified SSL
    "B324": "CWE-328",  # hashlib insecure
    "B501": "CWE-295",  # verify=False
    "B502": "CWE-295",  # ssl no verify
    "B506": "CWE-295",  # unsafe YAML
    "B601": "CWE-78",  # paramiko exec
    "B602": "CWE-78",  # subprocess shell=True
    "B603": "CWE-78",  # subprocess no shell
    "B604": "CWE-78",  # function call shell
    "B605": "CWE-78",  # os.system
    "B607": "CWE-78",  # partial path
    "B608": "CWE-89",  # SQL injection
    "B609": "CWE-78",  # wildcard injection
    "B610": "CWE-78",  # django extra
    "B611": "CWE-89",  # django raw SQL
    "B701": "CWE-94",  # jinja2 autoescape
    "B702": "CWE-79",  # mako templates
    "B703": "CWE-79",  # django XSS
}


class BanditScanner(BaseScanner):
    """Wrapper for Bandit Python SAST scanner."""

    name = "bandit"

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, target_path: Path) -> ScanResult:
        start = time.monotonic()
        try:
            result = subprocess.run(
                ["bandit", "-r", "-f", "json", str(target_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner=self.name,
                target_path=str(target_path),
                error="Scanner timed out after 300s",
                duration_seconds=300.0,
            )

        duration = time.monotonic() - start
        findings: list[Finding] = []

        if result.stdout:
            try:
                data = json.loads(result.stdout)
                for issue in data.get("results", []):
                    test_id = issue.get("test_id", "")
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id=test_id,
                            severity=issue.get("issue_severity", "MEDIUM").lower(),
                            cwe_id=BANDIT_TO_CWE.get(test_id),
                            file_path=issue.get("filename", ""),
                            line_start=issue.get("line_number", 0),
                            line_end=issue.get("line_range", [0])[-1],
                            message=issue.get("issue_text", ""),
                            confidence=issue.get("issue_confidence", "MEDIUM").lower(),
                        )
                    )
            except json.JSONDecodeError:
                log.warning("bandit_json_parse_error")

        return ScanResult(
            scanner=self.name,
            target_path=str(target_path),
            findings=findings,
            duration_seconds=duration,
        )
