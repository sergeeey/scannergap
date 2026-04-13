"""Semgrep scanner wrapper."""

import json
import subprocess
import time
from pathlib import Path

import structlog

from blindspotsec.scanners.base import BaseScanner, Finding, ScanResult

log = structlog.get_logger()


class SemgrepScanner(BaseScanner):
    """Wrapper for Semgrep SAST scanner."""

    name = "semgrep"

    def __init__(self, config: str = "auto") -> None:
        self.config = config

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
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
                [
                    "semgrep",
                    "scan",
                    "--config",
                    self.config,
                    "--json",
                    "--quiet",
                    str(target_path),
                ],
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

        if result.returncode in (0, 1) and result.stdout:
            try:
                data = json.loads(result.stdout)
                for match in data.get("results", []):
                    metadata = match.get("extra", {}).get("metadata", {})
                    cwe_list = metadata.get("cwe", [])
                    cwe_id = cwe_list[0] if cwe_list else None
                    # WHY: Semgrep returns CWE as "CWE-89: ..." — we extract just the ID
                    if cwe_id and ":" in cwe_id:
                        cwe_id = cwe_id.split(":")[0].strip()

                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id=match.get("check_id", ""),
                            severity=match.get("extra", {}).get("severity", "INFO").lower(),
                            cwe_id=cwe_id,
                            file_path=match.get("path", ""),
                            line_start=match.get("start", {}).get("line", 0),
                            line_end=match.get("end", {}).get("line", 0),
                            message=match.get("extra", {}).get("message", ""),
                            confidence=metadata.get("confidence", "MEDIUM").lower(),
                        )
                    )
            except json.JSONDecodeError:
                log.warning("semgrep_json_parse_error", stderr=result.stderr[:200])

        return ScanResult(
            scanner=self.name,
            target_path=str(target_path),
            findings=findings,
            error=result.stderr if result.returncode > 1 else None,
            duration_seconds=duration,
        )
