"""Base scanner interface.

All scanner wrappers implement this interface for uniform comparison.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    """A single vulnerability finding from a scanner."""

    scanner: str
    rule_id: str
    severity: str  # "critical", "high", "medium", "low", "info"
    cwe_id: str | None = None
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    message: str = ""
    confidence: str = "medium"  # "high", "medium", "low"


@dataclass
class ScanResult:
    """Aggregated result from running a scanner on a target."""

    scanner: str
    target_path: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_seconds: float = 0.0

    @property
    def detected_cwes(self) -> set[str]:
        """CWE IDs detected by this scanner."""
        return {f.cwe_id for f in self.findings if f.cwe_id}

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class BaseScanner(ABC):
    """Abstract base for all scanner wrappers."""

    name: str

    @abstractmethod
    def scan(self, target_path: Path) -> ScanResult:
        """Run scanner on target and return findings."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if scanner is installed and accessible."""
        ...
