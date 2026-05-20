"""Guard against unsupported production/benchmark claims in public docs."""

from __future__ import annotations

import re
import sys
from pathlib import Path


DOC_GLOBS = ["*.md", "docs/*.md", "docs/*.html", "demo/*.md", "BENCHMARK_EVIDENCE.md"]
SKIP_DIRS = {".git", ".ruff_cache", ".pytest_cache"}


RULES: list[tuple[str, re.Pattern[str], re.Pattern[str] | None]] = [
    (
        "unsupported all-three scanner claim",
        re.compile(r"\ball three\b|\b3 leading\b", re.IGNORECASE),
        re.compile(r"not|avoid|will not|certified", re.IGNORECASE),
    ),
    (
        "unsupported all-scanners claim",
        re.compile(r"\ball scanners\b|\ball SAST scanners\b", re.IGNORECASE),
        re.compile(r"not|avoid|may|benchmark-backed|scanner coverage gaps", re.IGNORECASE),
    ),
    (
        "unsupported production-ready claim",
        re.compile(r"\bproduction ready\b|\bproduction-ready\b", re.IGNORECASE),
        re.compile(r"not|avoid|not yet|release blocker", re.IGNORECASE),
    ),
    (
        "unsupported 4/4 pass claim",
        re.compile(r"\b4/4\b.*\bpass\b|\b4%2F4_PASS\b", re.IGNORECASE),
        re.compile(r"not|avoid|do not", re.IGNORECASE),
    ),
    (
        "unsupported Snyk implementation claim",
        re.compile(r"\bSnyk\b", re.IGNORECASE),
        re.compile(
            r"already uses|future|disabled|avoid|not|question|tools do you currently use",
            re.IGNORECASE,
        ),
    ),
    (
        "unsafe scanner replacement wording",
        re.compile(r"\bscanner replacement\b|\breplaces SAST\b|\breplace SAST\b", re.IGNORECASE),
        re.compile(r"not|avoid|will not", re.IGNORECASE),
    ),
]


def iter_docs() -> list[Path]:
    files: set[Path] = set()
    for glob in DOC_GLOBS:
        for path in Path(".").glob(glob):
            if path.is_file() and not any(part in SKIP_DIRS for part in path.parts):
                files.add(path)
    return sorted(files)


def check_line(path: Path, line_number: int, line: str) -> list[str]:
    errors: list[str] = []
    for name, forbidden, allowed in RULES:
        if not forbidden.search(line):
            continue
        if allowed and allowed.search(line):
            continue
        errors.append(f"{path}:{line_number}: {name}: {line.strip()}")
    return errors


def main() -> None:
    errors: list[str] = []
    for path in iter_docs():
        for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            errors.extend(check_line(path, idx, line))

    if errors:
        print("FAIL: unsupported public claims detected")
        for error in errors:
            print(error)
        sys.exit(1)

    print(f"PASS: checked {len(iter_docs())} public documentation files")


if __name__ == "__main__":
    main()
