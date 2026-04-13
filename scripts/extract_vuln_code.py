"""Extract vulnerable code from patch diffs.

Parses unified diffs and reconstructs the pre-fix (vulnerable) version
of each changed file.
"""

import os
import re
from pathlib import Path


def extract_from_patches(corpus_raw: Path, corpus_code: Path) -> int:
    """Extract vulnerable code from all patches in corpus_raw.

    Returns:
        Number of CVEs with extracted code.
    """
    corpus_code.mkdir(parents=True, exist_ok=True)
    extracted = 0

    for cve_id in sorted(os.listdir(corpus_raw)):
        patch_path = corpus_raw / cve_id / "patch.diff"
        if not patch_path.exists():
            continue

        patch = patch_path.read_text(encoding="utf-8", errors="replace")

        # Parse unified diff: extract context + removed lines (= vulnerable code)
        current_file: str | None = None
        vuln_files: dict[str, list[str]] = {}

        for line in patch.split("\n"):
            if line.startswith("diff --git"):
                match = re.search(r"b/(.+)", line)
                if match:
                    current_file = match.group(1)
                    if current_file not in vuln_files:
                        vuln_files[current_file] = []
            elif line.startswith("---") or line.startswith("+++"):
                continue
            elif line.startswith("-") and not line.startswith("---"):
                # Removed line = existed in vulnerable version
                if current_file:
                    vuln_files.setdefault(current_file, []).append(line[1:])
            elif line.startswith(" "):
                # Context line = present in both versions
                if current_file:
                    vuln_files.setdefault(current_file, []).append(line[1:])

        # Save vulnerable code files
        cve_code_dir = corpus_code / cve_id
        cve_code_dir.mkdir(parents=True, exist_ok=True)

        file_count = 0
        for filepath, lines in vuln_files.items():
            if len(lines) < 3:
                continue
            # Flatten path separators for safe filename, truncate for Windows
            safe_name = filepath.replace("/", "__").replace("\\", "__")
            if len(safe_name) > 100:
                ext = Path(filepath).suffix or ".txt"
                safe_name = safe_name[:90] + ext
            out_path = cve_code_dir / safe_name
            out_path.write_text("\n".join(lines), encoding="utf-8")
            file_count += 1

        if file_count > 0:
            extracted += 1
            print(f"  {cve_id}: {file_count} files extracted")

    return extracted


if __name__ == "__main__":
    raw = Path("corpus/raw")
    code = Path("corpus/code")
    count = extract_from_patches(raw, code)
    print(f"\nExtracted vulnerable code from {count} CVEs")

    # Count total
    total = sum(len(list(d.iterdir())) for d in code.iterdir() if d.is_dir())
    print(f"Total code files: {total}")
