"""Build a frozen manifest for the checked-out CVE corpus.

This records the corpus that is reproducible from the current repository state.
Historical/exploratory reports may reference different corpus sizes; keep those
claims scoped in docs instead of changing this manifest to match old artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".h": "c/cpp",
    ".hpp": "cpp",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_metadata(cve_dir: Path) -> dict[str, Any]:
    meta_path = cve_dir / "metadata.json"
    if not meta_path.exists():
        return {}
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"metadata_parse_error": True}


def detect_languages(files: list[Path]) -> list[str]:
    languages = sorted(
        {LANG_BY_EXT[f.suffix.lower()] for f in files if f.suffix.lower() in LANG_BY_EXT}
    )
    return languages or ["unknown"]


def build_manifest(corpus_dir: Path) -> dict[str, Any]:
    cve_dirs = sorted(path for path in corpus_dir.iterdir() if path.is_dir())
    entries: list[dict[str, Any]] = []

    for cve_dir in cve_dirs:
        files = sorted(path for path in cve_dir.rglob("*") if path.is_file())
        metadata = load_metadata(cve_dir)
        content_files = [path for path in files if path.name != "metadata.json"]

        entries.append(
            {
                "cve_id": cve_dir.name,
                "path": cve_dir.as_posix(),
                "languages": detect_languages(content_files),
                "file_count": len(content_files),
                "metadata_present": (cve_dir / "metadata.json").exists(),
                "cwe_ids": metadata.get("cwe_ids", []),
                "cvss_score": metadata.get("cvss_score"),
                "patch_url": metadata.get("patch_url"),
                "files": [
                    {
                        "path": path.relative_to(cve_dir).as_posix(),
                        "bytes": path.stat().st_size,
                        "sha256": sha256_file(path),
                    }
                    for path in content_files
                ],
            }
        )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus_dir": corpus_dir.as_posix(),
        "scope": "current_checked_out_corpus",
        "notes": [
            "This manifest reflects the corpus directories present in the current repository state.",
            "Historical 135-CVE results are exploratory until their exact manifest is restored.",
        ],
        "cve_count": len(entries),
        "entries": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build benchmark_manifest.json from corpus/fullcode"
    )
    parser.add_argument("--corpus-dir", default="corpus/fullcode")
    parser.add_argument("--output", default="benchmark_manifest.json")
    args = parser.parse_args()

    manifest = build_manifest(Path(args.corpus_dir))
    output = Path(args.output)
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {output} with {manifest['cve_count']} CVEs")


if __name__ == "__main__":
    main()
