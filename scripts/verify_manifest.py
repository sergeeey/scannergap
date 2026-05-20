"""Verify benchmark_manifest.json against the checked-out corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"manifest not found: {path}")
    except json.JSONDecodeError as exc:
        fail(f"manifest JSON is invalid: {exc}")


def verify(manifest_path: Path) -> None:
    manifest = load_manifest(manifest_path)
    corpus_dir = Path(manifest.get("corpus_dir", "corpus/fullcode"))
    if not corpus_dir.exists():
        fail(f"corpus_dir does not exist: {corpus_dir}")

    entries = manifest.get("entries", [])
    if not isinstance(entries, list):
        fail("manifest entries must be a list")

    manifest_ids = [entry.get("cve_id") for entry in entries]
    if len(manifest_ids) != len(set(manifest_ids)):
        fail("manifest has duplicate CVE IDs")

    corpus_ids = sorted(path.name for path in corpus_dir.iterdir() if path.is_dir())
    if sorted(manifest_ids) != corpus_ids:
        missing = sorted(set(corpus_ids) - set(manifest_ids))
        extra = sorted(set(manifest_ids) - set(corpus_ids))
        fail(f"manifest/corpus mismatch; missing={missing[:10]} extra={extra[:10]}")

    declared_count = manifest.get("cve_count")
    if declared_count != len(entries):
        fail(f"cve_count={declared_count} but entries={len(entries)}")

    for entry in entries:
        cve_id = entry["cve_id"]
        cve_dir = corpus_dir / cve_id
        if not cve_dir.exists():
            fail(f"missing CVE directory: {cve_dir}")

        files = entry.get("files", [])
        if entry.get("file_count") != len(files):
            fail(f"{cve_id}: file_count does not match files list")

        for file_entry in files:
            rel_path = file_entry.get("path")
            if not rel_path:
                fail(f"{cve_id}: file entry missing path")
            file_path = cve_dir / rel_path
            if not file_path.exists():
                fail(f"{cve_id}: missing file {rel_path}")
            actual_size = file_path.stat().st_size
            if file_entry.get("bytes") != actual_size:
                fail(f"{cve_id}: size mismatch for {rel_path}")
            actual_hash = sha256_file(file_path)
            if file_entry.get("sha256") != actual_hash:
                fail(f"{cve_id}: sha256 mismatch for {rel_path}")

    print(f"PASS: manifest matches {len(entries)} CVE directories in {corpus_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify benchmark_manifest.json")
    parser.add_argument("--manifest", default="benchmark_manifest.json")
    args = parser.parse_args()

    try:
        verify(Path(args.manifest))
    except SystemExit:
        raise
    except Exception as exc:
        print(f"FAIL: unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
