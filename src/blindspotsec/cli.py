"""CLI entry point for BlindSpotSec."""

import json
from pathlib import Path

import click
import structlog

from blindspotsec import __version__

log = structlog.get_logger()


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """BlindSpotSec — find what all SAST scanners miss."""
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )


@main.command()
@click.argument("corpus_dir", type=click.Path(exists=True))
@click.option("--scanners", "-s", multiple=True, default=("semgrep", "bandit"))
@click.option("--output", "-o", type=click.Path(), default="results/scan_results.json")
def scan(corpus_dir: str, scanners: tuple[str, ...], output: str) -> None:
    """Stage 1: Run all scanners on the corpus."""
    from blindspotsec.scanners.bandit_scanner import BanditScanner
    from blindspotsec.scanners.semgrep_scanner import SemgrepScanner

    scanner_map = {
        "bandit": BanditScanner,
        "semgrep": SemgrepScanner,
    }

    corpus_path = Path(corpus_dir)
    cve_dirs = sorted([d for d in corpus_path.iterdir() if d.is_dir()])
    log.info("scanning_corpus", cve_count=len(cve_dirs), scanners=list(scanners))

    all_results: dict[str, dict[str, list[str]]] = {}

    for scanner_name in scanners:
        scanner_cls = scanner_map.get(scanner_name)
        if scanner_cls is None:
            log.warning("unknown_scanner", name=scanner_name)
            continue

        scanner = scanner_cls()
        if not scanner.is_available():
            log.warning("scanner_not_available", name=scanner_name)
            continue

        detected_cves: list[str] = []
        for cve_dir in cve_dirs:
            result = scanner.scan(cve_dir)
            if result.finding_count > 0:
                detected_cves.append(cve_dir.name)
            log.info(
                "scanned",
                scanner=scanner_name,
                cve=cve_dir.name,
                findings=result.finding_count,
            )

        all_results[scanner_name] = {
            "detected": detected_cves,
            "total_scanned": len(cve_dirs),
        }

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    log.info("scan_complete", output=str(output_path))


@main.command()
@click.argument("scan_results", type=click.Path(exists=True))
@click.argument("corpus_dir", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="results/quadrant.json")
def quadrant(scan_results: str, corpus_dir: str, output: str) -> None:
    """Stage 2: Build quadrant matrix — who found what, who missed what."""
    from blindspotsec.quadrant.analysis import (
        analyze_blind_spot_patterns,
        build_coverage_matrix,
        classify_quadrants,
    )

    raw = json.loads(Path(scan_results).read_text(encoding="utf-8"))
    corpus_path = Path(corpus_dir)
    cve_ids = sorted([d.name for d in corpus_path.iterdir() if d.is_dir()])

    scanner_results: dict[str, set[str]] = {}
    for scanner_name, data in raw.items():
        scanner_results[scanner_name] = set(data["detected"])

    scanner_columns = list(scanner_results.keys())
    matrix = build_coverage_matrix(cve_ids, scanner_results)
    confirmed_cves = set(cve_ids)
    result = classify_quadrants(matrix, confirmed_cves, scanner_columns)

    log.info("quadrant_result", **result.summary())

    cve_metadata: dict[str, dict] = {}
    for cve_id in result.q2_blind_spot:
        cve_metadata[cve_id] = {"cwe_ids": ["CWE-UNKNOWN"], "description": ""}

    patterns = analyze_blind_spot_patterns(result.q2_blind_spot, cve_metadata)

    report = {
        "quadrant_summary": result.summary(),
        "q2_blind_spots": result.q2_blind_spot,
        "q1_detected": result.q1_detected,
        "cwe_patterns": {k: v for k, v in patterns.items()},
        "coverage_matrix": matrix.to_dict(),
    }

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    log.info("quadrant_saved", output=str(output_path))


@main.command()
@click.argument("quadrant_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="results/report.json")
def benchmark(quadrant_file: str, output: str) -> None:
    """Stage 3: Run falsification tests and generate benchmark report."""
    from blindspotsec.benchmark.falsification import run_all_falsification_tests
    from blindspotsec.benchmark.report import generate_report
    from blindspotsec.quadrant.analysis import QuadrantResult

    raw = json.loads(Path(quadrant_file).read_text(encoding="utf-8"))
    summary = raw["quadrant_summary"]

    qr = QuadrantResult(
        q1_detected=raw.get("q1_detected", []),
        q2_blind_spot=raw.get("q2_blind_spots", []),
    )

    cwe_patterns = raw.get("cwe_patterns", {})
    blind_spot_rate = summary["blind_spot_rate"]

    falsification = run_all_falsification_tests(
        blind_spot_rate=blind_spot_rate,
        cwe_clusters=cwe_patterns,
        trivial_count=0,
        total_blind_spots=summary["q2_blind_spot"],
    )

    scanner_names = [
        k
        for k in raw.get("coverage_matrix", {}).keys()
        if k not in ("any_scanner", "all_scanners", "scanner_count")
    ]

    output_path = Path(output)
    report_path = generate_report(
        quadrant_result=qr,
        falsification_results=falsification,
        cwe_clusters=cwe_patterns,
        scanner_names=scanner_names,
        corpus_size=summary["q1_detected"] + summary["q2_blind_spot"],
        output_dir=output_path.parent,
    )
    log.info("benchmark_report_generated", path=str(report_path))


@main.command()
@click.argument("corpus_dir", type=click.Path(exists=True))
@click.option("--scanners", "-s", multiple=True, default=("semgrep", "bandit"))
@click.option("--output-dir", "-o", type=click.Path(), default="results")
def pipeline(corpus_dir: str, scanners: tuple[str, ...], output_dir: str) -> None:
    """Run full pipeline: scan -> quadrant -> benchmark in one command."""
    from blindspotsec.benchmark.falsification import run_all_falsification_tests
    from blindspotsec.benchmark.report import generate_report
    from blindspotsec.quadrant.analysis import (
        analyze_blind_spot_patterns,
        build_coverage_matrix,
        classify_quadrants,
    )
    from blindspotsec.scanners.bandit_scanner import BanditScanner
    from blindspotsec.scanners.semgrep_scanner import SemgrepScanner

    scanner_map = {
        "bandit": BanditScanner,
        "semgrep": SemgrepScanner,
    }

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    corpus_path = Path(corpus_dir)
    cve_dirs = sorted([d for d in corpus_path.iterdir() if d.is_dir()])
    cve_ids = [d.name for d in cve_dirs]

    log.info("pipeline_start", cve_count=len(cve_ids), scanners=list(scanners))

    # Stage 1: Scan
    scanner_results: dict[str, set[str]] = {}
    for scanner_name in scanners:
        scanner_cls = scanner_map.get(scanner_name)
        if not scanner_cls:
            continue
        scanner = scanner_cls()
        if not scanner.is_available():
            log.warning("scanner_not_available", name=scanner_name)
            continue

        detected: set[str] = set()
        for cve_dir in cve_dirs:
            result = scanner.scan(cve_dir)
            if result.finding_count > 0:
                detected.add(cve_dir.name)
        scanner_results[scanner_name] = detected
        log.info("scan_done", scanner=scanner_name, detected=len(detected), total=len(cve_ids))

    # Stage 2: Quadrant
    scanner_columns = list(scanner_results.keys())
    matrix = build_coverage_matrix(cve_ids, scanner_results)
    qr = classify_quadrants(matrix, set(cve_ids), scanner_columns)

    log.info("quadrant_done", **qr.summary())

    cve_metadata: dict[str, dict] = {}
    for cve_id in qr.q2_blind_spot:
        meta_file = corpus_path / cve_id / "metadata.json"
        if meta_file.exists():
            cve_metadata[cve_id] = json.loads(meta_file.read_text(encoding="utf-8"))
        else:
            cve_metadata[cve_id] = {"cwe_ids": ["CWE-UNKNOWN"]}
    patterns = analyze_blind_spot_patterns(qr.q2_blind_spot, cve_metadata)

    # Stage 3: Falsification + Report
    falsification = run_all_falsification_tests(
        blind_spot_rate=qr.blind_spot_rate,
        cwe_clusters=patterns,
        trivial_count=0,
        total_blind_spots=len(qr.q2_blind_spot),
    )

    report_path = generate_report(
        quadrant_result=qr,
        falsification_results=falsification,
        cwe_clusters=patterns,
        scanner_names=scanner_columns,
        corpus_size=len(cve_ids),
        output_dir=out,
    )

    passed = sum(1 for r in falsification if r.verdict.value == "PASS")
    failed = sum(1 for r in falsification if r.verdict.value == "FAIL")

    log.info(
        "pipeline_complete",
        blind_spot_rate=f"{qr.blind_spot_rate:.1%}",
        blind_spots=len(qr.q2_blind_spot),
        detected=len(qr.q1_detected),
        falsification_passed=passed,
        falsification_failed=failed,
        report=str(report_path),
    )


if __name__ == "__main__":
    main()
