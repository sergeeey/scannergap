"""CLI entry point for BlindSpotSec."""

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
def ingest(corpus_dir: str) -> None:
    """Stage 1: Ingest CVE corpus from NVD with source code."""
    log.info("ingesting_corpus", path=corpus_dir)
    # TODO: Implement CVE ingestion from NVD API + GitHub source code


@main.command()
@click.argument("corpus_dir", type=click.Path(exists=True))
@click.option("--scanners", "-s", multiple=True, default=["codeql", "semgrep", "bandit"])
def scan(corpus_dir: str, scanners: tuple[str, ...]) -> None:
    """Stage 2: Run all scanners on the corpus."""
    log.info("scanning_corpus", path=corpus_dir, scanners=list(scanners))
    # TODO: Implement scanner orchestration


@main.command()
@click.argument("results_dir", type=click.Path(exists=True))
def quadrant(results_dir: str) -> None:
    """Stage 3: Build quadrant matrix — who found what, who missed what."""
    log.info("building_quadrant", path=results_dir)
    # TODO: Implement quadrant analysis


@main.command()
@click.argument("quadrant_file", type=click.Path(exists=True))
def taxonomy(quadrant_file: str) -> None:
    """Stage 4: Classify blind spot types from Q2 quadrant."""
    log.info("classifying_blind_spots", path=quadrant_file)
    # TODO: Implement taxonomy extraction


@main.command()
def benchmark() -> None:
    """Stage 5: Generate reproducible benchmark report."""
    log.info("generating_benchmark")
    # TODO: Implement benchmark generation


if __name__ == "__main__":
    main()
