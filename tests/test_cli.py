"""Tests for CLI commands."""

from click.testing import CliRunner

from scannergap.cli import main


class TestCLI:
    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_version(self) -> None:
        result = self.runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self) -> None:
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "ScannerGap" in result.output

    def test_scan_help(self) -> None:
        result = self.runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "CORPUS_DIR" in result.output

    def test_quadrant_help(self) -> None:
        result = self.runner.invoke(main, ["quadrant", "--help"])
        assert result.exit_code == 0
        assert "SCAN_RESULTS" in result.output

    def test_benchmark_help(self) -> None:
        result = self.runner.invoke(main, ["benchmark", "--help"])
        assert result.exit_code == 0
        assert "QUADRANT_FILE" in result.output

    def test_pipeline_help(self) -> None:
        result = self.runner.invoke(main, ["pipeline", "--help"])
        assert result.exit_code == 0
        assert "CORPUS_DIR" in result.output

    def test_scan_missing_dir(self) -> None:
        result = self.runner.invoke(main, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0
