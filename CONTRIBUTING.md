# Contributing to ScannerGap

## Quick Setup

```bash
# Clone
git clone https://github.com/sergeeey/scannergap.git
cd scannergap

# Install
pip install -e ".[dev]"

# Verify
scannergap --version
pytest tests/ -v
semgrep scan --config src/scannergap/detector/rules/ --validate
```

## Download CVE Corpus

The corpus (vulnerable source files) is not in the repo due to size.
To download it:

```bash
# Fetch CVEs from NVD and download vulnerable files (~30 min)
python scripts/expand_corpus.py

# Or run the full pipeline which includes scanning
scannergap pipeline corpus/fullcode -o results/output
```

## Project Layout

```
src/scannergap/       Python package (CLI, scanners, analysis)
scripts/              Standalone analysis scripts
tests/                Unit tests
corpus/               CVE data (gold_subset.json = ground truth)
docs/                 Documentation and findings
demo/                 Presentation materials
```

## Running Tests

```bash
pytest tests/ -v                    # Unit tests
semgrep scan --config src/scannergap/detector/rules/ --validate  # Rule validation
python scripts/gold_evaluation.py   # Full evaluation (requires corpus)
```

## Adding Detector Rules

Rules live in `src/scannergap/detector/rules/`. Each file covers one language.

To add a rule:
1. Pick the right file (e.g., `blind-spot-python.yaml`)
2. Follow existing rule format (id, message, severity, metadata, pattern)
3. Test: `semgrep scan --config src/scannergap/detector/rules/ --validate`
4. Verify on a real CVE if available

Rule IDs use the `blindspot-` prefix (e.g., `blindspot-python-ssrf-boto3-endpoint`).

## Code Style

- Python 3.11+, type hints
- `ruff format` (double quotes, 100 chars)
- `structlog` for logging
- No `print()` in library code
