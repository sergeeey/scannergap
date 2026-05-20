# Demo Script — ScannerGap

## Before the demo (5 min prep)

```bash
# Clone the project
cd /path/to/workspace
git clone <repo-url> scannergap
cd scannergap
pip install -e .

# Pick a target for demo (open-source project similar to your stack)
# Option A: Python fintech
git clone https://github.com/apache/fineract-client.git /tmp/demo-target

# Option B: Your team's repo (if approved by security lead)
# /tmp/demo-target = /path/to/your/repo
```

## Part 1: "What your scanner sees" (3 min)

**Say**: "Let's run Semgrep with default config — this is what most teams use."

```bash
semgrep scan --config auto /tmp/demo-target --json --quiet \
  | python -c "import json,sys; d=json.load(sys.stdin); print(f'{len(d[\"results\"])} findings')"
```

**Say**: "Semgrep found N issues. Great. Pipeline passes, team feels safe."

**Say**: "But here's the question — what is it NOT seeing?"

## Part 2: "What your scanner misses" (3 min)

**Say**: "Now I'll run the same code through ScannerGap — prototype rules for patterns baseline Semgrep may not cover."

```bash
semgrep scan --config src/scannergap/detector/rules/ /tmp/demo-target
```

**Pause. Let findings appear on screen.**

**Say**: "These N findings are prompts for review that the baseline scan did not surface."

**Walk through 1-2 findings:**
- Show the code
- Explain why it's dangerous
- Explain why standard rules miss it

## Part 3: "This is not just us" (2 min)

**Say**: "We didn't just guess these patterns. We built the methodology from real CVE artifacts."

Show the table:

```
Exploratory 135-CVE artifact (NVD, 2023-2025)
Semgrep + Bandit baseline
= 61.5% missed by both baseline scanners

Not random — 13 systematic categories of blind spots.
```

**Say**: "CodeQL evidence exists as a separate exploratory subset. This is not a production claim against every scanner; it is a way to structure a scanner-gap review."

## Part 4: "What we do about it" (2 min)

**Say**: "Three immediate actions:"

1. **Today**: Run the prototype rules locally and review whether any findings matter.
   ```yaml
   # In your CI config, add alongside existing semgrep:
   - semgrep scan --config scannergap/detector/rules/ ./src
   ```

2. **This sprint**: Triage the findings from Part 2.

3. **This quarter**: Map which of our services have the most cross-function logic — those are highest risk for Type I blind spots.

## Handling Questions

**Q: "Why don't scanner vendors just add these rules?"**
A: Some patterns can be added as rules, and some need deeper data-flow or semantic analysis. The audit separates those cases instead of treating every miss as the same kind of gap.

**Q: "Is this just FUD to sell something?"**
A: Every CVE is public (NVD), every rule is open source, the evaluation script is reproducible. Run it yourself: `python scripts/gold_evaluation.py`

**Q: "How is this different from DAST/IAST?"**
A: Those tools test running applications (dynamic). We audit static analyzers. Complementary, not competing. If your DAST finds something your SAST missed — that's exactly a blind spot we're mapping.

**Q: "Can we run this on our production code?"**
A: Yes. It's just Semgrep rules (YAML). Runs locally, nothing leaves the machine. No cloud, no API calls, no telemetry.

**Q: "What about false positives?"**
A: Some rules (like PHP echo) are intentionally broad. For internal use, tune severity thresholds. For the benchmark, we use strict HIT/PARTIAL/MISS matching.
