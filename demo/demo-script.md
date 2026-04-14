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

**Say**: "Now I'll run the same code through ScannerGap — 26 rules for patterns that standard Semgrep doesn't have."

```bash
semgrep scan --config src/scannergap/detector/rules/ /tmp/demo-target
```

**Pause. Let findings appear on screen.**

**Say**: "These N findings are in your codebase RIGHT NOW and your scanner says everything is clean."

**Walk through 1-2 findings:**
- Show the code
- Explain why it's dangerous
- Explain why standard rules miss it

## Part 3: "This is not just us" (2 min)

**Say**: "We didn't just guess these patterns. We tested 135 real CVEs."

Show the table:

```
135 real CVEs (NVD, 2023-2025)
× 3 scanners (Semgrep + Bandit + CodeQL)
= 61.5% invisible to ALL THREE

Not random — 13 systematic categories of blind spots.
```

**Say**: "CodeQL — the most advanced free static analyzer from GitHub — missed 76% of these CVEs. This isn't about tool quality. The whole approach has structural limits."

## Part 4: "What we do about it" (2 min)

**Say**: "Three immediate actions:"

1. **Today**: Add these 26 rules to our CI. One YAML config change.
   ```yaml
   # In your CI config, add alongside existing semgrep:
   - semgrep scan --config scannergap/detector/rules/ ./src
   ```

2. **This sprint**: Triage the findings from Part 2.

3. **This quarter**: Map which of our services have the most cross-function logic — those are highest risk for Type I blind spots.

## Handling Questions

**Q: "Why don't scanner vendors just add these rules?"**
A: Some patterns (eval, extractall) they could add — and our rules do exactly that. But 70% of blind spots need interprocedural analysis that current SAST architectures can't do. That's a fundamental limitation, not a missing rule.

**Q: "Is this just FUD to sell something?"**
A: Every CVE is public (NVD), every rule is open source, the evaluation script is reproducible. Run it yourself: `python scripts/gold_evaluation.py`

**Q: "How is this different from DAST/IAST?"**
A: Those tools test running applications (dynamic). We audit static analyzers. Complementary, not competing. If your DAST finds something your SAST missed — that's exactly a blind spot we're mapping.

**Q: "Can we run this on our production code?"**
A: Yes. It's just Semgrep rules (YAML). Runs locally, nothing leaves the machine. No cloud, no API calls, no telemetry.

**Q: "What about false positives?"**
A: Some rules (like PHP echo) are intentionally broad. For internal use, tune severity thresholds. For the benchmark, we use strict HIT/PARTIAL/MISS matching.
