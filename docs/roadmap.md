# ScannerGap — 30-Day MVP Roadmap

## Week 1: Corpus Collection (Apr 14-20, 2026)
- [ ] Set up NVD API client
- [ ] Fetch 100-200 CVEs with GitHub source code
- [ ] Filter by language (Python, JavaScript, Java, C)
- [ ] Download vulnerable code + patches
- [ ] Verify: >= 100 CVEs with parseable source code
- **Gate:** If <100 CVEs -> extend by 3 days

## Week 2: Scanner Execution + Quadrant (Apr 21-27, 2026)
- [ ] Install and configure: Semgrep, Bandit
- [ ] Set up CodeQL CLI (if feasible)
- [ ] Run selected baseline scanners on corpus
- [ ] Build coverage matrix
- [ ] Calculate blind_spot_rate
- **Kill Gate:** If blind_spot_rate <5% -> KILL project
- **Gate:** If blind_spot_rate 5-15% -> extend corpus to 500 CVEs

## Week 3: Taxonomy + Falsification (Apr 28 - May 4, 2026)
- [ ] Group Q2 by CWE category
- [ ] Identify top 5 blind spot clusters
- [ ] Manual review: triviality check on top 20
- [ ] Robustness test: 3x 50% subsample
- **Kill Gate:** If no systematic clusters -> PIVOT
- **Kill Gate:** If >80% trivial -> PIVOT

## Week 4: Benchmark + Report (May 5-11, 2026)
- [ ] Freeze corpus + results
- [ ] Generate benchmark report
- [ ] Draft findings document
- [ ] Reproducibility verification
- **Deliverable:** Public benchmark v0.1

## Post-MVP (If Survived)
- Week 5-6: Build detector for top blind spot category
- Week 7-8: Validate on held-out corpus
- Month 3: Public release + blog post
- Month 4: First B2B pilot
