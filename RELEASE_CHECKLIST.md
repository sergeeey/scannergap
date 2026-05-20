# ScannerGap Release Checklist

## Public GitHub Release Candidate

- [ ] README states current status as research MVP / paid audit prototype.
- [ ] `BENCHMARK_EVIDENCE.md` is linked from README.
- [ ] `docs/reproducibility.md` explains current and historical artifacts.
- [ ] `benchmark_manifest.json` matches `corpus/fullcode`.
- [ ] `python scripts/verify_manifest.py` passes.
- [ ] `python scripts/check_claims.py` passes.
- [ ] `ruff check --no-cache src/ tests/ scripts/` passes.
- [ ] `ruff format --check --no-cache src/ tests/ scripts/` passes.
- [ ] `pytest -q --no-cov` passes.
- [ ] Semgrep rule validation passes in a clean runner or documented container.
- [ ] No production benchmark claim while reproducibility is skipped.
- [ ] No wording that presents ScannerGap as a SAST or pentest replacement.
- [ ] No wording that says the 61.5% artifact includes full CodeQL or commercial scanner coverage.

## Paid POC Readiness

- [ ] `demo/ciso-demo.md` reviewed.
- [ ] `demo/poc-offer.md` reviewed.
- [ ] `demo/sample-report.md` ready to share.
- [ ] `demo/intake-questionnaire.md` ready to send before scoping.
- [ ] `demo/data-handling.md` ready to send before repo access.
- [ ] `demo/outreach-email.md` ready.
- [ ] `demo/discovery-call-script.md` ready.
- [ ] `demo/outreach-tracker.md` created.

## Go / No-Go

Go for manual POC when the paid POC checklist is complete and the quality gate passes.

No-go for production benchmark until reproducibility is a real PASS and the headline corpus has a matching manifest.

No-go for SaaS until scan workers are isolated, customer data handling is implemented, and auth/tenant boundaries exist.
