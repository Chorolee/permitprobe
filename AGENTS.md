# PermitProbe

Independent security regression CLI. Python 3.11+, POSIX handoff reader.

- Keep policy parsing strict and report exit codes 0/pass, 1/violation, 2/inconclusive.
- Unknown outcomes and failed positive controls must never produce a clean run.
- Reports contain labels and findings, not credentials, response bodies or scanned text.
- The library reuses Overstep and Gitleaks; do not silently widen their execution scope.
- All fixtures are synthetic. Tests use loopback; never point tests at production.
- Run `python -m pytest -q` and `ruff check src tests scripts` for behavior changes.
  Gitleaks 8.30.1 must be installed; missing-engine tests may not be silently skipped.
- Keep explicit boundary checks and the checked-byte bundle guarantee covered by tests.
- Keep examples, README and the generated policy schema synchronized.
- Do not commit environments, generated reports, archives, private data or scanner binaries.
- Keep optional future integrations clearly distinguished from implemented capabilities.
