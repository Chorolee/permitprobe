# PermitProbe

Independent security regression CLI. Python 3.11+, POSIX handoff reader.

- Keep policy parsing strict and report exit codes 0/pass-or-reviewed-known,
  1/new violation, 2/inconclusive.
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
- OpenAPI inventory is offline and local-file-only. Discovered operations never grant
  execution authority; only explicit PermitProbe resources may produce GET requests.
- Known-finding baselines must keep failure checks visible, match exact code/target pairs,
  and never turn incomplete evidence, handoff failures or latency failures into a clean run.
- One-shot scans may read only discovery sources fixed by the explicit policy contract. Extracted
  page links, redirects, robots entries and sitemap locations are sanitized proposals and must
  never become requests automatically.
