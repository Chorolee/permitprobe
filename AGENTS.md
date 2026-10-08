# PermitProbe

Independent security regression CLI. Python 3.11+, POSIX handoff reader.

- Keep policy parsing strict and report exit codes 0/pass-or-reviewed-known,
  1/new violation, 2/inconclusive.
- Unknown outcomes and failed positive controls must never produce a clean run.
- Reports contain labels and findings, not credentials, response bodies or scanned text.
- Response-derived discovery labels remain reportable only through an explicit policy allowlist;
  entropy or length must never be treated as a confidentiality boundary.
- The library reuses Overstep and Gitleaks; do not silently widen their execution scope.
- All fixtures are synthetic. Tests use loopback; never point tests at production.
- Run `python -m pytest -q` and `ruff check src tests scripts` for behavior changes.
  Gitleaks 8.30.1 must be installed; missing-engine tests may not be silently skipped.
- Keep explicit boundary checks and the checked-byte bundle guarantee covered by tests.
- Keep examples, README and the generated policy schema synchronized.
- Do not commit environments, generated reports, archives, private data or scanner binaries.
- Keep the project and import-package versions identical. Release candidates must pass a fresh
  wheel install, strict metadata checks and the packaged safe demo before tagging.
- Keep optional future integrations clearly distinguished from implemented capabilities.
- OpenAPI inventory is offline and local-file-only. Discovered operations never grant
  execution authority; only explicit PermitProbe resources may produce GET requests.
- Known-finding baselines must keep failure checks visible, match exact code/target pairs,
  bind to the normalized target origin, and never turn incomplete evidence, discovery gaps,
  handoff failures or latency failures into a clean run.
- Response parsing, schema evaluation and ownership validation must share a fail-closed local
  wall-clock budget; transport timeouts alone are insufficient.
- One-shot scans may read only discovery sources fixed by the explicit policy contract. Extracted
  page links, redirects, robots entries and sitemap locations are sanitized proposals and must
  never become requests automatically.
- Registry publication must verify downloaded asset digests and prove executable wheel/sdist
  package bytes match the requested release tag.
- Replay manifests may contain only digests and normalized case IDs. Replay must bind to the same
  target origin, require the exact deterministic baseline, revalidate every ID against the current
  policy catalogue, invoke no provider, and preserve the GET-only zero-write boundary.
- Linked read checks must use an explicitly pinned origin and a protected source-object control.
  Never forward primary credentials, follow redirects, consume linked response bodies, or call a
  linked denial safe when the corresponding source object was not established.
