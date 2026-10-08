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
- Install development and release dependencies from the complete SHA256-locked requirements file,
  install PermitProbe itself without dependency resolution, and build without an isolated resolver.
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
- Registry verification code, dependency locks and scanner installers must execute from the trusted
  main checkout; a requested release tag is data and source evidence, never the verifier.
- Resolve a release tag inside the trusted full-history checkout, require its commit to be an
  ancestor of main, and materialize that exact commit without running tag-controlled code.
- Keep GitHub Actions pinned to full commit SHAs. Dependency updates must pass dependency review,
  CodeQL and the ordinary test/build workflow before release.
- Keep Ruff security rules enabled for production code. Suppress a finding only at its reviewed
  call site with a concrete trust-boundary comment; tests may ignore fixture-only assertions and
  synthetic credentials.
- Replay manifests may contain only digests and normalized case IDs. Replay must bind to the same
  target origin, require the exact deterministic baseline, revalidate every ID against the current
  policy catalogue, invoke no provider, and preserve the GET-only zero-write boundary.
- Linked read checks must use an explicitly pinned origin and a protected source-object control.
  Forward primary credentials only for explicit `source_subjects` checks at the exact normalized
  primary origin. Never forward them cross-origin, follow redirects, consume linked response
  bodies, or call a denial safe when its object/caller controls were not established.
- Browser-facing response checks must be explicit public-resource contracts. Never retain observed
  header, Origin, or cookie values in reports. Classify every declared Origin variant, preserve the
  GET-only boundary, and fail duplicate, malformed, reflected, or under-protected responses closed.
- Parse COOP and COEP as single structured-field items, keep CORP case-sensitive, and require the
  exact true structured boolean for origin agent clustering.
- Parse the complete bounded Permissions-Policy structured dictionary and require an exact empty
  allowlist for every feature declared disabled; never retain observed policy values.
- Publish local reports, baselines, replay/retest records, matrices, state and checked bundles with
  owner-only permissions; never replace an existing immutable artifact.
- Match CORS allow-origin values to the request's serialized Origin byte-for-byte and accept only
  canonical request Origin values and the exact case-sensitive `true` credentials literal.
- Treat prior reports as strict bounded JSON: reject duplicate keys, non-finite values and invalid
  Unicode before validating finding lineage or compiling any retest request.
- Pin GitHub Actions to an explicit supported runner OS as well as full action SHAs; runner label
  migrations must be an intentional reviewed change.
