# PermitProbe

Independent security regression CLI. Python 3.11+, POSIX handoff reader.

- Keep policy parsing strict and report exit codes 0/pass-or-reviewed-known,
  1/new violation, 2/inconclusive.
- Preserve exact finite JSON numbers and valid Unicode when loading policies; policy digests and
  response validators must see the same mathematical schema values.
- Read local JSON inputs only from size-bounded regular files; resolve an intentional symlink to its
  final file and never block on a FIFO, socket, directory or device.
- Unknown outcomes and failed positive controls must never produce a clean run.
- Require one allow rule per resource role and reject anonymous `own` scope; ambiguous policy
  entries must never widen the engine's expected authorization effect.
- Reports contain labels and findings, not credentials, response bodies or scanned text.
- Response-derived discovery labels remain reportable only through an explicit policy allowlist;
  entropy or length must never be treated as a confidentiality boundary.
- The library reuses Overstep and Gitleaks; do not silently widen their execution scope.
- Keep live API credentials in PermitProbe's delivery layer; planning and classification engines
  receive environment-reference placeholders rather than bearer-token or cookie values.
- Parse request Cookie credentials as unambiguous name/value pairs and compare normalized pair sets
  across subjects; reordering or quoting must not bypass the distinct-credential preflight.
- Never forward a policy-referenced subject credential or request-header environment variable to
  an exploration provider, even when it is also named explicitly with `--provider-env`.
- Give an exploration provider only the fixed platform default `PATH`, a fixed locale, and
  explicitly allowed variables; never inherit the caller's `PATH` implicitly.
- All fixtures are synthetic. Tests use loopback; never point tests at production.
- Run `python -m pytest -q` and `ruff check src tests scripts` for behavior changes.
  Gitleaks 8.30.1 must be installed; missing-engine tests may not be silently skipped.
- Keep explicit boundary checks and the checked-byte bundle guarantee covered by tests.
- Resolve handoff roots relative to the real policy file, require canonical relative components,
  and open every directory component without following links or bypassing private directories.
- Bundle member paths must remain unique after Unicode normalization and case folding, including
  the receipt name, and no file path may be an ancestor of another member, so extraction cannot
  alias a file with a directory or two separately checked entries.
- Reject reserved device names in every bundle path component, including extension-bearing and
  superscript-digit Windows aliases; checked bytes must always extract as ordinary files.
- Reject characters that Win32 reserves in every file or directory name before a checked bundle
  can be published from a POSIX host.
- Limit each bundle path component to 255 UTF-16 code units for common Windows filesystem
  extraction, including snapshots passed directly to the bundle writer.
- Keep examples, README and the generated policy schema synchronized.
- Keep `docs/threat-model.md` synchronized with every new executable input, credential path,
  parser, report field, artifact path, trust assumption, and failure-to-pass transition.
- Do not commit environments, generated reports, archives, private data or scanner binaries.
- Keep the project and import-package versions identical. Release candidates must pass a fresh
  wheel install, dependency-consistency check, strict metadata checks and the packaged safe demo
  before tagging.
- Run release-smoke Python subprocesses in isolated interpreter mode so an inherited `PYTHONPATH`,
  user site, or other `PYTHON*` setting cannot replace the installed wheel under test.
- Install development and release dependencies from the complete SHA256-locked requirements file,
  install PermitProbe itself without dependency resolution, and build without an isolated resolver.
- Keep optional future integrations clearly distinguished from implemented capabilities.
- OpenAPI inventory is offline and local-file-only. Discovered operations never grant
  execution authority; only explicit PermitProbe resources may produce GET requests.
- Validate every referenced OpenAPI security scheme's inline type and required structural fields;
  malformed field types must become policy errors, and an empty, referenced or unsupported scheme
  must never become protected coverage or an uncaught exception.
- Known-finding baselines must keep failure checks visible, match exact code/target pairs,
  bind to the normalized target origin, and never turn incomplete evidence, discovery gaps,
  handoff failures or latency failures into a clean run.
- Response parsing, schema evaluation and ownership validation must share a fail-closed local
  wall-clock budget; transport timeouts alone are insufficient.
- Preserve response JSON numbers exactly through schema validation; binary floating-point rounding
  must never make a different numeric value satisfy a declared response contract.
- Reject JSON Schema `format` assertions while format checking is unavailable; never silently
  accept an annotation that a policy author could mistake for an enforced response constraint.
- Permit only the reviewed Draft 2020-12 keyword set at actual schema nodes; unknown, legacy,
  content-annotation and alternate-dialect keywords must fail policy validation.
- Convert Python regular-expression ambiguity warnings during JSON Schema checking into policy
  failures; a version-dependent pattern must never become an executable response assertion.
- One-shot scans may read only discovery sources fixed by the explicit policy contract. Extracted
  page links, redirects, robots entries and sitemap locations are sanitized proposals and must
  never become requests automatically.
- Registry publication must verify downloaded asset digests and prove executable wheel/sdist
  package bytes match the requested release tag, bounding the complete decompressed sdist stream
  and every archive's member count during parsing.
- Require the complete distribution core-metadata field set, values, ordering and multiplicity to
  match the tagged project; undeclared or duplicate artifact-only metadata must fail verification.
- Build source distributions with neutral root ownership and reject any TAR member whose numeric or
  named owner/group identifies the local build account.
- Registry verification code, dependency locks and scanner installers must execute from the trusted
  main checkout; a requested release tag is data and source evidence, never the verifier.
- Scanner installation must hash-verify the complete archive before publishing a complete executable
  at a new path; never expose partial bytes or replace an existing scanner path.
- Before every handoff scan, require the platform-specific official scanner binary digest and run a
  private verified copy; a version string alone is not an executable trust boundary.
- Resolve a release tag inside the trusted full-history checkout, require its commit to be an
  ancestor of main, and materialize that exact commit without running tag-controlled code.
- Keep GitHub Actions pinned to full commit SHAs. Dependency updates must pass dependency review,
  CodeQL and the ordinary test/build workflow before release.
- Scan the clean checked-out source with the verified pinned Gitleaks binary before tests generate
  bytecode or build artifacts. Pin its built-in rules and ignore repository suppression files and
  inline allow comments; synthetic fixtures must not require broad source-scan exceptions.
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
- Enforce browser cookie acceptance prerequisites in addition to declared attributes: Partitioned
  is valueless and requires Secure, while every supported security prefix keeps its full invariant
  under ASCII case-insensitive prefix matching.
- Accept only ASCII visible bytes plus HTAB in response security and cache header fields, and trim
  only HTTP SP/HTAB optional whitespace; Unicode whitespace must never normalize into a pass.
- Parse COOP and COEP as single structured-field items, keep CORP case-sensitive, and require the
  exact true structured boolean for origin agent clustering.
- Validate HSTS delta-seconds without converting attacker-controlled digit strings to integers;
  accept only unquoted or simply quoted ASCII decimal values, validate every extension directive
  as an HTTP token or quoted string, and require known flag directives to remain valueless.
- Parse the complete bounded Permissions-Policy structured dictionary and require an exact empty
  allowlist for every feature declared disabled; never retain observed policy values.
- Publish local reports, baselines, replay/retest records, matrices, state and checked bundles with
  owner-only permissions; never replace an existing immutable artifact.
- Create starter policy directories and files with owner-only permissions so later user edits do
  not inherit public-readable modes from the initialization template.
- Flush and fsync complete staged artifact and scanner bytes through their open descriptor before
  atomic link or replacement; set permissions through the descriptor rather than its temporary name.
- Match CORS allow-origin values to the request's serialized Origin byte-for-byte and accept only
  canonical request Origin values and the exact case-sensitive `true` credentials literal.
- Parse `Vary` as a bounded HTTP field-name list before accepting `Origin` or `*` as CORS cache
  separation; a valid-looking member must never hide malformed remainder bytes.
- Treat the exact case-sensitive `null` value as a valid opaque serialized CORS Origin; variants
  using it remain subject to the same explicit allow/deny classification and byte comparison.
- Treat prior reports as strict bounded JSON: reject duplicate keys, non-finite values and invalid
  Unicode before validating finding lineage or compiling any retest request.
- Require exact JSON integer types for every baseline, report, checkpoint, trace, and replay version
  field; booleans and numerically equal decimals must never select a document format.
- Pin GitHub Actions to an explicit supported runner OS as well as full action SHAs; runner label
  migrations must be an intentional reviewed change.
