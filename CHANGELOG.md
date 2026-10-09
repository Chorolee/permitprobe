# Changelog

All notable changes to PermitProbe are recorded here. The project uses semantic versioning
while it is in the `0.x` development series.

## [Unreleased]

### Added

- A maintained threat model records credentials, DNS/TLS, provider process authority, local
  artifact assumptions, supply-chain controls, and fail-closed result semantics.
- Public GET resources can declare browser-facing response contracts for HSTS, CSP,
  `X-Content-Type-Options`, Referrer-Policy, X-Frame-Options, response-cookie attributes and CORS
  behavior without retaining observed header, Origin or cookie values.
- Browser-facing contracts can also require COOP, COEP, CORP and `Origin-Agent-Cluster`, including
  bounded structured-field parsing for COOP/COEP reporting parameters.
- Browser-facing contracts can require selected `Permissions-Policy` features to use empty
  allowlists, with bounded parsing of the complete structured dictionary.

### Changed

- Loopback demo and regression servers now poll shutdown promptly, reducing local and CI test time
  without changing the requests or security verdicts they exercise.
- GitHub Actions jobs pin Ubuntu 24.04 so test, analysis and publication environments do not change
  implicitly during the announced `ubuntu-latest` migration.
- Public maintainer attribution uses the GitHub handle `@Chorolee` only. Package metadata contains
  no maintainer email address.
- GitHub now runs pinned Python CodeQL and pull-request dependency review, with weekly grouped
  Dependabot updates for Python packages and GitHub Actions.

### Security

- OpenAPI inventory now validates referenced security-scheme objects, required OAuth scopes and
  HTTPS flow endpoints, rejecting incomplete schemes before reporting protected-route coverage.
- OpenAPI 3.0 inventory now rejects nonempty requirement arrays for API-key and HTTP schemes while
  retaining the role-name arrays permitted by OpenAPI 3.1 and 3.2.
- Release provenance now rejects author names and author or maintainer email fields that are absent
  from the reviewed project metadata, preventing identity data from being added only to artifacts.
- Registry verification now rejects a GitHub Release containing any asset beyond the exact expected
  wheel and source distribution, so unverified downloads cannot share a verified release page.
- CI now scans the clean checked-out source with hash-verified Gitleaks and fixed default rules
  before tests or builds, ignoring repository suppression files and inline allow comments.
- API response validation now preserves exact decimal numbers so large or high-precision values
  cannot pass a different numeric schema constraint after binary floating-point rounding.
- Policy JSON now preserves exact decimal schema values and rejects invalid Unicode or excessive
  numeric complexity before either can alter a contract digest or runtime verdict.
- Response and denial schemas now reject `format` assertions instead of silently treating them as
  annotations and creating false assurance that an email, URI, or other format was checked.
- Executable response schemas now reject unknown, legacy, content-annotation and alternate-dialect
  keywords instead of silently ignoring misspelled or unsupported security constraints.
- JSON Schema patterns that Python marks as ambiguous are rejected without emitting a warning,
  preventing version-dependent character-set semantics from changing a response verdict.
- Policy, OpenAPI, baseline, prior-report and replay inputs now resolve to bounded regular files and
  are opened nonblocking, preventing FIFOs or device paths from stalling an assessment.
- Handoff scans now hash-pin the official Gitleaks executable itself and run a private verified
  copy, so a forged version string or scanner path replacement cannot execute untrusted bytes.
- Live bearer tokens and cookies are now kept outside the third-party planning and classification
  matrix, which receives environment-reference placeholders while PermitProbe alone sends values.
- Exploration rejects attempts to forward any policy-referenced credential or request-header
  environment variable to a provider, preventing an explicit allowlist mistake from crossing the
  target-delivery boundary.
- Cookie credentials now require unambiguous request-header syntax and normalized pair-set
  uniqueness, so reordering or quoting the same session cannot bypass the distinct-subject check.
- Resource policies now reject duplicate or conflicting rules for one role and reject anonymous
  `own` scope before an ambiguous rule can widen the expected authorization result.
- Checked bundles reject case-insensitive and Unicode-normalization path collisions, including
  aliases of the embedded manifest, before an ambiguous cross-platform ZIP can be published.
- Handoff roots must now be canonical paths relative to the real policy file; traversal, absolute
  roots, private-directory roots and symlinked directory components are refused.
- Checked bundle member paths now reject Windows device-name aliases, including names with an
  extension or legacy superscript digit, before creating an archive.
- Checked bundle member paths now reject every Win32-reserved filename character before a POSIX
  name can become an unextractable or differently interpreted Windows archive entry.
- Bundle paths now reject components longer than 255 UTF-16 code units before publication.
- Response-cookie checks now reject insecure or valued `Partitioned` attributes and require the
  current Secure/HttpOnly invariants for `__Http-` and `__Host-Http-` cookie declarations.
- CORS request variants now support the exact opaque serialized Origin `null`, allowing sandboxed
  and other opaque-origin access to be classified explicitly with the same byte-exact response rule.
- CORS cache separation now requires the complete bounded `Vary` value to be a valid HTTP
  field-name list, so an `Origin` prefix cannot hide malformed remainder bytes.
- The pinned Gitleaks installer now publishes verified bytes atomically with executable permissions
  and refuses to replace an existing path, leaving no partial scanner after a failed publication.
- Reports, checked bundles, exploration state and installed scanner binaries now fsync their staged
  inode before atomic publication; state permissions no longer depend on a path-based chmod.
- HSTS validation compares unbounded RFC delta-seconds as decimal strings, preventing oversized
  response values from raising an integer-conversion exception, and accepts quoted decimal values.
- Registry publication now resolves release tags inside the trusted full-history checkout and
  rejects any tag whose commit is not an ancestor of `main` before materializing its source.
- Release verification now bounds the complete decompressed sdist stream and archive member counts,
  preventing a compact release asset from exhausting the publication runner during traversal.
- Isolated wheel smoke tests now run `pip check` after hash-locked installation, rejecting an
  internally inconsistent installed dependency graph before tagging or publication.
- Prior reports used for baselines, replay creation and finding retests now reject duplicate JSON
  keys, non-finite numbers and invalid Unicode before they can influence a verdict or request.
- CORS response checks now apply Fetch's byte-exact serialized Origin and case-sensitive
  credentials literal rules instead of accepting normalized lookalikes that browsers reject.
- Local security artifacts are published complete with owner-only permissions, independently of
  the invoking process's umask, and existing paths are never replaced.
- Starter directories and their policy and review files now use owner-only permissions, preventing
  later user edits from inheriting a public-readable initialization mode.
- The synthetic read-path demo emits redirects only for its declared canonical fixture paths;
  request path input can no longer flow into a response `Location` header.
- CI now enforces Ruff's security rules on production code, keeps checkout credentials out of
  Git configuration, validates release tags before checkout, bounds job duration and shortens the
  lifetime of verified publication artifacts.
- Dependabot waits seven days before proposing ordinary new releases while security updates remain
  immediate, reducing exposure to newly published supply-chain compromises.
- Development, CI and release verification now install only SHA256-locked binary dependency files;
  PermitProbe and its wheel install without dependency resolution, and package builds reuse that
  verified environment instead of creating an unpinned isolated build environment.
- PyPI verification executes its verifier, dependency lock, scanner installer and smoke harness
  from trusted `main`; the requested tag is checked out separately and cannot redefine the code
  that decides whether its release artifacts are publishable.

## [0.3.0] - 2026-10-09

### Added

- Exploration reports and checkpoints can produce a private sanitized replay manifest containing
  only the target-bound policy digest, source-report digest and normalized case IDs. The manifest
  reruns the exact deterministic baseline and completed exploration cases without invoking an AI
  provider or storing URLs, credentials, headers or response bodies.
- Linked API/storage read contracts anonymously probe a pinned direct-object origin after the
  protected source API establishes each seeded object. Anonymous contracts never forward primary
  credentials; response bodies are never consumed, redirects are never followed, and a denial
  cannot pass when its source positive control failed.
- Same-origin linked routes can opt into `source_subjects` authentication to replay the source
  object's full caller/owner matrix. Bearer or cookie credentials are forwarded only after exact
  normalized-origin equality, while cross-origin linked reads remain credential-free. Finding
  retests require both source controls and the relevant linked allow controls before declaring a
  violation fixed.

### Compatibility

- The policy format remains version 1 and the report schema remains version 2. Existing v0.2.1
  policies remain valid; replay and linked-read execution require explicit new commands or policy
  declarations.

## [0.2.1] - 2026-10-08

### Security

- Discovery now retains response-derived path segments and query names only when the same literal
  is already declared by policy or explicitly allowlisted for reporting. Every other observed
  value is replaced deterministically, including short tokens and person-like names.
- Response JSON parsing, JSON Schema evaluation and collection/identity validation now share an
  absolute local wall-clock budget. Exhaustion is reported as `data.validation_budget` and exits
  `2`; schema error collection is also bounded.
- Policy digests now include the normalized target scheme, host and port. Baselines, finding IDs,
  exploration state and retests therefore fail closed when moved to another origin.
- PyPI verification checks out the exact release tag and proves that package code in the wheel and
  sdist plus sdist build metadata match that tag before publication.

### Changed

- `api.validation_timeout_ms` configures the total response-validation budget for one execution
  batch and defaults to 5000 ms. Active exploration shares it across batches and enforces its
  remaining total deadline during validation.
- `api.discovery.report_path_literals` and `report_query_names` explicitly authorize otherwise
  redacted response-derived labels in reports.
- Discovery findings cannot enter a known-finding baseline because privacy-preserving path shapes
  can intentionally merge multiple observed locations.

### Compatibility

- Baselines and prior reports created by v0.2.0 do not match v0.2.1 target-bound policy digests.
  Re-run the intended target and create a newly reviewed baseline instead of editing an old file.
- Report schema version remains 2 and the policy format remains version 1. New policy fields are
  optional and have bounded defaults.

## [0.2.0] - 2026-10-08

### Added

- One-shot `scan` orchestration for offline OpenAPI inventory, selected handoff inspection,
  bounded route discovery, declared live GET checks and known-finding classification.
- Public and retired route contracts for status, JSON shape, cache policy, request variants and
  fail-fast latency.
- Cookie-backed identities, full caller/owner pair probing, private collection ownership,
  file-grant redirect contracts and private-cache header validation.
- Offline OpenAPI 3.0–3.2 GET-operation coverage inventory. Imported operations remain
  non-executable.
- Reviewed known-finding baselines that preserve failed checks and distinguish new, expired and
  unobserved findings.
- Model-neutral bounded exploration, append-only checkpoints, evidence-linked findings and
  deterministic finding retests.
- Policy-fixed same-origin discovery from seed pages, `robots.txt` and `sitemap.xml`. Extracted
  locations are sanitized, non-executable proposals.
- Synthetic examples for public routes, private collections, role/file boundaries, OpenAPI and
  proposal discovery.

### Changed

- Reports now use schema version 2 with policy digests, normalized evidence, coverage, grouped
  findings and optional inventory, discovery, baseline and one-shot stage summaries.
- Ordinary object checks probe every declared victim by default. `api.probe_victims: "one"`
  retains the lower-cost representative mode.
- Response validation covers successful and denied JSON bodies. Unknown delivery, failed positive
  controls and incomplete coverage continue to exit `2`.

### Compatibility

- Policy files remain at version 1, and valid v0.1.1 policies remain accepted.
- Existing policies may send more GET requests because full victim-pair coverage is now the
  default. `max_cases` still stops an oversized plan before delivery.
- Consumers of v0.1.1 JSON reports must add schema-version-2 support. Version-1 reports are not
  accepted as retest inputs.
- Python 3.11 or newer and Gitleaks 8.30.1 remain the supported runtime and handoff scanner.

## [0.1.1] - 2026-10-07

- Renamed the distribution, import package and CLI to PermitProbe.
- Added verified GitHub-release-to-PyPI publication through Trusted Publishing.

## [0.1.0] - 2026-10-07

- Initial authorization, response-schema and selected handoff boundary checks.

[0.3.0]: https://github.com/Chorolee/permitprobe/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/Chorolee/permitprobe/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Chorolee/permitprobe/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Chorolee/permitprobe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Chorolee/permitprobe/releases/tag/v0.1.0
