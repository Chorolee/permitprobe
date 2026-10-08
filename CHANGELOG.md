# Changelog

All notable changes to PermitProbe are recorded here. The project uses semantic versioning
while it is in the `0.x` development series.

## [0.2.0] - Unreleased

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

[0.2.0]: https://github.com/Chorolee/permitprobe/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Chorolee/permitprobe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Chorolee/permitprobe/releases/tag/v0.1.0
