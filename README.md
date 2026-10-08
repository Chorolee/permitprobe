# PermitProbe

[![CI](https://github.com/Chorolee/permitprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Chorolee/permitprobe/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE) [![Release](https://img.shields.io/github/v/release/Chorolee/permitprobe)](https://github.com/Chorolee/permitprobe/releases)

Open-source defensive security CLI for testing API authorization, response-data boundaries, and AI handoff exposure.

Maintainer: Susan (@Chorolee)<br>
Security Maintainer: Susan (@Chorolee)<br>
Security maintenance: vulnerability triage, security releases, and coordinated disclosure.

License: Apache-2.0<br>
Published release: [v0.1.1](https://github.com/Chorolee/permitprobe/releases/tag/v0.1.1) · Development version: [v0.2.0](docs/releases/v0.2.0.md)

PermitProbe helps service operators validate:

- cross-user authorization boundaries
- unexpected API response fields
- public-route response, cache, and fail-fast boundaries
- OpenAPI GET-operation coverage against executable checks
- bounded same-origin route proposals from fixed public sources
- reviewed known findings versus new regressions
- secrets included in AI handoff files

It is designed exclusively for systems the operator owns or is authorized to test.

PermitProbe was developed from recurring defensive security checks used while operating data-backed production services.

PermitProbe is an early open-source CLI for small teams running data-backed services.
It turns an explicit policy into repeatable checks and a local, machine-readable report.
It reuses [Overstep](https://github.com/kabiri-labs/overstep) for authorization planning and
classification, [JSON Schema](https://github.com/python-jsonschema/jsonschema) for response
contracts, and [Gitleaks](https://github.com/gitleaks/gitleaks) for secret detection.

Published version **0.1.1** supports GET-only JSON REST APIs and explicit UTF-8 text-file
handoffs on Linux/macOS. The **v0.2.0 development source** adds the one-shot assessment,
public-route, inventory, baseline, exploration, retest and proposal-discovery capabilities
documented below. See the [changelog](CHANGELOG.md) and [v0.2.0 release notes](docs/releases/v0.2.0.md).
A passing result applies only to the declared cases and scanned bytes.

## Try the working demo

Install the Python package from [PyPI](https://pypi.org/project/permitprobe/) (Python 3.11+):

```sh
python -m pip install 'permitprobe==0.1.1'
permitprobe --version
```

The full demos and handoff checks also require Gitleaks 8.30.1. The source-checkout
instructions below install the pinned scanner. Release maintainers can follow the
[Trusted Publishing guide](CONTRIBUTING.md#publishing-a-verified-github-release-to-pypi).

The project was renamed from BoundaryGuard in v0.1.1 because the PyPI package
`boundaryguard` belongs to an unrelated project. The historical v0.1.0 release
remains unchanged.

Python 3.11+ is required. From this repository:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -c requirements.lock -e '.[dev]'
python scripts/install_gitleaks.py

permitprobe demo --scenario safe --gitleaks .tools/gitleaks
permitprobe demo --scenario leaky --gitleaks .tools/gitleaks
permitprobe demo --scenario expired --gitleaks .tools/gitleaks
```

The demos start an ephemeral server on literal loopback and use synthetic credentials
and documents. They do not contact an application or a database.

| Scenario | Expected exit | What it demonstrates |
| --- | --- | --- |
| `safe` | `0` | Both users can read their own document; cross-owner reads are denied; fields and handoff match policy |
| `leaky` | `1` | Cross-owner access, an extra private response field, and a synthetic token in a handoff are detected |
| `schema-leak` | `1` | Authorization can be correct while the response exposes an extra field |
| `expired` | `2` | One user's working credential cannot hide another user's failed positive control |
| `server-error` | `2` | A server error on a negative test is not evidence that authorization worked |

Exit `1` and `2` in the last examples are intentional. No response bodies, token values,
file contents, or raw scanner diagnostics are included in PermitProbe reports.

## Check your own staging API

```sh
permitprobe init my-security-checks
```

Edit `my-security-checks/permitprobe.json`:

- Set the HTTPS origin of a target you operate. HTTP is accepted only for literal loopback.
- Name one anonymous identity and at least two authenticated identities with distinct objects.
- Point `token_env` at environment variables containing the corresponding bearer tokens.
  PermitProbe does not read dotenv files, create users, or obtain credentials.
- Declare each resource's allowed roles and `own`/`any` scope.
- For object resources, name the URL parameter, identity attribute, and JSON pointer that
  proves a successful response actually returned the intended object.
- Set `response_schema` and `denial_schema` for successful and refused responses.
  Close objects with `additionalProperties: false`, including nested objects, when all
  undeclared fields must be forbidden. The starter also constrains denial error values.
- Select only the text files intended for an AI handoff. Paths are relative to `handoff.root`,
  itself relative to the policy file. They are never inferred from the whole repository.

After supplying the token variables through your normal local credential mechanism:

```sh
permitprobe check my-security-checks/permitprobe.json \
  --gitleaks .tools/gitleaks --report result.json
```

The starter origin is a non-working `example.invalid` placeholder. A missing token,
unreachable target, unsupported response, failed control, or missing scanner exits `2`.
Reports and exports are created exclusively; existing files are not overwritten.

Use `permitprobe schema` to print the policy's JSON Schema. Unknown policy keys,
duplicate JSON keys, reused object IDs, and reused token references are rejected.
`examples/permitprobe.json` is a complete configuration with synthetic placeholders.

## Run one declared website assessment (v0.2.0 development source)

`scan` is the one-command path through every deterministic surface declared for a site:

```sh
permitprobe scan my-security-checks/permitprobe.json \
  --openapi my-security-checks/openapi.json \
  --baseline my-security-checks/permitprobe-baseline.json \
  --gitleaks .tools/gitleaks \
  --report website-assessment.json
```

The stages run in one bounded assessment:

1. Compare the optional local OpenAPI document with executable GET contracts.
2. Inspect explicitly selected AI-handoff text when the policy declares it.
3. Read the fixed anonymous discovery sources when `api.discovery` is declared and propose
   same-origin paths that lack a check contract.
4. Execute the declared authorization, public response, cache and latency GET checks.
5. Classify exact reviewed findings through the optional baseline.
6. Emit one exit code and one report with stage status, planned/observed request counts and
   an explicit production-write count of zero.

This is PermitProbe's current meaning of a one-shot website scan: one command covers the
declared application surface without letting imported or discovered data expand execution.
It does not recursively crawl, execute JavaScript, fuzz parameters, follow redirects or send
writes. OpenAPI, handoff and proposal-discovery stages are optional and appear as `skipped`
when absent.
An invalid OpenAPI or baseline is rejected before the scan starts. An inconclusive declared
handoff preflight also skips live delivery, so a partial local setup cannot look like a complete
website assessment.

### Propose routes from fixed public sources

[examples/discovery.json](examples/discovery.json) enables proposal discovery inside `scan`:

```json
{
  "discovery": {
    "seed_paths": ["/", "/account"],
    "include_robots": true,
    "include_sitemap": true,
    "max_candidates": 128,
    "max_response_bytes": 262144,
    "timeout_seconds": 5
  }
}
```

The only added requests are anonymous GETs to those exact seed paths plus `/robots.txt` and
`/sitemap.xml` when enabled. PermitProbe parses navigation links, form actions, concrete robots
paths and sitemap locations in memory. It accepts proposals only from the exact configured
origin, omits query values, replaces identifier-shaped path segments with `{value}`, and records
the source element or directive without retaining source text.

A same-origin GET proposal with no matching `resources` or `public_resources` path exits `1` as
`discovery.undeclared`. A source delivery, parse or truncation problem exits `2`. POST form
actions are reported as unsupported metadata. Every proposal has `executable: false`; linked
pages, redirect destinations, nested sitemaps and robots entries are never fetched. The report
states `discovered_requests_executed: 0` and counts the fixed source requests separately from
the declared live checks. The ordinary `check` command ignores `api.discovery`; this contract is
used only by the one-shot `scan` workflow.

## Inventory an OpenAPI surface (v0.2.0 development source)

Before running live checks, compare a local OpenAPI document with the GET resources that
PermitProbe can actually execute:

```sh
permitprobe inventory-openapi examples/permitprobe.json \
  --openapi examples/openapi.json --format json \
  --report openapi-inventory.json
```

The command makes no network requests and does not resolve credential variables. It discovers
OpenAPI 3.0, 3.1 and 3.2 operations, then checks every GET operation for:

- a structurally matching ordinary or public PermitProbe resource;
- agreement between the OpenAPI security requirement and the policy's public/protected surface;
- coverage of every required query-parameter name; and
- stale policy resources that no longer have a matching OpenAPI GET operation.

Path placeholder names may differ (`{documentId}` matches `{id}`). Required query values are
not imported; a public resource must still declare its own bounded values. Non-GET operations
are counted as unsupported and never compiled into requests. An uncovered or mismatched GET
exits `1`; an invalid or ambiguous document exits `2`.

This is structural coverage, not proof that an owner placeholder, OpenAPI security scheme, or
runtime authorization implementation is correct. Live boundary checks remain responsible for
those conclusions.

Input is a bounded local JSON file. Local parameter `$ref` values are resolved with a depth
limit. External references, referenced path items, URLs, YAML, callbacks, webhooks and generated
requests are outside this command's scope. Spec examples, response schemas and authentication
values are not copied into the report. The report binds the result to the PermitProbe policy
digest and the exact input document's SHA256 digest.

## Public and retired route contracts (v0.2.0 development source)

[examples/public-contracts.json](examples/public-contracts.json) checks anonymous GET
routes without requiring test accounts. This supports public-only Cloudflare or edge
services as well as mixed policies that also contain the authorization resources above.

Each `public_resources` entry declares:

- an origin-relative `path` and ordered `query` name/value pairs;
- `active` or `retired` lifecycle metadata;
- one or more expected final HTTP statuses;
- an absolute `max_elapsed_ms` fail-fast limit;
- an optional inline JSON response schema and strict `no-store` cache contract; and
- named request variants whose header values come from environment references.

```json
{
  "name": "retired-account-page",
  "path": "/account",
  "lifecycle": "retired",
  "variants": [
    {"name": "default"},
    {
      "name": "session-shaped",
      "header_envs": {"Cookie": "PP_SYNTHETIC_ATTACKER_COOKIE"}
    }
  ],
  "expected_statuses": [307, 404, 410, 503],
  "max_elapsed_ms": 500
}
```

Query values are encoded by the core and cannot be embedded in `path`. Ordered entries
preserve deliberate duplicate-name cases. The allowed variant headers are `Cookie`,
`Origin`, `Referer`, `User-Agent`, `X-Forwarded-For`, and `X-Real-IP`; their values must
be supplied through named environment variables and never appear in reports. PermitProbe
still sends only GET requests, follows no redirects, ignores proxy environment variables,
and creates a fresh HTTP client for every case.

An unexpected status, schema mismatch, cache mismatch, or completed response over the
declared limit exits `1`. A transport failure with no latency conclusion exits `2`.
The latency limit covers connection setup, response headers, and the complete bounded body,
and cannot be greater than the API-level `timeout_seconds` value.
Reports retain the measured milliseconds but omit URLs, query values, header values, and
response bodies. A public finding can be passed to `permitprobe retest`; the retest adds a
header-free variant for the same resource when one is declared.

## Private collections (v0.2.0 development source)

The v0.2.0 development source adds cookie authentication and per-item collection ownership
checks. These additions are not in the published **v0.1.1** package. Install from this checkout
using the development instructions above to run this example. Gitleaks is not needed for an
API-only policy or this collection demo.

```sh
permitprobe demo-collection --scenario safe     # exit 0
permitprobe demo-collection --scenario leaky    # exit 1
permitprobe demo-collection --scenario empty    # exit 2
permitprobe demo-collection --scenario expired  # exit 2
```

Each member can read the same `/saved-searches` endpoint with HTTP 200, but should only
receive their own rows. The leaky fixture returns both members' rows; even an own row
followed by a foreign row is detected. Empty collections cannot establish a working
ownership control: seed at least one row for each test member before checking.

Copy [examples/private-collection.json](examples/private-collection.json), then adapt
the origin, route, subject owner IDs, response schemas and these collection locations:

```json
"kind": "function",
"collection": {
  "items_pointer": "/items",
  "owner_pointer": "/ownerId",
  "owner_attr": "user_id"
}
```

`items_pointer` selects the response array (`""` selects a root array). `owner_pointer`
is relative to **each** item; its nonempty string must equal the requesting subject's
`attributes.user_id`. Every returned item is inspected. The rule checks declared owner
fields; it does not establish that rows were correctly labelled or that a list is complete.
An empty/missing list or unusable owner is inconclusive. Proven foreign-owner findings
are retained even alongside malformed entries; any incomplete check keeps the run at
exit `2`, with violations still listed in the report.

For cookie sessions, use `cookie_env` instead of `token_env`. The environment value is
the complete request Cookie header, such as the synthetic `session=example; theme=light`.
Exactly one mechanism is required per authenticated subject; anonymous has neither.
Use separate test accounts: different credential strings alone do not prove different
authenticated identities, especially when Cookie headers differ only in preferences.
Credentials are sent only to the configured origin. Responses cannot refresh a session
or transfer cookies between identities. Expired sessions must be refreshed by the operator.
Bearer authentication also works with collection rules.

```sh
# Supply the two test-session variables through your normal credential mechanism.
permitprobe check my-private-collection.json --format json
```

## File grants and role boundaries (v0.2.0 development source)

[examples/read-paths.json](examples/read-paths.json) covers private attachments,
published attachments, application documents, verification documents, and private
request lists with two members, a moderator, an administrator and an anonymous caller.
The same settings can be adapted to your staging routes and seeded test objects.

```sh
permitprobe demo-read-paths --scenario safe             # exit 0
permitprobe demo-read-paths --scenario private-leak     # exit 1
permitprobe demo-read-paths --scenario moderator-leak   # exit 1
permitprobe demo-read-paths --scenario collection-leak  # exit 1
permitprobe demo-read-paths --scenario cache-leak       # exit 1
permitprobe demo-read-paths --scenario wrong-location   # exit 2
permitprobe demo-read-paths --scenario expired-auth     # exit 2
```

For a route that grants access by issuing a signed file URL, an object resource can
replace its JSON `response_schema` and `identity_pointer` with an explicit redirect
contract. `owner_param`, `owner_attr` and `denial_schema` are still required:

```json
"redirect": {
  "status": 302,
  "origin": "https://storage.example.invalid",
  "path": "/signed/files/{id}/document.pdf",
  "required_query": ["token"]
},
"private_cache": true
```

The Location must occur once and match the pinned origin (including port), exact
owner-expanded path and declared query names. Each query name must occur once with
a nonblank value; extra names, userinfo, fragments and ambiguous URLs are refused.
Supported statuses are 302, 303, 307 and 308; select the one your route uses. A login
redirect, wrong object or missing Location is inconclusive. Grant bodies are not read:
a malformed or interrupted body cannot hide a grant already established by its headers.
JSON success/denial bodies retain the usual size, encoding and schema checks.

This establishes issuance of a **structurally matching URL**, not a working download.
The destination is never requested; its signed token's signature and expiry are not
verified. An expired token with the declared URL shape still counts as an issued grant.
Locations, query values, cookies and response bodies are omitted from reports.

Optional `private_cache: true` checks successful responses for a deliberately strict
header contract: unqualified `no-store`, or unqualified `private` plus `Vary` naming
the request's Cookie/Authorization header (or a lone `*`). `max-age` with an unquoted
nonnegative integer, `no-cache`, `must-revalidate` and `no-transform` are the only other
accepted directives. Public, shared, qualified, duplicate, unknown or contradictory
directives fail this configured contract, including `must-understand`, which can
override `no-store`. The rule checks headers only; actual cache behavior remains
unverified. See [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2).
Denial responses do not run this optional header check.

Lists that omit an owner field can instead use `collection.item_pointer` and
`collection.items_attr`, with each subject declaring `owned_items`, for example:

```json
"owned_items": {"requests": ["request-alice-1", "request-alice-2"]}
```

```json
"collection": {
  "items_pointer": "/items",
  "item_pointer": "/id",
  "items_attr": "requests"
}
```

Use exactly one collection mode. The operator supplies the complete allowed set for
each test account; sets must be nonempty and disjoint. Every returned ID must belong
to the requesting subject's set, but every seeded ID need not appear. Unlisted IDs
are policy violations even if they belong to that account in the database. Empty lists
and unusable IDs remain inconclusive. Matching IDs do not prove the provenance of the
other fields or list completeness. Reports never include the observed IDs or values.

Object resources use `api.probe_victims: "all"` by default. Every caller is checked
against every authenticated subject's declared object, so a failure limited to one specific
caller/owner pair is not hidden behind a representative victim. `"one"` remains an explicit
lower-cost option; its report proves only those selected pairs. `max_cases` is checked before
delivery and prevents an unexpectedly large full matrix from sending any requests.

## Active AI exploration (v0.2.0 development source)

The v0.2.0 development source adds a bounded active explorer. The AI observes normalized
results, forms hypotheses and chooses the next **pre-authorized case IDs**. PermitProbe retains
control of credentials, HTTP delivery, expected policy, classification, budgets, coverage and
completion. The provider cannot create a URL, header, token, request body, shell command or tool
call.

Providers use a JSON-over-stdio protocol, so Astra, Claude, Gemini, local models, agent
frameworks and deterministic programs can all use the same contract. The core contains no
model-specific branch. See [exploration provider protocol v1](docs/exploration-provider-v1.md).

```sh
permitprobe explore my-security-checks/permitprobe.json \
  --provider-command /absolute/path/to/provider-adapter \
  --provider-name my-provider \
  --state exploration-state.json \
  --complete \
  --report exploration-result.json
```

The deterministic baseline establishes positive controls and one representative cross-owner
probe per caller/resource. Each provider round receives remaining normalized capabilities and
prior observations, selects a bounded batch, and sees the new facts on the next round. With
`--complete`, any remaining declared cases run deterministically. Without it, confirmed findings
are retained but unprobed cases force exit `2`; a model's `done_hint` can never produce a pass.

Additional routes can be authorized without making them part of ordinary regression checks by
placing full `Resource` contracts in `api.exploration_resources`. They are absent from `check`
and from the baseline, and become selectable capabilities only in `explore`. A model may also
emit non-executable capability-gap proposals. A proposal must be converted into a strict policy
entry before any later run can send it.

`public_resources` run deterministically through `check` and public-finding `retest`; they are
not exposed to an exploration provider as selectable capabilities.

The required state path is created privately and checkpointed atomically after the baseline and
every round. Its graph distinguishes subjects, resources, planned cases, hypotheses, intents,
observations, capability proposals and findings. Broken provider output, a timeout, repeated or
unknown cases, missing evidence dependencies and exceeded budgets stop inconclusively.

## Finding history and retests (v0.2.0 development source)

Schema-version-2 reports contain stable finding IDs, owner-specific evidence IDs and coverage
counts without response bodies or credentials. Retest one finding against the current policy:

```sh
permitprobe retest my-security-checks/permitprobe.json \
  --prior-report exploration-result.json \
  --finding pp-0123456789abcdef \
  --output retest.json
```

The retest executes the finding's cases plus authenticated and anonymous controls. Public
contract findings also add a header-free same-route control when available. It records
`reproduced`, `not_reproduced` or `inconclusive`. `fixed` requires the same successful controls
and an explicit safe revision/deployment label such as `--change-ref deploy:abc123`; absence on
one run alone is not called a fix. A prior report is rejected unless its checks reproduce its
grouped findings exactly, so swapping a finding's evidence IDs cannot redirect the retest to
benign cases. Prior reports remain unchanged and every retest carries its own lineage graph.

## Known-finding baselines (v0.2.0 development source)

A reviewed baseline lets CI distinguish accepted findings from new regressions while keeping
every failed check and grouped finding in the report. First create a normal report, review its
failures, and explicitly capture them:

```sh
permitprobe check my-security-checks/permitprobe.json --report first-run.json
permitprobe baseline first-run.json --output permitprobe-baseline.json
```

Apply the committed baseline to later deterministic checks or OpenAPI inventories:

```sh
permitprobe check my-security-checks/permitprobe.json \
  --baseline permitprobe-baseline.json --report current.json
```

When every failure matches the same policy digest plus exact check code and target, the report
status is `known_findings` and the command exits `0`. The failed checks remain visible. A new
target or check exits `1`; any incomplete evidence still exits `2`.

Baseline files are strict, bounded JSON. Each entry has a derived ID, `first_seen`, `last_seen`,
and optional `expires`. The expiry date remains active through that date and resurfaces on the
following day. Extra annotations such as `reason` or `ticket` are preserved but have no runtime
meaning. Do not put credentials or private response data in annotations.

Create an updated file rather than mutating one in place:

```sh
permitprobe baseline latest-run.json \
  --previous permitprobe-baseline.json --output permitprobe-baseline.next.json
```

An update adds newly reviewed failures and refreshes observed entries while carrying unobserved
entries forward. It never prunes an entry or calls an unobserved finding fixed. Latency findings
and AI-handoff failures cannot be recorded in a baseline. One entry identifies a normalized
code/target pair, so separate root causes that produce the same pair remain a documented limit.

## Check and package an AI handoff

```sh
permitprobe bundle my-security-checks/permitprobe.json \
  --gitleaks .tools/gitleaks --output reviewed-handoff.zip
```

`bundle` checks the **handoff surface only** and makes no API requests. Its report states
that API/data surfaces were not checked. It captures each named file, checks the captured
bytes with Gitleaks, and only emits a ZIP when all handoff checks pass. The ZIP contains a
SHA256 manifest and those exact bytes, even if source files change afterward. Nothing is
uploaded or sent to an agent. Send the checked archive, not a re-read of the original tree.

The built-in boundary refuses dotenv files, private-key files, credential directories,
Git/private-memory directories, symlinks, hard links, non-regular files, binary content,
path traversal, and configured size overruns. User deny patterns win over allow patterns;
neither can override the built-in exclusions. Glob patterns match the whole POSIX path,
and `*` can cross directory separators. Include specific files rather than a broad `*`.

Scanner configuration and inline `gitleaks:allow` comments in a payload cannot suppress
the scan. Gitleaks runs with a small explicit environment, without inherited credentials
or configuration overrides. It receives neutral filenames and private temporary files.
These controls are a preflight check, not a sandbox for a malicious scanner executable.

## What is reused, and what PermitProbe adds

| Component | Responsibility |
| --- | --- |
| Overstep **1.5.0** | Generate identity/resource cases and classify unexpected access, including cross-owner access |
| JSON Schema / `jsonschema` | Validate nested JSON response contracts |
| Gitleaks **8.30.1** | Detect known secret patterns in captured handoff text |
| PermitProbe | One-shot orchestration of declared website checks, bounded same-origin proposal discovery, strict configuration, offline OpenAPI-to-policy GET inventory, explicit known-finding baselines, bounded GET transport, full owner-pair coverage, per-identity positive controls, public-route status/schema/cache/latency contracts, safe environment-backed request variants, model-neutral active exploration, evidence lineage and retests, object/collection checks, declared redirect grants and private-cache headers, success **and denial** response contracts, explicit file boundaries, and checked-byte bundles |

The Gitleaks installer pins the release and archive hashes. `requirements.lock` records
the tested Python dependency versions. Engine updates must pass the regression fixtures.
No code from a source-available-only security product is embedded here.

An auth-only matrix can be exported for direct use with Overstep:

```sh
permitprobe export-overstep my-security-checks/permitprobe.json --output matrix.json
```

The output is JSON, also valid YAML for Overstep, and retains `${TOKEN_ENV}` references.
It does **not** include PermitProbe's JSON Schema checks, collection ownership checks,
public-route contracts, private-cache checks, strict control rules, or handoff checks. Cookie and redirect
policies cannot be exported and are refused before creating an output file. Direct Overstep execution
has its own behavior and scope.

## Exit codes and evidence

| Exit | Meaning |
| --- | --- |
| `0` | Every configured check passed, or every failure exactly matched an applied baseline and remains reported as `known_findings` |
| `1` | At least one policy violation; no incomplete checks |
| `2` | Configuration error or incomplete evidence; failures may also be present |

`--format json` prints the versioned report. `--report path.json` additionally creates
a local report file. Schema version 2 includes normalized evidence IDs, owner aliases,
coverage and grouped findings. Public-contract evidence also records elapsed milliseconds.
Reports still omit credential and request-header values, response bodies, query values,
raw discovered URLs, redirect destinations and observed collection IDs. Discovery reports retain
only normalized path shapes, safe query names and fixed source labels. Unconfigured surfaces are
named explicitly. An empty run cannot pass.
Applied baseline summaries list known, new, unobserved and expired entry IDs without removing
the underlying failure checks.
One-shot reports additionally name each configured or skipped stage and record request counts,
GET-only scope, optional proposal discovery, disabled automatic expansion, disabled redirect
following and zero writes.
Responses are consumed only in memory and capped in size/time. Proxy environment variables,
redirect following, automatic login, fixture mutations by `check`, and shared cross-identity
cookie jars are not used. Declared redirect responses are checked from their headers only.

## Scope and limitations

- Only declared GET cases and explicitly configured anonymous discovery sources are requested.
  This is not a full application security audit.
- A forbidden `2xx` response is an access-policy violation; content markers can strengthen
  evidence, but a status code alone does not prove a particular secret was disclosed.
- The owner must supply the intended policy, real test identities, and existing test objects.
  A wrong policy or overly permissive JSON Schema can produce misleading conclusions.
- JSON Schemas are inline Draft 2020-12; reference resolution and format enforcement are
  not supported. Denial responses must also be valid JSON matching their declared schema.
- These are API observations, **not** a proof of database grants, RLS, storage, GraphQL,
  intermediary cache behavior, or write-path correctness. Cache checks cover response headers
  only. The tool never connects to a database in v0.2.
- Handoff scanning covers selected UTF-8 text only. It is not complete PII classification,
  archive scanning, prompt-injection prevention, continuous DLP, or runtime egress enforcement.
- Policy files, schemas, installed dependencies, scanner and exploration-provider executables
  are trusted local inputs. Reports retain configured labels and filenames; do not put secrets
  in those names.
- GET handlers must actually be safe to call. Choose a staging target with synthetic fixtures.
- `scan` covers declared routes and can derive non-executable proposals from fixed public sources;
  it is not a recursive crawler or a claim of whole-internet-style DAST coverage.

## Development

```sh
python -m pytest -q
ruff check src tests scripts
python -m build
```

Tests use real loopback HTTP and the installed Gitleaks binary. Missing Gitleaks fails the
suite rather than silently skipping secret-detection tests. Set `PERMITPROBE_GITLEAKS`
to an absolute binary path when it is not at `.tools/gitleaks`.

## What expanding verification means

This means adding **security checks that users can apply to their services**, separately
from adding unit tests for PermitProbe itself. The present regression suite tests the
tool against synthetic safe, vulnerable, and inconclusive cases; it does not audit a
deployed application automatically.

| Planned capability | Concrete question it would test |
| --- | --- |
| Database adapter (Supabase/pgTAP) | Can one authenticated user directly read another user's private row, even if the HTTP API denies it? |
| Linked API/storage cases | Does a document denied by its API remain readable through a direct object URL or another declared route? |
| Write authorization cases | Can a user modify or delete another user's seeded test record? Run against disposable test data with explicit write-test scope. |
| MCP adapter | Can an agent identity invoke a tool or name a resource outside its declared permissions? |
| Sanitized proposal replay | Which reviewed route proposal should become a declared, reproducible check without retaining raw requests? |

These are **not implemented in v0.2**. Finding history, bounded active exploration and
declared exploration capabilities are included in the v0.2.0 development source described above.
Each remaining addition needs a known-vulnerable fixture, a fixed counterpart, and an
incomplete-evidence case that must not pass.

## Design references

[Reference designs](docs/reference-designs.md) records the pinned Nuclei, Schemathesis,
RESTler, Katana, ZAP and ARTEX revisions reviewed for PermitProbe, the concepts adapted, and the
active boundaries that were deliberately retained.

### ARTEX

[ARTEX](https://github.com/Autumn-27/ARTEX) is an AI-driven penetration-testing system.
Reference review: [revision b55ceb1](https://github.com/Autumn-27/ARTEX/tree/b55ceb1fdd84a813d77de09a06af83d323a81f85).
Its documented asset/exploration graphs distinguish targets from investigation progress;
its finding retests retain prior evidence and separate reproduced, fixed, and inconclusive
outcomes. See its [architecture](https://github.com/Autumn-27/ARTEX/blob/b55ceb1fdd84a813d77de09a06af83d323a81f85/README.md),
[retest model](https://github.com/Autumn-27/ARTEX/blob/b55ceb1fdd84a813d77de09a06af83d323a81f85/db/finding_retests.go),
and [evidence store](https://github.com/Autumn-27/ARTEX/blob/b55ceb1fdd84a813d77de09a06af83d323a81f85/evidence/store.go).

The implemented source adaptation is a scoped workflow: inventory declared surfaces, build a
deterministic baseline, let a model-neutral provider form evidence-linked hypotheses, validate
its case selections, execute through the existing bounded transport, retain normalized lineage,
and rerun a finding with comparable controls. Configured executable checks decide the result;
provider prose and completion hints do not. Untested surfaces remain visible, and response bodies
and credentials stay outside provider requests and ordinary reports.

ARTEX's reviewed source is [AGPL-3.0](https://github.com/Autumn-27/ARTEX/blob/b55ceb1fdd84a813d77de09a06af83d323a81f85/LICENSE).
It is a **conceptual reference**, not an installed dependency or an imported implementation.
No ARTEX code, prompts, screenshots, or other assets are copied into PermitProbe. The independent
implementation does not claim compatibility with, endorsement by, or an audit of ARTEX.

Apache-2.0. See [NOTICE](NOTICE), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).
