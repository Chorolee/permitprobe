# PermitProbe

[![CI](https://github.com/Chorolee/permitprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Chorolee/permitprobe/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE) [![Release](https://img.shields.io/github/v/release/Chorolee/permitprobe)](https://github.com/Chorolee/permitprobe/releases)

Open-source defensive security CLI for testing API authorization, response-data boundaries, and AI handoff exposure.

Maintainer: Susan (@Chorolee)<br>
Security Maintainer: Susan (@Chorolee)<br>
Security maintenance: vulnerability triage, security releases, and coordinated disclosure.

License: Apache-2.0 · Current release: [v0.1.1](https://github.com/Chorolee/permitprobe/releases/tag/v0.1.1)

PermitProbe helps service operators validate:

- cross-user authorization boundaries
- unexpected API response fields
- secrets included in AI handoff files

It is designed exclusively for systems the operator owns or is authorized to test.

PermitProbe was developed from recurring defensive security checks used while operating data-backed production services.

PermitProbe is an early open-source CLI for small teams running data-backed services.
It turns an explicit policy into repeatable checks and a local, machine-readable report.
It reuses [Overstep](https://github.com/kabiri-labs/overstep) for authorization planning and
classification, [JSON Schema](https://github.com/python-jsonschema/jsonschema) for response
contracts, and [Gitleaks](https://github.com/gitleaks/gitleaks) for secret detection.

Version **0.1.1** supports GET-only JSON REST APIs and explicit UTF-8 text-file handoffs on
Linux/macOS. A passing result applies only to the declared cases and scanned bytes.

## Try the working demo

Install the Python package from [PyPI](https://pypi.org/project/permitprobe/) (Python 3.11+):

```sh
python -m pip install permitprobe
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

## Private collections (unreleased; source checkout)

The current source adds cookie authentication and per-item collection ownership checks.
These additions are not in the published **v0.1.1** package. Install from this checkout
using the development instructions above to run this example. Gitleaks is not needed
for an API-only policy or this collection demo.

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

## File grants and role boundaries (unreleased; source checkout)

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
| PermitProbe | Strict configuration, bounded GET transport, per-identity positive controls, object/collection checks, declared redirect grants and private-cache headers, success **and denial** response contracts, explicit file boundaries, checked-byte bundles, and one privacy-conscious report |

The Gitleaks installer pins the release and archive hashes. `requirements.lock` records
the tested Python dependency versions. Engine updates must pass the regression fixtures.
No code from a source-available-only security product is embedded here.

An auth-only matrix can be exported for direct use with Overstep:

```sh
permitprobe export-overstep my-security-checks/permitprobe.json --output matrix.json
```

The output is JSON, also valid YAML for Overstep, and retains `${TOKEN_ENV}` references.
It does **not** include PermitProbe's JSON Schema checks, collection ownership checks,
private-cache checks, strict control rules, or handoff checks. Cookie and redirect
policies cannot be exported and are refused before creating an output file. Direct Overstep execution
has its own behavior and scope.

## Exit codes and evidence

| Exit | Meaning |
| --- | --- |
| `0` | Every configured check completed and passed |
| `1` | At least one policy violation; no incomplete checks |
| `2` | Configuration error or incomplete evidence; failures may also be present |

`--format json` prints the versioned report. `--report path.json` additionally creates
a local report file. Unconfigured surfaces are named explicitly. An empty run cannot pass.
Responses are consumed only in memory and capped in size/time. Proxy environment variables,
redirect following, automatic login, fixture mutations by `check`, and shared cross-identity
cookie jars are not used. Declared redirect responses are checked from their headers only.

## Scope and limitations

- Only declared GET cases are tested. This is not a full application security audit.
- A forbidden `2xx` response is an access-policy violation; content markers can strengthen
  evidence, but a status code alone does not prove a particular secret was disclosed.
- The owner must supply the intended policy, real test identities, and existing test objects.
  A wrong policy or overly permissive JSON Schema can produce misleading conclusions.
- JSON Schemas are inline Draft 2020-12; reference resolution and format enforcement are
  not supported. Denial responses must also be valid JSON matching their declared schema.
- These are API observations, **not** a proof of database grants, RLS, storage, GraphQL,
  caching, or write-path correctness. The tool never connects to a database in v0.1.
- Handoff scanning covers selected UTF-8 text only. It is not complete PII classification,
  archive scanning, prompt-injection prevention, continuous DLP, or runtime egress enforcement.
- Policy files, schemas, the installed dependencies, and the chosen scanner executable are
  trusted. Reports retain configured labels and filenames; do not put secrets in those names.
- GET handlers must actually be safe to call. Choose a staging target with synthetic fixtures.

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
| Finding history and retests | Is a previously reproduced defect still present after a change, with valid credentials and a working positive control? |

These are **not implemented in v0.1**. Each addition needs a known-vulnerable fixture,
a fixed counterpart, and an incomplete-evidence case that must not pass.

## Design reference: ARTEX

[ARTEX](https://github.com/Autumn-27/ARTEX) is an AI-driven penetration-testing system.
Reference review: [revision b55ceb1](https://github.com/Autumn-27/ARTEX/tree/b55ceb1fdd84a813d77de09a06af83d323a81f85).
Its documented asset/exploration graphs distinguish targets from investigation progress;
its finding retests retain prior evidence and separate reproduced, fixed, and inconclusive
outcomes. See its [architecture](https://github.com/Autumn-27/ARTEX/blob/b55ceb1fdd84a813d77de09a06af83d323a81f85/README.md),
[retest model](https://github.com/Autumn-27/ARTEX/blob/b55ceb1fdd84a813d77de09a06af83d323a81f85/db/finding_retests.go),
and [evidence store](https://github.com/Autumn-27/ARTEX/blob/b55ceb1fdd84a813d77de09a06af83d323a81f85/evidence/store.go).

The proposed PermitProbe adaptation is a scoped workflow: inventory declared surfaces,
identify a candidate, reproduce it with an executable check, retain safe evidence metadata,
then rerun the same case after a fix. A future AI-assisted discovery layer would produce
candidates; configured executable checks would decide the result. Any coverage view must
keep untested surfaces visible. Response bodies and credentials would remain excluded from
ordinary reports under this project's existing data-handling contract.

ARTEX's reviewed source is [AGPL-3.0](https://github.com/Autumn-27/ARTEX/blob/b55ceb1fdd84a813d77de09a06af83d323a81f85/LICENSE).
It is a **conceptual reference**, not an installed dependency or an imported implementation.
No ARTEX code, prompts, screenshots, or other assets are copied into PermitProbe.
This reference review does not claim to have run or audited ARTEX.

Apache-2.0. See [NOTICE](NOTICE), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).
