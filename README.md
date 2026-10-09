# PermitProbe

[![CI](https://github.com/Chorolee/permitprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Chorolee/permitprobe/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE) [![Release](https://img.shields.io/github/v/release/Chorolee/permitprobe)](https://github.com/Chorolee/permitprobe/releases)

Open-source defensive security CLI for testing API authorization, response-data boundaries, and AI handoff exposure.

Maintainer: [@Chorolee](https://github.com/Chorolee)<br>
Security Maintainer: [@Chorolee](https://github.com/Chorolee)<br>
Security maintenance: vulnerability triage, security releases, and coordinated disclosure.

License: Apache-2.0<br>
Current release: [v0.3.0](https://github.com/Chorolee/permitprobe/releases/tag/v0.3.0)

PermitProbe helps service operators validate:

- cross-user authorization boundaries
- unexpected API response fields
- public-route response, cache, and fail-fast boundaries
- OpenAPI GET-operation coverage against executable checks
- bounded same-origin route proposals from fixed public sources
- deterministic replay of completed exploration cases
- anonymous and authenticated linked-route authorization boundaries
- reviewed known findings versus new regressions
- secrets included in AI handoff files

It is designed exclusively for systems the operator owns or is authorized to test.

PermitProbe was developed from recurring defensive security checks used while operating data-backed production services.

PermitProbe is an early open-source CLI for small teams running data-backed services.
It turns an explicit policy into repeatable checks and a local, machine-readable report.
It reuses [Overstep](https://github.com/kabiri-labs/overstep) for authorization planning and
classification, [JSON Schema](https://github.com/python-jsonschema/jsonschema) for response
contracts, and [Gitleaks](https://github.com/gitleaks/gitleaks) for secret detection.

Version **0.3.0** supports GET-only JSON REST APIs, one-shot declared website assessments and
explicit UTF-8 text-file handoffs on Linux/macOS. It includes the public-route, inventory,
baseline, exploration, replay, retest, linked-read and proposal-discovery capabilities documented
below. See the [changelog](CHANGELOG.md) and
[v0.3.0 release notes](docs/releases/v0.3.0.md). A passing result
applies only to the declared cases and scanned bytes.

## Try the working demo

Install the Python package from [PyPI](https://pypi.org/project/permitprobe/) (Python 3.11+):

```sh
python -m pip install 'permitprobe==0.3.0'
permitprobe --version
```

The full demos and handoff checks also require the official Gitleaks 8.30.1 binary. PermitProbe
verifies its platform-specific executable digest before every scan. The source-checkout
instructions below install the pinned scanner. Release maintainers can follow the
[Trusted Publishing guide](CONTRIBUTING.md#publishing-a-verified-github-release-to-pypi).

The project was renamed from BoundaryGuard in v0.1.1 because the PyPI package
`boundaryguard` belongs to an unrelated project. The historical v0.1.0 release
remains unchanged.

Python 3.11+ is required. From this repository:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --no-deps -e .
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

The starter directory is created with mode `0700`; its policy and review files use `0600`.

Edit `my-security-checks/permitprobe.json`:

- Set the HTTPS origin of a target you operate. HTTP is accepted only for literal loopback.
- Name one anonymous identity and at least two authenticated identities with distinct objects.
- Point `token_env` at environment variables containing the corresponding bearer tokens.
  PermitProbe does not read dotenv files, create users, or obtain credentials.
  Live values stay in PermitProbe's HTTP delivery layer; the planning and classification engine
  receives only the environment-reference placeholders.
- Declare each resource's allowed roles and `own`/`any` scope. Each role has exactly one rule;
  anonymous access can use only `any` because it has no declared owner identity.
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
duplicate JSON keys, invalid Unicode, excessive numeric values, reused object IDs, and reused
token references are rejected. Decimal values inside response schemas retain their exact JSON
precision in both validation and the policy digest.
Policy, OpenAPI, baseline, prior-report and replay JSON inputs must resolve to bounded regular
files; pipes, sockets, directories and devices are refused without waiting for content.
`examples/permitprobe.json` is a complete configuration with synthetic placeholders.

## Run one declared website assessment

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
4. Execute the declared authorization, public response, browser-security, cache and latency GET
   checks.
5. Probe declared linked edge/storage reads without cross-origin credential forwarding or consuming
   response bodies.
6. Classify exact reviewed findings through the optional baseline.
7. Emit one exit code and one report with stage status, planned/observed request counts and
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
    "report_path_literals": ["admin", "login"],
    "report_query_names": ["page"],
    "max_candidates": 128,
    "max_response_bytes": 262144,
    "timeout_seconds": 5
  }
}
```

The only added requests are anonymous GETs to those exact seed paths plus `/robots.txt` and
`/sitemap.xml` when enabled. PermitProbe parses navigation links, form actions, concrete robots
paths and sitemap locations in memory. It accepts proposals only from the exact configured
origin and always omits query values. Response-derived path segments and query names remain
visible only when the same literal is already declared by policy or explicitly listed in
`report_path_literals` or `report_query_names`; every other value is replaced. The report records
the source element or directive and merged-variant count without retaining source text.

A same-origin GET proposal with no matching `resources` or `public_resources` path exits `1` as
`discovery.undeclared`. A source delivery, parse or truncation problem exits `2`. POST form
actions are reported as unsupported metadata. Every proposal has `executable: false`; linked
pages, redirect destinations, nested sitemaps and robots entries are never fetched. The report
states `discovered_requests_executed: 0` and counts the fixed source requests separately from
the declared live checks. The ordinary `check` command ignores `api.discovery`; this contract is
used only by the one-shot `scan` workflow.
Discovery failures cannot be placed in a known-finding baseline because multiple private raw
locations can intentionally collapse into the same report-safe path shape.

## Inventory an OpenAPI surface

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
limit, while referenced security schemes must be inline supported scheme objects with valid
required fields, including declared OAuth scopes, version-appropriate non-OAuth requirement values,
and HTTPS flow endpoints. External references,
referenced path items, URLs, YAML, callbacks, webhooks and generated requests are outside this
command's scope. Spec examples, response schemas and authentication
values are not copied into the report. The report binds the result to the PermitProbe policy
digest and the exact input document's SHA256 digest.

## Public and retired route contracts

[examples/public-contracts.json](examples/public-contracts.json) checks anonymous GET
routes without requiring test accounts. This supports public-only Cloudflare or edge
services as well as mixed policies that also contain the authorization resources above.

Each `public_resources` entry declares:

- an origin-relative `path` and ordered `query` name/value pairs;
- `active` or `retired` lifecycle metadata;
- one or more expected final HTTP statuses;
- an absolute `max_elapsed_ms` fail-fast limit;
- an optional inline JSON response schema and strict `no-store` cache contract;
- optional declared browser-facing response security; and
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

### Browser-facing response security (unreleased)

`response_security` extends an existing public GET contract without adding requests beyond its
declared variants. It can require HSTS age/directives, `nosniff`, accepted Referrer-Policy and
X-Frame-Options values, selected CSP directives with stable source tokens, browser cross-origin
isolation policies, and origin-keyed agent clustering:

```json
{
  "response_security": {
    "security_headers": {
      "hsts": {"min_max_age": 31536000, "include_subdomains": true},
      "content_type_options": "nosniff",
      "referrer_policy": ["strict-origin-when-cross-origin", "no-referrer"],
      "frame_options": ["deny"],
      "content_security_policy": {
        "required_directives": {
          "default-src": ["'none'"],
          "frame-ancestors": ["'none'"]
        }
      },
      "permissions_policy": {
        "disabled_features": ["camera", "geolocation", "microphone"]
      },
      "cross_origin_opener_policy": ["same-origin"],
      "cross_origin_embedder_policy": ["require-corp"],
      "cross_origin_resource_policy": ["same-origin"],
      "origin_agent_cluster": true
    }
  }
}
```

Header checks require one unambiguous field value. Missing, duplicated, malformed or weaker values
fail the declared contract. Each configured CSP directive must have exactly the declared token set;
undeclared directives are not graded. The check does not execute a browser. HSTS has browser effect
only over HTTPS, even though the synthetic loopback fixtures can exercise its parser over HTTP.
HSTS `max-age` accepts the RFC decimal or quoted-decimal form and compares arbitrarily long values
without a fixed-width integer conversion.
Each required `Permissions-Policy` feature must be present exactly once with an empty allowlist
(`feature=()`). PermitProbe parses the complete bounded structured dictionary, including supported
origin allowlists and an optional token-valued `report-to` parameter, so malformed or duplicate
members fail instead of being hidden behind a required feature.
COOP and COEP accept valid structured-field parameters such as a string-valued `report-to` while
grading the effective policy token. CORP values remain case-sensitive, and
`origin_agent_cluster: true` requires the structured boolean `?1`. COOP plus compatible COEP can
declare cross-origin isolation; each header is reported independently so a partial deployment fails
the corresponding contract.

Declared response cookies are matched by exact cookie name. Each contract can require `Secure`,
`HttpOnly`, accepted `SameSite` values, host-only scope and an exact Path. Duplicate matching
cookies fail. `Partitioned` is accepted only as a valueless attribute alongside `Secure`.
`__Host-`, `__Secure-`, `__Http-` and `__Host-Http-` declarations must include their browser
prefix requirements:

```json
{
  "cookies": [
    {
      "name": "__Host-session",
      "secure": true,
      "http_only": true,
      "same_site": ["strict", "lax"],
      "host_only": true,
      "path": "/"
    }
  ]
}
```

CORS uses existing environment-backed `Origin` request variants. A contract must classify every
and only variant that sends a distinct canonical serialized HTTP(S) Origin or the exact opaque
serialization `null` as allowed or denied. Allowed
credentialed responses require a byte-for-byte matching serialized origin, the exact
case-sensitive value `true` and, by default, `Vary: Origin`; wildcard with credentials is invalid.
Noncredentialed wildcard access must be opted into explicitly. Denied variants fail if the response
reflects their origin or grants wildcard access. PermitProbe sends no OPTIONS preflight request.

Observed header values, Origin values, cookie values and cookie names stay out of reports. Reports
contain only the resource/variant target, normalized evidence ID and the configured check code.
These checks run only after an expected response status and participate in `scan`, baselines and
finding retests.

## Private collections

PermitProbe supports cookie authentication and per-item collection ownership checks. Gitleaks is
not needed for an API-only policy or this collection demo.

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
Cookie headers must contain unambiguous name/value pairs with no repeated names. PermitProbe
rejects the same cookie pair set across subjects even when order, spacing, or value quoting differs.
Use separate test accounts: different credential strings alone do not prove different
authenticated identities, especially when Cookie headers differ only in preferences.
Credentials are sent only to the configured origin. Responses cannot refresh a session
or transfer cookies between identities. Expired sessions must be refreshed by the operator.
Bearer authentication also works with collection rules.

```sh
# Supply the two test-session variables through your normal credential mechanism.
permitprobe check my-private-collection.json --format json
```

## File grants and role boundaries

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

## Linked API/storage read boundaries

A private object can be protected by its API while a direct edge or storage route remains public.
Declare the direct route separately and bind it to the protected source object:

```json
"linked_resources": [
  {
    "name": "direct-private-documents",
    "source_resource": "private-documents",
    "origin": "https://objects.example.invalid",
    "path": "/objects/{id}.pdf",
    "authentication": "anonymous",
    "denial_statuses": [403, 404]
  }
]
```

The linked path must contain the source object's one owner placeholder. PermitProbe first runs the
ordinary authenticated self-case and establishes the exact object identity (or a structurally valid
file-grant redirect). It then sends one credential-free GET to the pinned linked origin for every
declared owner. Any `2xx` is `linked.public_access`; a declared `401`, `403`, `404` or `410` passes
only when the source control succeeded. Redirects, server errors, delivery failures and denials
without a valid source control remain inconclusive.

For a second API route at the exact same normalized origin, set `authentication` to
`source_subjects`. PermitProbe mirrors the source resource's complete anonymous and authenticated
caller/owner matrix. It forwards each subject's usual bearer or cookie credential only to that
same origin, treats a forbidden `2xx` as `linked.authorization`, and requires successful object and
caller controls before a denial can pass. A cross-origin `source_subjects` contract is invalid.

Cross-origin linked reads never receive primary Authorization or Cookie values. Every linked
request uses a new client, ignores proxy environment variables, never follows a redirect, never
reuses `Set-Cookie`, and closes after response headers without consuming a potentially private or
binary body. The origin, object value, body, redirect destination and headers stay out of reports.
Linked cases count toward `max_cases`, participate in one-shot `scan`, known-finding baselines and
finding retests. A same-origin linked route participates in local OpenAPI coverage inventory; a
separate storage origin remains outside the primary API document's inventory.
Authenticated finding retests rerun the relevant source controls and same-origin linked allow
controls; a route that starts denying every request is inconclusive rather than fixed.

Run the loopback fixtures without external credentials:

```sh
permitprobe demo-linked --scenario safe         # exit 0
permitprobe demo-linked --scenario public-leak  # exit 1
permitprobe demo-linked --scenario redirect     # exit 2
permitprobe demo-linked --scenario authenticated-safe  # exit 0
permitprobe demo-linked --scenario authenticated-leak  # exit 1
```

[examples/linked-reads.json](examples/linked-reads.json) contains the complete synthetic contract.

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

## Active AI exploration

PermitProbe includes a bounded active explorer. The AI observes normalized results, forms
hypotheses and chooses the next **pre-authorized case IDs**. PermitProbe retains control of
credentials, HTTP delivery, expected policy, classification, budgets, coverage and completion.
The provider cannot create a URL, header, token, request body, shell command or tool call.
Variables explicitly forwarded with `--provider-env` may supply model authentication, but a
variable referenced by policy for a subject credential or public request header is rejected.

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

## Replay an exploration without AI

Turn an exploration report or its private checkpoint into a small deterministic manifest:

```sh
permitprobe replay-create exploration-result.json \
  --output exploration-replay.json

permitprobe replay my-security-checks/permitprobe.json \
  --manifest exploration-replay.json \
  --report replay-result.json
```

The manifest contains the target-bound policy digest, a digest of the source report, the exact
deterministic baseline case IDs and the additional completed case IDs scheduled during exploration.
It contains no URL, credential, header, response body, query value, provider rationale or raw
request. `replay-create` performs no network requests and creates the manifest privately (`0600`)
without overwriting an existing file.

`replay` does not invoke a provider. It accepts only case IDs still present in the current strict
policy catalogue, requires the exact deterministic baseline, requires the same normalized target
origin and sends GET requests through the ordinary bounded transport. A changed target or policy,
missing baseline control, unknown case, incomplete delivery or failed positive control exits `2`.
The replay report states the exact planned and observed counts and an explicit write count of zero.
The manifest ID detects accidental edits; it is not a signature or proof of who created the file.

## Finding history and retests

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
benign cases. Duplicate JSON keys, non-finite numbers and invalid Unicode are rejected before any
request. Prior reports remain unchanged and every retest carries its own lineage graph.

## Known-finding baselines

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

When every eligible failure matches the same target-bound policy digest plus exact check code and
target, the report status is `known_findings` and the command exits `0`. The digest includes the
normalized target scheme, host and port, so a baseline cannot move between environments. The
failed checks remain visible. A new target or check exits `1`; any incomplete evidence still
exits `2`. Availability, handoff and discovery findings are never baseline-eligible.

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
path traversal, cross-platform case or Unicode path collisions, Windows-reserved characters,
device names and overlong path components, and configured size overruns.
User deny patterns win over allow patterns;
neither can override the built-in exclusions. Glob patterns match the whole POSIX path,
and `*` can cross directory separators. Include specific files rather than a broad `*`.
The handoff root must be a canonical relative directory beside the real policy file. Absolute or
parent-traversing roots and any symlinked root component are refused.

Scanner configuration and inline `gitleaks:allow` comments in a payload cannot suppress
the scan. Gitleaks runs with a small explicit environment, without inherited credentials
or configuration overrides. PermitProbe verifies the official platform-specific executable
digest, copies those verified bytes into a private directory and runs that copy against neutral
filenames and private temporary files.

## What is reused, and what PermitProbe adds

| Component | Responsibility |
| --- | --- |
| Overstep **1.5.0** | Generate identity/resource cases and classify unexpected access, including cross-owner access |
| JSON Schema / `jsonschema` | Validate nested JSON response contracts |
| Gitleaks **8.30.1** | Detect known secret patterns in captured handoff text |
| PermitProbe | One-shot orchestration of declared website checks, bounded same-origin proposal discovery, strict configuration, offline OpenAPI-to-policy GET inventory, explicit known-finding baselines, bounded GET transport, full owner-pair coverage, per-identity positive controls, public-route status/schema/cache/latency contracts, safe environment-backed request variants, model-neutral active exploration, evidence lineage and retests, object/collection checks, declared redirect grants and private-cache headers, success **and denial** response contracts, explicit file boundaries, and checked-byte bundles |

The Gitleaks installer pins the release and archive hashes. `requirements.lock` pins the tested
Python dependency versions and every accepted distribution SHA256; project installation then runs
without dependency resolution. The verified scanner is published complete and executable at a new
path without replacing an existing file. Engine and dependency updates must pass the regression fixtures.
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
only normalized path shapes, policy-approved query names, counts and fixed source labels.
New reports, baselines, replay manifests, retest records, authentication matrices, exploration
state and checked bundles are created as owner-only files and never replace an existing artifact.
Unconfigured surfaces are named explicitly. An empty run cannot pass.
Replay reports additionally retain only the manifest and source-report digests plus case counts;
their ordinary evidence remains normalized in the same way as any declared API check.
Applied baseline summaries list known, new, unobserved and expired entry IDs without removing
the underlying failure checks.
One-shot reports additionally name each configured or skipped stage and record request counts,
GET-only scope, optional proposal discovery, disabled automatic expansion, disabled redirect
following, linked-read contract counts, disabled credential forwarding/body consumption for linked
cross-origin checks, explicit same-origin credential use, and zero writes.
Responses are consumed only in memory and capped in size/time. Proxy environment variables,
redirect following, automatic login, fixture mutations by `check`, and shared cross-identity
cookie jars are not used. `api.validation_timeout_ms` additionally caps the cumulative local
JSON parsing, schema and ownership-validation work in each execution batch. Declared redirect
responses are checked from their headers only.

The validation interrupt uses POSIX `SIGALRM`. The CLI runs validation on the main thread with no
pre-existing `ITIMER_REAL`. A library embedding that validates from another thread or already owns
that timer fails closed with `data.validation_budget` instead of running validation without a
deadline. During active exploration, validation is also clipped to the remaining `--max-seconds`
total deadline.

## Scope and limitations

The [threat model](docs/threat-model.md) records the protected assets, trusted inputs, DNS/TLS and
local-process assumptions, artifact boundary, and fail-closed guarantees in one reviewable place.

- Only declared GET cases and explicitly configured anonymous discovery sources are requested.
  This is not a full application security audit.
- A forbidden `2xx` response is an access-policy violation; content markers can strengthen
  evidence, but a status code alone does not prove a particular secret was disclosed.
- The owner must supply the intended policy, real test identities, and existing test objects.
  A wrong policy or overly permissive JSON Schema can produce misleading conclusions.
- JSON Schemas use a strict Draft 2020-12 keyword set. Unknown, legacy and content-annotation
  keywords, reference keywords, `format` assertions, and other declared dialects are rejected
  rather than silently ignored. Denial responses must also be valid JSON matching their declared
  schema. Regular expressions that Python identifies as ambiguous are also rejected at policy
  load instead of running with version-dependent character-set semantics.
- These observations are **not** a proof of database grants, RLS, complete storage/bucket policy,
  GraphQL, intermediary cache behavior, or write-path correctness. Cache checks cover response
  headers only. The tool never connects to a database in v0.3.
- Linked reads test status-level access to exact seeded object paths, anonymously or with the
  source identities on the exact primary origin. They do not validate returned body identity,
  signed-token cryptography or expiry, enumerate a bucket, use a storage service credential, or
  infer access rules for undeclared objects.
- Browser-facing response checks validate declared HTTP fields only. They do not execute CSP in a
  browser, prove that an application is free of XSS/CSRF, or exercise CORS preflight behavior.
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

Repository security automation runs Python CodeQL on pushes, pull requests and a weekly schedule.
Pull requests also receive dependency review, while grouped Python and GitHub Actions updates are
proposed weekly through Dependabot. Workflow actions remain pinned to full commit SHAs, and jobs
pin their Ubuntu release instead of following a moving `ubuntu-latest` label.

Registry publication resolves the requested release tag inside that trusted full-history `main`
checkout. Its exact commit must be an ancestor of `main` before PermitProbe materializes the release
source, compares wheel and sdist bytes and identity metadata, or makes a distribution available to
the publish job. The GitHub Release may contain only those two verified distributions; additional
assets are rejected. Artifact-only author names and author or maintainer email fields are rejected.

## What expanding verification means

This means adding **security checks that users can apply to their services**, separately
from adding unit tests for PermitProbe itself. The present regression suite tests the
tool against synthetic safe, vulnerable, and inconclusive cases; it does not audit a
deployed application automatically.

| Planned capability | Concrete question it would test |
| --- | --- |
| Declared datastore adapter | Can one authenticated user directly read another user's private row, even if the HTTP API denies it? |
| Write authorization cases | Can a user modify or delete another user's seeded test record? Run against disposable test data with explicit write-test scope. |
| MCP adapter | Can an agent identity invoke a tool or name a resource outside its declared permissions? |

These remaining items are **not implemented**. Finding history and bounded active exploration are
available from v0.2; sanitized case replay and linked API/storage reads are available from v0.3.
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
