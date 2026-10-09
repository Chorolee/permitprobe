# Threat model

This document describes the security boundary implemented by the current PermitProbe source.
The policy author decides which staging system, identities, objects, routes, and local files are
authorized for a run. PermitProbe's job is to keep execution inside that declaration, preserve
the evidence needed to distinguish a pass from an unknown result, and avoid copying sensitive
values into ordinary reports or handoff bundles.

## Assets and security objectives

PermitProbe protects four classes of asset:

- bearer tokens and cookies supplied through named environment variables;
- response bodies, headers, redirect destinations, object identifiers, and discovery source text;
- local handoff files and the exact bytes approved for a checked bundle; and
- the integrity of the request plan, evidence lineage, result, baseline, replay manifest, and
  release artifacts.

The core security objectives are:

1. execute only finite, policy-declared GET requests;
2. send a credential only to the normalized origin that the policy authorized for it;
3. never turn a missing control, timeout, malformed input, unavailable scanner, incomplete
   coverage, or provider failure into a clean result;
4. keep raw sensitive values out of reports, exploration state, baselines, replay manifests, and
   provider requests; and
5. publish private local artifacts without silently replacing an existing immutable artifact.

## Trust boundaries and assumptions

| Component | Treatment | Required assumption |
| --- | --- | --- |
| Policy | Syntax, size, numbers, Unicode, and schema shape are validated strictly. Its declared authority is accepted. | The operator reviewed the policy and chose safe staging fixtures and GET handlers. |
| Credential environment variables | Values are private delivery inputs. Planning and classification receive placeholders. | The shell and local account supplying them are trusted. |
| Target service and responses | Network failures, status, headers, and bounded body bytes are untrusted evidence. | The configured HTTPS name identifies the intended staging service. |
| DNS and TLS | The platform resolver and certificate verifier are used. Redirects and proxy environment variables are disabled. | The host resolver, CA store, clock, and TLS implementation are trusted. |
| Discovery content | Parsed as bounded, untrusted input. Extracted locations are report-safe proposals only. | Only the fixed anonymous sources declared in policy may be fetched. |
| Exploration provider reply | Parsed as bounded, untrusted advice and restricted to current case IDs. | The selected provider executable itself is trusted local code. |
| Local JSON and handoff content | Read with byte limits and strict parsers; special files and unsafe handoff paths are rejected. | The local account and parent directories chosen for inputs and outputs are trusted. |
| Dependencies, Python runtime, OS, and scanner | Outside the runtime containment boundary. Locks and release checks reduce supply-chain risk. | Installed trusted bytes match the reviewed locks and pinned digests. |

A policy is an authorization document, not hostile remote input. Strict parsing prevents ambiguous
or resource-exhausting policy shapes; it cannot decide whether an operator intended to test a
particular host or whether a declared GET handler is free of side effects.

An exploration provider is a capability-selection boundary, not an operating-system sandbox.
PermitProbe does not send it URLs, credentials, headers, response bodies, redirect destinations,
query values, or files, and it cannot make PermitProbe execute an invented request. The executable
runs under the caller's account, however, and retains any filesystem or network access that the OS
already grants that account. Use a separately sandboxed adapter when the provider itself is not
trusted.

## Network execution boundary

Configured origins must use HTTPS, except that HTTP is accepted for literal loopback addresses so
local tests can run without TLS. Origin equality is based on normalized scheme, hostname, and port.
Each case uses a fresh client with proxy environment variables disabled, redirect following off,
and no shared cookie jar. The core constructs the URL, headers, query, and path values from the
validated policy and selected case; provider output, OpenAPI content, and discovery proposals do
not become request components.

OpenAPI security requirements are validated against their declared version before they can mark a
route protected. OAuth scopes must exist in the inline scheme, and non-OAuth requirement arrays
follow the different OpenAPI 3.0 and 3.1+ rules.

Hostnames use ordinary platform DNS resolution. PermitProbe does not pin an IP address or require
successive resolutions to return the same address. HTTPS still validates the configured hostname,
and credentials remain bound to that normalized name and port. A result therefore describes the
service reached through the operator's resolver and current load-balancing path; it is not evidence
that every backend address behaved identically.

Response bodies are streamed under a byte cap and are consumed only in memory. Transport timeouts
bound network work, and a separate cumulative validation deadline bounds local JSON parsing,
schema evaluation, ownership checks, and browser-response checks. Exact JSON numbers are retained
during validation. Reports store normalized findings and evidence IDs rather than response bodies,
raw headers, URLs, query values, or observed object values. Operator-configured resource, subject,
variant, and file labels are retained for diagnosis; those names must not contain secrets.

Linked reads can forward a source identity only when the linked origin exactly matches the primary
origin and the policy explicitly selects `source_subjects`. Cross-origin linked reads are
anonymous. Redirect locations are validated from headers and are never followed.

## Discovery and exploration boundary

Discovery fetches only the exact anonymous seed, robots, and sitemap paths fixed in the policy.
Parsed links, forms, redirects, robots directives, and sitemap entries can produce sanitized
coverage proposals, but the discovery stage never fetches them. Response-derived labels survive
in a report only through an explicit policy allowlist.

Active exploration exposes a finite catalogue of precompiled case IDs. The provider may prioritize
those IDs and attach evidence dependencies. PermitProbe validates every selection, builds and
delivers the request itself, records the observation, and controls completion. Provider prose,
completion hints, malformed output, timeouts, and failures cannot create a passing result.
Replay revalidates sanitized IDs against the current policy and does not invoke a provider.

## Local files and artifact boundary

Local JSON inputs must resolve to bounded regular files. Handoff roots and member paths are
canonical relative paths; directory and file components are opened without following symlinks.
Private directories, credentials, keys, hard links, binary content, device names, cross-platform
case or Unicode aliases, and configured size overruns are rejected. Gitleaks is copied to a private
temporary location and its complete platform-specific digest is verified before it scans staged
bytes. The archive is then built from those checked bytes rather than by rereading source paths.

Starter directories and files, reports, and other immutable artifacts are created with owner-only
permissions; immutable artifacts always use a new path.
Exploration state also starts at a new owner-only path, then uses atomic replacement for its
checkpoints. Complete report, bundle, state and installed-scanner bytes are flushed from the open
file descriptor before their staged inode is published. These guarantees assume a trusted parent
directory and local account. PermitProbe is not a defense against another process with the same
account privileges, a hostile output-directory owner, filesystem rollback, or a compromised kernel.

## Supply-chain boundary

Development and release dependencies are installed from a complete SHA256-locked requirements
file, and isolated wheel smoke requires `pip check` to accept the installed dependency graph.
GitHub Actions use commit-pinned actions and an explicit supported runner OS label. The scanner
installer verifies the official archive and executable digests before publication, and
every scan verifies the executable again before use. CI scans the clean source checkout before
generating artifacts, using fixed built-in scanner rules without repository suppression files or
inline allow comments. Release verification runs from the trusted main checkout, requires the
requested tag to be an ancestor of main, downloads registry artifacts, verifies their digests,
requires the release to contain only the expected wheel and source distribution, bounds decompressed
sdist bytes and archive member counts, and compares their executable package bytes with that exact
commit. Distribution validation also rejects author and maintainer identity fields that are absent
from the reviewed project metadata.

These measures make reviewed bytes traceable; they do not sandbox the Python interpreter, an
installed dependency, the operating system, or a deliberately selected local executable.

## Failure semantics

Exit code `0` means every configured control completed and passed, or each remaining failure was
matched by an exact reviewed baseline entry. Exit code `1` means a new violation was observed. Exit
code `2` means the run is inconclusive, including incomplete coverage, failed positive controls,
validation-budget exhaustion, missing inputs, malformed evidence, scanner failure, or transport
failure that prevents a conclusion. A baseline cannot suppress an inconclusive control.

## Outside this model

PermitProbe does not claim to provide:

- write-path testing, automatic remediation, authentication, or production safety;
- recursive crawling, JavaScript execution, parameter fuzzing, CORS preflight, or exhaustive DAST;
- proof of database grants, row-level security, storage policy, cryptographic token validity, or
  behavior across every CDN or load-balancer backend;
- browser execution of CSP, CSRF or XSS resistance, complete PII classification, archive scanning,
  prompt-injection prevention, or runtime egress control; or
- containment of a malicious policy author, provider executable, dependency, local account,
  output-directory owner, resolver, CA store, Python runtime, operating system, or kernel.

Security-sensitive changes should preserve the objectives above and add a regression test for any
new executable input, credential path, report field, artifact path, parser, or failure-to-pass
transition.
