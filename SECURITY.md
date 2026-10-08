# Security policy

Security Maintainer: [@Chorolee](https://github.com/Chorolee)

Responsible for vulnerability triage, security fixes, private vulnerability reports, and coordinated disclosure for PermitProbe.

PermitProbe is an early security testing tool. Version 0.3.x is the current supported line;
versions 0.2.x and 0.1.x are retained as release history. Report suspected security defects
through this repository's private vulnerability reporting channel (Security → Report a
vulnerability). If that channel is unavailable, contact the maintainer on GitHub to arrange a
private report before sharing sensitive details.
Do not include real credentials, response bodies, or customer data in public issues.

The threat model and current coverage limits are in the README. A passing check applies
only to configured cases and captured files; it does not certify a service or authorize
an external transfer. Test only systems you operate or are authorized to test.

Sensitive handling rules:

- Credentials enter through named environment variables and are not persisted in reports.
- Generated security artifacts use owner-only file permissions and never replace existing paths.
- Response bodies and raw scanner output must never reach PermitProbe reports.
- Exploration providers receive normalized case and observation metadata only. They do not
  receive target credentials, response bodies, headers, URLs, redirect destinations or files.
- A provider may select only precompiled case IDs. Its completion hint, prose or malformed
  output cannot produce a passing result or introduce a request outside the declared policy.
- Provider rationale and correlation strings are not retained in reports or state.
- Unknown outcomes, missing tools, missing files, and failed controls must not pass.
- No automatic remediation, production writes, deployment, or external upload.
- Dependency updates must retain known-bad and known-good regression fixtures.

The dependency, scanner and explicitly selected exploration-provider executables and their
configuration are trusted inputs. This project does not
claim to contain malicious local programs or protect a machine compromised by its owner.
