# Contributing

Start with the installation and test commands in README.md. Keep examples synthetic.
Use an issue to describe a reproducible boundary failure, expected policy, and current
coverage gap. Security-sensitive reports belong in the private reporting channel.

A useful change includes a failing fixture, the smallest correction, and a passing
regression. Keep API authorization, response schemas, and handoff checks independently
usable. Document untested surfaces and errors explicitly; never trade them for a green exit.

The public contract is the policy schema, CLI, report schema, exit-code semantics, and
checked-bundle manifest. Change them deliberately and update examples and tests together.
Public documentation is in English. Contributions are provided under Apache-2.0.

## Publishing a verified GitHub release to PyPI

PermitProbe v0.1.1 is [published on PyPI](https://pypi.org/project/permitprobe/0.1.1/).
The maintainer's GitHub Trusted Publisher is configured; subsequent releases can
use the same workflow without creating another pending publisher.

The distribution, import package, and command are all named `permitprobe`. The former
name `boundaryguard` is already used by an unrelated PyPI project. Keep historical
GitHub tags and assets unchanged; the rename is released as v0.1.1.

One-time account setup belongs to the maintainer: create a PyPI account, verify its
email and configure two-factor authentication, then add a pending GitHub publisher at
<https://pypi.org/manage/account/publishing/> using:

| Field | Value |
| --- | --- |
| PyPI project name | `permitprobe` |
| GitHub owner | `Chorolee` |
| GitHub repository | `permitprobe` |
| Workflow filename | `publish-pypi.yml` |
| GitHub environment | `pypi` |

No long-lived PyPI token is stored in this repository. See the official
[pending publisher guide](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).
A pending publisher does not reserve a name or publish a package.

Before publication, run **Publish verified release to PyPI** on `main` with the
release tag and `publish=false`. This downloads the existing GitHub wheel and source
distribution, verifies their GitHub SHA256 digests, checks package name/version,
and runs strict metadata validation. It does not rebuild or upload the package.
After account setup and a successful validation, run the same workflow with
`publish=true`. Only the upload job receives the short-lived OIDC publishing permission.

Confirm the public PyPI version and file hashes after upload before adding registry
installation instructions to the README. Publication establishes availability;
downloads or dependent projects must be reported from real, independently verifiable
usage. Do not equate an automated installation with a distinct external user.
