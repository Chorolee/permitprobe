# Contributing

Start with the installation and test commands in README.md. Keep examples synthetic.
Use an issue to describe a reproducible boundary failure, expected policy, and current
coverage gap. Security-sensitive reports belong in the private reporting channel.

A useful change includes a failing fixture, the smallest correction, and a passing
regression. Keep API authorization, response schemas, and handoff checks independently
usable. Document untested surfaces and errors explicitly; never trade them for a green exit.
Exploration changes must remain model-neutral, use scripted fake providers in tests, and prove
that unknown cases, broken provider output, failed controls and partial coverage cannot pass.
OpenAPI inventory changes must remain offline: use synthetic local documents in tests, never
fetch schema references, and never convert a discovered operation into an executable request.
Baseline changes must prove that new targets still fail, expired entries resurface, unobserved
entries are retained, and any inconclusive check keeps exit code `2`.
One-shot scan changes must test stage attribution, request counts, zero writes, and the rule that
invalid offline inputs stop before live delivery. Discovery changes must keep source requests
fixed by policy, anonymous, same-origin and bounded; extracted locations remain sanitized,
proposal-only and unrequested.

The public contract is the policy schema, CLI, report schema, exit-code semantics, and
checked-bundle manifest. Change them deliberately and update examples and tests together.
Public documentation is in English. Contributions are provided under Apache-2.0.

## Preparing a release

The release commit must use the same stable version in
`pyproject.toml`, `permitprobe.__version__`, the changelog, release notes and publishing-workflow
default.

From a clean checkout with Gitleaks 8.30.1 installed, run:

```sh
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --no-deps -e .
ruff check src tests scripts
PERMITPROBE_GITLEAKS=.tools/gitleaks python -m pytest -q
python -m build --no-isolation
python -m twine check --strict dist/*
python scripts/smoke_wheel.py \
  --wheel dist/permitprobe-0.3.2-py3-none-any.whl \
  --requirements requirements.lock \
  --gitleaks .tools/gitleaks
```

The smoke test creates a new virtual environment outside the source tree, installs only the
hash-locked binary dependency files, installs the wheel without dependency resolution, verifies
the installed dependency graph, then runs the installed version command, policy-schema generator
and safe loopback demo. Before tagging a
release, replace `Unreleased` with the release date in
`CHANGELOG.md`, change the README and security policy to the new published line, and rerun the
checks above. Create an annotated tag from that exact commit, build the two distributions from the
tag, and attach only the wheel and source archive to the matching non-prerelease GitHub Release.
Do not rebuild between GitHub publication and registry publication.

## Publishing a verified GitHub release to PyPI

PermitProbe v0.3.2 is [published on PyPI](https://pypi.org/project/permitprobe/0.3.2/).
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
distribution, verifies their GitHub SHA256 digests, checks package name/version, proves that the
wheel package code and sdist build metadata match the separately checked-out release tag, then runs
strict metadata validation and the installed-wheel smoke test. The verifier, dependency lock,
scanner installer and smoke harness always come from the trusted `main` workflow checkout; release
tag contents cannot redefine their own verification. The validation run does not rebuild or upload.
After account setup and a successful validation, run the same workflow with
`publish=true`. Only the upload job receives the short-lived OIDC publishing permission.

Confirm the public PyPI version and file hashes after upload before adding registry
installation instructions to the README. Publication establishes availability;
downloads or dependent projects must be reported from real, independently verifiable
usage. Do not equate an automated installation with a distinct external user.
