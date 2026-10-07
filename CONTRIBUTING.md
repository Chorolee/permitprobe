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
