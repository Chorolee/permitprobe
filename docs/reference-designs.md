# Reference designs

PermitProbe studies established security tools at pinned revisions and adapts narrowly
selected design ideas to its own defensive, GET-only contract. This document records what
was observed, what was implemented independently, and what remains outside scope.

Reviewed on 2026-10-08.

## Reviewed sources

| Project | Reviewed revision | Relevant design | License at review |
|---|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei/tree/80a001ca0f2953ad789ffdd67a4d74b6689a2f40) | `80a001ca` | Declarative templates, strict validation, explicit input modes, bounded execution controls, and template provenance controls | MIT |
| [Schemathesis](https://github.com/schemathesis/schemathesis/tree/f15d63c7e54e43404fb339eaf4d2b1d81fadc50b) | `f15d63c7` | Load → discover → plan → generate → send/check → report phases; OpenAPI operation discovery; coverage and stateful phases; replay/baseline separation | MIT |
| [RESTler](https://github.com/microsoft/restler-fuzzer/tree/6d984deedbc54aad957fa3da0c7e9e5df23a2aee) | `6d984dee` | Compile an OpenAPI description, run a smoke test before fuzzing, measure operation coverage, infer dependencies, and retain replayable bug buckets | MIT |
| [ZAP](https://github.com/zaproxy/zaproxy/tree/816a41507336c4fe74bb6f08ab9ce6856127df01), its [API scan](https://github.com/zaproxy/zaproxy-website/blob/3cdbd50944f8a7358701b0c7708e3d1a16e03bcf/site/content/docs/docker/api-scan.md), and [automation framework](https://github.com/zaproxy/zaproxy-website/blob/3cdbd50944f8a7358701b0c7708e3d1a16e03bcf/site/content/docs/automate/automation-framework.md) | `816a4150` / `3cdbd509` | Import an API definition before scanning; separate automation jobs from outcome tests and alert policy | Apache-2.0 core / MIT website |
| [ARTEX](https://github.com/Autumn-27/ARTEX/tree/b55ceb1fdd84a813d77de09a06af83d323a81f85) | `b55ceb1f` | Asset/exploration graphs, evidence retention, and explicit finding retests | AGPL-3.0 |

No source code, templates, prompts, or test assets from these projects are copied into
PermitProbe. The links above are design references and do not imply compatibility,
endorsement, or a security assessment of those projects.

## Adaptation decisions

### Implemented

- ARTEX's graph/retest distinction informed PermitProbe's model-neutral exploration graph,
  append-only reports, evidence-bound findings, and deterministic retests.
- Schemathesis and RESTler both start from operation discovery and coverage before deeper
  generation. PermitProbe's `inventory-openapi` command therefore performs an offline
  OpenAPI-to-policy coverage pass before any live testing.
- ZAP's definition-import stage supports keeping inventory separate from active scanning.
  PermitProbe reads a local document only and never turns an imported operation into an
  executable request.
- Nuclei's declarative and validation-first model reinforces PermitProbe's strict policy
  parser: unknown fields fail, request capabilities are compiled by the core, and external
  providers cannot invent target requests.
- Schemathesis's [baseline separation](https://github.com/schemathesis/schemathesis/blob/f15d63c7e54e43404fb339eaf4d2b1d81fadc50b/docs/guides/baseline.md)
  informed PermitProbe's explicit known-finding files. PermitProbe keeps normalized failures
  visible, gates only exact code/target matches, retains unobserved entries, and lets incomplete
  evidence override every baseline match.

### Deliberately excluded

- OpenAPI inventory accepts bounded local JSON files only. It does not fetch a URL or an
  external `$ref`.
- Imported operations do not grant execution authority. Live execution remains limited to
  explicit PermitProbe resources and GET.
- RESTler-style state-changing dependency sequences, Schemathesis-style generated fuzzing,
  Nuclei community-template execution, and ZAP active scanning are not implemented.
- PermitProbe does not load code, hooks, authentication scripts, or plugins from an OpenAPI
  document.

## Next candidates

1. A sanitized replay bundle containing normalized case IDs and policy digests rather than
   raw requests, following RESTler's reproducibility goal while preserving PermitProbe's
   credential and response-body boundary.
2. Policy provenance or signatures if third-party policy distribution is introduced,
   following Nuclei's signed-template trust boundary.
3. Explicit staged automation plans only after each stage has independent budgets and outcome
   tests, following ZAP's job/test separation.
