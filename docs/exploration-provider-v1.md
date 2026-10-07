# Exploration provider protocol v1

PermitProbe's active explorer is model-neutral. A provider is an executable that reads one
JSON request from standard input and writes one JSON reply to standard output. It may call
Astra, Claude, Gemini, a local model, an agent framework, or a deterministic program. The
PermitProbe core has no model-name branches and does not use a provider's native tool-call
format.

The provider is advisory. It cannot supply a URL, method, credential, header, body, expected
effect, shell command, or arbitrary tool call. It can select only the `case_id` values in the
current request's `capabilities` array. PermitProbe validates the selection, builds the request
from the trusted policy, performs the HTTP request, classifies the result, accounts for the
budget, and decides when the run is complete.

## Process boundary

Invoke an adapter with an absolute executable path:

```sh
permitprobe explore policy.json \
  --provider-command /absolute/path/to/my-model-adapter \
  --provider-name my-provider \
  --state exploration-state.json \
  --complete \
  --report result.json
```

Repeat `--provider-arg` for adapter arguments. The command is executed directly without a
shell. It receives a small environment containing only `PATH`, `LANG`, and variables named by
repeatable `--provider-env`. Subject token and cookie variables are not inherited implicitly.
The adapter is trusted local code and is responsible for its own model authentication.
Free-form provider rationale and correlation IDs are accepted for adapter interoperability but
are neither execution inputs nor retained in reports or state. State records only whether they
were present; capability proposals retain their typed gap and evidence dependencies.

`--state` must name a new path. PermitProbe checkpoints a private (`0600`) graph and report
atomically after the baseline and every exploration round. A provider failure therefore leaves
the last completed evidence state available without turning the run into a pass.

## Request

The request contains:

- `protocol_version`, `run_id`, `round_id`, and a digest of the policy contract;
- remaining round and request budgets;
- normalized capability records: case ID, resource, subject, owner alias, role, variant,
  expected effect, and method;
- normalized prior observations and check outcomes;
- the exact JSON Schema for the reply.

It never contains the base URL, path parameters, bearer tokens, cookies, response bodies,
response headers, redirect destinations, query values, or handoff file contents.

## Reply

```json
{
  "protocol_version": 1,
  "candidates": [
    {
      "case_id": "declared-case-id",
      "hypothesis_code": "cross_owner_access",
      "depends_on": ["earlier-evidence-id"],
      "priority": 90
    }
  ],
  "proposals": [
    {
      "capability_gap": "linked_storage",
      "depends_on": ["earlier-evidence-id"],
      "rationale": "Declare a linked storage read as an authorized capability in a later run."
    }
  ],
  "done_hint": false,
  "rationale": "Why these bounded cases should run next",
  "provider_request_id": "optional-provider-correlation-id"
}
```

Supported hypothesis codes are authorization, role, anonymous, collection, response, cache,
and retest hypotheses. A proposal describes a capability gap but is never executed. An operator
must add a fully contracted entry to `api.exploration_resources` before a later provider can
select it.

Unknown or repeated cases, missing dependencies, over-budget batches, broken JSON, an adapter
error, or a timeout stop exploration as inconclusive. `done_hint` is advisory: it cannot hide
unprobed cases or produce a clean result. With `--complete`, PermitProbe runs the remaining
authorized catalogue deterministically after successful provider rounds. Without it, confirmed
findings remain visible while unprobed coverage keeps exit code 2.

## Completion and lineage

The state graph distinguishes resources, subjects, planned cases, provider hypotheses, intents,
observations, capability proposals, and findings. PermitProbe owns the state transition:

`PRECHECK → BASELINE → PROPOSE → VALIDATE → EXECUTE → OBSERVE → FINALIZE`

Limits cover rounds, candidates per round, total requests, each provider call, and total elapsed
time. Reporter prose and provider completion claims are not completion gates. Reports are built
from the normalized ledger after execution.
