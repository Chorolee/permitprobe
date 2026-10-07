"""Overstep plans/classifies; BoundaryGuard adds strict delivery and data contracts.

Only the compiled GET-only REST subset is accepted. No upstream fixtures, auth
providers, MCP commands, waivers, or raw upstream reports are executed/written.
"""

import asyncio
import json
import os
from importlib.metadata import version

import httpx
from jsonschema import Draft202012Validator
from overstep.matrix import Matrix
from overstep.models import Effect, Observation
from overstep.pipeline import run_pipeline
from overstep.planner import plan

from boundaryguard.policy import API
from boundaryguard.report import Report

OVERSTEP_VERSION = "1.5.0"
DENIAL_STATUSES = {401, 403, 404}


async def fetch(url: str, headers: dict[str, str], config: API) -> tuple[int, str]:
    # Absolute deadline includes connect, headers, and a trickling response body.
    # A per-read socket timeout alone cannot bound a slow-drip server.
    async with asyncio.timeout(config.timeout_seconds):
        # New client per case: cookies cannot cross identity boundaries.
        async with httpx.AsyncClient(
            trust_env=False, follow_redirects=False, timeout=config.timeout_seconds
        ) as client:
            async with client.stream("GET", url, headers=headers) as response:
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("encoded response")
                body = bytearray()
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > config.max_response_bytes:
                        raise ValueError("response budget exceeded")
                    body.extend(chunk)
                return response.status_code, body.decode("utf-8")


def compile_matrix(config: API, *, resolve_tokens: bool = False) -> dict:
    subjects = []
    seen_tokens = set()
    for s in config.subjects:
        token = None
        if s.token_env:
            token = "${" + s.token_env + "}"
            if resolve_tokens:
                token = os.environ.get(s.token_env, "")
                if (
                    not token
                    or token in seen_tokens
                    or len(token) > 8192
                    or any(ord(c) < 33 or ord(c) > 126 for c in token)
                ):
                    raise ValueError("missing, duplicated, or invalid subject credential")
                seen_tokens.add(token)
        subjects.append(
            {
                "name": s.name,
                "role": s.role,
                "token": token,
                "attributes": s.attributes,
                "marker": s.marker,
            }
        )
    resources = []
    for r in config.resources:
        item = {"name": r.name, "type": r.kind, "request": {"method": "GET", "path": r.path}}
        if r.kind == "object":
            item.update(owner=r.owner_param, owner_attr=r.owner_attr)
        resources.append(item)
    return {
        "roles": list(dict.fromkeys(["anonymous", *[s.role for s in config.subjects]])),
        "modules": {"rest": {"base_url": config.base_url}},
        "subjects": subjects,
        "resources": resources,
        "policy": {r.name: {"allow": [a.model_dump() for a in r.allow]} for r in config.resources},
    }


def pointer_value(data, pointer: str):
    value = data
    for key in pointer[1:].split("/"):
        key = key.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if not key.isdecimal():
                raise KeyError(key)
            value = value[int(key)]
        elif isinstance(value, dict):
            value = value[key]
        else:
            raise KeyError(key)
    return value


def check_api(config: API, report: Report) -> None:
    report.configured.extend(["api", "data"])
    report.engines["overstep"] = version("overstep")
    if report.engines["overstep"] != OVERSTEP_VERSION:
        report.add("api.engine_version", "inconclusive", "api", "Untested Overstep version.")
        return
    try:
        matrix = Matrix.model_validate(compile_matrix(config, resolve_tokens=True))
        cases = plan(matrix)
    except Exception:
        report.add(
            "api.configuration",
            "inconclusive",
            "api",
            "Cannot compile matrix; check distinct credentials and resource declarations.",
        )
        return
    if not cases or len(cases) > config.max_cases or not any(c.is_negative for c in cases):
        report.add(
            "api.coverage",
            "inconclusive",
            "api",
            "Expected a bounded plan containing both allowed and denied requests.",
        )
        return
    # A public endpoint cannot establish that an authenticated credential works.
    anonymous = next(s.name for s in config.subjects if s.role == "anonymous")
    protected = {
        r.name for r in config.resources if not any(a.role == "anonymous" for a in r.allow)
    }
    for s in config.subjects:
        if s.name != anonymous and not any(
            c.subject == s.name and c.is_positive_control and c.resource in protected for c in cases
        ):
            report.add(
                "api.positive_control",
                "inconclusive",
                s.name,
                "Each authenticated subject needs an allowed request on a protected resource.",
            )
            return
    resources = {r.name: r for r in config.resources}
    subjects = {s.name: s for s in config.subjects}
    validators = {r.name: Draft202012Validator(r.response_schema) for r in config.resources}
    denial_validators = {r.name: Draft202012Validator(r.denial_schema) for r in config.resources}

    def executor(base_url, engine_subjects, planned, **_):
        tokens = {s.name: s.token for s in engine_subjects}
        observations = []
        for case in planned:
            target = f"{case.resource}/{case.subject}/{case.variant.value}"
            headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
            if tokens[case.subject]:
                headers["Authorization"] = "Bearer " + tokens[case.subject]
            try:
                status, text = asyncio.run(fetch(base_url.rstrip("/") + case.path, headers, config))
            except Exception:
                report.add(
                    "api.delivery",
                    "inconclusive",
                    target,
                    "Request failed, response encoding unsupported, or budget exceeded.",
                )
                observations.append(
                    Observation(
                        test_id=case.id, status=0, effect=Effect.DENY, error="delivery failed"
                    )
                )
                continue
            effect = Effect.ALLOW if 200 <= status < 300 else Effect.DENY
            observations.append(
                Observation(
                    test_id=case.id,
                    status=status,
                    effect=effect,
                    matched_markers=[m for m in case.expect_markers if m and m in text],
                )
            )
            if not 200 <= status < 300 and status not in DENIAL_STATUSES:
                report.add(
                    "api.unexpected_status",
                    "inconclusive",
                    target,
                    f"HTTP {status} does not establish an access-control decision.",
                )
                continue
            if case.expected == effect:
                report.add(
                    "api.authorization",
                    "pass",
                    target,
                    f"Expected {case.expected.value}; received HTTP {status}.",
                )
            elif case.expected == Effect.ALLOW:
                report.add(
                    "api.positive_control",
                    "inconclusive",
                    target,
                    f"Allowed control returned HTTP {status}; identity is unverified.",
                )
            # Unexpected allows are classified by Overstep below.
            try:
                data = json.loads(
                    text, parse_constant=lambda _: (_ for _ in ()).throw(ValueError())
                )
            except (ValueError, RecursionError):
                report.add(
                    "data.json",
                    "inconclusive",
                    target,
                    "Response is not valid JSON; fields were not verified.",
                )
                continue
            validator = (validators if effect == Effect.ALLOW else denial_validators)[case.resource]
            errors = list(validator.iter_errors(data))
            schema_code = "data.schema" if effect == Effect.ALLOW else "data.denial_schema"
            if errors:
                keywords = ", ".join(sorted({str(e.validator) for e in errors}))
                report.add(
                    schema_code,
                    "fail",
                    target,
                    f"Response violates declared schema ({keywords}); values omitted.",
                )
            else:
                report.add(schema_code, "pass", target, "Response matches declared schema.")
            resource = resources[case.resource]
            if (
                resource.kind == "object"
                and case.expected == Effect.ALLOW
                and effect == Effect.ALLOW
            ):
                owner = subjects[case.victim or case.subject]
                try:
                    actual = pointer_value(data, resource.identity_pointer)
                    valid_identity = actual == owner.attributes[resource.owner_attr]
                except (KeyError, IndexError, TypeError, ValueError):
                    valid_identity = False
                report.add(
                    "api.object_control",
                    "pass" if valid_identity else "inconclusive",
                    target,
                    "Expected object identity returned."
                    if valid_identity
                    else "Allowed control did not return its declared object identity.",
                )
        return observations

    try:
        result = run_pipeline(
            matrix, executor=executor, concurrency=1, read_only=True, max_retries=0
        )
    except Exception:
        report.add("api.engine", "inconclusive", "api", "Overstep did not complete the run.")
        return
    if result.coverage.unprobed:
        report.add("api.coverage", "inconclusive", "api", "Some object boundaries were not probed.")
    if len(result.observations) != len(cases):
        report.add("api.coverage", "inconclusive", "api", "Some planned observations are missing.")
    for finding in result.vulnerabilities:
        report.add(
            "api." + finding.vuln_class.value,
            "fail",
            f"{finding.resource}/{finding.subject}/{finding.variant.value}",
            f"Expected denial; HTTP {finding.status}. Evidence: {finding.confidence}.",
        )
