"""Overstep plans/classifies; PermitProbe adds strict delivery and data contracts.

Only the compiled GET-only REST subset is accepted. No upstream fixtures, auth
providers, MCP commands, waivers, or raw upstream reports are executed/written.
"""

import asyncio
import json
import os
import re
from importlib.metadata import version

import httpx
from jsonschema import Draft202012Validator
from overstep.matrix import Matrix
from overstep.models import Effect, Observation
from overstep.pipeline import run_pipeline
from overstep.planner import plan

from permitprobe.policy import API, ID_VALUE, _unique
from permitprobe.report import Report
from permitprobe.response_contracts import private_cache_matches, redirect_matches

OVERSTEP_VERSION = "1.5.0"
DENIAL_STATUSES = {401, 403, 404}


async def fetch(
    url: str, headers: dict[str, str], config: API, redirect_status: int | None = None
) -> tuple[int, str, httpx.Headers]:
    # Absolute deadline includes connect, headers, and a trickling response body.
    # A per-read socket timeout alone cannot bound a slow-drip server.
    async with asyncio.timeout(config.timeout_seconds):
        # New client per case: cookies cannot cross identity boundaries.
        async with httpx.AsyncClient(
            trust_env=False, follow_redirects=False, timeout=config.timeout_seconds
        ) as client:
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code == redirect_status:
                    # A declared redirect grant is fully observed in its headers.
                    # Do not let an irrelevant/invalid body erase that evidence.
                    return response.status_code, "", response.headers
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("encoded response")
                body = bytearray()
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > config.max_response_bytes:
                        raise ValueError("response budget exceeded")
                    body.extend(chunk)
                return response.status_code, body.decode("utf-8"), response.headers


def compile_matrix(config: API, *, resolve_tokens: bool = False) -> dict:
    if not resolve_tokens and (
        any(s.cookie_env for s in config.subjects) or any(r.redirect for r in config.resources)
    ):
        raise ValueError("cookie and redirect contracts cannot be exported as an auth-only matrix")
    subjects = []
    seen_tokens = set()
    for s in config.subjects:
        token = None
        credential_env = s.token_env or s.cookie_env
        if credential_env:
            token = "${" + credential_env + "}"
            if resolve_tokens:
                token = os.environ.get(credential_env, "")
                if (
                    not token.strip()
                    or token in seen_tokens
                    or len(token) > 8192
                    or any(ord(c) < (32 if s.cookie_env else 33) or ord(c) > 126 for c in token)
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
    if pointer == "":
        return value
    for key in pointer[1:].split("/"):
        key = key.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", key):
                raise KeyError(key)
            value = value[int(key)]
        elif isinstance(value, dict):
            value = value[key]
        else:
            raise KeyError(key)
    return value


def check_collection(data, rule, subject, report: Report, target: str) -> None:
    try:
        items = pointer_value(data, rule.items_pointer)
    except (KeyError, IndexError, TypeError, ValueError):
        items = None
    if not isinstance(items, list) or not items:
        report.add(
            "data.collection_control",
            "inconclusive",
            target,
            "Expected a nonempty collection; ownership control is unverified.",
        )
        return
    foreign = 0
    unknown = 0
    by_items = rule.items_attr is not None
    expected = (
        set(subject.owned_items[rule.items_attr])
        if by_items
        else {subject.attributes[rule.owner_attr]}
    )
    pointer = rule.item_pointer if by_items else rule.owner_pointer
    for item in items:
        try:
            owner = pointer_value(item, pointer)
        except (KeyError, IndexError, TypeError, ValueError):
            owner = None
        if (
            not isinstance(owner, str)
            or not owner.strip()
            or (by_items and not ID_VALUE.fullmatch(owner))
        ):
            unknown += 1
        elif owner not in expected:
            foreign += 1
    # Inspect every item: a malformed sibling must not hide a proven violation.
    if foreign:
        report.add(
            "data.collection_items" if by_items else "data.collection_owner",
            "fail",
            target,
            "Collection contains IDs outside the subject's declared item set."
            if by_items
            else "Collection contains items owned by someone other than the requesting subject.",
        )
    if unknown:
        report.add(
            "data.collection_control",
            "inconclusive",
            target,
            "Some collection items have no usable identity; ownership is unverified.",
        )
    if not foreign and not unknown:
        report.add(
            "data.collection_items" if by_items else "data.collection_owner",
            "pass",
            target,
            "Every returned item ID is in the subject's declared item set."
            if by_items
            else "Every returned collection item belongs to the requesting subject.",
        )


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
    validators = {
        r.name: Draft202012Validator(r.response_schema) for r in config.resources if not r.redirect
    }
    denial_validators = {r.name: Draft202012Validator(r.denial_schema) for r in config.resources}

    def executor(base_url, engine_subjects, planned, **_):
        tokens = {s.name: s.token for s in engine_subjects}
        observations = []
        for case in planned:
            target = f"{case.resource}/{case.subject}/{case.variant.value}"
            resource = resources[case.resource]
            owner = subjects[case.victim or case.subject]
            headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
            if tokens[case.subject]:
                if subjects[case.subject].cookie_env:
                    headers["Cookie"] = tokens[case.subject]
                else:
                    headers["Authorization"] = "Bearer " + tokens[case.subject]
            try:
                status, text, response_headers = asyncio.run(
                    fetch(
                        base_url.rstrip("/") + case.path,
                        headers,
                        config,
                        resource.redirect.status if resource.redirect else None,
                    )
                )
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
            if resource.redirect:
                is_grant = status == resource.redirect.status and redirect_matches(
                    resource.redirect,
                    response_headers,
                    resource.owner_param,
                    owner.attributes[resource.owner_attr],
                )
            else:
                is_grant = 200 <= status < 300
            effect = Effect.ALLOW if is_grant else Effect.DENY
            observations.append(
                Observation(
                    test_id=case.id,
                    status=status,
                    effect=effect,
                    matched_markers=[m for m in case.expect_markers if m and m in text],
                )
            )
            if not is_grant and status not in DENIAL_STATUSES:
                report.add(
                    "api.redirect_control" if resource.redirect else "api.unexpected_status",
                    "inconclusive",
                    target,
                    f"HTTP {status} did not establish the declared redirect grant."
                    if resource.redirect
                    else f"HTTP {status} does not establish an access-control decision.",
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
            if is_grant and resource.private_cache:
                valid_cache = private_cache_matches(
                    response_headers,
                    "Cookie" if subjects[case.subject].cookie_env else "Authorization",
                )
                report.add(
                    "data.private_cache",
                    "pass" if valid_cache else "fail",
                    target,
                    "Response matches the declared private-cache header contract."
                    if valid_cache
                    else "Response does not match the declared private-cache header contract.",
                )
            if is_grant and resource.redirect:
                report.add(
                    "api.redirect_control",
                    "pass",
                    target,
                    "Location matches the pinned origin, object path and query shape; destination not fetched.",
                )
                continue
            try:
                data = json.loads(
                    text,
                    object_pairs_hook=_unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
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
            if resource.collection and case.expected == Effect.ALLOW and effect == Effect.ALLOW:
                check_collection(data, resource.collection, subjects[case.subject], report, target)
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
