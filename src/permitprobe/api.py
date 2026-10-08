"""Overstep plans/classifies; PermitProbe adds strict delivery and data contracts.

Only the compiled GET-only REST subset is accepted. No upstream fixtures, auth
providers, MCP commands, waivers, or raw upstream reports are executed/written.
"""

import asyncio
import json
import os
import re
from dataclasses import dataclass
from importlib.metadata import version
from time import monotonic
from typing import Callable

import httpx
from jsonschema import Draft202012Validator
from overstep.classifier import classify
from overstep.matrix import Matrix
from overstep.models import Effect, Observation, RunResult, TestCase
from overstep.planner import plan

from permitprobe.policy import API, ID_VALUE, _unique, api_contract_digest
from permitprobe.report import Evidence, Report
from permitprobe.response_contracts import private_cache_matches, redirect_matches
from permitprobe.validation import (
    ValidationBudgetExceeded,
    ValidationLimiter,
    schema_errors,
)

OVERSTEP_VERSION = "1.5.0"
DENIAL_STATUSES = {401, 403, 404}


async def fetch(
    url: str,
    headers: dict[str, str],
    config: API,
    redirect_status: int | None = None,
    timeout_seconds: float | None = None,
) -> tuple[int, str, httpx.Headers]:
    # Absolute deadline includes connect, headers, and a trickling response body.
    # A per-read socket timeout alone cannot bound a slow-drip server.
    timeout = (
        config.timeout_seconds
        if timeout_seconds is None
        else min(config.timeout_seconds, timeout_seconds)
    )
    async with asyncio.timeout(timeout):
        # New client per case: cookies cannot cross identity boundaries.
        async with httpx.AsyncClient(
            trust_env=False, follow_redirects=False, timeout=timeout
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


def compile_matrix(
    config: API, *, resolve_tokens: bool = False, include_exploration: bool = False
) -> dict:
    if not config.resources:
        raise ValueError("an authorization matrix requires an ordinary resource")
    if not resolve_tokens and (
        any(s.cookie_env for s in config.subjects)
        or any(
            r.redirect
            for r in [
                *config.resources,
                *(config.exploration_resources if include_exploration else []),
            ]
        )
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
    selected_resources = [
        *config.resources,
        *(config.exploration_resources if include_exploration else []),
    ]
    for r in selected_resources:
        item = {"name": r.name, "type": r.kind, "request": {"method": "GET", "path": r.path}}
        if r.kind == "object":
            item.update(owner=r.owner_param, owner_attr=r.owner_attr)
        resources.append(item)
    return {
        "roles": list(dict.fromkeys(["anonymous", *[s.role for s in config.subjects]])),
        "modules": {"rest": {"base_url": config.base_url}},
        "probe_victims": config.probe_victims,
        "subjects": subjects,
        "resources": resources,
        "policy": {
            resource.name: {"allow": [rule.model_dump() for rule in resource.allow]}
            for resource in selected_resources
        },
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


def collection_results(data, rule, subject) -> list[tuple[str, str, str]]:
    try:
        items = pointer_value(data, rule.items_pointer)
    except (KeyError, IndexError, TypeError, ValueError):
        items = None
    if not isinstance(items, list) or not items:
        return [
            (
                "data.collection_control",
                "inconclusive",
                "Expected a nonempty collection; ownership control is unverified.",
            )
        ]
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
    results = []
    # Inspect every item: a malformed sibling must not hide a proven violation.
    if foreign:
        results.append(
            (
                "data.collection_items" if by_items else "data.collection_owner",
                "fail",
                "Collection contains IDs outside the subject's declared item set."
                if by_items
                else "Collection contains items owned by someone other than the requesting subject.",
            )
        )
    if unknown:
        results.append(
            (
                "data.collection_control",
                "inconclusive",
                "Some collection items have no usable identity; ownership is unverified.",
            )
        )
    if not foreign and not unknown:
        results.append(
            (
                "data.collection_items" if by_items else "data.collection_owner",
                "pass",
                "Every returned item ID is in the subject's declared item set."
                if by_items
                else "Every returned collection item belongs to the requesting subject.",
            )
        )
    return results


def check_collection(
    data, rule, subject, report: Report, target: str, evidence_id: str | None = None
) -> None:
    for code, outcome, detail in collection_results(data, rule, subject):
        report.add(code, outcome, target, detail, evidence_id)


def case_target(case: TestCase) -> str:
    parts = [case.resource, case.subject, case.variant.value]
    if case.victim:
        parts.append(case.victim)
    return "/".join(parts)


def case_descriptor(case: TestCase) -> dict:
    return {
        "case_id": case.id,
        "resource": case.resource,
        "subject": case.subject,
        "owner": case.victim,
        "role": case.role,
        "variant": case.variant.value,
        "expected": case.expected.value,
        "method": case.method,
    }


@dataclass
class PreparedAPI:
    config: API
    matrix: Matrix
    cases: list[TestCase]
    resources: dict
    subjects: dict
    validators: dict
    denial_validators: dict


def prepare_api(
    config: API,
    report: Report,
    *,
    include_exploration: bool = False,
    include_public: bool = True,
) -> PreparedAPI | None:
    for surface in ("api", "data"):
        if surface not in report.configured:
            report.configured.append(surface)
    report.engines["overstep"] = version("overstep")
    if report.engines["overstep"] != OVERSTEP_VERSION:
        report.add("api.engine_version", "inconclusive", "api", "Untested Overstep version.")
        return None
    try:
        matrix = Matrix.model_validate(
            compile_matrix(
                config,
                resolve_tokens=True,
                include_exploration=include_exploration,
            )
        )
        cases = plan(matrix)
    except Exception:
        report.add(
            "api.configuration",
            "inconclusive",
            "api",
            "Cannot compile matrix; check distinct credentials and resource declarations.",
        )
        return None
    if not cases or len(cases) > config.max_cases or not any(c.is_negative for c in cases):
        report.add(
            "api.coverage",
            "inconclusive",
            "api",
            "Expected a bounded plan containing both allowed and denied requests.",
        )
        return None
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
            return None
    selected_resources = [
        *config.resources,
        *(config.exploration_resources if include_exploration else []),
    ]
    resources = {resource.name: resource for resource in selected_resources}
    subjects = {s.name: s for s in config.subjects}
    validators = {
        resource.name: Draft202012Validator(resource.response_schema)
        for resource in selected_resources
        if not resource.redirect
    }
    denial_validators = {
        resource.name: Draft202012Validator(resource.denial_schema)
        for resource in selected_resources
    }
    report.policy_digest = api_contract_digest(
        config,
        include_exploration=include_exploration,
        include_public=include_public,
    )
    report.plan([case_descriptor(case) for case in cases])
    return PreparedAPI(
        config, matrix, cases, resources, subjects, validators, denial_validators
    )


def execute_api_cases(
    prepared: PreparedAPI,
    planned: list[TestCase],
    report: Report,
    *,
    deadline: float | None = None,
    validation_limiter: ValidationLimiter | None = None,
    clock: Callable[[], float] = monotonic,
) -> list[Observation]:
    if validation_limiter is None:
        validation_limiter = ValidationLimiter(
            prepared.config.validation_timeout_ms / 1_000
        )
    tokens = {subject.name: subject.token for subject in prepared.matrix.subjects}
    observations = []
    for case in planned:
        remaining = None if deadline is None else deadline - clock()
        if remaining is not None and remaining <= 0:
            break
        target = case_target(case)
        resource = prepared.resources[case.resource]
        owner = prepared.subjects[case.victim or case.subject]
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if tokens[case.subject]:
            if prepared.subjects[case.subject].cookie_env:
                headers["Cookie"] = tokens[case.subject]
            else:
                headers["Authorization"] = "Bearer " + tokens[case.subject]
        try:
            status, text, response_headers = asyncio.run(
                fetch(
                    prepared.config.base_url.rstrip("/") + case.path,
                    headers,
                    prepared.config,
                    resource.redirect.status if resource.redirect else None,
                    remaining,
                )
            )
        except Exception:
            observation = Observation(
                test_id=case.id, status=0, effect=Effect.DENY, error="delivery failed"
            )
            observations.append(observation)
            report.observe(
                Evidence(
                    case.id,
                    case.resource,
                    case.subject,
                    case.victim,
                    case.variant.value,
                    case.expected.value,
                    "unknown",
                    0,
                    "failed",
                )
            )
            report.add(
                "api.delivery",
                "inconclusive",
                target,
                "Request failed, response encoding unsupported, or budget exceeded.",
                case.id,
            )
            continue
        if deadline is not None and clock() >= deadline:
            observation = Observation(
                test_id=case.id,
                status=0,
                effect=Effect.DENY,
                error="delivery exceeded total deadline",
            )
            observations.append(observation)
            report.observe(
                Evidence(
                    case.id,
                    case.resource,
                    case.subject,
                    case.victim,
                    case.variant.value,
                    case.expected.value,
                    "unknown",
                    0,
                    "failed",
                )
            )
            report.add(
                "api.delivery",
                "inconclusive",
                target,
                "Request exceeded the total run deadline; its response was discarded.",
                case.id,
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
        observation = Observation(
            test_id=case.id,
            status=status,
            effect=effect,
            matched_markers=[marker for marker in case.expect_markers if marker and marker in text],
        )
        observations.append(observation)
        report.observe(
            Evidence(
                case.id,
                case.resource,
                case.subject,
                case.victim,
                case.variant.value,
                case.expected.value,
                effect.value,
                status,
                "complete",
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
                case.id,
            )
            continue
        if case.expected == effect:
            report.add(
                "api.authorization",
                "pass",
                target,
                f"Expected {case.expected.value}; received HTTP {status}.",
                case.id,
            )
        elif case.expected == Effect.ALLOW:
            report.add(
                "api.positive_control",
                "inconclusive",
                target,
                f"Allowed control returned HTTP {status}; identity is unverified.",
                case.id,
            )
        # Unexpected allows are classified after every selected case is observed.
        if is_grant and resource.private_cache:
            valid_cache = private_cache_matches(
                response_headers,
                "Cookie" if prepared.subjects[case.subject].cookie_env else "Authorization",
            )
            report.add(
                "data.private_cache",
                "pass" if valid_cache else "fail",
                target,
                "Response matches the declared private-cache header contract."
                if valid_cache
                else "Response does not match the declared private-cache header contract.",
                case.id,
            )
        if is_grant and resource.redirect:
            report.add(
                "api.redirect_control",
                "pass",
                target,
                "Location matches the pinned origin, object path and query shape; destination not fetched.",
                case.id,
            )
            continue
        resource_collection_results = []
        valid_identity = None
        try:
            with validation_limiter.run(
                max_seconds=None if deadline is None else deadline - clock()
            ):
                data = json.loads(
                    text,
                    object_pairs_hook=_unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
                )
                validator = (
                    prepared.validators if effect == Effect.ALLOW else prepared.denial_validators
                )[case.resource]
                errors = schema_errors(validator, data)
                if resource.collection and case.expected == Effect.ALLOW and effect == Effect.ALLOW:
                    resource_collection_results = collection_results(
                        data,
                        resource.collection,
                        prepared.subjects[case.subject],
                    )
                if (
                    resource.kind == "object"
                    and case.expected == Effect.ALLOW
                    and effect == Effect.ALLOW
                ):
                    try:
                        actual = pointer_value(data, resource.identity_pointer)
                        valid_identity = actual == owner.attributes[resource.owner_attr]
                    except (KeyError, IndexError, TypeError, ValueError):
                        valid_identity = False
        except ValidationBudgetExceeded:
            report.add(
                "data.validation_budget",
                "inconclusive",
                target,
                "Response parsing or contract validation exceeded the total validation budget.",
                case.id,
            )
            continue
        except (ValueError, RecursionError):
            report.add(
                "data.json",
                "inconclusive",
                target,
                "Response is not valid JSON; fields were not verified.",
                case.id,
            )
            continue
        schema_code = "data.schema" if effect == Effect.ALLOW else "data.denial_schema"
        if errors:
            keywords = ", ".join(sorted({str(error.validator) for error in errors}))
            report.add(
                schema_code,
                "fail",
                target,
                f"Response violates declared schema ({keywords}); values omitted.",
                case.id,
            )
        else:
            report.add(
                schema_code, "pass", target, "Response matches declared schema.", case.id
            )
        for code, outcome, detail in resource_collection_results:
            report.add(code, outcome, target, detail, case.id)
        if valid_identity is not None:
            report.add(
                "api.object_control",
                "pass" if valid_identity else "inconclusive",
                target,
                "Expected object identity returned."
                if valid_identity
                else "Allowed control did not return its declared object identity.",
                case.id,
            )
    return observations


def finalize_api(
    prepared: PreparedAPI,
    executed_cases: list[TestCase],
    observations: list[Observation],
    report: Report,
    *,
    require_full_coverage: bool = True,
) -> None:
    observed_ids = {observation.test_id for observation in observations}
    if require_full_coverage and observed_ids != {case.id for case in prepared.cases}:
        report.add(
            "api.coverage",
            "inconclusive",
            "api",
            "Some planned observations are missing.",
        )
    try:
        findings = classify(
            prepared.matrix,
            executed_cases,
            observations,
            base_url=prepared.config.base_url,
        )
        result = RunResult(
            base_url=prepared.config.base_url,
            cases=executed_cases,
            observations=observations,
            findings=findings,
        )
    except Exception:
        report.add("api.engine", "inconclusive", "api", "Overstep did not complete the run.")
        return
    cases = {case.id: case for case in executed_cases}
    for finding in result.vulnerabilities:
        case = cases.get(finding.test_id)
        target = case_target(case) if case else (
            f"{finding.resource}/{finding.subject}/{finding.variant.value}"
        )
        report.add(
            "api." + finding.vuln_class.value,
            "fail",
            target,
            f"Expected denial; HTTP {finding.status}. Evidence: {finding.confidence}.",
            finding.test_id,
        )


def check_api(config: API, report: Report) -> None:
    from permitprobe.public_contracts import execute_public_cases, prepare_public

    prepared = prepare_api(config, report) if config.resources else None
    if config.resources and prepared is None:
        return
    public = prepare_public(config, report) if config.public_resources else None
    if config.public_resources and public is None:
        return
    planned = (len(prepared.cases) if prepared else 0) + (len(public.cases) if public else 0)
    if planned > config.max_cases:
        report.add(
            "api.coverage",
            "inconclusive",
            "api",
            "The combined authorization and public contract plan exceeds max_cases.",
        )
        return
    validation_limiter = ValidationLimiter(config.validation_timeout_ms / 1_000)
    if prepared:
        observations = execute_api_cases(
            prepared,
            prepared.cases,
            report,
            validation_limiter=validation_limiter,
        )
        finalize_api(prepared, prepared.cases, observations, report)
    if public:
        execute_public_cases(
            public,
            public.cases,
            report,
            validation_limiter=validation_limiter,
        )
