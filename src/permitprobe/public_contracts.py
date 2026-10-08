"""Bounded anonymous GET contracts for public and retired application routes."""

import asyncio
import hashlib
import os
from dataclasses import dataclass
from math import ceil
from time import monotonic
from typing import Callable
from urllib.parse import urlencode

import httpx

from permitprobe.policy import API, PublicResource, RequestVariant, api_contract_digest
from permitprobe.report import Evidence, Report
from permitprobe.response_contracts import no_store_matches
from permitprobe.validation import (
    ExactDraft202012Validator,
    ValidationBudgetExceeded,
    ValidationLimiter,
    exact_json_loads,
    exact_validator,
    schema_errors,
)
from permitprobe.web_security import cors_origin_key, response_security_results


@dataclass(frozen=True)
class PublicCase:
    id: str
    resource: PublicResource
    variant: RequestVariant


@dataclass
class PreparedPublic:
    config: API
    cases: list[PublicCase]
    headers: dict[str, dict[str, str]]
    validators: dict[str, ExactDraft202012Validator]


def _case_id(resource: str, variant: str) -> str:
    key = f"public-contract\0{resource}\0{variant}"
    return "ppc-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def public_case_descriptor(case: PublicCase) -> dict:
    return {
        "case_id": case.id,
        "case_type": "public_contract",
        "resource": case.resource.name,
        "subject": "anonymous",
        "owner": None,
        "role": "anonymous",
        "variant": case.variant.name,
        "expected": "match",
        "method": "GET",
        "lifecycle": case.resource.lifecycle,
    }


def public_cases(config: API) -> list[PublicCase]:
    return [
        PublicCase(_case_id(resource.name, variant.name), resource, variant)
        for resource in config.public_resources
        for variant in resource.variants
    ]


def _configure(report: Report) -> None:
    for surface in ("api", "data"):
        if surface not in report.configured:
            report.configured.append(surface)


def prepare_public(config: API, report: Report) -> PreparedPublic | None:
    _configure(report)
    cases = public_cases(config)
    resolved: dict[str, dict[str, str]] = {}
    seen_cors_origins = set()
    for case in cases:
        headers = {}
        for name, env in case.variant.header_envs.items():
            value = os.environ.get(env, "")
            if (
                not value
                or len(value) > 8_192
                or any(ord(char) < 32 or ord(char) > 126 for char in value)
            ):
                report.add(
                    "public.configuration",
                    "inconclusive",
                    case.resource.name,
                    "A request-variant header environment value is missing or invalid.",
                )
                return None
            headers[name] = value
        response_security = case.resource.response_security
        cors = response_security.cors if response_security else None
        if cors and case.variant.name in {*cors.allow_variants, *cors.deny_variants}:
            origin = next(
                (value for name, value in headers.items() if name.lower() == "origin"),
                "",
            )
            origin_key = cors_origin_key(origin)
            if origin_key is None or (case.resource.name, origin_key) in seen_cors_origins:
                report.add(
                    "public.configuration",
                    "inconclusive",
                    case.resource.name,
                    "Declared CORS request Origins must be valid and distinct.",
                )
                return None
            seen_cors_origins.add((case.resource.name, origin_key))
        resolved[case.id] = headers
    digest = api_contract_digest(config)
    if report.policy_digest is not None and report.policy_digest != digest:
        raise ValueError("inconsistent API policy digest")
    report.policy_digest = digest
    report.plan([public_case_descriptor(case) for case in cases])
    return PreparedPublic(
        config,
        cases,
        resolved,
        {
            resource.name: exact_validator(resource.response_schema)
            for resource in config.public_resources
            if resource.response_schema is not None
        },
    )


def _elapsed_ms(started: float, clock: Callable[[], float]) -> int:
    return max(0, ceil((clock() - started) * 1_000))


def execute_public_cases(
    prepared: PreparedPublic,
    selected: list[PublicCase],
    report: Report,
    *,
    validation_limiter: ValidationLimiter | None = None,
    clock: Callable[[], float] = monotonic,
) -> None:
    # Imported here to keep the transport in one place without a module cycle.
    from permitprobe.api import fetch

    if validation_limiter is None:
        validation_limiter = ValidationLimiter(
            prepared.config.validation_timeout_ms / 1_000
        )
    for case in selected:
        resource = case.resource
        target = f"{resource.name}/{case.variant.name}"
        query = urlencode([(item.name, item.value) for item in resource.query])
        url = prepared.config.base_url.rstrip("/") + resource.path
        if query:
            url += "?" + query
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            **prepared.headers[case.id],
        }
        started = clock()
        try:
            status, text, response_headers = asyncio.run(
                fetch(
                    url,
                    headers,
                    prepared.config,
                    timeout_seconds=resource.max_elapsed_ms / 1_000,
                )
            )
        except (TimeoutError, httpx.TimeoutException):
            elapsed = max(resource.max_elapsed_ms, _elapsed_ms(started, clock))
            report.observe(
                Evidence(
                    case.id,
                    resource.name,
                    "anonymous",
                    None,
                    case.variant.name,
                    "match",
                    "mismatch",
                    0,
                    "complete",
                    elapsed,
                )
            )
            report.add(
                "availability.latency",
                "fail",
                target,
                f"Response exceeded the declared {resource.max_elapsed_ms} ms limit.",
                case.id,
            )
            continue
        except Exception:
            elapsed = _elapsed_ms(started, clock)
            report.observe(
                Evidence(
                    case.id,
                    resource.name,
                    "anonymous",
                    None,
                    case.variant.name,
                    "match",
                    "unknown",
                    0,
                    "failed",
                    elapsed,
                )
            )
            report.add(
                "api.delivery",
                "inconclusive",
                target,
                "Request failed, response encoding unsupported, or response budget exceeded.",
                case.id,
            )
            continue

        elapsed = _elapsed_ms(started, clock)
        response_headers = httpx.Headers(response_headers)
        outcomes = []
        status_ok = status in resource.expected_statuses
        outcomes.append("pass" if status_ok else "fail")
        report.add(
            "public.status",
            "pass" if status_ok else "fail",
            target,
            f"HTTP {status} matched the declared status contract."
            if status_ok
            else f"HTTP {status} was outside the declared status contract.",
            case.id,
        )

        latency_ok = elapsed <= resource.max_elapsed_ms
        outcomes.append("pass" if latency_ok else "fail")
        report.add(
            "availability.latency",
            "pass" if latency_ok else "fail",
            target,
            f"Response completed in {elapsed} ms within the {resource.max_elapsed_ms} ms limit."
            if latency_ok
            else f"Response took {elapsed} ms, over the {resource.max_elapsed_ms} ms limit.",
            case.id,
        )

        if status_ok and resource.response_schema is not None:
            try:
                with validation_limiter.run():
                    data = exact_json_loads(text)
                    errors = schema_errors(prepared.validators[resource.name], data)
            except ValidationBudgetExceeded:
                outcomes.append("inconclusive")
                report.add(
                    "data.validation_budget",
                    "inconclusive",
                    target,
                    "Response parsing or contract validation exceeded the total validation budget.",
                    case.id,
                )
            except (ValueError, RecursionError):
                outcomes.append("fail")
                report.add(
                    "data.json",
                    "fail",
                    target,
                    "Response is not valid JSON; the public response contract was not met.",
                    case.id,
                )
            else:
                outcomes.append("fail" if errors else "pass")
                keywords = ", ".join(sorted({str(error.validator) for error in errors}))
                report.add(
                    "data.schema",
                    "fail" if errors else "pass",
                    target,
                    f"Response violates declared schema ({keywords}); values omitted."
                    if errors
                    else "Response matches declared schema.",
                    case.id,
                )

        if status_ok and resource.cache == "no-store":
            cache_ok = no_store_matches(response_headers)
            outcomes.append("pass" if cache_ok else "fail")
            report.add(
                "data.no_store",
                "pass" if cache_ok else "fail",
                target,
                "Response matches the declared no-store cache contract."
                if cache_ok
                else "Response does not match the declared no-store cache contract.",
                case.id,
            )

        if status_ok and resource.response_security is not None:
            try:
                with validation_limiter.run():
                    security_results = response_security_results(
                        resource.response_security,
                        case.variant.name,
                        prepared.headers[case.id],
                        response_headers,
                    )
            except ValidationBudgetExceeded:
                outcomes.append("inconclusive")
                report.add(
                    "data.validation_budget",
                    "inconclusive",
                    target,
                    "Response security validation exceeded the total validation budget.",
                    case.id,
                )
            else:
                for code, outcome, detail in security_results:
                    outcomes.append(outcome)
                    report.add(code, outcome, target, detail, case.id)

        report.observe(
            Evidence(
                case.id,
                resource.name,
                "anonymous",
                None,
                case.variant.name,
                "match",
                "unknown"
                if "inconclusive" in outcomes
                else "mismatch"
                if "fail" in outcomes
                else "match",
                status,
                "complete",
                elapsed,
            )
        )
