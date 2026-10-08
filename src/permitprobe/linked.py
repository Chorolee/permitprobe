"""Header-only alternate reads linked to established private API objects."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass

import httpx
from overstep.models import Effect, TestCase, Variant

from permitprobe.api import PreparedAPI
from permitprobe.policy import (
    API,
    LinkedResource,
    Resource,
    Subject,
    api_contract_digest,
    origin_key,
)
from permitprobe.report import Evidence, Report


@dataclass(frozen=True)
class LinkedCase:
    id: str
    resource: LinkedResource
    source: Resource
    subject: Subject
    owner: Subject
    variant: str
    expected: Effect
    control_id: str
    caller_control_id: str | None


@dataclass
class PreparedLinked:
    config: API
    cases: list[LinkedCase]
    tokens: dict[str, str | None]


def _case_id(resource: LinkedResource, source: str, subject: str, owner: str) -> str:
    key = (
        f"linked-read\0{resource.name}\0{source}\0{owner}"
        if resource.authentication == "anonymous"
        else f"linked-read\0{resource.name}\0{source}\0source_subjects\0{subject}\0{owner}"
    )
    return "ppl-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def _target(case: LinkedCase) -> str:
    if case.resource.authentication == "anonymous":
        return f"{case.resource.name}/anonymous/{case.owner.name}"
    parts = [case.resource.name, case.subject.name, case.variant]
    if case.subject.name != case.owner.name:
        parts.append(case.owner.name)
    return "/".join(parts)


def _reported_subject(case: LinkedCase) -> str:
    # Keep the original anonymous linked-read report contract stable. Authenticated
    # route mirrors use the configured subject names from the source matrix.
    if case.resource.authentication == "anonymous":
        return "anonymous"
    return case.subject.name


def linked_case_descriptor(case: LinkedCase) -> dict:
    descriptor = {
        "case_id": case.id,
        "case_type": "linked_read",
        "resource": case.resource.name,
        "source_resource": case.source.name,
        "subject": _reported_subject(case),
        "owner": case.owner.name,
        "role": case.subject.role,
        "variant": case.variant,
        "expected": case.expected.value,
        "method": "GET",
    }
    if case.resource.authentication != "anonymous":
        descriptor["authentication"] = case.resource.authentication
    return descriptor


def _positive_control(
    cases: list[TestCase], source: Resource, owner: Subject
) -> TestCase | None:
    return next(
        (
            case
            for case in cases
            if case.resource == source.name
            and case.subject == owner.name
            and case.variant == Variant.SELF
            and case.expected == Effect.ALLOW
        ),
        None,
    )


def prepare_linked(
    config: API,
    primary: PreparedAPI,
    report: Report,
) -> PreparedLinked | None:
    digest = api_contract_digest(config)
    if report.policy_digest is not None and report.policy_digest != digest:
        raise ValueError("inconsistent API policy digest")
    report.policy_digest = digest
    sources = {resource.name: resource for resource in config.resources}
    subjects = {subject.name: subject for subject in config.subjects}
    owners = [subject for subject in config.subjects if subject.role != "anonymous"]
    anonymous = next(subject for subject in config.subjects if subject.role == "anonymous")
    tokens = {subject.name: subject.token for subject in primary.matrix.subjects}
    cases = []
    for resource in config.linked_resources:
        source = sources[resource.source_resource]
        controls = {
            owner.name: _positive_control(primary.cases, source, owner) for owner in owners
        }
        if any(control is None for control in controls.values()):
            report.add(
                "linked.configuration",
                "inconclusive",
                resource.name,
                "A linked read has no matching source-object positive control.",
            )
            return None
        if resource.authentication == "source_subjects" and origin_key(
            resource.origin
        ) != origin_key(config.base_url):
            report.add(
                "linked.configuration",
                "inconclusive",
                resource.name,
                "Authenticated linked reads require the exact primary origin.",
            )
            return None
        if resource.authentication == "anonymous":
            for owner in owners:
                cases.append(
                    LinkedCase(
                        _case_id(resource, source.name, anonymous.name, owner.name),
                        resource,
                        source,
                        anonymous,
                        owner,
                        "direct",
                        Effect.DENY,
                        controls[owner.name].id,
                        None,
                    )
                )
            continue
        for primary_case in primary.cases:
            if primary_case.resource != source.name:
                continue
            owner_name = primary_case.victim or primary_case.subject
            owner = subjects[owner_name]
            subject = subjects[primary_case.subject]
            caller_control = (
                None
                if subject.role == "anonymous"
                else _positive_control(primary.cases, source, subject)
            )
            if subject.role != "anonymous" and caller_control is None:
                report.add(
                    "linked.configuration",
                    "inconclusive",
                    resource.name,
                    "An authenticated linked caller has no positive control.",
                )
                return None
            cases.append(
                LinkedCase(
                    _case_id(resource, source.name, subject.name, owner.name),
                    resource,
                    source,
                    subject,
                    owner,
                    primary_case.variant.value,
                    primary_case.expected,
                    controls[owner.name].id,
                    caller_control.id if caller_control else None,
                )
            )
    report.plan([linked_case_descriptor(case) for case in cases])
    return PreparedLinked(config, cases, tokens)


def source_control_cases(primary: PreparedAPI, selected: list[LinkedCase]) -> list[TestCase]:
    selected_ids = {
        control_id
        for case in selected
        for control_id in (case.control_id, case.caller_control_id)
        if control_id is not None
    }
    return [case for case in primary.cases if case.id in selected_ids]


def linked_control_cases(
    prepared: PreparedLinked, selected: list[LinkedCase]
) -> list[LinkedCase]:
    required = set()
    for case in selected:
        if case.resource.authentication != "source_subjects":
            continue
        required.add((case.resource.name, case.owner.name))
        if case.subject.role != "anonymous":
            required.add((case.resource.name, case.subject.name))
    return [
        case
        for case in prepared.cases
        if case.expected == Effect.ALLOW
        and case.subject.name == case.owner.name
        and (case.resource.name, case.subject.name) in required
    ]


def _control_passed(control_id: str, source: Resource, report: Report) -> bool:
    evidence = report.evidence.get(control_id)
    code = "api.redirect_control" if source.redirect else "api.object_control"
    return bool(
        evidence
        and evidence.delivery == "complete"
        and evidence.expected == "allow"
        and evidence.observed == "allow"
        and any(
            check.evidence_id == control_id
            and check.code == code
            and check.outcome == "pass"
            for check in report.checks
        )
    )


def _controls_passed(case: LinkedCase, report: Report) -> bool:
    return _control_passed(case.control_id, case.source, report) and (
        case.caller_control_id is None
        or _control_passed(case.caller_control_id, case.source, report)
    )


async def _fetch_status(url: str, headers: dict[str, str], timeout_seconds: int) -> int:
    async with asyncio.timeout(timeout_seconds):
        async with httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            timeout=timeout_seconds,
        ) as client:
            async with client.stream("GET", url, headers=headers) as response:
                # Access is decided from final response headers. Never consume a
                # potentially private or binary linked-object response body.
                return response.status_code


def _request_headers(case: LinkedCase, prepared: PreparedLinked) -> dict[str, str]:
    headers = {"Accept": "*/*", "Accept-Encoding": "identity"}
    token = prepared.tokens[case.subject.name]
    if token:
        if origin_key(case.resource.origin) != origin_key(prepared.config.base_url):
            raise ValueError("refusing to forward a credential to another origin")
        if case.subject.cookie_env:
            headers["Cookie"] = token
        else:
            headers["Authorization"] = "Bearer " + token
    return headers


def execute_linked_cases(
    prepared: PreparedLinked,
    selected: list[LinkedCase],
    report: Report,
) -> None:
    for case in selected:
        owner_value = case.owner.attributes[case.source.owner_attr]
        path = case.resource.path.replace("{" + case.source.owner_param + "}", owner_value)
        target = _target(case)
        try:
            headers = _request_headers(case, prepared)
            status = asyncio.run(
                _fetch_status(
                    case.resource.origin.rstrip("/") + path,
                    headers,
                    prepared.config.timeout_seconds,
                )
            )
        except Exception:
            report.observe(
                Evidence(
                    case.id,
                    case.resource.name,
                    _reported_subject(case),
                    case.owner.name,
                    case.variant,
                    case.expected.value,
                    "unknown",
                    0,
                    "failed",
                )
            )
            report.add(
                "linked.delivery",
                "inconclusive",
                target,
                (
                    "The credential-free linked read did not produce a bounded response."
                    if case.resource.authentication == "anonymous"
                    else "The linked read did not produce a bounded response."
                ),
                case.id,
            )
            continue
        granted = 200 <= status < 300
        denied = status in case.resource.denial_statuses
        report.observe(
            Evidence(
                case.id,
                case.resource.name,
                _reported_subject(case),
                case.owner.name,
                case.variant,
                case.expected.value,
                "allow" if granted else "deny" if denied else "unknown",
                status,
                "complete",
            )
        )
        code = (
            "linked.public_access"
            if case.resource.authentication == "anonymous"
            else "linked.authorization"
        )
        controls_passed = _controls_passed(case, report)
        if case.expected == Effect.DENY and granted:
            report.add(
                code,
                "fail",
                target,
                (
                    f"Credential-free direct GET returned HTTP {status} for a declared private object."
                    if case.resource.authentication == "anonymous"
                    else f"Forbidden linked GET returned HTTP {status}."
                ),
                case.id,
            )
        elif case.expected == Effect.ALLOW and granted and controls_passed:
            report.add(
                code,
                "pass",
                target,
                f"Allowed linked GET returned HTTP {status} after valid source controls.",
                case.id,
            )
        elif case.expected == Effect.DENY and denied and controls_passed:
            report.add(
                code,
                "pass",
                target,
                (
                    f"Credential-free direct GET was denied with HTTP {status} after a valid source control."
                    if case.resource.authentication == "anonymous"
                    else f"Forbidden linked GET was denied with HTTP {status} after valid source controls."
                ),
                case.id,
            )
        elif case.expected == Effect.ALLOW and denied:
            report.add(
                "linked.positive_control",
                "inconclusive",
                target,
                f"Allowed linked control was denied with HTTP {status}.",
                case.id,
            )
        elif (granted or denied) and not controls_passed:
            report.add(
                "linked.source_control",
                "inconclusive",
                target,
                (
                    "The direct read was denied, but the source API did not establish this object."
                    if case.resource.authentication == "anonymous"
                    else "The linked result is unverified because its source controls failed."
                ),
                case.id,
            )
        else:
            report.add(
                "linked.unexpected_status",
                "inconclusive",
                target,
                (
                    f"HTTP {status} does not establish denial or public access."
                    if case.resource.authentication == "anonymous"
                    else f"HTTP {status} does not establish the expected linked access decision."
                ),
                case.id,
            )
