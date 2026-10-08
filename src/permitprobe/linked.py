"""Credential-free direct reads linked to established private API objects."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass

import httpx
from overstep.models import Effect, TestCase, Variant

from permitprobe.api import PreparedAPI
from permitprobe.policy import API, LinkedResource, Resource, Subject, api_contract_digest
from permitprobe.report import Evidence, Report


@dataclass(frozen=True)
class LinkedCase:
    id: str
    resource: LinkedResource
    source: Resource
    owner: Subject
    control_id: str


@dataclass
class PreparedLinked:
    config: API
    cases: list[LinkedCase]


def _case_id(resource: str, source: str, owner: str) -> str:
    key = f"linked-read\0{resource}\0{source}\0{owner}"
    return "ppl-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def linked_case_descriptor(case: LinkedCase) -> dict:
    return {
        "case_id": case.id,
        "case_type": "linked_read",
        "resource": case.resource.name,
        "source_resource": case.source.name,
        "subject": "anonymous",
        "owner": case.owner.name,
        "role": "anonymous",
        "variant": "direct",
        "expected": "deny",
        "method": "GET",
    }


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
    owners = [subject for subject in config.subjects if subject.role != "anonymous"]
    cases = []
    for resource in config.linked_resources:
        source = sources[resource.source_resource]
        for owner in owners:
            control = _positive_control(primary.cases, source, owner)
            if control is None:
                report.add(
                    "linked.configuration",
                    "inconclusive",
                    resource.name,
                    "A linked read has no matching source-object positive control.",
                )
                return None
            cases.append(
                LinkedCase(
                    _case_id(resource.name, source.name, owner.name),
                    resource,
                    source,
                    owner,
                    control.id,
                )
            )
    report.plan([linked_case_descriptor(case) for case in cases])
    return PreparedLinked(config, cases)


def source_control_cases(primary: PreparedAPI, selected: list[LinkedCase]) -> list[TestCase]:
    selected_ids = {case.control_id for case in selected}
    return [case for case in primary.cases if case.id in selected_ids]


def _source_control_passed(case: LinkedCase, report: Report) -> bool:
    evidence = report.evidence.get(case.control_id)
    code = "api.redirect_control" if case.source.redirect else "api.object_control"
    return bool(
        evidence
        and evidence.delivery == "complete"
        and evidence.expected == "allow"
        and evidence.observed == "allow"
        and any(
            check.evidence_id == case.control_id
            and check.code == code
            and check.outcome == "pass"
            for check in report.checks
        )
    )


async def _fetch_status(url: str, timeout_seconds: int) -> int:
    headers = {"Accept": "*/*", "Accept-Encoding": "identity"}
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


def execute_linked_cases(
    prepared: PreparedLinked,
    selected: list[LinkedCase],
    report: Report,
) -> None:
    for case in selected:
        owner_value = case.owner.attributes[case.source.owner_attr]
        path = case.resource.path.replace("{" + case.source.owner_param + "}", owner_value)
        target = f"{case.resource.name}/anonymous/{case.owner.name}"
        try:
            status = asyncio.run(
                _fetch_status(
                    case.resource.origin.rstrip("/") + path,
                    prepared.config.timeout_seconds,
                )
            )
        except Exception:
            report.observe(
                Evidence(
                    case.id,
                    case.resource.name,
                    "anonymous",
                    case.owner.name,
                    "direct",
                    "deny",
                    "unknown",
                    0,
                    "failed",
                )
            )
            report.add(
                "linked.delivery",
                "inconclusive",
                target,
                "The credential-free linked read did not produce a bounded response.",
                case.id,
            )
            continue
        exposed = 200 <= status < 300
        denied = status in case.resource.denial_statuses
        report.observe(
            Evidence(
                case.id,
                case.resource.name,
                "anonymous",
                case.owner.name,
                "direct",
                "deny",
                "allow" if exposed else "deny" if denied else "unknown",
                status,
                "complete",
            )
        )
        if exposed:
            report.add(
                "linked.public_access",
                "fail",
                target,
                f"Credential-free direct GET returned HTTP {status} for a declared private object.",
                case.id,
            )
        elif not denied:
            report.add(
                "linked.unexpected_status",
                "inconclusive",
                target,
                f"HTTP {status} does not establish denial or public access.",
                case.id,
            )
        elif _source_control_passed(case, report):
            report.add(
                "linked.public_access",
                "pass",
                target,
                f"Credential-free direct GET was denied with HTTP {status} after a valid source control.",
                case.id,
            )
        else:
            report.add(
                "linked.source_control",
                "inconclusive",
                target,
                "The direct read was denied, but the source API did not establish this object.",
                case.id,
            )
