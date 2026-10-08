"""Deterministic finding retests with comparable controls and retained history."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal

from overstep.models import Effect, TestCase, Variant

from permitprobe.api import (
    case_descriptor,
    execute_api_cases,
    finalize_api,
    prepare_api,
)
from permitprobe.linked import (
    execute_linked_cases,
    linked_case_descriptor,
    linked_control_cases,
    prepare_linked,
    source_control_cases,
)
from permitprobe.policy import API, PolicyError, _unique, api_contract_digest
from permitprobe.public_contracts import (
    execute_public_cases,
    prepare_public,
    public_case_descriptor,
)
from permitprobe.report import Report

MAX_PRIOR_REPORT_BYTES = 10_000_000
RetestVerdict = Literal["reproduced", "fixed", "not_reproduced", "inconclusive"]


def load_prior_report(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_PRIOR_REPORT_BYTES + 1)
        if len(raw) > MAX_PRIOR_REPORT_BYTES:
            raise ValueError
        data = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        return _validate_prior_report(data)
    except (OSError, ValueError, RecursionError, UnicodeError):
        raise PolicyError("cannot read a compatible prior PermitProbe report") from None


def _validate_prior_report(data) -> dict:
    try:
        canonical = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise ValueError from None
    if (
        len(canonical) > MAX_PRIOR_REPORT_BYTES
        or not isinstance(data, dict)
        or data.get("schema_version") != 2
        or not isinstance(data.get("policy_digest"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", data["policy_digest"])
        or not isinstance(data.get("findings"), list)
        or not isinstance(data.get("evidence"), list)
        or not isinstance(data.get("checks"), list)
        or data.get("exploration") is not None
        and not isinstance(data.get("exploration"), dict)
    ):
        raise ValueError
    evidence_ids = []
    evidence_resources = {}
    for item in data["evidence"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("evidence_id"), str)
            or not isinstance(item.get("resource"), str)
        ):
            raise ValueError
        evidence_ids.append(item["evidence_id"])
        evidence_resources[item["evidence_id"]] = item["resource"]
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError
    known_evidence = set(evidence_ids)
    finding_ids = []
    for finding in data["findings"]:
        ids = finding.get("evidence_ids") if isinstance(finding, dict) else None
        finding_id = finding.get("finding_id") if isinstance(finding, dict) else None
        code = finding.get("code") if isinstance(finding, dict) else None
        resource = finding.get("resource") if isinstance(finding, dict) else None
        expected_id = None
        if isinstance(code, str) and isinstance(resource, str):
            key = f"{data['policy_digest']}\0{code}\0{resource}"
            expected_id = "pp-" + hashlib.sha256(key.encode()).hexdigest()[:16]
        if (
            not isinstance(finding_id, str)
            or finding_id != expected_id
            or not isinstance(ids, list)
            or any(not isinstance(item, str) for item in ids)
            or len(set(ids)) != len(ids)
            or not set(ids).issubset(known_evidence)
            or any(evidence_resources[item] != resource for item in ids)
        ):
            raise ValueError
        finding_ids.append(finding_id)
    if len(set(finding_ids)) != len(finding_ids):
        raise ValueError
    reconstructed = Report(policy_digest=data["policy_digest"])
    for check in data["checks"]:
        if (
            not isinstance(check, dict)
            or not isinstance(check.get("code"), str)
            or check.get("outcome") not in ("pass", "fail", "inconclusive")
            or not isinstance(check.get("target"), str)
            or not isinstance(check.get("detail"), str)
            or not (
                check.get("evidence_id") is None
                or isinstance(check.get("evidence_id"), str)
                and check["evidence_id"] in known_evidence
            )
        ):
            raise ValueError
        reconstructed.add(
            check["code"],
            check["outcome"],
            check["target"],
            check["detail"],
            check.get("evidence_id"),
        )
    if data["findings"] != reconstructed.finding_groups():
        raise ValueError
    return data


def _positive_control(
    cases: list[TestCase], subject: str, resource: str, excluded: set[str]
) -> TestCase | None:
    same = [
        case
        for case in cases
        if case.subject == subject
        and case.id not in excluded
        and case.resource == resource
        and case.expected == Effect.ALLOW
        and case.variant in (Variant.SELF, Variant.NA)
    ]
    if same:
        return same[0]
    fallback = [
        case
        for case in cases
        if case.subject == subject
        and case.id not in excluded
        and case.expected == Effect.ALLOW
        and case.variant in (Variant.SELF, Variant.NA)
    ]
    return fallback[0] if fallback else None


def select_retest_cases(cases: list[TestCase], finding: dict) -> list[TestCase]:
    by_id = {case.id: case for case in cases}
    evidence_ids = finding.get("evidence_ids")
    if not isinstance(evidence_ids, list) or not evidence_ids:
        raise PolicyError("finding has no executable evidence")
    try:
        original = [by_id[item] for item in evidence_ids]
    except (KeyError, TypeError):
        raise PolicyError("finding evidence is not present in the current policy") from None
    selected = {case.id: case for case in original}
    original_ids = set(selected)
    subjects = {case.subject for case in original if case.role != "anonymous"}
    subjects.update(case.victim for case in original if case.victim)
    for subject in sorted(subjects):
        related = next(
            (case for case in original if subject in (case.subject, case.victim)), original[0]
        )
        control = _positive_control(cases, subject, related.resource, original_ids)
        if control is None:
            raise PolicyError("finding cannot be retested without a positive control")
        selected[control.id] = control
    for resource in sorted({case.resource for case in original}):
        if any(
            case.resource == resource
            and case.expected == Effect.ALLOW
            and case.variant in (Variant.SELF, Variant.NA)
            for case in selected.values()
        ):
            continue
        endpoint_control = next(
            (
                case
                for case in cases
                if case.resource == resource
                and case.id not in original_ids
                and case.expected == Effect.ALLOW
                and case.variant in (Variant.SELF, Variant.NA)
            ),
            None,
        )
        if endpoint_control is None:
            raise PolicyError("finding cannot be retested without an endpoint control")
        selected[endpoint_control.id] = endpoint_control
    for case in original:
        anonymous = next(
            (
                item
                for item in cases
                if item.role == "anonymous"
                and item.resource == case.resource
                and item.expected == Effect.DENY
                and (
                    case.victim is None
                    or item.victim == case.victim
                    or item.victim == case.subject
                )
            ),
            None,
        )
        if anonymous:
            selected[anonymous.id] = anonymous
    return [case for case in cases if case.id in selected]


def run_retest(
    config: API,
    prior: dict,
    finding_id: str,
    *,
    change_ref: str | None = None,
) -> tuple[RetestVerdict, dict]:
    try:
        prior = _validate_prior_report(prior)
    except ValueError:
        raise PolicyError("cannot read a compatible prior PermitProbe report") from None
    if change_ref is not None and (
        not 1 <= len(change_ref) <= 256
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@~-]*", change_ref)
    ):
        raise PolicyError("change reference must be a safe deployment or revision label")
    finding = next(
        (item for item in prior["findings"] if item.get("finding_id") == finding_id), None
    )
    if finding is None:
        raise PolicyError("finding does not exist in the prior report")
    report = Report()
    finding_evidence = finding.get("evidence_ids", [])
    is_public = bool(finding_evidence) and all(
        item.startswith("ppc-") for item in finding_evidence
    )
    is_linked = bool(finding_evidence) and all(
        item.startswith("ppl-") for item in finding_evidence
    )
    if any(
        item.startswith(("ppc-", "ppl-")) for item in finding_evidence
    ) and not (is_public or is_linked):
        raise PolicyError("finding mixes incompatible evidence types")

    selected = []
    verdict: RetestVerdict
    if is_linked:
        current_digest = api_contract_digest(config)
        report.policy_digest = current_digest
        if prior["policy_digest"] != current_digest:
            report.add(
                "retest.policy",
                "inconclusive",
                "retest",
                "The current policy differs from the finding's original policy.",
            )
            verdict = "inconclusive"
        else:
            prepared = prepare_api(config, report)
            prepared_linked = (
                prepare_linked(config, prepared, report)
                if prepared is not None and config.linked_resources
                else None
            )
            if prepared is None or prepared_linked is None:
                verdict = "inconclusive"
            else:
                by_id = {case.id: case for case in prepared_linked.cases}
                try:
                    linked_cases = [by_id[item] for item in finding_evidence]
                except KeyError:
                    raise PolicyError(
                        "finding evidence is not present in the current policy"
                    ) from None
                controls = source_control_cases(prepared, linked_cases)
                linked_controls = linked_control_cases(prepared_linked, linked_cases)
                selected_linked = [*linked_controls, *linked_cases]
                selected = [*controls, *selected_linked]
                report.planned_cases = {
                    **{case.id: case_descriptor(case) for case in controls},
                    **{
                        case.id: linked_case_descriptor(case)
                        for case in selected_linked
                    },
                }
                if len(selected) > config.max_cases:
                    report.add(
                        "api.coverage",
                        "inconclusive",
                        "api",
                        "The retest control plan exceeds max_cases.",
                    )
                else:
                    observations = execute_api_cases(prepared, controls, report)
                    finalize_api(
                        prepared,
                        controls,
                        observations,
                        report,
                        require_full_coverage=False,
                    )
                    execute_linked_cases(prepared_linked, selected_linked, report)
                verdict = "inconclusive"
    elif is_public:
        prepared_public = prepare_public(config, report) if config.public_resources else None
        if prepared_public is None:
            verdict = "inconclusive"
        elif prior["policy_digest"] != report.policy_digest:
            report.add(
                "retest.policy",
                "inconclusive",
                "retest",
                "The current policy differs from the finding's original policy.",
            )
            verdict = "inconclusive"
        else:
            by_id = {case.id: case for case in prepared_public.cases}
            try:
                original = [by_id[item] for item in finding_evidence]
            except KeyError:
                raise PolicyError(
                    "finding evidence is not present in the current policy"
                ) from None
            selected_ids = {case.id for case in original}
            for resource in {case.resource.name for case in original}:
                control = next(
                    (
                        case
                        for case in prepared_public.cases
                        if case.resource.name == resource and not case.variant.header_envs
                    ),
                    None,
                )
                if control:
                    selected_ids.add(control.id)
            selected = [case for case in prepared_public.cases if case.id in selected_ids]
            report.planned_cases = {
                case.id: public_case_descriptor(case) for case in selected
            }
            execute_public_cases(prepared_public, selected, report)
            verdict = "inconclusive"
    else:
        exploration_retest = prior.get("exploration") is not None
        prepared = prepare_api(
            config,
            report,
            include_exploration=exploration_retest,
            include_public=not exploration_retest,
            include_linked=not exploration_retest,
        )
        if prepared is None:
            verdict = "inconclusive"
        elif prior["policy_digest"] != report.policy_digest:
            report.add(
                "retest.policy",
                "inconclusive",
                "retest",
                "The current policy differs from the finding's original policy.",
            )
            verdict = "inconclusive"
        else:
            selected = select_retest_cases(prepared.cases, finding)
            report.planned_cases = {case.id: case_descriptor(case) for case in selected}
            observations = execute_api_cases(prepared, selected, report)
            finalize_api(
                prepared,
                selected,
                observations,
                report,
                require_full_coverage=False,
            )
            verdict = "inconclusive"

    if selected:
        current_ids = {item["finding_id"] for item in report.finding_groups()}
        if report.exit_code == 2:
            verdict = "inconclusive"
        elif finding_id in current_ids:
            verdict = "reproduced"
        elif report.exit_code != 0:
            verdict = "inconclusive"
        elif change_ref:
            verdict = "fixed"
        else:
            verdict = "not_reproduced"
    prior_digest = hashlib.sha256(
        json.dumps(prior, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    graph_nodes = [
        {"id": "finding:" + finding_id, "kind": "finding", "source": "prior_report"},
        {"id": "retest:" + prior_digest[:16], "kind": "retest", "verdict": verdict},
    ]
    graph_edges = [
        {
            "from": "finding:" + finding_id,
            "to": "retest:" + prior_digest[:16],
            "kind": "retested_by",
        }
    ]
    if change_ref:
        graph_nodes.append({"id": "change:" + change_ref, "kind": "change"})
        graph_edges.append(
            {
                "from": "change:" + change_ref,
                "to": "retest:" + prior_digest[:16],
                "kind": "evaluated_by",
            }
        )
    for case in selected:
        oid = "observation:" + case.id
        graph_nodes.append({"id": oid, "kind": "observation", "case_id": case.id})
        graph_edges.append(
            {
                "from": oid,
                "to": "retest:" + prior_digest[:16],
                "kind": "supports",
            }
        )
    result = {
        "schema_version": 1,
        "finding_id": finding_id,
        "verdict": verdict,
        "change_ref": change_ref,
        "prior_report_digest": prior_digest,
        "policy_digest": report.policy_digest,
        "selected_case_ids": [case.id for case in selected],
        "graph": {"nodes": graph_nodes, "edges": graph_edges},
        "report": report.to_dict(),
    }
    return verdict, result
