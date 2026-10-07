"""Bounded, model-neutral active exploration over pre-authorized API cases.

Providers choose hypotheses and case IDs. PermitProbe alone owns credentials,
HTTP delivery, policy expectations, classification, budgets and completion.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import selectors
import signal
import subprocess
import tempfile
from dataclasses import asdict
from pathlib import Path
from time import monotonic
from typing import Callable, Literal, Protocol

from overstep.models import Observation, TestCase, Variant
from pydantic import BaseModel, ConfigDict, Field, field_validator

from permitprobe.api import case_descriptor, execute_api_cases, finalize_api, prepare_api
from permitprobe.policy import API, ENV
from permitprobe.report import Report

MAX_PROVIDER_BYTES = 1_000_000
SAFE_TEXT = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$")
HypothesisCode = Literal[
    "cross_owner_access",
    "role_boundary",
    "anonymous_access",
    "collection_ownership",
    "response_contract",
    "cache_contract",
    "retest",
]
CapabilityGap = Literal[
    "new_route",
    "linked_storage",
    "alternate_identity",
    "write_boundary",
    "protocol_surface",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Candidate(StrictModel):
    case_id: str = Field(min_length=1, max_length=256)
    hypothesis_code: HypothesisCode
    depends_on: list[str] = Field(default_factory=list, max_length=32)
    priority: int = Field(default=50, ge=0, le=100)

    @field_validator("case_id")
    @classmethod
    def safe_case_id(cls, value: str) -> str:
        if not SAFE_TEXT.fullmatch(value):
            raise ValueError("unsafe case id")
        return value


class CapabilityProposal(StrictModel):
    capability_gap: CapabilityGap
    depends_on: list[str] = Field(default_factory=list, max_length=32)
    rationale: str = Field(min_length=1, max_length=1000)

    @field_validator("rationale")
    @classmethod
    def safe_rationale(cls, value: str) -> str:
        if not SAFE_TEXT.fullmatch(value):
            raise ValueError("unsafe proposal text")
        return value


class ExplorationReply(StrictModel):
    protocol_version: Literal[1]
    candidates: list[Candidate] = Field(default_factory=list, max_length=64)
    proposals: list[CapabilityProposal] = Field(default_factory=list, max_length=16)
    done_hint: bool = False
    rationale: str = Field(default="", max_length=2000)
    provider_request_id: str | None = Field(default=None, max_length=256)

    @field_validator("rationale", "provider_request_id")
    @classmethod
    def safe_text(cls, value):
        if value is not None and not SAFE_TEXT.fullmatch(value):
            raise ValueError("unsafe provider text")
        return value


class ExplorationProvider(Protocol):
    name: str

    def propose(self, request: dict, *, timeout_seconds: float) -> ExplorationReply: ...


class ProviderError(RuntimeError):
    pass


def _stop_provider(process: subprocess.Popen) -> None:
    """Stop the provider's whole session, including children that inherited its pipes."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.SubprocessError):
        pass


def _bounded_provider_call(
    command: list[str], payload: bytes, env: dict[str, str], timeout_seconds: float
) -> tuple[int, bytes, bytes]:
    """Exchange bounded bytes without buffering an untrusted provider's output."""

    process: subprocess.Popen | None = None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    deadline = monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, ("stdin", None))
        selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout))
        selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr))
        written = 0
        while selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise ProviderError("provider did not return a usable reply")
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                raise ProviderError("provider did not return a usable reply")
            for key, _ in events:
                label, output = key.data
                stream = key.fileobj
                if label == "stdin":
                    try:
                        written += os.write(stream.fileno(), payload[written : written + 65536])
                    except (BrokenPipeError, OSError):
                        written = len(payload)
                    if written >= len(payload):
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                output.extend(chunk)
                if len(output) > MAX_PROVIDER_BYTES:
                    raise ProviderError("provider did not return a usable reply")
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ProviderError("provider did not return a usable reply")
        returncode = process.wait(timeout=remaining)
        return returncode, bytes(stdout), bytes(stderr)
    except (OSError, subprocess.SubprocessError) as error:
        raise ProviderError("provider did not return a usable reply") from error
    finally:
        selector.close()
        # Always address the provider's private group. The parent may have exited
        # after starting a child, including on an output-limit failure.
        if process is not None:
            _stop_provider(process)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


class StateWriter:
    """Atomic, private, mutable checkpoint created only at a new path."""

    def __init__(self, path: Path) -> None:
        self.path = path
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"schema_version": 1, "status": "initializing"}, handle)
            handle.write("\n")

    def write(self, payload: dict) -> None:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".permitprobe-exploration-", dir=self.path.parent
        )
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise


class ExternalProvider:
    """JSON-over-stdio adapter usable with any model or agent runtime."""

    def __init__(
        self,
        name: str,
        command: list[str],
        pass_env: list[str] | None = None,
    ) -> None:
        if (
            not name
            or not SAFE_TEXT.fullmatch(name)
            or len(name) > 128
            or not command
            or not Path(command[0]).is_absolute()
            or not Path(command[0]).is_file()
            or not os.access(command[0], os.X_OK)
        ):
            raise ValueError("provider needs a safe name and absolute executable")
        if any(not arg or len(arg) > 4096 or "\0" in arg for arg in command):
            raise ValueError("invalid provider argument")
        self.name = name
        self.command = command
        self.pass_env = pass_env or []
        if any(not re.fullmatch(ENV, item) for item in self.pass_env):
            raise ValueError("provider environment names must be explicit and safe")

    def propose(self, request: dict, *, timeout_seconds: float) -> ExplorationReply:
        payload = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode()
        if len(payload) > MAX_PROVIDER_BYTES or timeout_seconds <= 0:
            raise ProviderError("provider request exceeds budget")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
        for name in self.pass_env:
            if name in os.environ:
                env[name] = os.environ[name]
        returncode, stdout, _ = _bounded_provider_call(
            self.command, payload, env, timeout_seconds
        )
        if returncode != 0:
            raise ProviderError("provider did not return a usable reply")
        try:
            return ExplorationReply.model_validate_json(stdout)
        except Exception as error:
            raise ProviderError("provider reply violates the protocol") from error


def baseline_cases(cases: list[TestCase], baseline_resources: set[str]) -> list[TestCase]:
    """Positive/NA controls plus one representative owner per caller/resource."""

    selected: dict[str, TestCase] = {}
    other: dict[tuple[str, str], list[TestCase]] = {}
    for case in cases:
        if case.resource not in baseline_resources:
            continue
        if case.variant != Variant.OTHER:
            selected[case.id] = case
        else:
            other.setdefault((case.resource, case.subject), []).append(case)
    for group in other.values():
        case = sorted(group, key=lambda item: (item.victim or "", item.id))[0]
        selected[case.id] = case
    return [case for case in cases if case.id in selected]


def provider_request(
    report: Report,
    remaining: list[TestCase],
    *,
    run_id: str,
    round_id: int,
    remaining_rounds: int,
    remaining_requests: int,
    max_candidates: int,
) -> dict:
    candidate_schema = ExplorationReply.model_json_schema()
    candidate_schema["properties"]["candidates"]["maxItems"] = max_candidates
    return {
        "protocol_version": 1,
        "run_id": run_id,
        "round_id": round_id,
        "objective": "Select the next authorized cases that best test unresolved access hypotheses.",
        "policy_digest": report.policy_digest,
        "remaining_rounds": remaining_rounds,
        "remaining_requests": remaining_requests,
        "max_candidates": max_candidates,
        "capabilities": [case_descriptor(case) for case in remaining],
        "observations": [asdict(item) for item in report.evidence.values()],
        "checks": [
            {
                "code": check.code,
                "outcome": check.outcome,
                "target": check.target,
                "evidence_id": check.evidence_id,
            }
            for check in report.checks
        ],
        "candidate_schema": candidate_schema,
        "rules": {
            "case_ids_only": True,
            "dependencies_must_reference_prior_observations": True,
            "provider_never_executes_target_requests": True,
            "done_hint_is_advisory": True,
        },
    }


def _graph(report: Report, trace: dict, origin: dict[str, str]) -> dict:
    nodes = [
        {
            "id": "goal:authorization-assessment",
            "kind": "goal",
            "state": "met" if trace["complete"] else "open",
        }
    ]
    edges = []
    resources = sorted({item["resource"] for item in report.planned_cases.values()})
    subjects = sorted({item["subject"] for item in report.planned_cases.values()})
    for resource in resources:
        nodes.append({"id": "resource:" + resource, "kind": "resource", "label": resource})
    for subject in subjects:
        nodes.append({"id": "subject:" + subject, "kind": "subject", "label": subject})
    for case_id, case in report.planned_cases.items():
        cid = "case:" + case_id
        nodes.append(
            {
                "id": cid,
                "kind": "case",
                "case_id": case_id,
                "owner": case["owner"],
                "expected": case["expected"],
                "status": "observed" if case_id in report.evidence else "unprobed",
            }
        )
        edges.extend(
            [
                {"from": "subject:" + case["subject"], "to": cid, "kind": "calls_as"},
                {"from": "resource:" + case["resource"], "to": cid, "kind": "targets"},
            ]
        )
    intent_cases = {
        "intent:baseline": trace["baseline"],
        "intent:deterministic-tail": trace["deterministic_tail"],
    }
    for round_item in trace["rounds"]:
        intent_cases[f"intent:provider-round-{round_item['round_id']}"] = [
            item["case_id"] for item in round_item["accepted"]
        ]
    for intent_id, case_ids in intent_cases.items():
        if not case_ids:
            continue
        nodes.append(
            {
                "id": intent_id,
                "kind": "intent",
                "source": intent_id.removeprefix("intent:"),
                "case_count": len(case_ids),
            }
        )
        for case_id in case_ids:
            edges.append({"from": intent_id, "to": "case:" + case_id, "kind": "schedules"})
        edges.append(
            {
                "from": intent_id,
                "to": "goal:authorization-assessment",
                "kind": "advances",
            }
        )
    for item in report.evidence.values():
        oid = "observation:" + item.evidence_id
        nodes.append(
            {
                "id": oid,
                "kind": "observation",
                "case_id": item.evidence_id,
                "origin": origin[item.evidence_id],
                "expected": item.expected,
                "observed": item.observed,
                "status": item.status,
            }
        )
        edges.extend(
            [
                {"from": "subject:" + item.subject, "to": oid, "kind": "called_as"},
                {"from": "resource:" + item.resource, "to": oid, "kind": "observed_on"},
                {"from": "case:" + item.evidence_id, "to": oid, "kind": "produced"},
            ]
        )
    for round_item in trace["rounds"]:
        for index, candidate in enumerate(round_item["accepted"]):
            hid = f"hypothesis:{round_item['round_id']}:{index}"
            nodes.append(
                {
                    "id": hid,
                    "kind": "hypothesis",
                    "hypothesis_code": candidate["hypothesis_code"],
                    "provider": trace["provider"],
                }
            )
            edges.append(
                {"from": hid, "to": "case:" + candidate["case_id"], "kind": "selected"}
            )
            if candidate["case_id"] in report.evidence:
                edges.append(
                    {
                        "from": hid,
                        "to": "observation:" + candidate["case_id"],
                        "kind": "tested_by",
                    }
                )
            edges.append(
                {
                    "from": hid,
                    "to": f"intent:provider-round-{round_item['round_id']}",
                    "kind": "selected_in",
                }
            )
            for dependency in candidate["depends_on"]:
                edges.append({"from": "observation:" + dependency, "to": hid, "kind": "informed"})
        for index, proposal in enumerate(round_item["proposals"]):
            pid = f"proposal:{round_item['round_id']}:{index}"
            nodes.append(
                {
                    "id": pid,
                    "kind": "capability_proposal",
                    "capability_gap": proposal["capability_gap"],
                    "executable": False,
                }
            )
            for dependency in proposal["depends_on"]:
                edges.append(
                    {"from": "observation:" + dependency, "to": pid, "kind": "informed"}
                )
    for finding in report.finding_groups():
        fid = "finding:" + finding["finding_id"]
        nodes.append({"id": fid, "kind": "finding", "code": finding["code"]})
        for evidence_id in finding["evidence_ids"]:
            edges.append({"from": "observation:" + evidence_id, "to": fid, "kind": "supports"})
    return {"nodes": nodes, "edges": edges}


def _checkpoint(
    report: Report,
    trace: dict,
    origin: dict[str, str],
    writer: Callable[[dict], None] | None,
    status: Literal["running", "complete"],
) -> None:
    if writer is None:
        return
    snapshot = dict(trace)
    snapshot["graph"] = _graph(report, trace, origin)
    writer(
        {
            "schema_version": 1,
            "status": status,
            "policy_digest": report.policy_digest,
            "exploration": snapshot,
            "report": report.to_dict(),
        }
    )


def explore_api(
    config: API,
    report: Report,
    provider: ExplorationProvider,
    *,
    max_rounds: int = 4,
    max_candidates_per_round: int = 16,
    max_requests_total: int | None = None,
    provider_timeout_seconds: int = 120,
    max_seconds_total: int = 600,
    complete: bool = False,
    checkpoint: Callable[[dict], None] | None = None,
    clock: Callable[[], float] = monotonic,
) -> None:
    if not 1 <= max_rounds <= 20 or not 1 <= max_candidates_per_round <= 64:
        raise ValueError("invalid exploration budget")
    if not 1 <= provider_timeout_seconds <= 600 or not 1 <= max_seconds_total <= 3600:
        raise ValueError("invalid exploration deadline")
    deadline = clock() + max_seconds_total
    run_id = "run-" + secrets.token_hex(16)
    request_budget = config.max_cases if max_requests_total is None else max_requests_total
    if not 1 <= request_budget <= config.max_cases:
        raise ValueError("invalid request budget")
    prepared = prepare_api(config, report, include_exploration=True)
    if prepared is None:
        trace = {
            "protocol_version": 1,
            "run_id": run_id,
            "provider": provider.name,
            "baseline": [],
            "rounds": [],
            "deterministic_tail": [],
            "stop_reason": "precheck",
            "complete": False,
        }
        trace["graph"] = _graph(report, trace, {})
        report.exploration = trace
        _checkpoint(report, trace, {}, checkpoint, "complete")
        return
    by_id = {case.id: case for case in prepared.cases}
    seed = baseline_cases(prepared.cases, {resource.name for resource in config.resources})
    origin: dict[str, str] = {}
    trace = {
        "protocol_version": 1,
        "run_id": run_id,
        "provider": provider.name,
        "baseline": [case.id for case in seed],
        "rounds": [],
        "deterministic_tail": [],
        "stop_reason": None,
        "complete": False,
    }
    if len(seed) > request_budget:
        report.add(
            "exploration.budget",
            "inconclusive",
            "exploration",
            "The deterministic baseline exceeds the request budget.",
        )
        trace["stop_reason"] = "baseline_budget"
        trace["graph"] = _graph(report, trace, origin)
        report.exploration = trace
        _checkpoint(report, trace, origin, checkpoint, "complete")
        return
    observations: list[Observation] = execute_api_cases(
        prepared, seed, report, deadline=deadline, clock=clock
    )
    executed = [by_id[item.test_id] for item in observations]
    origin.update({case.id: "baseline" for case in executed})
    remaining_ids = set(by_id) - set(origin)
    _checkpoint(report, trace, origin, checkpoint, "running")
    provider_failed = False
    deadline_failed = clock() >= deadline
    for round_id in range(1, max_rounds + 1):
        if deadline_failed or clock() >= deadline:
            deadline_failed = True
            report.add(
                "exploration.deadline",
                "inconclusive",
                "exploration",
                "The total exploration deadline was reached.",
            )
            trace["stop_reason"] = "total_deadline"
            break
        if not remaining_ids or len(executed) >= request_budget:
            trace["stop_reason"] = "catalog_exhausted" if not remaining_ids else "request_budget"
            break
        remaining = [case for case in prepared.cases if case.id in remaining_ids]
        request = provider_request(
            report,
            remaining,
            run_id=run_id,
            round_id=round_id,
            remaining_rounds=max_rounds - round_id + 1,
            remaining_requests=request_budget - len(executed),
            max_candidates=min(
                max_candidates_per_round,
                request_budget - len(executed),
                len(remaining),
            ),
        )
        try:
            reply = ExplorationReply.model_validate(
                provider.propose(
                    request,
                    timeout_seconds=min(
                        provider_timeout_seconds,
                        max(0.001, deadline - clock()),
                    ),
                )
            )
        except Exception:
            if clock() >= deadline:
                deadline_failed = True
                report.add(
                    "exploration.deadline",
                    "inconclusive",
                    "exploration",
                    "The total exploration deadline was reached.",
                )
                trace["stop_reason"] = "total_deadline"
            else:
                report.add(
                    "exploration.provider",
                    "inconclusive",
                    "exploration",
                    "The exploration provider did not return a valid bounded reply.",
                )
                trace["stop_reason"] = "provider_error"
            provider_failed = True
            _checkpoint(report, trace, origin, checkpoint, "running")
            break
        if clock() >= deadline:
            deadline_failed = True
            report.add(
                "exploration.deadline",
                "inconclusive",
                "exploration",
                "The total exploration deadline was reached.",
            )
            trace["stop_reason"] = "total_deadline"
            _checkpoint(report, trace, origin, checkpoint, "running")
            break
        candidates = sorted(reply.candidates, key=lambda item: (-item.priority, item.case_id))
        accepted = []
        seen = set()
        available_evidence = set(report.evidence)
        valid = all(
            dependency in available_evidence
            for proposal in reply.proposals
            for dependency in proposal.depends_on
        )
        for candidate in candidates[:max_candidates_per_round]:
            if (
                candidate.case_id not in remaining_ids
                or candidate.case_id in seen
                or any(item not in available_evidence for item in candidate.depends_on)
            ):
                valid = False
                break
            seen.add(candidate.case_id)
            accepted.append(candidate)
        if len(candidates) > max_candidates_per_round or not valid:
            report.add(
                "exploration.provider",
                "inconclusive",
                "exploration",
                "The provider proposed an unknown, duplicate, over-budget or ungrounded case.",
            )
            trace["rounds"].append(
                {
                    "round_id": round_id,
                    "provider_request_id_present": reply.provider_request_id is not None,
                    "done_hint": reply.done_hint,
                    "rationale_present": bool(reply.rationale),
                    "accepted": [],
                    "proposals": [],
                    "rejected_reply": True,
                }
            )
            trace["stop_reason"] = "invalid_provider_candidate"
            provider_failed = True
            _checkpoint(report, trace, origin, checkpoint, "running")
            break
        allowed = min(len(accepted), request_budget - len(executed))
        accepted = accepted[:allowed]
        trace["rounds"].append(
            {
                "round_id": round_id,
                "provider_request_id_present": reply.provider_request_id is not None,
                "done_hint": reply.done_hint,
                "rationale_present": bool(reply.rationale),
                "accepted": [item.model_dump(mode="json") for item in accepted],
                "proposals": [
                    {
                        "capability_gap": item.capability_gap,
                        "depends_on": item.depends_on,
                    }
                    for item in reply.proposals
                ],
                "rejected_reply": False,
            }
        )
        if not accepted:
            trace["stop_reason"] = "provider_done" if reply.done_hint else "provider_empty"
            _checkpoint(report, trace, origin, checkpoint, "running")
            break
        selected = [by_id[item.case_id] for item in accepted]
        new_observations = execute_api_cases(
            prepared, selected, report, deadline=deadline, clock=clock
        )
        observations.extend(new_observations)
        executed_ids = {item.test_id for item in new_observations}
        executed.extend(case for case in selected if case.id in executed_ids)
        for item in accepted:
            if item.case_id in executed_ids:
                remaining_ids.remove(item.case_id)
                origin[item.case_id] = f"provider-round-{round_id}"
        if len(executed_ids) != len(selected) or clock() >= deadline:
            deadline_failed = True
            report.add(
                "exploration.deadline",
                "inconclusive",
                "exploration",
                "The total exploration deadline was reached.",
            )
            trace["stop_reason"] = "total_deadline"
            _checkpoint(report, trace, origin, checkpoint, "running")
            break
        _checkpoint(report, trace, origin, checkpoint, "running")
    else:
        trace["stop_reason"] = "round_budget"

    if (
        complete
        and not provider_failed
        and not deadline_failed
        and clock() < deadline
        and remaining_ids
        and len(executed) < request_budget
    ):
        tail = [
            case
            for case in prepared.cases
            if case.id in remaining_ids
        ][: request_budget - len(executed)]
        tail_observations = execute_api_cases(
            prepared, tail, report, deadline=deadline, clock=clock
        )
        observations.extend(tail_observations)
        tail_ids = {item.test_id for item in tail_observations}
        executed.extend(case for case in tail if case.id in tail_ids)
        trace["deterministic_tail"] = [case.id for case in tail if case.id in tail_ids]
        for case in tail:
            if case.id in tail_ids:
                remaining_ids.remove(case.id)
                origin[case.id] = "deterministic-tail"
        if len(tail_ids) != len(tail) or clock() >= deadline:
            deadline_failed = True
            report.add(
                "exploration.deadline",
                "inconclusive",
                "exploration",
                "The total exploration deadline was reached.",
            )
            trace["stop_reason"] = "total_deadline"
    trace["complete"] = (
        not remaining_ids
        and not deadline_failed
        and all(
            case_id in report.evidence and report.evidence[case_id].delivery == "complete"
            for case_id in by_id
        )
    )
    if trace["complete"]:
        trace["stop_reason"] = "complete"
    elif not remaining_ids and trace["stop_reason"] != "total_deadline":
        trace["stop_reason"] = "delivery_failure"
    finalize_api(prepared, executed, observations, report)
    trace["graph"] = _graph(report, trace, origin)
    report.exploration = trace
    _checkpoint(report, trace, origin, checkpoint, "complete")
