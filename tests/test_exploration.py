import copy
import json
import os
import time
from pathlib import Path

import pytest

import permitprobe.api as api_module
from permitprobe.api import check_api
from permitprobe.cli import main
from permitprobe.demo import demo_environment, example_policy, fixture_server
from permitprobe.exploration import (
    Candidate,
    CapabilityProposal,
    ExplorationReply,
    ExternalProvider,
    ProviderError,
    explore_api,
)
from permitprobe.policy import Policy
from permitprobe.read_demo import COOKIES, read_environment, read_policy, read_server
from permitprobe.report import Report


class SelectiveProvider:
    name = "scripted-model"

    def __init__(self, *, empty=False, invalid=False):
        self.requests = []
        self.empty = empty
        self.invalid = invalid

    def propose(self, request, *, timeout_seconds):
        self.requests.append(request)
        if self.invalid:
            candidates = [Candidate(case_id="outside-scope", hypothesis_code="cross_owner_access")]
        elif self.empty or len(self.requests) > 1:
            candidates = []
        else:
            case = next(
                item
                for item in request["capabilities"]
                if item["resource"] == "private-attachments"
                and item["subject"] == "bob"
                and item["owner"] == "moderator"
            )
            dependency = next(
                item["evidence_id"]
                for item in request["observations"]
                if item["resource"] == "private-attachments" and item["subject"] == "bob"
            )
            candidates = [
                Candidate(
                    case_id=case["case_id"],
                    hypothesis_code="cross_owner_access",
                    depends_on=[dependency],
                    priority=100,
                )
            ]
        return ExplorationReply(
            protocol_version=1,
            candidates=candidates,
            done_hint=not candidates,
            rationale="bounded synthetic selection",
        )


def test_provider_feedback_finds_selective_owner_pair_without_direct_target_access():
    provider = SelectiveProvider()
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        report = Report()
        explore_api(
            Policy.model_validate(read_policy(url)).api,
            report,
            provider,
            max_rounds=2,
            max_candidates_per_round=1,
        )
    payload = report.to_dict()
    assert len(requests) == 42  # 41-case baseline plus one model-selected owner pair
    assert len(provider.requests) == 2
    assert provider.requests[0]["run_id"] == provider.requests[1]["run_id"]
    assert provider.requests[0]["run_id"].startswith("run-")
    assert provider.requests[0]["max_candidates"] == 1
    assert provider.requests[0]["candidate_schema"]["properties"]["candidates"]["maxItems"] == 1
    assert provider.requests[0]["rules"]["dependencies_must_reference_prior_observations"] is True
    selected_id = provider.requests[0]["capabilities"][
        next(
            index
            for index, item in enumerate(provider.requests[0]["capabilities"])
            if item["resource"] == "private-attachments"
            and item["subject"] == "bob"
            and item["owner"] == "moderator"
        )
    ]["case_id"]
    assert any(
        item["evidence_id"] == selected_id
        for item in provider.requests[1]["observations"]
    )
    assert report.exit_code == 2  # partial exploration can retain a finding, never pass
    assert any(
        check.code == "api.BOLA"
        and check.target == "private-attachments/bob/other/moderator"
        and check.outcome == "fail"
        for check in report.checks
    )
    assert payload["coverage"]["observed"] == 42
    assert payload["coverage"]["unprobed"]
    assert payload["findings"][0]["evidence_ids"]
    graph = payload["exploration"]["graph"]
    assert any(node["kind"] == "hypothesis" for node in graph["nodes"])
    assert any(node["kind"] == "intent" for node in graph["nodes"])
    assert any(node["kind"] == "case" and node["status"] == "unprobed" for node in graph["nodes"])
    assert any(edge["kind"] == "informed" for edge in graph["edges"])

    serialized = json.dumps(provider.requests)
    assert not any(secret in serialized for secret in COOKIES.values())
    assert "response_body" not in serialized
    assert "headers" not in serialized


def test_swapping_ai_provider_keeps_execution_and_finding_semantics():
    results = []
    with read_server("selective-owner-leak") as (url, _), read_environment():
        for provider_name in ("astra-adapter", "local-model-adapter"):
            provider = SelectiveProvider()
            provider.name = provider_name
            report = Report()
            explore_api(
                Policy.model_validate(read_policy(url)).api,
                report,
                provider,
                max_rounds=1,
                max_candidates_per_round=1,
            )
            payload = report.to_dict()
            results.append(
                {
                    "evidence": payload["evidence"],
                    "findings": payload["findings"],
                    "coverage": payload["coverage"],
                    "accepted": payload["exploration"]["rounds"][0]["accepted"],
                }
            )
    assert results[0] == results[1]


def test_provider_done_hint_cannot_hide_unprobed_cases_but_complete_tail_can_finish():
    provider = SelectiveProvider(empty=True)
    with read_server("safe") as (url, requests), read_environment():
        partial = Report()
        explore_api(Policy.model_validate(read_policy(url)).api, partial, provider)
    assert len(requests) == 41
    assert partial.exit_code == 2
    assert partial.to_dict()["exploration"]["stop_reason"] == "provider_done"

    provider = SelectiveProvider(empty=True)
    with read_server("safe") as (url, requests), read_environment():
        complete = Report()
        explore_api(Policy.model_validate(read_policy(url)).api, complete, provider, complete=True)
    assert len(requests) == 85
    assert complete.exit_code == 0
    assert complete.to_dict()["exploration"]["complete"] is True


def test_invalid_provider_candidate_sends_no_candidate_request():
    provider = SelectiveProvider(invalid=True)
    with read_server("safe") as (url, requests), read_environment():
        report = Report()
        explore_api(Policy.model_validate(read_policy(url)).api, report, provider)
    assert len(requests) == 41
    assert report.exit_code == 2
    assert any(
        check.code == "exploration.provider" and check.outcome == "inconclusive"
        for check in report.checks
    )
    assert report.to_dict()["exploration"]["stop_reason"] == "invalid_provider_candidate"


class BrokenProvider:
    name = "broken-model"

    def propose(self, request, *, timeout_seconds):
        raise ProviderError("synthetic failure")


def test_provider_failure_is_finite_and_inconclusive():
    with read_server("safe") as (url, requests), read_environment():
        report = Report()
        explore_api(Policy.model_validate(read_policy(url)).api, report, BrokenProvider())
    assert len(requests) == 41
    assert report.exit_code == 2
    assert report.to_dict()["exploration"]["stop_reason"] == "provider_error"


class ProposalProvider:
    name = "surface-research-model"

    def propose(self, request, *, timeout_seconds):
        dependency = request["observations"][0]["evidence_id"]
        return ExplorationReply(
            protocol_version=1,
            proposals=[
                CapabilityProposal(
                    capability_gap="linked_storage",
                    depends_on=[dependency],
                    rationale="Declare an authorized linked storage capability for a later run.",
                )
            ],
            done_hint=True,
            rationale="provider-output-must-not-be-retained",
            provider_request_id="provider-correlation-must-not-be-retained",
        )


def test_new_surface_proposal_is_visible_but_never_executed():
    with read_server("safe") as (url, requests), read_environment():
        report = Report()
        explore_api(Policy.model_validate(read_policy(url)).api, report, ProposalProvider())
    assert len(requests) == 41
    graph = report.to_dict()["exploration"]["graph"]
    proposal = next(node for node in graph["nodes"] if node["kind"] == "capability_proposal")
    assert proposal["capability_gap"] == "linked_storage"
    assert proposal["executable"] is False
    serialized = json.dumps(report.to_dict())
    assert "provider-output-must-not-be-retained" not in serialized
    assert "provider-correlation-must-not-be-retained" not in serialized


class InventoryProvider:
    name = "inventory-model"

    def propose(self, request, *, timeout_seconds):
        case = next(
            item
            for item in request["capabilities"]
            if item["resource"] == "candidate-private"
            and item["subject"] == "bob"
            and item["owner"] == "moderator"
        )
        return ExplorationReply(
            protocol_version=1,
            candidates=[
                Candidate(
                    case_id=case["case_id"],
                    hypothesis_code="cross_owner_access",
                    priority=100,
                )
            ],
            done_hint=True,
        )


def test_authorized_exploration_resource_is_model_selectable_but_not_in_baseline_check():
    policy = read_policy()
    candidate = copy.deepcopy(policy["api"]["resources"][0])
    candidate["name"] = "candidate-private"
    policy["api"]["exploration_resources"] = [candidate]
    with read_server("safe") as (url, requests), read_environment():
        policy["api"]["base_url"] = url
        baseline = Report()
        check_api(Policy.model_validate(policy).api, baseline)
    assert len(requests) == 85
    assert all(
        item["resource"] != "candidate-private" for item in baseline.planned_cases.values()
    )

    with read_server("selective-owner-leak") as (url, requests), read_environment():
        policy["api"]["base_url"] = url
        report = Report()
        explore_api(
            Policy.model_validate(policy).api,
            report,
            InventoryProvider(),
            max_rounds=1,
            max_candidates_per_round=1,
        )
    assert len(requests) == 42  # primary sparse baseline plus one inventory capability
    assert any(
        check.code == "api.BOLA"
        and check.target == "candidate-private/bob/other/moderator"
        for check in report.checks
    )
    assert report.to_dict()["coverage"]["planned"] == 105


def test_request_budget_smaller_than_baseline_sends_nothing():
    checkpoints = []
    with read_server("safe") as (url, requests), read_environment():
        report = Report()
        explore_api(
            Policy.model_validate(read_policy(url)).api,
            report,
            SelectiveProvider(),
            max_requests_total=10,
            checkpoint=checkpoints.append,
        )
    assert not requests
    assert report.exit_code == 2
    assert any(check.code == "exploration.budget" for check in report.checks)
    assert report.to_dict()["exploration"]["stop_reason"] == "baseline_budget"
    assert checkpoints[-1]["status"] == "complete"


def test_explicit_zero_request_budget_is_rejected_before_any_request():
    provider = SelectiveProvider()
    with read_server("safe") as (url, requests), read_environment():
        report = Report()
        with pytest.raises(ValueError, match="request budget"):
            explore_api(
                Policy.model_validate(read_policy(url)).api,
                report,
                provider,
                max_requests_total=0,
            )
    assert not requests
    assert not provider.requests


def test_total_deadline_includes_provider_time_and_stops_before_candidate():
    class Clock:
        value = 0.0

        def monotonic(self):
            return self.value

    clock = Clock()

    class DelayedProvider(SelectiveProvider):
        def propose(self, request, *, timeout_seconds):
            reply = super().propose(request, timeout_seconds=timeout_seconds)
            clock.value = 2.0
            return reply

    with read_server("safe") as (url, requests), read_environment():
        report = Report()
        explore_api(
            Policy.model_validate(read_policy(url)).api,
            report,
            DelayedProvider(),
            max_seconds_total=1,
            clock=clock.monotonic,
        )
    assert len(requests) == 41
    assert report.exit_code == 2
    assert any(check.code == "exploration.deadline" for check in report.checks)
    assert report.to_dict()["exploration"]["stop_reason"] == "total_deadline"


def test_total_deadline_includes_local_response_validation(monkeypatch):
    data = example_policy()
    data["api"]["validation_timeout_ms"] = 3_000
    resource = data["api"]["resources"][0]
    resource.update(
        kind="function",
        path="/expensive",
        owner_param=None,
        owner_attr=None,
        identity_pointer=None,
        allow=[{"role": "user", "scope": "any"}],
        response_schema={"type": "string", "pattern": "^(a+)+$"},
    )
    config = Policy.model_validate(data).api

    async def immediate_response(_url, headers, *_args, **_kwargs):
        if headers.get("Authorization"):
            return 200, json.dumps("a" * 34 + "!"), {}
        return 403, '{"error":"denied"}', {}

    monkeypatch.setattr(api_module, "fetch", immediate_response)
    started = time.monotonic()
    report = Report()
    with demo_environment():
        explore_api(
            config,
            report,
            SelectiveProvider(empty=True),
            max_seconds_total=1,
        )
    assert time.monotonic() - started < 1.5
    assert report.exit_code == 2
    assert report.to_dict()["exploration"]["stop_reason"] == "total_deadline"
    assert any(check.code == "exploration.deadline" for check in report.checks)


def test_last_delivery_crossing_deadline_stays_inconclusive(monkeypatch):
    class Clock:
        value = 0.0

        def monotonic(self):
            return self.value

    clock = Clock()
    original_fetch = api_module.fetch
    seen_timeouts = []

    async def advancing_fetch(
        url, headers, config, redirect_status=None, timeout_seconds=None
    ):
        seen_timeouts.append(timeout_seconds)
        result = await original_fetch(
            url, headers, config, redirect_status, timeout_seconds
        )
        if len(requests) == 6:
            clock.value = 2.0
        return result

    class LateTailProvider(SelectiveProvider):
        def propose(self, request, *, timeout_seconds):
            clock.value = 0.75
            return ExplorationReply(protocol_version=1, candidates=[], done_hint=True)

    monkeypatch.setattr(api_module, "fetch", advancing_fetch)
    with fixture_server("safe") as (url, requests), demo_environment():
        report = Report()
        explore_api(
            Policy.model_validate(example_policy(url)).api,
            report,
            LateTailProvider(empty=True),
            max_rounds=1,
            max_seconds_total=1,
            complete=True,
            clock=clock.monotonic,
        )
    payload = report.to_dict()
    assert len(requests) == 6
    assert seen_timeouts[-1] == pytest.approx(0.25)
    assert report.exit_code == 2
    assert payload["exploration"]["complete"] is False
    assert payload["exploration"]["stop_reason"] == "total_deadline"
    assert any(check.code == "api.delivery" for check in report.checks)


def test_external_provider_is_model_neutral_and_receives_only_explicit_environment(
    tmp_path, monkeypatch
):
    adapter = tmp_path / "adapter.py"
    adapter.write_text(
        "import json, os, sys\n"
        "request = json.load(sys.stdin)\n"
        "assert request['protocol_version'] == 1\n"
        "print(json.dumps({'protocol_version': 1, 'candidates': [], "
        "'done_hint': True, 'rationale': str(bool(os.getenv('PP_ALICE_COOKIE'))) + ':' + "
        "os.getenv('MODEL_TOKEN', '') + ':' + os.getenv('PATH', '')}))\n"
    )
    monkeypatch.setenv("PP_ALICE_COOKIE", "must-not-reach-provider")
    monkeypatch.setenv("MODEL_TOKEN", "explicit")
    monkeypatch.setenv("PATH", "synthetic-target-secret")
    provider = ExternalProvider(
        "any-model",
        [str(Path("/usr/bin/python3")), str(adapter)],
        ["MODEL_TOKEN"],
    )
    reply = provider.propose(
        {"protocol_version": 1, "candidate_schema": {}}, timeout_seconds=5
    )
    assert reply.done_hint is True
    assert reply.rationale == f"False:explicit:{os.defpath}"


@pytest.mark.parametrize("request_value", ["credential", "public-header"])
def test_explore_cli_refuses_to_forward_target_request_environment(
    request_value, tmp_path, monkeypatch, capsys
):
    adapter = tmp_path / "must-not-run.py"
    marker = tmp_path / "provider-ran"
    adapter.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1]).write_text('provider ran')\n"
    )
    data = read_policy()
    sensitive = "PP_ALICE_COOKIE"
    if request_value == "public-header":
        sensitive = "PP_PUBLIC_COOKIE"
        data["api"]["public_resources"] = [
            {
                "name": "public-page",
                "path": "/public",
                "variants": [
                    {
                        "name": "session-shaped",
                        "header_envs": {"Cookie": sensitive},
                    }
                ],
            }
        ]
        monkeypatch.setenv(sensitive, "synthetic-public-cookie")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(data))
    state = tmp_path / "state.json"
    with read_environment():
        exit_code = main(
            [
                "explore",
                str(policy),
                "--provider-command",
                "/usr/bin/python3",
                "--provider-arg",
                str(adapter),
                "--provider-arg",
                str(marker),
                "--provider-env",
                sensitive,
                "--state",
                str(state),
                "--format",
                "json",
            ]
        )
    assert exit_code == 2
    assert not marker.exists()
    assert not state.exists()
    assert json.loads(capsys.readouterr().out)["status"] == "inconclusive"


def test_external_provider_stops_output_flood_and_its_child(tmp_path):
    adapter = tmp_path / "flood.py"
    marker = tmp_path / "child-survived"
    adapter.write_text(
        "import json, subprocess, sys, time\n"
        "json.load(sys.stdin)\n"
        "subprocess.Popen([sys.executable, '-c', "
        "\"import pathlib,sys,time; time.sleep(0.5); "
        "pathlib.Path(sys.argv[1]).write_text('alive')\", sys.argv[1]])\n"
        "sys.stdout.write('x' * 1100000)\n"
        "sys.stdout.flush()\n"
        "time.sleep(30)\n"
    )
    provider = ExternalProvider(
        "flood-model",
        [str(Path("/usr/bin/python3")), str(adapter), str(marker)],
    )
    started = time.monotonic()
    with pytest.raises(ProviderError):
        provider.propose(
            {"protocol_version": 1, "candidate_schema": {}}, timeout_seconds=5
        )
    assert time.monotonic() - started < 3
    time.sleep(0.8)
    assert not marker.exists()


def test_explore_cli_runs_external_provider_then_deterministic_completion(tmp_path, capsys):
    adapter = tmp_path / "adapter.py"
    adapter.write_text(
        "import json, sys\n"
        "json.load(sys.stdin)\n"
        "print(json.dumps({'protocol_version': 1, 'candidates': [], "
        "'done_hint': True, 'rationale': 'model-neutral'}))\n"
    )
    with read_server("safe") as (url, requests), read_environment():
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps(read_policy(url)))
        report = tmp_path / "exploration.json"
        state = tmp_path / "state.json"
        exit_code = main(
            [
                "explore",
                str(policy),
                "--provider-command",
                "/usr/bin/python3",
                "--provider-arg",
                str(adapter),
                "--provider-name",
                "any-ai",
                "--state",
                str(state),
                "--complete",
                "--format",
                "json",
                "--report",
                str(report),
            ]
        )
    assert exit_code == 0
    assert len(requests) == 85
    payload = json.loads(report.read_text())
    assert payload["exploration"]["provider"] == "any-ai"
    checkpoint = json.loads(state.read_text())
    assert checkpoint["status"] == "complete"
    assert checkpoint["exploration"]["graph"]["nodes"]
    assert state.stat().st_mode & 0o777 == 0o600
    assert json.loads(capsys.readouterr().out)["exit_code"] == 0


def test_existing_exploration_state_prevents_provider_and_target_requests(tmp_path):
    adapter = tmp_path / "must-not-run.py"
    adapter.write_text("raise SystemExit('must not run')\n")
    state = tmp_path / "existing-state.json"
    state.write_text("{}")
    with read_server("safe") as (url, requests), read_environment():
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps(read_policy(url)))
        exit_code = main(
            [
                "explore",
                str(policy),
                "--provider-command",
                "/usr/bin/python3",
                "--provider-arg",
                str(adapter),
                "--state",
                str(state),
            ]
        )
    assert exit_code == 2
    assert not requests
