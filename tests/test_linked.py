import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import permitprobe.linked as linked_module
from permitprobe.api import check_api
from permitprobe.cli import main
from permitprobe.linked_demo import (
    PRIVATE_BODY,
    REDIRECT_SENTINEL,
    TOKENS,
    linked_environment,
    linked_policy,
    linked_servers,
)
from permitprobe.policy import Policy, api_contract_digest
from permitprobe.read_demo import read_environment, read_policy, read_server
from permitprobe.report import Report
from permitprobe.retest import run_retest
from permitprobe.scan import run_scan


@pytest.mark.parametrize(
    "scenario,expected,code",
    [
        ("safe", 0, "linked.public_access"),
        ("public-leak", 1, "linked.public_access"),
        ("source-missing", 2, "linked.source_control"),
        ("redirect", 2, "linked.unexpected_status"),
        ("server-error", 2, "linked.unexpected_status"),
    ],
)
def test_linked_private_object_boundary(scenario, expected, code):
    with linked_servers(scenario) as (api, storage, api_requests, storage_requests):
        with linked_environment():
            report = Report()
            check_api(Policy.model_validate(linked_policy(api, storage)).api, report)
    payload = report.to_dict()
    assert report.exit_code == expected, payload
    assert len(api_requests) == 6
    assert len(storage_requests) == 2
    assert payload["coverage"] == {"planned": 8, "observed": 8, "unprobed": []}
    assert all(item["evidence_id"].startswith("ppl-") for item in payload["evidence"][-2:])
    assert all(
        "Authorization" not in headers and "Cookie" not in headers
        for _, headers in storage_requests
    )
    assert any(check.code == code for check in report.checks)
    if scenario == "safe":
        assert all(
            check.outcome == "pass"
            for check in report.checks
            if check.code == "linked.public_access"
        )
    if scenario == "public-leak":
        assert sum(
            check.outcome == "fail" and check.code == "linked.public_access"
            for check in report.checks
        ) == 2
    serialized = json.dumps(payload)
    for private in [*TOKENS.values(), PRIVATE_BODY, REDIRECT_SENTINEL, storage]:
        assert private not in serialized


def test_linked_plan_respects_combined_case_budget_before_any_delivery():
    with linked_servers("safe") as (api, storage, api_requests, storage_requests):
        policy = linked_policy(api, storage)
        policy["api"]["max_cases"] = 7
        with linked_environment():
            report = Report()
            check_api(Policy.model_validate(policy).api, report)
    assert not api_requests
    assert not storage_requests
    assert report.exit_code == 2
    assert any(check.code == "api.coverage" for check in report.checks)


def test_linked_reads_ignore_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    with linked_servers("safe") as (api, storage, _, storage_requests):
        with linked_environment():
            report = Report()
            check_api(Policy.model_validate(linked_policy(api, storage)).api, report)
    assert report.exit_code == 0
    assert len(storage_requests) == 2


def test_linked_delivery_error_is_inconclusive(monkeypatch):
    async def failed_delivery(*_args, **_kwargs):
        raise OSError("synthetic transport failure")

    monkeypatch.setattr(linked_module, "_fetch_status", failed_delivery)
    with linked_servers("safe") as (api, storage, api_requests, storage_requests):
        with linked_environment():
            report = Report()
            check_api(Policy.model_validate(linked_policy(api, storage)).api, report)

    linked_evidence = [
        evidence
        for evidence in report.evidence.values()
        if evidence.evidence_id.startswith("ppl-")
    ]
    assert report.exit_code == 2
    assert len(api_requests) == 6
    assert not storage_requests
    assert len(linked_evidence) == 2
    assert all(
        evidence.delivery == "failed" and evidence.observed == "unknown"
        for evidence in linked_evidence
    )
    delivery_checks = [check for check in report.checks if check.code == "linked.delivery"]
    assert len(delivery_checks) == 2
    assert all(check.outcome == "inconclusive" for check in delivery_checks)


@pytest.mark.parametrize(
    "scenario,expected,failures",
    [("authenticated-safe", 0, 0), ("authenticated-leak", 1, 2)],
)
def test_same_origin_linked_route_mirrors_source_authorization(
    scenario, expected, failures
):
    with linked_servers(scenario) as (api, storage, api_requests, storage_requests):
        with linked_environment():
            report = Report()
            check_api(
                Policy.model_validate(
                    linked_policy(api, storage, "source_subjects")
                ).api,
                report,
            )
    payload = report.to_dict()
    assert report.exit_code == expected, payload
    assert len(api_requests) == 6
    assert len(api_requests.linked_requests) == 6
    assert not storage_requests
    assert payload["coverage"] == {"planned": 12, "observed": 12, "unprobed": []}
    assert sum(
        check.code == "linked.authorization" and check.outcome == "fail"
        for check in report.checks
    ) == failures
    anonymous = [headers for subject, _, headers in api_requests.linked_requests if subject is None]
    assert len(anonymous) == 2
    assert all("Authorization" not in headers and "Cookie" not in headers for headers in anonymous)
    assert any(
        headers.get("Authorization") == "Bearer " + TOKENS["PP_LINKED_ALICE_TOKEN"]
        for _, _, headers in api_requests.linked_requests
    )
    assert any(
        headers.get("Cookie") == TOKENS["PP_LINKED_BOB_COOKIE"]
        for _, _, headers in api_requests.linked_requests
    )
    assert PRIVATE_BODY not in json.dumps(payload)


def test_authenticated_linked_denial_requires_source_and_caller_controls():
    with linked_servers("source-missing") as (api, storage, api_requests, _):
        with linked_environment():
            report = Report()
            check_api(
                Policy.model_validate(
                    linked_policy(api, storage, "source_subjects")
                ).api,
                report,
            )
    assert report.exit_code == 2
    assert len(api_requests.linked_requests) == 6
    assert any(check.code == "linked.source_control" for check in report.checks)


def test_mutated_cross_origin_authenticated_contract_sends_nothing():
    with linked_servers("authenticated-safe") as (api, storage, api_requests, storage_requests):
        config = Policy.model_validate(
            linked_policy(api, storage, "source_subjects")
        ).api
        config.linked_resources[0].origin = storage
        with linked_environment():
            report = Report()
            check_api(config, report)
    assert report.exit_code == 2
    assert not api_requests
    assert not api_requests.linked_requests
    assert not storage_requests
    assert any(check.code == "linked.configuration" for check in report.checks)


def test_redirect_source_control_can_establish_linked_objects():
    with linked_servers("safe") as (_, storage, _, storage_requests):
        with read_server("safe") as (api, api_requests), read_environment():
            policy = read_policy(api)
            policy["api"]["linked_resources"] = [
                {
                    "name": "direct-private-attachments",
                    "source_resource": "private-attachments",
                    "origin": storage,
                    "path": "/objects/{id}.png",
                    "denial_statuses": [404],
                }
            ]
            report = Report()
            check_api(Policy.model_validate(policy).api, report)
    assert report.exit_code == 0, report.to_dict()
    assert len(api_requests) == 85
    assert len(storage_requests) == 4
    assert all(
        check.outcome == "pass"
        for check in report.checks
        if check.code == "linked.public_access"
    )


def _add_function_source(policy):
    policy["api"]["resources"].append(
        {
            "name": "status",
            "path": "/status",
            "kind": "function",
            "allow": [{"role": "member", "scope": "any"}],
            "response_schema": {"type": "object"},
            "denial_schema": {"type": "object"},
        }
    )
    policy["api"]["linked_resources"][0]["source_resource"] = "status"


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["api"]["linked_resources"][0].update(source_resource="unknown"),
        _add_function_source,
        lambda p: p["api"]["resources"][0]["allow"].append(
            {"role": "anonymous", "scope": "any"}
        ),
        lambda p: p["api"]["linked_resources"][0].update(path="/objects/{other}.pdf"),
        lambda p: p["api"]["linked_resources"][0].update(path="/objects/static.pdf"),
        lambda p: p["api"]["linked_resources"][0].update(
            path="/objects/{id}/{id}.pdf"
        ),
        lambda p: p["api"]["linked_resources"][0].update(
            origin="http://objects.example.invalid"
        ),
        lambda p: p["api"]["linked_resources"][0].update(
            authentication="source_subjects"
        ),
        lambda p: p["api"]["linked_resources"][0].update(name="private-documents"),
        lambda p: p["api"]["linked_resources"][0].update(denial_statuses=[404, 404]),
        lambda p: p["api"]["linked_resources"][0].update(denial_statuses=[200]),
    ],
)
def test_rejects_ambiguous_linked_contracts(change):
    policy = linked_policy()
    change(policy)
    with pytest.raises(ValidationError):
        Policy.model_validate(policy)


def test_empty_linked_default_preserves_existing_digest_and_normalizes_origins():
    without = linked_policy()
    without["api"].pop("linked_resources")
    explicit_empty = copy.deepcopy(without)
    explicit_empty["api"]["linked_resources"] = []
    assert api_contract_digest(Policy.model_validate(without).api) == api_contract_digest(
        Policy.model_validate(explicit_empty).api
    )

    implicit_port = Policy.model_validate(linked_policy()).api
    legacy_anonymous = linked_policy()
    legacy_anonymous["api"]["linked_resources"][0].pop("authentication")
    assert api_contract_digest(implicit_port) == api_contract_digest(
        Policy.model_validate(legacy_anonymous).api
    )
    explicit_port = Policy.model_validate(
        linked_policy(storage_origin="https://objects.example.invalid:443")
    ).api
    other = Policy.model_validate(
        linked_policy(storage_origin="https://other.example.invalid")
    ).api
    assert api_contract_digest(implicit_port) == api_contract_digest(explicit_port)
    assert api_contract_digest(implicit_port) != api_contract_digest(other)
    authenticated = Policy.model_validate(
        linked_policy(authentication="source_subjects")
    ).api
    assert api_contract_digest(implicit_port) != api_contract_digest(authenticated)
    assert api_contract_digest(implicit_port, include_linked=False) == api_contract_digest(
        Policy.model_validate(without).api,
        include_linked=False,
    )


def test_anonymous_linked_report_contract_remains_compatible():
    with linked_servers("safe") as (api, storage, _, _), linked_environment():
        report = Report()
        check_api(Policy.model_validate(linked_policy(api, storage)).api, report)
    linked_plans = [
        item
        for item in report.planned_cases.values()
        if item.get("case_type") == "linked_read"
    ]
    linked_evidence = [
        item for item in report.evidence.values() if item.evidence_id.startswith("ppl-")
    ]
    assert [item["case_id"] for item in linked_plans] == [
        "ppl-c76e5b9c41542819b033",
        "ppl-2e1d3908a9725bfe02bc",
    ]
    assert all("authentication" not in item for item in linked_plans)
    assert all(item["subject"] == "anonymous" for item in linked_plans)
    assert all(item.subject == "anonymous" for item in linked_evidence)
    assert [
        check.target for check in report.checks if check.code == "linked.public_access"
    ] == [
        "direct-private-documents/anonymous/alice",
        "direct-private-documents/anonymous/bob",
    ]


def test_linked_finding_retest_uses_source_controls_and_can_be_fixed():
    with linked_servers("public-leak") as (api, storage, api_requests, storage_requests):
        with linked_environment():
            config = Policy.model_validate(linked_policy(api, storage)).api
            original = Report()
            check_api(config, original)
            finding = next(
                item
                for item in original.finding_groups()
                if item["code"] == "linked.public_access"
            )
            api_requests.clear()
            storage_requests.clear()
            storage_requests.active_scenario = "safe"
            verdict, result = run_retest(
                config,
                original.to_dict(),
                finding["finding_id"],
                change_ref="deploy:linked-private",
            )
    assert verdict == "fixed"
    assert len(api_requests) == 2
    assert len(storage_requests) == 2
    assert result["report"]["exit_code"] == 0
    assert len(result["selected_case_ids"]) == 4


def test_authenticated_linked_finding_retest_uses_both_caller_controls():
    with linked_servers("authenticated-leak") as (
        api,
        storage,
        api_requests,
        storage_requests,
    ):
        with linked_environment():
            config = Policy.model_validate(
                linked_policy(api, storage, "source_subjects")
            ).api
            original = Report()
            check_api(config, original)
            finding = next(
                item
                for item in original.finding_groups()
                if item["code"] == "linked.authorization"
            )
            api_requests.clear()
            api_requests.linked_requests.clear()
            storage_requests.active_scenario = "authenticated-safe"
            verdict, result = run_retest(
                config,
                original.to_dict(),
                finding["finding_id"],
                change_ref="deploy:alternate-route-owner-check",
            )
    assert verdict == "fixed"
    assert len(api_requests) == 2
    assert not storage_requests
    assert result["report"]["exit_code"] == 0
    assert len(api_requests.linked_requests) == 4
    assert len(result["selected_case_ids"]) == 6


def test_authenticated_linked_retest_requires_linked_positive_controls():
    with linked_servers("authenticated-leak") as (
        api,
        storage,
        api_requests,
        storage_requests,
    ):
        with linked_environment():
            config = Policy.model_validate(
                linked_policy(api, storage, "source_subjects")
            ).api
            original = Report()
            check_api(config, original)
            finding = next(
                item
                for item in original.finding_groups()
                if item["code"] == "linked.authorization"
            )
            api_requests.clear()
            api_requests.linked_requests.clear()
            storage_requests.active_scenario = "authenticated-deny-all"
            verdict, result = run_retest(
                config,
                original.to_dict(),
                finding["finding_id"],
                change_ref="deploy:alternate-route-deny-all",
            )
    assert verdict == "inconclusive"
    assert len(api_requests) == 2
    assert len(api_requests.linked_requests) == 4
    assert not storage_requests
    assert result["report"]["exit_code"] == 2
    assert any(
        check["code"] == "linked.positive_control"
        for check in result["report"]["checks"]
    )
    assert len(result["selected_case_ids"]) == 6


def test_authenticated_linked_retest_enforces_combined_case_budget():
    with linked_servers("authenticated-public-leak") as (
        api,
        storage,
        api_requests,
        storage_requests,
    ):
        with linked_environment():
            config = Policy.model_validate(
                linked_policy(api, storage, "source_subjects")
            ).api
            original = Report()
            check_api(config, original)
            finding = next(
                item
                for item in original.finding_groups()
                if item["code"] == "linked.authorization"
            )
            config.max_cases = 6
            api_requests.clear()
            api_requests.linked_requests.clear()
            verdict, result = run_retest(
                config,
                original.to_dict(),
                finding["finding_id"],
                change_ref="deploy:alternate-route-owner-check",
            )
    assert verdict == "inconclusive"
    assert not api_requests
    assert not api_requests.linked_requests
    assert not storage_requests
    assert result["report"]["exit_code"] == 2
    assert any(
        check["code"] == "api.coverage" and check["outcome"] == "inconclusive"
        for check in result["report"]["checks"]
    )
    assert len(result["selected_case_ids"]) == 8


def test_linked_retest_refuses_a_different_origin_before_delivery():
    with linked_servers("public-leak") as (api, storage, _, _), linked_environment():
        original = Report()
        check_api(Policy.model_validate(linked_policy(api, storage)).api, original)
    finding = next(
        item
        for item in original.finding_groups()
        if item["code"] == "linked.public_access"
    )
    with linked_servers("safe") as (other_api, other_storage, api_requests, storage_requests):
        verdict, result = run_retest(
            Policy.model_validate(linked_policy(other_api, other_storage)).api,
            original.to_dict(),
            finding["finding_id"],
        )
    assert verdict == "inconclusive"
    assert not api_requests
    assert not storage_requests
    assert any(check["code"] == "retest.policy" for check in result["report"]["checks"])


def test_one_shot_scan_counts_linked_reads_and_zero_writes(tmp_path):
    with linked_servers("safe") as (api, storage, api_requests, storage_requests):
        with linked_environment():
            report = Report()
            run_scan(
                Policy.model_validate(linked_policy(api, storage)),
                tmp_path,
                report,
            )
    assert len(api_requests) == 6
    assert len(storage_requests) == 2
    assert report.exit_code == 0
    assert report.scan["stages"]["live_get_checks"]["status"] == "pass"
    assert report.scan["stages"]["linked_reads"] == {"configured": True, "status": "pass"}
    assert report.scan["scope"]["linked_read_contracts"] == 1
    assert report.scan["scope"]["linked_credentials_forwarded"] is False
    assert report.scan["scope"]["linked_same_origin_credentials_used"] is False
    assert report.scan["scope"]["linked_cross_origin_credentials_forwarded"] is False
    assert report.scan["scope"]["linked_response_bodies_consumed"] is False
    assert report.scan["requests"] == {
        "planned": 8,
        "observed": 8,
        "completed": 8,
        "failed": 0,
        "writes": 0,
    }


def test_one_shot_scan_records_same_origin_credential_scope(tmp_path):
    with linked_servers("authenticated-safe") as (api, storage, api_requests, _):
        with linked_environment():
            report = Report()
            run_scan(
                Policy.model_validate(
                    linked_policy(api, storage, "source_subjects")
                ),
                tmp_path,
                report,
            )
    assert report.exit_code == 0
    assert len(api_requests) == 6
    assert len(api_requests.linked_requests) == 6
    assert report.scan["scope"]["linked_credentials_forwarded"] is True
    assert report.scan["scope"]["linked_same_origin_credentials_used"] is True
    assert report.scan["scope"]["linked_cross_origin_credentials_forwarded"] is False
    assert report.scan["scope"]["linked_response_bodies_consumed"] is False


@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("safe", 0),
        ("public-leak", 1),
        ("redirect", 2),
        ("authenticated-safe", 0),
        ("authenticated-leak", 1),
    ],
)
def test_linked_demo_cli(scenario, expected, capsys):
    assert main(["demo-linked", "--scenario", scenario, "--format", "json"]) == expected
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == expected


def test_linked_example_matches_implementation():
    root = Path(__file__).resolve().parents[1]
    assert json.loads((root / "examples" / "linked-reads.json").read_text()) == linked_policy()
