import copy
import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from permitprobe.api import check_api, check_collection
from permitprobe.cli import main
from permitprobe.policy import Collection, Policy, Subject
from permitprobe.read_demo import (
    COOKIES,
    DESTINATION,
    SIGNED_SENTINEL,
    read_environment,
    read_policy,
    read_server,
)
from permitprobe.report import Report


@pytest.mark.parametrize(
    "scenario,expected,code",
    [
        ("safe", 0, "api.redirect_control"),
        ("private-leak", 1, "api.BOLA"),
        ("selective-owner-leak", 1, "api.BOLA"),
        ("moderator-leak", 1, "api.BOLA"),
        ("collection-leak", 1, "data.collection_items"),
        ("cache-leak", 1, "data.private_cache"),
        ("expired-auth", 2, "api.positive_control"),
        ("wrong-location", 2, "api.redirect_control"),
        ("wrong-object", 2, "api.redirect_control"),
        ("login-redirect", 2, "api.redirect_control"),
        ("duplicate-location", 2, "api.redirect_control"),
        ("unexpected-200", 2, "api.redirect_control"),
        ("empty", 2, "data.collection_control"),
        ("invalid-item-id", 2, "data.collection_control"),
        ("server-error", 2, "api.unexpected_status"),
        ("malformed-and-foreign", 2, "data.collection_items"),
    ],
)
def test_file_role_and_collection_boundaries(scenario, expected, code):
    with read_server(scenario) as (url, requests), read_environment():
        report = Report()
        check_api(Policy.model_validate(read_policy(url)).api, report)
    assert report.exit_code == expected, report.to_dict()
    assert any(c.code == code for c in report.checks)
    assert len(requests) == 85
    assert all("/signed" not in path for _, path, _ in requests)
    assert all("injected" not in h.get("Cookie", "") for _, _, h in requests)
    assert all("Authorization" not in h for _, _, h in requests)
    if scenario == "safe":
        for target in (
            "applications/moderator/other/alice",
            "verifications/moderator/other/alice",
            "applications/admin/other/alice",
        ):
            assert any(
                c.target == target and c.code == "api.authorization" and c.outcome == "pass"
                for c in report.checks
            )
    if scenario == "moderator-leak":
        assert any(
            c.target.startswith("applications/moderator/other/") and c.outcome == "fail"
            for c in report.checks
        )
    if scenario == "selective-owner-leak":
        assert any(
            c.target == "private-attachments/bob/other/moderator" and c.outcome == "fail"
            for c in report.checks
        )
    if scenario in ("collection-leak", "malformed-and-foreign"):
        assert any(
            c.target == "requests/alice/na"
            and c.code == "data.collection_items"
            and c.outcome == "fail"
            for c in report.checks
        )
    serialized = json.dumps(report.to_dict())
    for private in [*COOKIES.values(), DESTINATION, SIGNED_SENTINEL, "synthetic-private-detail"]:
        assert private not in serialized


@pytest.mark.parametrize(
    "scenario",
    ["grant-body-invalid", "grant-body-encoded", "grant-body-oversize", "grant-body-interrupted"],
)
def test_irrelevant_redirect_body_cannot_hide_forbidden_grant(scenario):
    with read_server(scenario) as (url, _), read_environment():
        policy = read_policy(url)
        # Below the fixture's redirect body size, above the JSON list size.
        policy["api"]["max_response_bytes"] = 256
        report = Report()
        check_api(Policy.model_validate(policy).api, report)
    assert report.exit_code == 1, report.to_dict()
    assert any(c.code == "api.BOLA" and c.outcome == "fail" for c in report.checks)
    assert not any(c.outcome == "inconclusive" for c in report.checks)


def test_read_demo_redirects_only_declared_fixture_paths():
    with read_server("safe") as (url, _):
        response = httpx.get(
            url + "/attachments/alice/undeclared.bin",
            headers={"Cookie": COOKIES["PP_ALICE_COOKIE"]},
        )
    assert response.status_code == 401
    assert "location" not in response.headers


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["resources"][0].update(response_schema={"type": "object"}),
        lambda p: p["resources"][0].update(identity_pointer="/id"),
        lambda p: p["resources"][0].update(kind="function"),
        lambda p: p["resources"][0]["redirect"].update(path="/signed/{other}"),
        lambda p: p["resources"][0]["redirect"].update(path="/signed/{id}/{id}"),
        lambda p: p["resources"][0]["redirect"].update(origin="http://storage.example.invalid"),
        lambda p: p["resources"][0]["redirect"].update(origin="https://storage.example.invalid:0"),
        lambda p: p["resources"][0]["redirect"].update(
            origin="https://name@storage.example.invalid"
        ),
        lambda p: p["resources"][0]["redirect"].update(origin="https://storage.example.invalid?"),
        lambda p: p["resources"][0]["redirect"].update(status=301),
        lambda p: p["resources"][0]["redirect"].update(required_query=[]),
        lambda p: p["resources"][0]["redirect"].update(required_query=["token", "token"]),
        lambda p: p["resources"][0]["allow"].append({"role": "anonymous", "scope": "any"}),
        lambda p: p["resources"][-1]["collection"].update(
            owner_pointer="/ownerId", owner_attr="user_id"
        ),
        lambda p: p["resources"][-1]["collection"].pop("item_pointer"),
        lambda p: p["subjects"][1].update(owned_items={}),
        lambda p: p["subjects"][1].update(owned_items={"requests": []}),
        lambda p: p["subjects"][1].update(owned_items={"requests": ["same", "same"]}),
        lambda p: p["subjects"][1].update(owned_items={"requests": ["request-bob"]}),
        lambda p: p["subjects"][1].update(owned_items={"requests": ["../foreign"]}),
    ],
)
def test_reject_ambiguous_read_contracts(change):
    policy = read_policy()
    change(policy["api"])
    with pytest.raises(ValidationError):
        Policy.model_validate(policy)


def test_owned_item_contract_does_not_require_every_fixture_to_appear():
    rule = Collection(items_pointer="", item_pointer="/id", items_attr="requests")
    subject = Subject(name="alice", role="member", owned_items={"requests": ["one", "two"]})
    report = Report()
    check_collection([{"id": "two"}], rule, subject, report, "fixture")
    assert report.exit_code == 0
    mixed = Report()
    check_collection([{}, {"id": "foreign"}, {"id": "one"}], rule, subject, mixed, "fixture")
    assert mixed.exit_code == 2
    assert any(c.code == "data.collection_items" and c.outcome == "fail" for c in mixed.checks)


@pytest.mark.parametrize("invalid_id", ["", "\0", "bad/id", "../x", "has space", "é", "x" * 129])
def test_malformed_seeded_ids_are_inconclusive_and_preserve_foreign_siblings(invalid_id):
    rule = Collection(items_pointer="", item_pointer="/id", items_attr="requests")
    subject = Subject(name="alice", role="member", owned_items={"requests": ["own"]})
    report = Report()
    check_collection([{"id": invalid_id}], rule, subject, report, "fixture")
    assert report.exit_code == 2
    assert not any(c.outcome == "fail" for c in report.checks)
    mixed = Report()
    check_collection(
        [{"id": invalid_id}, {"id": "foreign"}, {"id": "own"}], rule, subject, mixed, "fixture"
    )
    assert mixed.exit_code == 2
    assert any(c.code == "data.collection_items" and c.outcome == "fail" for c in mixed.checks)


def test_redirect_export_refused_even_with_bearer_credentials(tmp_path, capsys):
    policy = read_policy()
    for s in policy["api"]["subjects"][1:]:
        s["token_env"] = s.pop("cookie_env")
    config = tmp_path / "policy.json"
    config.write_text(json.dumps(policy))
    output = tmp_path / "matrix.json"
    assert main(["export-overstep", str(config), "--output", str(output)]) == 2
    assert not output.exists()
    assert SIGNED_SENTINEL not in capsys.readouterr().out


@pytest.mark.parametrize(
    "scenario,expected", [("safe", 0), ("moderator-leak", 1), ("wrong-location", 2)]
)
def test_read_demo_cli(scenario, expected, capsys):
    assert main(["demo-read-paths", "--scenario", scenario, "--format", "json"]) == expected
    report = json.loads(capsys.readouterr().out)
    assert report["exit_code"] == expected
    assert report["unconfigured_surfaces"] == ["handoff"]


def test_read_example_matches_implementation():
    root = Path(__file__).resolve().parents[1]
    assert json.loads((root / "examples/read-paths.json").read_text()) == read_policy()


def test_full_owner_matrix_has_distinct_private_evidence_and_grouped_finding():
    with read_server("selective-owner-leak") as (url, _), read_environment():
        report = Report()
        check_api(Policy.model_validate(read_policy(url)).api, report)
    payload = report.to_dict()
    assert payload["schema_version"] == 2
    assert payload["coverage"] == {"planned": 85, "observed": 85, "unprobed": []}
    ids = [item["evidence_id"] for item in payload["evidence"]]
    assert len(ids) == len(set(ids)) == 85
    finding = next(item for item in payload["findings"] if item["code"] == "api.BOLA")
    assert finding["occurrences"] == 1
    evidence = next(
        item for item in payload["evidence"] if item["evidence_id"] in finding["evidence_ids"]
    )
    assert (evidence["subject"], evidence["owner"]) == ("bob", "moderator")


def test_single_victim_mode_is_explicitly_lower_coverage():
    policy = read_policy()
    policy["api"]["probe_victims"] = "one"
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        policy["api"]["base_url"] = url
        report = Report()
        check_api(Policy.model_validate(policy).api, report)
    assert len(requests) == 41
    assert report.exit_code == 0
    assert not any(check.code == "api.BOLA" for check in report.checks)


def test_full_owner_matrix_respects_case_budget_before_delivery():
    policy = read_policy()
    policy["api"]["max_cases"] = 84
    with read_server("safe") as (url, requests), read_environment():
        policy["api"]["base_url"] = url
        report = Report()
        check_api(Policy.model_validate(policy).api, report)
    assert not requests
    assert report.exit_code == 2
    assert any(check.code == "api.coverage" for check in report.checks)


@pytest.mark.parametrize("problem", ["duplicate", "unknown-role"])
def test_exploration_resources_share_primary_policy_validation(problem):
    policy = read_policy()
    candidate = copy.deepcopy(policy["api"]["resources"][0])
    if problem == "duplicate":
        pass
    else:
        candidate["name"] = "candidate-private"
        candidate["allow"] = [{"role": "unconfigured-role", "scope": "any"}]
    policy["api"]["exploration_resources"] = [candidate]
    with pytest.raises(ValidationError):
        Policy.model_validate(policy)
