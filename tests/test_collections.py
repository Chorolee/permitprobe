import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from permitprobe.api import check_api, check_collection, pointer_value
from permitprobe.cli import main
from permitprobe.collection_demo import (
    DEMO_COOKIES,
    collection_environment,
    collection_policy,
    collection_server,
)
from permitprobe.policy import Collection, Policy, Subject
from permitprobe.report import Report


@pytest.mark.parametrize(
    "scenario,expected,rule",
    [
        ("safe", 0, "data.collection_owner"),
        ("leaky", 1, "data.collection_owner"),
        ("empty", 2, "data.collection_control"),
        ("expired", 2, "api.positive_control"),
        ("server-error", 2, "api.unexpected_status"),
        ("anonymous-leak", 1, "api.privilege-escalation"),
        ("malformed-and-foreign", 2, "data.collection_control"),
        ("leaky-and-expired", 2, "api.positive_control"),
        ("duplicate-owner", 2, "data.json"),
    ],
)
def test_private_collection_over_real_http(scenario, expected, rule):
    with collection_server(scenario) as (url, requests), collection_environment():
        report = Report()
        check_api(Policy.model_validate(collection_policy(url)).api, report)
    assert report.exit_code == expected, report.to_dict()
    assert len(requests) == 3
    assert any(c.code == rule for c in report.checks)
    for subject, request_path, headers in requests:
        assert request_path == "/saved-searches"
        assert "Authorization" not in headers
        assert "injected" not in headers.get("Cookie", "")
        if subject:
            assert headers["Cookie"] == DEMO_COOKIES[f"PP_{subject.upper()}_COOKIE"]
    if scenario == "leaky":
        # Alice's own row is first; Bob's later row must still be detected.
        assert any(
            c.code == "data.collection_owner" and c.outcome == "fail" and "/alice/" in c.target
            for c in report.checks
        )
    if scenario in ("malformed-and-foreign", "leaky-and-expired"):
        # Preserve the known violation even when the run is also incomplete.
        assert any(c.code == "data.collection_owner" and c.outcome == "fail" for c in report.checks)
        assert report.to_dict()["counts"]["inconclusive"] > 0
    serialized = json.dumps(report.to_dict())
    for private in [*DEMO_COOKIES.values(), "Synthetic saved search", "third-user"]:
        assert private not in serialized


@pytest.mark.parametrize(
    "credential",
    [
        None,
        "",
        "  ",
        "a=b\r\nx=y",
        "a=b\t",
        "a=é",
        "a=\x7f",
        "missing-pair",
        "a=b;",
        "a=b;;c=d",
        "a=b, c=d",
        "a=b; a=c",
        'a="unterminated',
        'a="value with space"',
        "x" * 8193,
    ],
)
def test_bad_cookies_send_no_requests(credential, monkeypatch):
    with collection_server() as (url, requests), collection_environment():
        if credential is None:
            monkeypatch.delenv("PP_ALICE_COOKIE")
        else:
            monkeypatch.setenv("PP_ALICE_COOKIE", credential)
        report = Report()
        check_api(Policy.model_validate(collection_policy(url)).api, report)
    assert not requests
    assert report.exit_code == 2


def test_duplicated_cookie_values_send_no_requests(monkeypatch):
    with collection_server() as (url, requests), collection_environment():
        monkeypatch.setenv("PP_BOB_COOKIE", DEMO_COOKIES["PP_ALICE_COOKIE"])
        report = Report()
        check_api(Policy.model_validate(collection_policy(url)).api, report)
    assert not requests
    assert report.exit_code == 2


@pytest.mark.parametrize(
    "equivalent",
    [
        "theme=light; session=synthetic-alice",
        'session="synthetic-alice"; theme=light',
        " session=synthetic-alice ;  theme=light ",
    ],
)
def test_equivalent_cookie_sets_send_no_requests(equivalent, monkeypatch):
    with collection_server() as (url, requests), collection_environment():
        monkeypatch.setenv("PP_BOB_COOKIE", equivalent)
        report = Report()
        check_api(Policy.model_validate(collection_policy(url)).api, report)
    assert not requests
    assert report.exit_code == 2


@pytest.mark.parametrize("bearer_names", [("alice", "bob"), ("bob",)])
def test_bearer_and_mixed_auth_collections(bearer_names, monkeypatch):
    with collection_server() as (url, requests), collection_environment():
        policy = collection_policy(url)
        for subject in policy["api"]["subjects"]:
            if subject["name"] in bearer_names:
                subject.pop("cookie_env")
                subject["token_env"] = f"PP_{subject['name'].upper()}_TOKEN"
                monkeypatch.setenv(subject["token_env"], f"synthetic-{subject['name']}")
        report = Report()
        check_api(Policy.model_validate(policy).api, report)
    assert report.exit_code == 0, report.to_dict()
    for subject, _, headers in requests:
        if subject in bearer_names:
            assert headers["Authorization"] == f"Bearer synthetic-{subject}"
            assert "Cookie" not in headers
        else:
            assert "Authorization" not in headers


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["subjects"][0].update(cookie_env="ANON_COOKIE"),
        lambda p: p["subjects"][1].update(token_env="ALICE_TOKEN"),
        lambda p: p["subjects"][1].pop("cookie_env"),
        lambda p: p["subjects"][2].update(cookie_env="PP_ALICE_COOKIE"),
        lambda p: p["subjects"][2].update(attributes={}),
        lambda p: p["subjects"][2].update(attributes={"user_id": "alice"}),
        lambda p: p["resources"][0].update(kind="object"),
        lambda p: p["resources"][0]["allow"].append({"role": "anonymous"}),
        lambda p: p["resources"][0]["allow"][0].update(scope="own"),
        lambda p: p["resources"][0]["collection"].update(items_pointer="items"),
        lambda p: p["resources"][0]["collection"].update(owner_pointer="/bad~2escape"),
        lambda p: p["resources"][0]["collection"].update(owner_pointer=""),
    ],
)
def test_reject_ambiguous_collection_policy(change):
    policy = collection_policy()
    change(policy["api"])
    with pytest.raises(ValidationError):
        Policy.model_validate(policy)


@pytest.mark.parametrize(
    "items", [None, {}, [], [{}], [{"owner/id~": None}], [{"owner/id~": 1}], [{"owner/id~": " "}]]
)
def test_unusable_ownership_cannot_pass(items):
    rule = Collection(items_pointer="", owner_pointer="/owner~1id~0", owner_attr="user_id")
    subject = Subject(name="alice", role="user", attributes={"user_id": "alice"})
    report = Report()
    check_collection(items, rule, subject, report, "fixture")
    assert report.exit_code == 2


def test_root_array_and_escaped_owner_pointer():
    rule = Collection(items_pointer="", owner_pointer="/owner~1id~0", owner_attr="user_id")
    subject = Subject(name="alice", role="user", attributes={"user_id": "alice"})
    report = Report()
    check_collection([{"owner/id~": "alice"}], rule, subject, report, "fixture")
    assert report.exit_code == 0
    assert pointer_value(["zero", "one"], "/1") == "one"
    with pytest.raises(KeyError):
        pointer_value(["zero", "one"], "/01")


def test_cookie_export_refused_without_output_or_credentials(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(collection_policy()))
    output = tmp_path / "matrix.json"
    with collection_environment():
        assert main(["export-overstep", str(policy), "--output", str(output)]) == 2
    assert not output.exists()
    stdout = capsys.readouterr().out
    assert all(value not in stdout for value in DEMO_COOKIES.values())


@pytest.mark.parametrize("scenario,expected", [("safe", 0), ("leaky", 1), ("empty", 2)])
def test_collection_cli(scenario, expected, capsys):
    assert main(["demo-collection", "--scenario", scenario, "--format", "json"]) == expected
    assert json.loads(capsys.readouterr().out)["exit_code"] == expected


def test_collection_example_matches_implementation():
    root = Path(__file__).resolve().parents[1]
    assert (
        json.loads((root / "examples/private-collection.json").read_text()) == collection_policy()
    )
