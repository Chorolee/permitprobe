import json
import stat

import pytest

import permitprobe.api as api_module
from permitprobe.api import check_api
from permitprobe.cli import main
from permitprobe.exploration import explore_api
from permitprobe.policy import Policy, PolicyError
from permitprobe.read_demo import COOKIES, read_environment, read_policy, read_server
from permitprobe.report import Report
from permitprobe.retest import load_prior_report, run_retest


def prior_selective_finding(url=None):
    if url is None:
        with read_server("selective-owner-leak") as (server_url, _), read_environment():
            return prior_selective_finding(server_url)
    report = Report()
    check_api(Policy.model_validate(read_policy(url)).api, report)
    payload = report.to_dict()
    finding = next(item for item in payload["findings"] if item["code"] == "api.BOLA")
    assert finding["evidence_ids"]
    return payload, finding["finding_id"]


def prior_collection_finding(url=None):
    if url is None:
        with read_server("collection-leak") as (server_url, _), read_environment():
            return prior_collection_finding(server_url)
    report = Report()
    check_api(Policy.model_validate(read_policy(url)).api, report)
    payload = report.to_dict()
    finding = next(
        item for item in payload["findings"] if item["code"] == "data.collection_items"
    )
    assert finding["occurrences"] == 4
    return payload, finding["finding_id"]


def test_retest_reproduced_then_not_reproduced_or_fixed_with_explicit_change():
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        prior, finding_id = prior_selective_finding(url)
        requests.clear()
        verdict, result = run_retest(
            Policy.model_validate(read_policy(url)).api, prior, finding_id
        )
        assert verdict == "reproduced"
        assert len(requests) == 4
        assert result["report"]["coverage"] == {
            "planned": 4,
            "observed": 4,
            "unprobed": [],
        }

        requests.active_scenario = "safe"
        requests.clear()
        verdict, result = run_retest(
            Policy.model_validate(read_policy(url)).api, prior, finding_id
        )
        assert verdict == "not_reproduced"
        assert len(requests) == 4
        assert result["report"]["exit_code"] == 0

        requests.clear()
        verdict, result = run_retest(
            Policy.model_validate(read_policy(url)).api,
            prior,
            finding_id,
            change_ref="deploy:fix-123",
        )
        assert verdict == "fixed"
        assert result["change_ref"] == "deploy:fix-123"
        serialized = json.dumps(result)
        assert not any(value in serialized for value in COOKIES.values())


def test_retest_missing_credential_and_policy_change_are_inconclusive(monkeypatch):
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        prior, finding_id = prior_selective_finding(url)
        requests.active_scenario = "safe"
        requests.clear()
        monkeypatch.delenv("PP_BOB_COOKIE")
        verdict, result = run_retest(
            Policy.model_validate(read_policy(url)).api,
            prior,
            finding_id,
            change_ref="deploy:fix-123",
        )
        assert verdict == "inconclusive"
        assert not requests
        assert result["report"]["exit_code"] == 2

    with read_server("selective-owner-leak") as (url, requests), read_environment():
        prior, finding_id = prior_selective_finding(url)
        requests.active_scenario = "safe"
        requests.clear()
        policy = read_policy(url)
        policy["api"]["probe_victims"] = "one"
        verdict, result = run_retest(
            Policy.model_validate(policy).api,
            prior,
            finding_id,
            change_ref="deploy:fix-123",
        )
        assert verdict == "inconclusive"
        assert not requests
        assert any(
            check["code"] == "retest.policy" for check in result["report"]["checks"]
        )


def test_retest_cli_writes_append_only_result(tmp_path, capsys):
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        prior, finding_id = prior_selective_finding(url)
        prior_path = tmp_path / "prior.json"
        prior_path.write_text(json.dumps(prior))
        requests.active_scenario = "safe"
        requests.clear()
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps(read_policy(url)))
        output = tmp_path / "retest.json"
        exit_code = main(
            [
                "retest",
                str(policy),
                "--prior-report",
                str(prior_path),
                "--finding",
                finding_id,
                "--change-ref",
                "deploy:fix-123",
                "--output",
                str(output),
                "--format",
                "json",
            ]
        )
    assert exit_code == 0
    assert len(requests) == 4
    assert json.loads(output.read_text())["verdict"] == "fixed"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(capsys.readouterr().out)["verdict"] == "fixed"


def test_grouped_collection_retest_adds_independent_authentication_controls():
    with read_server("collection-leak") as (url, requests), read_environment():
        prior, finding_id = prior_collection_finding(url)
        requests.clear()
        verdict, result = run_retest(
            Policy.model_validate(read_policy(url)).api, prior, finding_id
        )
    assert verdict == "reproduced"
    assert len(requests) == 9  # four leaks, four independent own-object controls, anonymous
    evidence = {
        item["evidence_id"]: item for item in result["report"]["evidence"]
    }
    for subject in ("alice", "bob", "moderator", "admin"):
        assert any(
            item["subject"] == subject
            and item["resource"] == "private-attachments"
            and item["variant"] == "self"
            for item in evidence.values()
        )


def test_anonymous_finding_cannot_be_fixed_without_same_endpoint_control(monkeypatch):
    with read_server("selective-owner-leak") as (url, _), read_environment():
        prior, _ = prior_selective_finding(url)
        anonymous = next(
            item
            for item in prior["evidence"]
            if item["resource"] == "requests" and item["subject"] == "anon"
        )
        synthetic = Report(policy_digest=prior["policy_digest"])
        synthetic.add(
            "api.BFLA",
            "fail",
            "requests/anon/na",
            "Synthetic retained authorization finding.",
            anonymous["evidence_id"],
        )
        prior["findings"] = synthetic.finding_groups()
        prior["checks"] = synthetic.to_dict()["checks"]
        calls = []

        async def unavailable_endpoint(
            _url, headers, config, redirect_status=None, timeout_seconds=None
        ):
            calls.append(headers.get("Cookie"))
            return 403, '{"error":"denied"}', {}

        monkeypatch.setattr(api_module, "fetch", unavailable_endpoint)
        verdict, result = run_retest(
            Policy.model_validate(read_policy(url)).api,
            prior,
            prior["findings"][0]["finding_id"],
            change_ref="deploy:fix",
        )
    assert len(calls) == 2
    assert any(call for call in calls)
    assert verdict == "inconclusive"
    assert any(
        check["code"] == "api.positive_control"
        for check in result["report"]["checks"]
    )


def test_exploration_finding_uses_same_catalog_and_digest_for_retest():
    class Provider:
        name = "scripted"

        def propose(self, request, *, timeout_seconds):
            candidate = next(
                item
                for item in request["capabilities"]
                if item["resource"] == "private-attachments"
                and item["subject"] == "bob"
                and item["owner"] == "moderator"
            )
            return {
                "protocol_version": 1,
                "candidates": [
                    {
                        "case_id": candidate["case_id"],
                        "hypothesis_code": "cross_owner_access",
                        "priority": 100,
                    }
                ],
                "done_hint": True,
            }

    with read_server("selective-owner-leak") as (url, requests), read_environment():
        original = Report()
        policy = Policy.model_validate(read_policy(url)).api
        explore_api(policy, original, Provider(), max_rounds=1, max_candidates_per_round=1)
        prior = original.to_dict()
        finding_id = next(
            item["finding_id"] for item in prior["findings"] if item["code"] == "api.BOLA"
        )
        requests.active_scenario = "safe"
        requests.clear()
        verdict, result = run_retest(
            Policy.model_validate(read_policy(url)).api,
            prior,
            finding_id,
        )
    assert verdict == "not_reproduced"
    assert len(requests) == 4
    assert not any(
        check["code"] == "retest.policy" for check in result["report"]["checks"]
    )


def test_retest_refuses_a_different_target_before_delivery():
    prior, finding_id = prior_selective_finding()
    calls = []

    async def unexpected_fetch(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("different target must not be contacted")

    with read_server("safe") as (url, _), read_environment():
        original_fetch = api_module.fetch
        api_module.fetch = unexpected_fetch
        try:
            verdict, result = run_retest(
                Policy.model_validate(read_policy(url)).api,
                prior,
                finding_id,
                change_ref="deploy:wrong-target",
            )
        finally:
            api_module.fetch = original_fetch
    assert verdict == "inconclusive"
    assert calls == []
    assert any(
        check["code"] == "retest.policy" for check in result["report"]["checks"]
    )


def test_malformed_prior_report_is_rejected_as_policy_error(tmp_path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "policy_digest": "0" * 64,
                "findings": ["not-an-object"],
                "evidence": [],
                "exploration": None,
            }
        )
    )
    with pytest.raises(PolicyError, match="compatible prior"):
        load_prior_report(malformed)


def test_prior_report_loader_rejects_ambiguous_nonstandard_json(tmp_path):
    prior, _ = prior_selective_finding()
    serialized = json.dumps(prior)
    cases = [
        serialized.replace(
            '"schema_version": 2', '"schema_version": 2, "schema_version": 2', 1
        ),
        serialized[:-1] + ', "nonfinite": NaN}',
        serialized[:-1] + ', "surrogate": "\\ud800"}',
    ]
    for index, raw in enumerate(cases):
        path = tmp_path / f"ambiguous-{index}.json"
        path.write_text(raw)
        with pytest.raises(PolicyError, match="compatible prior"):
            load_prior_report(path)


def test_in_memory_prior_report_rejects_nonfinite_values_before_delivery():
    prior, finding_id = prior_selective_finding()
    prior["nonfinite"] = float("nan")
    with pytest.raises(PolicyError, match="compatible prior"):
        run_retest(Policy.model_validate(read_policy()).api, prior, finding_id)


def test_prior_report_may_contain_a_nonexecutable_grouped_finding(tmp_path):
    prior, _ = prior_selective_finding()
    auxiliary = Report(policy_digest=prior["policy_digest"])
    auxiliary.add(
        "handoff.secret",
        "fail",
        "review.txt",
        "Synthetic finding without API evidence.",
    )
    prior["findings"].extend(auxiliary.finding_groups())
    prior["checks"].extend(auxiliary.to_dict()["checks"])
    path = tmp_path / "combined-report.json"
    path.write_text(json.dumps(prior))
    loaded = load_prior_report(path)
    assert any(
        item["code"] == "handoff.secret" and item["evidence_ids"] == []
        for item in loaded["findings"]
    )


def test_retest_rejects_substituted_finding_evidence_before_delivery():
    prior, finding_id = prior_selective_finding()
    benign_evidence = next(
        item["evidence_id"]
        for item in prior["evidence"]
        if item["resource"] == "private-attachments"
        and item["subject"] == "alice"
        and item["owner"] == "bob"
        and item["expected"] == "deny"
        and item["observed"] == "deny"
    )
    finding = next(item for item in prior["findings"] if item["finding_id"] == finding_id)
    finding["evidence_ids"] = [benign_evidence]

    with pytest.raises(PolicyError, match="compatible prior"):
        run_retest(Policy.model_validate(read_policy()).api, prior, finding_id)
