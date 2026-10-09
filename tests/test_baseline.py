import copy
import json
import stat
from datetime import date

import pytest

from permitprobe.baseline import (
    Baseline,
    BaselineEntry,
    apply_baseline,
    baseline_entry_id,
    build_baseline,
)
from permitprobe.cli import main
from permitprobe.demo import demo_environment, example_policy, fixture_server
from permitprobe.policy import Policy, PolicyError, api_contract_digest
from permitprobe.report import Report
from permitprobe.retest import load_prior_report

DIGEST = "a" * 64
TODAY = date(2026, 10, 8)


def report_with(*checks, digest=DIGEST):
    report = Report(policy_digest=digest)
    for code, outcome, target in checks:
        report.add(code, outcome, target, "Synthetic normalized detail.")
    return report


def baseline_for(report, *, today=TODAY):
    baseline, _ = build_baseline(report.to_dict(), today=today)
    return baseline


def test_known_failures_stay_visible_but_do_not_fail_the_gate():
    original = report_with(("api.BOLA", "fail", "documents/alice/other/bob"))
    baseline = baseline_for(original)
    current = report_with(("api.BOLA", "fail", "documents/alice/other/bob"))
    apply_baseline(current, baseline, today=TODAY)
    payload = current.to_dict()
    assert current.exit_code == 0
    assert payload["status"] == "known_findings"
    assert payload["counts"]["fail"] == 1
    assert payload["checks"][0]["outcome"] == "fail"
    assert payload["baseline"]["known"] == 1
    assert payload["baseline"]["new"] == 0


def test_new_target_is_a_regression_even_when_its_group_is_known():
    baseline = baseline_for(report_with(("api.BOLA", "fail", "documents/alice/other/bob")))
    current = report_with(
        ("api.BOLA", "fail", "documents/alice/other/bob"),
        ("api.BOLA", "fail", "documents/alice/other/moderator"),
    )
    apply_baseline(current, baseline, today=TODAY)
    assert current.exit_code == 1
    assert current.baseline["known"] == 1
    assert current.baseline["new"] == 1


def test_inconclusive_evidence_always_wins_over_a_known_failure():
    baseline = baseline_for(report_with(("data.schema", "fail", "documents/alice/self")))
    current = report_with(
        ("data.schema", "fail", "documents/alice/self"),
        ("api.delivery", "inconclusive", "documents/bob/self"),
    )
    apply_baseline(current, baseline, today=TODAY)
    assert current.exit_code == 2
    assert current.to_dict()["status"] == "inconclusive"


@pytest.mark.parametrize(
    "code",
    ["availability.latency", "discovery.undeclared", "handoff.secret"],
)
def test_variable_latency_and_handoff_failures_cannot_be_baselined(code):
    report = report_with((code, "fail", "synthetic/target"))
    with pytest.raises(PolicyError, match="non-baselineable"):
        build_baseline(report.to_dict(), today=TODAY)


def test_inconclusive_report_cannot_create_a_baseline():
    report = report_with(
        ("api.BOLA", "fail", "documents/alice/other/bob"),
        ("api.delivery", "inconclusive", "documents/bob/self"),
    )
    with pytest.raises(PolicyError, match="inconclusive"):
        build_baseline(report.to_dict(), today=TODAY)

    incomplete = report_with(("api.BOLA", "fail", "documents/alice/other/bob")).to_dict()
    incomplete["coverage"] = {"planned": 1, "observed": 0, "unprobed": ["case-1"]}
    incomplete["exit_code"] = 2
    with pytest.raises(PolicyError, match="inconclusive"):
        build_baseline(incomplete, today=TODAY)


def test_expired_entry_resurfaces_and_unobserved_entry_is_not_pruned():
    key = ("api.BOLA", "documents/alice/other/bob")
    expired = Baseline(
        DIGEST,
        [BaselineEntry(*key, "2026-10-01", "2026-10-02", "2026-10-07")],
    )
    current = report_with((key[0], "fail", key[1]))
    apply_baseline(current, expired, today=TODAY)
    assert current.exit_code == 1
    assert current.baseline["known"] == 0
    assert current.baseline["new"] == 1
    assert current.baseline["expired"] == 1

    active = Baseline(
        DIGEST,
        [BaselineEntry(*key, "2026-10-01", "2026-10-02")],
    )
    passing = report_with(("api.authorization", "pass", "documents/alice/self"))
    apply_baseline(passing, active, today=TODAY)
    assert passing.exit_code == 0
    assert passing.baseline["unobserved"] == 1
    assert len(active.entries) == 1


def test_policy_mismatch_is_inconclusive():
    baseline = baseline_for(report_with(("api.BOLA", "fail", "documents/alice/other/bob")))
    current = report_with(("api.BOLA", "fail", "documents/alice/other/bob"), digest="b" * 64)
    apply_baseline(current, baseline, today=TODAY)
    assert current.exit_code == 2
    assert current.baseline["policy_match"] is False
    assert any(check.code == "baseline.policy" for check in current.checks)


def test_baseline_cannot_move_between_target_origins():
    first = Policy.model_validate(example_policy("https://one.example.invalid")).api
    second = Policy.model_validate(example_policy("https://two.example.invalid")).api
    original = report_with(
        ("api.BOLA", "fail", "documents/alice/other/bob"),
        digest=api_contract_digest(first),
    )
    baseline = baseline_for(original)
    current = report_with(
        ("api.BOLA", "fail", "documents/alice/other/bob"),
        digest=api_contract_digest(second),
    )
    apply_baseline(current, baseline, today=TODAY)
    assert current.exit_code == 2
    assert current.baseline["policy_match"] is False


def test_update_preserves_annotations_and_carries_unobserved_entries():
    old = BaselineEntry(
        "api.BOLA",
        "documents/alice/other/bob",
        "2026-10-01",
        "2026-10-02",
        None,
        {"reason": "Tracked remediation", "ticket": "SEC-12"},
    )
    previous = Baseline(DIGEST, [old])
    report = report_with(("data.schema", "fail", "documents/alice/self"))
    updated, summary = build_baseline(report.to_dict(), previous, today=TODAY)
    assert summary == {
        "entries": 2,
        "observed": 1,
        "recorded": 1,
        "carried_unobserved": 1,
    }
    retained = next(entry for entry in updated.entries if entry.code == "api.BOLA")
    assert retained.extra == {"reason": "Tracked remediation", "ticket": "SEC-12"}
    assert retained.last_seen == "2026-10-02"


def test_baseline_annotations_never_enter_run_reports():
    entry = BaselineEntry(
        "data.schema",
        "documents/alice/self",
        "2026-10-01",
        "2026-10-02",
        None,
        {"reason": "PRIVATE-ANNOTATION-DO-NOT-REPORT"},
    )
    current = report_with(("data.schema", "fail", "documents/alice/self"))
    apply_baseline(current, Baseline(DIGEST, [entry]), today=TODAY)
    assert current.exit_code == 0
    assert "PRIVATE-ANNOTATION-DO-NOT-REPORT" not in json.dumps(current.to_dict())


def test_baseline_loader_rejects_tampering_duplicates_and_bad_dates(tmp_path):
    baseline = baseline_for(report_with(("api.BOLA", "fail", "documents/alice/other/bob")))
    valid = baseline.to_dict()
    cases = []
    tampered = copy.deepcopy(valid)
    tampered["entries"][0]["id"] = "ppb-tampered"
    cases.append(tampered)
    duplicate = copy.deepcopy(valid)
    duplicate["entries"].append(copy.deepcopy(duplicate["entries"][0]))
    cases.append(duplicate)
    bad_date = copy.deepcopy(valid)
    bad_date["entries"][0]["expires"] = "tomorrow"
    cases.append(bad_date)
    ineligible = copy.deepcopy(valid)
    entry = ineligible["entries"][0]
    entry["code"] = "availability.latency"
    entry["id"] = baseline_entry_id(DIGEST, entry["code"], entry["target"])
    cases.append(ineligible)
    unknown_top = copy.deepcopy(valid)
    unknown_top["unexpected"] = True
    cases.append(unknown_top)
    wrong_version_type = copy.deepcopy(valid)
    wrong_version_type["format_version"] = True
    cases.append(wrong_version_type)

    for index, data in enumerate(cases):
        path = tmp_path / f"invalid-{index}.json"
        path.write_text(json.dumps(data))
        with pytest.raises(PolicyError, match="compatible"):
            Baseline.load(path)

    duplicate_keys = tmp_path / "duplicate-keys.json"
    duplicate_keys.write_text('{"format_version":1,"format_version":1}')
    with pytest.raises(PolicyError, match="compatible"):
        Baseline.load(duplicate_keys)


def test_baseline_creation_rejects_boolean_exit_code():
    report = report_with(("api.BOLA", "fail", "documents/alice/other/bob")).to_dict()
    report["exit_code"] = True
    with pytest.raises(PolicyError, match="inconclusive"):
        build_baseline(report, today=TODAY)


def test_cli_creates_and_applies_baseline_without_hiding_report(tmp_path, capsys):
    with fixture_server("leaky") as (url, _), demo_environment():
        policy_data = example_policy(url)
        policy_data.pop("handoff")
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(policy_data))
        first_report = tmp_path / "first.json"
        assert (
            main(["check", str(policy_path), "--format", "json", "--report", str(first_report)])
            == 1
        )
        assert stat.S_IMODE(first_report.stat().st_mode) == 0o600
        capsys.readouterr()

        baseline_path = tmp_path / "baseline.json"
        assert (
            main(
                [
                    "baseline",
                    str(first_report),
                    "--output",
                    str(baseline_path),
                    "--format",
                    "json",
                ]
            )
            == 0
        )
        summary = json.loads(capsys.readouterr().out)
        assert summary["recorded"] > 0
        assert stat.S_IMODE(baseline_path.stat().st_mode) == 0o600
        original_baseline = baseline_path.read_bytes()
        assert (
            main(
                ["baseline", str(first_report), "--output", str(baseline_path), "--format", "json"]
            )
            == 2
        )
        assert baseline_path.read_bytes() == original_baseline
        capsys.readouterr()

        assert (
            main(["check", str(policy_path), "--baseline", str(baseline_path), "--format", "json"])
            == 0
        )
        payload = json.loads(capsys.readouterr().out)
        assert main(["check", str(policy_path), "--baseline", str(baseline_path)]) == 0
        text = capsys.readouterr().out
    assert payload["status"] == "known_findings"
    assert payload["counts"]["fail"] > 0
    assert payload["baseline"]["new"] == 0
    assert "PermitProbe KNOWN_FINDINGS" in text
    assert "Baseline:" in text


def test_invalid_or_wrong_policy_baseline_stops_before_delivery(tmp_path, capsys):
    with fixture_server("safe") as (url, requests), demo_environment():
        policy_data = example_policy(url)
        policy_data.pop("handoff")
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(policy_data))
        baseline_path = tmp_path / "wrong.json"
        Baseline("0" * 64, []).write(baseline_path)
        assert (
            main(["check", str(policy_path), "--baseline", str(baseline_path), "--format", "json"])
            == 2
        )
    assert not requests
    assert json.loads(capsys.readouterr().out)["status"] == "inconclusive"


def test_baselined_report_remains_compatible_with_retest_lineage_loader(tmp_path):
    original = report_with(("inventory.coverage", "fail", "openapi/GET /missing"))
    baseline = baseline_for(original)
    apply_baseline(original, baseline, today=TODAY)
    path = tmp_path / "known-report.json"
    path.write_text(json.dumps(original.to_dict()))
    loaded = load_prior_report(path)
    assert loaded["status"] == "known_findings"
    assert loaded["baseline"]["known"] == 1
