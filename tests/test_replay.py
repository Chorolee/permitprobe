import copy
import json
import stat
from dataclasses import replace

import pytest

from permitprobe.cli import main
from permitprobe.exploration import Candidate, ExplorationReply, explore_api
from permitprobe.policy import Policy, PolicyError
from permitprobe.read_demo import (
    COOKIES,
    DESTINATION,
    SIGNED_SENTINEL,
    read_environment,
    read_policy,
    read_server,
)
from permitprobe.replay import (
    ReplayManifest,
    build_replay_manifest,
    load_replay_source,
    run_replay,
)
from permitprobe.report import Report


class OneCaseProvider:
    name = "synthetic-selector"

    def propose(self, request, *, timeout_seconds):
        case = next(
            item
            for item in request["capabilities"]
            if item["resource"] == "private-attachments"
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
            rationale="must not enter the replay manifest",
        )


def exploration_report(url: str) -> dict:
    report = Report()
    explore_api(
        Policy.model_validate(read_policy(url)).api,
        report,
        OneCaseProvider(),
        max_rounds=1,
        max_candidates_per_round=1,
    )
    return report.to_dict()


def checkpoint(report: dict) -> dict:
    return {
        "schema_version": 1,
        "status": "complete",
        "policy_digest": report["policy_digest"],
        "exploration": report["exploration"],
        "report": report,
    }


def test_manifest_contains_only_digest_and_normalized_case_ids():
    with read_server("selective-owner-leak") as (url, _), read_environment():
        source = exploration_report(url)
    manifest = build_replay_manifest(source)
    payload = manifest.to_dict()
    assert len(manifest.baseline_case_ids) == 41
    assert len(manifest.case_ids) == 42
    assert payload["case_ids"][:41] == payload["baseline_case_ids"]
    assert payload["manifest_id"].startswith("ppr-")
    serialized = json.dumps(payload)
    assert "must not enter the replay manifest" not in serialized
    for private in [*COOKIES.values(), DESTINATION, SIGNED_SENTINEL, "synthetic-private-detail"]:
        assert private not in serialized


def test_replay_runs_exact_cases_without_provider_and_can_pass_after_fix():
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        manifest = build_replay_manifest(exploration_report(url))
        requests.active_scenario = "safe"
        requests.clear()
        report = Report()
        run_replay(Policy.model_validate(read_policy(url)).api, manifest, report)
    payload = report.to_dict()
    assert len(requests) == 42
    assert report.exit_code == 0
    assert payload["coverage"] == {"planned": 42, "observed": 42, "unprobed": []}
    assert payload["replay"] == {
        "format_version": 1,
        "manifest_id": manifest.manifest_id,
        "source_report_digest": manifest.source_report_digest,
        "baseline_cases": 41,
        "planned_cases": 42,
        "observed_cases": 42,
        "delivery": "complete",
        "writes": 0,
    }
    assert any(check.code == "replay.manifest" for check in report.checks)


def test_replay_reproduces_selected_authorization_failure():
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        manifest = build_replay_manifest(exploration_report(url))
        requests.clear()
        report = Report()
        run_replay(Policy.model_validate(read_policy(url)).api, manifest, report)
    assert len(requests) == 42
    assert report.exit_code == 1
    assert any(
        check.code == "api.BOLA"
        and check.target == "private-attachments/bob/other/moderator"
        for check in report.checks
    )


def test_replay_refuses_a_different_target_before_credentials_or_delivery():
    with read_server("selective-owner-leak") as (url, _), read_environment():
        manifest = build_replay_manifest(exploration_report(url))
    with read_server("safe") as (other_url, requests):
        report = Report()
        run_replay(Policy.model_validate(read_policy(other_url)).api, manifest, report)
    assert not requests
    assert report.exit_code == 2
    assert report.replay["delivery"] == "blocked"
    assert any(check.code == "replay.policy" for check in report.checks)


def test_replay_requires_the_exact_baseline_and_current_catalog():
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        manifest = build_replay_manifest(exploration_report(url))
        requests.clear()
        missing_baseline = replace(
            manifest,
            baseline_case_ids=manifest.baseline_case_ids[:-1],
        )
        with pytest.raises(PolicyError, match="exact deterministic baseline"):
            run_replay(
                Policy.model_validate(read_policy(url)).api,
                missing_baseline,
                Report(),
            )
        unknown = replace(manifest, case_ids=(*manifest.case_ids, "unknown::case"))
        with pytest.raises(PolicyError, match="outside the current policy"):
            run_replay(Policy.model_validate(read_policy(url)).api, unknown, Report())
    assert not requests


@pytest.mark.parametrize("problem", ["missing", "failed", "extra"])
def test_manifest_creation_refuses_incomplete_or_unscheduled_evidence(problem):
    with read_server("selective-owner-leak") as (url, _), read_environment():
        source = exploration_report(url)
    if problem == "missing":
        source["evidence"].pop()
    elif problem == "failed":
        source["evidence"][0]["delivery"] = "failed"
    else:
        extra = copy.deepcopy(source["evidence"][0])
        extra["evidence_id"] = "extra::case"
        source["evidence"].append(extra)
    with pytest.raises(PolicyError, match="compatible|complete source evidence"):
        build_replay_manifest(source)


def test_manifest_file_is_private_strict_and_tamper_evident(tmp_path):
    with read_server("selective-owner-leak") as (url, _), read_environment():
        manifest = build_replay_manifest(exploration_report(url))
    path = tmp_path / "replay.json"
    manifest.write(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert ReplayManifest.load(path) == manifest
    with pytest.raises(FileExistsError):
        manifest.write(path)

    payload = manifest.to_dict()
    payload["case_ids"][-1] = "changed::case"
    path.write_text(json.dumps(payload))
    with pytest.raises(PolicyError, match="valid replay manifest"):
        ReplayManifest.load(path)
    path.write_text('{"format_version":1,"format_version":1}')
    with pytest.raises(PolicyError, match="duplicate JSON keys"):
        ReplayManifest.load(path)

    payload = manifest.to_dict()
    payload["format_version"] = True
    path.write_text(json.dumps(payload))
    with pytest.raises(PolicyError, match="valid replay manifest"):
        ReplayManifest.load(path)


def test_checkpoint_and_report_sources_produce_the_same_manifest(tmp_path):
    with read_server("selective-owner-leak") as (url, _), read_environment():
        report = exploration_report(url)
    report_path = tmp_path / "report.json"
    state_path = tmp_path / "state.json"
    report_path.write_text(json.dumps(report))
    state_path.write_text(json.dumps(checkpoint(report)))
    assert build_replay_manifest(load_replay_source(report_path)) == build_replay_manifest(
        load_replay_source(state_path)
    )
    running = checkpoint(report)
    running["status"] = "running"
    running["report"] = dict(report)
    running["report"]["exploration"] = None
    state_path.write_text(json.dumps(running))
    assert build_replay_manifest(load_replay_source(state_path)) == build_replay_manifest(report)
    broken = checkpoint(report)
    broken["policy_digest"] = "0" * 64
    state_path.write_text(json.dumps(broken))
    with pytest.raises(PolicyError, match="internally inconsistent"):
        load_replay_source(state_path)


@pytest.mark.parametrize("field", ["report_schema", "checkpoint_schema", "protocol"])
def test_replay_source_rejects_non_integer_document_versions(tmp_path, field):
    with read_server("selective-owner-leak") as (url, _), read_environment():
        report = exploration_report(url)
    source = checkpoint(report) if field == "checkpoint_schema" else report
    if field == "report_schema":
        source["schema_version"] = 2.0
    elif field == "checkpoint_schema":
        source["schema_version"] = True
    else:
        source["exploration"]["protocol_version"] = 1.0
    path = tmp_path / "invalid-source.json"
    path.write_text(json.dumps(source))
    with pytest.raises(PolicyError, match="compatible|unsupported shape|trace"):
        build_replay_manifest(load_replay_source(path))


def test_replay_cli_creates_and_executes_manifest(tmp_path, capsys):
    with read_server("selective-owner-leak") as (url, requests), read_environment():
        source = exploration_report(url)
        source_path = tmp_path / "exploration.json"
        source_path.write_text(json.dumps(source))
        manifest_path = tmp_path / "replay.json"
        assert (
            main(
                [
                    "replay-create",
                    str(source_path),
                    "--output",
                    str(manifest_path),
                    "--format",
                    "json",
                ]
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out) == json.loads(manifest_path.read_text())

        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(read_policy(url)))
        report_path = tmp_path / "replay-report.json"
        requests.active_scenario = "safe"
        requests.clear()
        assert (
            main(
                [
                    "replay",
                    str(policy_path),
                    "--manifest",
                    str(manifest_path),
                    "--format",
                    "json",
                    "--report",
                    str(report_path),
                ]
            )
            == 0
        )
    payload = json.loads(capsys.readouterr().out)
    assert payload == json.loads(report_path.read_text())
    assert payload["replay"]["delivery"] == "complete"
    assert len(requests) == 42
