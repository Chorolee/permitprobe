import json
import os
from pathlib import Path

import pytest

from permitprobe.api import check_api
from permitprobe.baseline import build_baseline
from permitprobe.cli import main
from permitprobe.demo import demo_environment, example_policy, fixture_server
from permitprobe.policy import Policy
from permitprobe.report import Report


@pytest.fixture
def scanner():
    executable = os.environ.get("PERMITPROBE_GITLEAKS", ".tools/gitleaks")
    if not Path(executable).is_file():
        pytest.fail(
            "Install Gitleaks 8.30.1 for integration tests; missing engines are not skipped."
        )
    return str(Path(executable).resolve())


def write_policy(tmp_path, url, *, handoff=True):
    data = example_policy(url)
    if not handoff:
        data.pop("handoff")
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data))
    return path, data


def test_one_shot_scan_runs_inventory_live_api_and_handoff(tmp_path, scanner, capsys):
    openapi = Path(__file__).resolve().parents[1] / "examples" / "openapi.json"
    (tmp_path / "review.txt").write_text("Synthetic reviewed handoff.\n")
    with fixture_server("safe") as (url, requests), demo_environment():
        policy, _ = write_policy(tmp_path, url)
        output = tmp_path / "scan.json"
        exit_code = main(
            [
                "scan",
                str(policy),
                "--openapi",
                str(openapi),
                "--gitleaks",
                scanner,
                "--format",
                "json",
                "--report",
                str(output),
            ]
        )
    assert exit_code == 0
    assert len(requests) == 6
    payload = json.loads(output.read_text())
    assert json.loads(capsys.readouterr().out) == payload
    assert payload["status"] == "pass"
    assert payload["unconfigured_surfaces"] == []
    assert payload["scan"] == {
        "schema_version": 1,
        "mode": "declared_get_one_shot",
        "stages": {
            "openapi_inventory": {"configured": True, "status": "pass"},
            "live_get_checks": {"configured": True, "status": "pass"},
            "handoff": {"configured": True, "status": "pass"},
            "known_finding_baseline": {"configured": False, "status": "skipped"},
        },
        "requests": {
            "planned": 6,
            "observed": 6,
            "completed": 6,
            "failed": 0,
            "writes": 0,
        },
        "scope": {
            "methods": ["GET"],
            "automatic_discovery": False,
            "redirects_followed": False,
        },
    }


def test_invalid_openapi_stops_before_live_requests(tmp_path, scanner, capsys):
    bad_openapi = tmp_path / "bad-openapi.json"
    bad_openapi.write_text('{"openapi":"3.1.0","paths":[]}')
    (tmp_path / "review.txt").write_text("Synthetic reviewed handoff.\n")
    with fixture_server("safe") as (url, requests), demo_environment():
        policy, _ = write_policy(tmp_path, url)
        assert (
            main(
                [
                    "scan",
                    str(policy),
                    "--openapi",
                    str(bad_openapi),
                    "--gitleaks",
                    scanner,
                    "--format",
                    "json",
                ]
            )
            == 2
        )
    assert not requests
    assert json.loads(capsys.readouterr().out)["status"] == "inconclusive"


def test_scan_does_not_crawl_or_invent_requests(tmp_path, capsys):
    with fixture_server("safe") as (url, requests), demo_environment():
        policy, _ = write_policy(tmp_path, url, handoff=False)
        assert main(["scan", str(policy), "--format", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
    assert len(requests) == 6
    assert {owner for _, owner, _ in requests} == {"alice", "bob"}
    assert payload["scan"]["stages"]["openapi_inventory"]["status"] == "skipped"
    assert payload["scan"]["stages"]["handoff"]["status"] == "skipped"
    assert payload["scan"]["scope"]["automatic_discovery"] is False


def test_scan_applies_known_findings_without_hiding_failed_stage(tmp_path, capsys):
    with fixture_server("leaky") as (url, _), demo_environment():
        policy_path, data = write_policy(tmp_path, url, handoff=False)
        original = Report()
        check_api(Policy.model_validate(data).api, original)
        baseline, _ = build_baseline(original.to_dict())
        baseline_path = tmp_path / "baseline.json"
        baseline.write(baseline_path)

        assert (
            main(
                [
                    "scan",
                    str(policy_path),
                    "--baseline",
                    str(baseline_path),
                    "--format",
                    "json",
                ]
            )
            == 0
        )
        payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "known_findings"
    assert payload["counts"]["fail"] > 0
    assert payload["baseline"]["new"] == 0
    assert payload["scan"]["stages"]["live_get_checks"]["status"] == "fail"
    assert payload["scan"]["stages"]["known_finding_baseline"]["status"] == "applied"


def test_scan_requires_an_api_policy_before_handoff_work(tmp_path, scanner, capsys):
    policy = tmp_path / "handoff-only.json"
    policy.write_text(
        json.dumps(
            {
                "version": 1,
                "handoff": {"root": ".", "files": ["review.txt"], "allow": ["*.txt"]},
            }
        )
    )
    (tmp_path / "review.txt").write_text("Synthetic reviewed handoff.\n")
    assert main(["scan", str(policy), "--gitleaks", scanner, "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "inconclusive"


def test_incomplete_handoff_preflight_skips_live_delivery(tmp_path, capsys):
    (tmp_path / "review.txt").write_text("Synthetic reviewed handoff.\n")
    with fixture_server("safe") as (url, requests), demo_environment():
        policy, _ = write_policy(tmp_path, url)
        assert (
            main(
                [
                    "scan",
                    str(policy),
                    "--gitleaks",
                    "/nonexistent/permitprobe-gitleaks",
                    "--format",
                    "json",
                ]
            )
            == 2
        )
        payload = json.loads(capsys.readouterr().out)
    assert not requests
    assert payload["scan"]["stages"]["handoff"]["status"] == "inconclusive"
    assert payload["scan"]["stages"]["live_get_checks"]["status"] == "inconclusive"
    assert payload["scan"]["requests"]["planned"] == 0


def test_confirmed_handoff_failure_keeps_collecting_live_evidence(tmp_path, scanner, capsys):
    fake = "ghp_" + "7Qx4Kp9Vn2Ms8Rt6Wj3Yz5Bc1Df0Ha9Lu4Se"
    (tmp_path / "review.txt").write_text(f"synthetic = '{fake}'\n")
    with fixture_server("safe") as (url, requests), demo_environment():
        policy, _ = write_policy(tmp_path, url)
        assert (
            main(
                [
                    "scan",
                    str(policy),
                    "--gitleaks",
                    scanner,
                    "--format",
                    "json",
                ]
            )
            == 1
        )
        payload = json.loads(capsys.readouterr().out)
    assert len(requests) == 6
    assert payload["scan"]["stages"]["handoff"]["status"] == "fail"
    assert payload["scan"]["stages"]["live_get_checks"]["status"] == "pass"
    assert fake not in json.dumps(payload)
