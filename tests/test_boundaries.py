import asyncio
import copy
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from permitprobe.api import check_api, compile_matrix, fetch
from permitprobe.cli import main
from permitprobe.demo import (
    DEMO_TOKENS,
    demo_environment,
    example_policy,
    fixture_server,
    run_demo,
)
from permitprobe.handoff import RECEIPT_NAME, check_handoff, collect, write_bundle
from permitprobe.policy import Handoff, Policy, PolicyError, load_policy
from permitprobe.report import Report


@pytest.fixture
def scanner():
    executable = os.environ.get("PERMITPROBE_GITLEAKS", ".tools/gitleaks")
    if not Path(executable).is_file():
        pytest.fail(
            "Install Gitleaks 8.30.1 for integration tests; missing engines are not skipped."
        )
    return str(Path(executable).resolve())


@pytest.mark.parametrize(
    "scenario,code,rule",
    [
        ("safe", 0, None),
        ("leaky", 1, "api.BOLA"),
        ("schema-leak", 1, "data.schema"),
        ("nested-leak", 1, "data.schema"),
        ("denied-leak", 1, "data.denial_schema"),
        ("expired", 2, "api.positive_control"),
        ("server-error", 2, "api.unexpected_status"),
        ("redirect", 2, "api.unexpected_status"),
        ("wrong-object", 2, "api.object_control"),
        ("html", 2, "data.json"),
        ("cookie", 0, None),
    ],
)
def test_actual_http_boundaries(scenario, code, rule):
    with fixture_server(scenario) as (url, requests), demo_environment():
        report = Report()
        check_api(Policy.model_validate(example_policy(url)).api, report)
    assert report.exit_code == code, report.to_dict()
    assert len(requests) == 5  # one anonymous, two own-object, two cross-owner
    assert all("Cookie" not in headers for _, _, headers in requests)
    if rule:
        assert any(c.code == rule and c.outcome != "pass" for c in report.checks)
    serialized = json.dumps(report.to_dict())
    for secret in [*DEMO_TOKENS.values(), "synthetic@example.invalid", "synthetic-sensitive-value"]:
        assert secret not in serialized


def test_partial_positive_failure_is_not_masked_by_other_user():
    with fixture_server("expired") as (url, _), demo_environment():
        report = Report()
        check_api(Policy.model_validate(example_policy(url)).api, report)
    assert any(c.target == "documents/bob/self" and c.outcome == "pass" for c in report.checks)
    assert report.exit_code == 2


@pytest.mark.parametrize("tokens", ["missing", "identical"])
def test_invalid_credentials_send_no_requests(tokens, monkeypatch):
    with fixture_server() as (url, requests), demo_environment():
        if tokens == "missing":
            monkeypatch.delenv("PP_ALICE_TOKEN")
        else:
            monkeypatch.setenv("PP_BOB_TOKEN", DEMO_TOKENS["PP_ALICE_TOKEN"])
        report = Report()
        check_api(Policy.model_validate(example_policy(url)).api, report)
        assert not requests
        assert report.exit_code == 2


def test_public_endpoint_is_not_a_credential_control():
    data = example_policy()
    data["api"]["resources"][0]["allow"].append({"role": "anonymous", "scope": "any"})
    with demo_environment():
        report = Report()
        check_api(Policy.model_validate(data).api, report)
    assert report.exit_code == 2
    assert all(c.outcome != "pass" for c in report.checks)


def test_response_budget():
    with fixture_server("oversize") as (url, _), demo_environment():
        data = example_policy(url)
        data["api"]["max_response_bytes"] = 256
        report = Report()
        check_api(Policy.model_validate(data).api, report)
    assert report.exit_code == 2
    assert any(c.code == "api.delivery" for c in report.checks)


def test_closed_server_does_not_pass():
    with fixture_server() as (url, _):
        data = example_policy(url)
    with demo_environment():
        report = Report()
        check_api(Policy.model_validate(data).api, report)
    assert report.exit_code == 2
    assert any(c.code == "api.delivery" for c in report.checks)


def test_proxy_environment_cannot_receive_tokens(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    with fixture_server() as (url, _), demo_environment():
        report = Report()
        check_api(Policy.model_validate(example_policy(url)).api, report)
    assert report.exit_code == 0


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://name:password@example.com",
        "https://example.com/a",
        "https://example.com/?secret=value",
        "https://example.com/#x",
        "file:///etc/passwd",
        "https://example.com:invalid",
        "https://example.com\n",
        "https://example.com\\evil",
    ],
)
def test_reject_unsafe_origins(url):
    with pytest.raises(ValidationError):
        Policy.model_validate(example_policy(url))


@pytest.mark.parametrize(
    "path",
    [
        "//evil.invalid/{id}",
        "https://evil.invalid/{id}",
        "/../{id}",
        "/docs/{id}/..",
        "/docs/%2e%2e/{id}",
        "/docs/{other}",
        "/docs/{id}/{extra}",
        "/docs/{id}?token=value",
    ],
)
def test_reject_unsafe_resource_paths(path):
    data = example_policy()
    data["api"]["resources"][0]["path"] = path
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(unrecognized=True),
        lambda p: p["api"]["subjects"][1].update(token="DO-NOT-PRINT-ME"),
        lambda p: p["api"]["subjects"][2].update(token_env="PP_ALICE_TOKEN"),
        lambda p: p["api"]["subjects"][2]["attributes"].update(document_id="alice"),
        lambda p: p["api"]["subjects"][2]["attributes"].update(document_id="//foreign-host"),
        lambda p: p["api"]["resources"][0].update(
            response_schema={"$ref": "http://localhost/private"}
        ),
        lambda p: p["api"]["resources"][0]["response_schema"]["properties"].update(
            title={"$dynamicRef": "https://invalid.example/x"}
        ),
        lambda p: p["api"]["resources"][0]["allow"].append({"role": "unknown"}),
    ],
)
def test_policy_rejects_ambiguous_and_unsupported_features(change):
    data = example_policy()
    change(data)
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


@pytest.mark.parametrize(
    "text",
    [
        '{"version": 1, "version": 1}',
        '{"version": true}',
        '{"version": 1}',
        '{"version": NaN}',
        "[]",
        "{invalid}",
    ],
)
def test_json_policy_is_strict(text, tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(text)
    with pytest.raises(PolicyError):
        load_policy(path)


def handoff(files=None, **kwargs):
    return Handoff(root=".", files=files or ["review.txt"], allow=["*"], **kwargs)


def test_checked_bundle_contains_only_scanned_bytes(tmp_path, scanner):
    original = b"Original synthetic review.\n"
    (tmp_path / "review.txt").write_bytes(original)
    report = Report()
    snapshot = check_handoff(handoff(), tmp_path, report, scanner)
    assert report.exit_code == 0, report.to_dict()
    (tmp_path / "review.txt").write_text("Changed AFTER the scan, must NOT be bundled.")
    path = tmp_path / "bundle.zip"
    write_bundle(snapshot, path)
    with zipfile.ZipFile(path) as archive:
        assert set(archive.namelist()) == {"review.txt", RECEIPT_NAME}
        assert archive.read("review.txt") == original
        receipt = json.loads(archive.read(RECEIPT_NAME))
        assert receipt["files"][0]["bytes"] == len(original)
    with pytest.raises(FileExistsError):
        write_bundle(snapshot, path)


def test_interrupted_bundle_never_publishes_partial_archive(tmp_path, monkeypatch):
    def broken_write(*args, **kwargs):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(zipfile.ZipFile, "writestr", broken_write)
    destination = tmp_path / "never-published.zip"
    with pytest.raises(OSError):
        write_bundle({"safe.txt": b"synthetic"}, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".permitprobe-*"))


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".env.production",
        "backup.env",
        ".ssh/id_rsa",
        ".git/config",
        ".memory/private.md",
        "private.key",
        ".gitleaks.toml",
        ".gitleaksignore",
        "../outside.txt",
        "/absolute.txt",
        "a/../review.txt",
        "a//review.txt",
        "a\\review.txt",
        "C:/review.txt",
        ".. /review.txt",
        "folder./review.txt",
    ],
)
def test_private_paths_cannot_be_widened_by_allow_glob(name, tmp_path):
    report = Report()
    snapshot = collect(handoff([name]), tmp_path, report)
    assert snapshot == {}
    assert any(c.outcome == "fail" for c in report.checks)


@pytest.mark.parametrize("link", ["file", "directory", "hard", "root"])
def test_links_do_not_escape_or_alias_boundary(link, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("Not an approved artifact.")
    root = tmp_path / "root"
    root.mkdir()
    policy = handoff()
    if link == "file":
        (root / "review.txt").symlink_to(outside)
    elif link == "directory":
        (root / "linked").symlink_to(tmp_path, target_is_directory=True)
        policy = handoff(["linked/outside.txt"])
    elif link == "hard":
        os.link(outside, root / "review.txt")
    else:
        alternate = tmp_path / "alternate"
        alternate.symlink_to(root, target_is_directory=True)
        root = alternate
    report = Report()
    assert collect(policy, root, report) == {}
    assert report.exit_code == 2


@pytest.mark.parametrize("body", [b"\x00binary", b"\xff\xfe", b"too long"])
def test_unscannable_content_does_not_pass(body, tmp_path):
    (tmp_path / "review.txt").write_bytes(body)
    report = Report()
    assert collect(handoff(max_file_bytes=5), tmp_path, report) == {}
    assert report.exit_code == 2


def test_total_budget(tmp_path):
    (tmp_path / "one.txt").write_text("1234")
    (tmp_path / "two.txt").write_text("5678")
    report = Report()
    snapshot = collect(handoff(["one.txt", "two.txt"], max_total_bytes=5), tmp_path, report)
    assert len(snapshot) == 1 and report.exit_code == 2


def test_missing_scanner_is_inconclusive(tmp_path):
    (tmp_path / "review.txt").write_text("Normal review.")
    report = Report()
    check_handoff(handoff(), tmp_path, report, "/nonexistent/permitprobe-gitleaks")
    assert report.exit_code == 2


def test_gitleaks_real_detection_and_comment_cannot_suppress(tmp_path, scanner):
    fake = "ghp_" + "7Qx4Kp9Vn2Ms8Rt6Wj3Yz5Bc1Df0Ha9Lu4Se"
    (tmp_path / "review.txt").write_text(f"token = '{fake}' # gitleaks:allow\n")
    report = Report()
    check_handoff(handoff(), tmp_path, report, scanner)
    assert report.exit_code == 1, report.to_dict()
    assert fake not in json.dumps(report.to_dict())
    assert any(c.code == "handoff.secret" for c in report.checks)


def test_gitleaks_cannot_inherit_config_or_credentials(tmp_path, scanner, monkeypatch):
    monkeypatch.setenv("GITLEAKS_CONFIG", "/nonexistent/untrusted-config")
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", "[allowlist]\nregexes=['.*']")
    test_gitleaks_real_detection_and_comment_cannot_suppress(tmp_path, scanner)


def test_scanner_errors_do_not_leak_stdout(tmp_path, capsys):
    fake = tmp_path / "bad-scanner"
    fake.write_text("#!/bin/sh\nprintf 'SECRET-DO-NOT-PRINT'\nexit 5\n")
    fake.chmod(0o755)
    (tmp_path / "review.txt").write_text("safe")
    report = Report()
    check_handoff(handoff(), tmp_path, report, str(fake))
    assert report.exit_code == 2
    assert "SECRET-DO-NOT-PRINT" not in json.dumps(report.to_dict()) + capsys.readouterr().out


def test_export_uses_env_references_only(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(example_policy()))
    with demo_environment():
        assert (
            main(["export-overstep", str(policy), "--output", str(tmp_path / "matrix.json")]) == 0
        )
    text = (tmp_path / "matrix.json").read_text()
    assert "${PP_ALICE_TOKEN}" in text
    assert all(value not in text for value in DEMO_TOKENS.values())
    from overstep.matrix import load_matrix

    with demo_environment():
        upstream = load_matrix(str(tmp_path / "matrix.json"))
    assert len(upstream.subjects) == 3
    assert "Auth-only" in capsys.readouterr().out


def test_cli_initializer_does_not_overwrite(tmp_path, capsys):
    target = tmp_path / "starter"
    assert main(["init", str(target)]) == 0
    assert load_policy(target / "permitprobe.json")
    (target / "review.txt").write_text("User edit")
    assert main(["init", str(target)]) == 2
    assert (target / "review.txt").read_text() == "User edit"


def test_cli_bundle_is_handoff_only(tmp_path, scanner, capsys):
    data = example_policy()  # deliberately unreachable API; bundle must not call it
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(data))
    (tmp_path / "review.txt").write_text("Synthetic handoff")
    args = [
        "bundle",
        str(policy),
        "--gitleaks",
        scanner,
        "--format",
        "json",
        "--output",
        str(tmp_path / "result.zip"),
    ]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["unconfigured_surfaces"] == ["api", "data"]
    assert (tmp_path / "result.zip").is_file()


def test_cli_cannot_export_failed_handoff(tmp_path, scanner, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "handoff": handoff([".env"]).model_dump()}))
    (tmp_path / ".env").write_text("SYNTHETIC=NOT-A-REAL-SECRET")
    output = tmp_path / "blocked.zip"
    assert main(["bundle", str(policy), "--gitleaks", scanner, "--output", str(output)]) == 2
    assert not output.exists()
    assert "SYNTHETIC=NOT-A-REAL-SECRET" not in capsys.readouterr().out


def test_cli_json_error_does_not_echo_credentials(tmp_path, capsys):
    p = tmp_path / "policy.json"
    data = example_policy()
    data["api"]["subjects"][1]["token"] = "DO-NOT-PRINT-ME"
    p.write_text(json.dumps(data))
    assert main(["check", str(p), "--format", "json"]) == 2
    captured = capsys.readouterr()
    assert "DO-NOT-PRINT-ME" not in captured.out + captured.err
    assert json.loads(captured.out)["status"] == "inconclusive"


@pytest.mark.parametrize("scenario,expected", [("safe", 0), ("leaky", 1), ("expired", 2)])
def test_packaged_cli_exit_codes(scenario, expected, scanner):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "permitprobe",
            "demo",
            "--scenario",
            scenario,
            "--gitleaks",
            scanner,
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == expected, result.stderr + result.stdout
    payload = json.loads(result.stdout)
    assert payload["exit_code"] == expected
    assert payload["unconfigured_surfaces"] == []


def test_full_demo_catches_all_three_boundaries(scanner):
    report = run_demo("leaky", scanner)
    assert {c.code for c in report.checks if c.outcome == "fail"} == {
        "api.BOLA",
        "data.schema",
        "handoff.secret",
    }


def test_empty_report_is_not_success():
    assert Report().exit_code == 2


def test_published_example_and_schema_match_implementation():
    root = Path(__file__).resolve().parents[1]
    assert json.loads((root / "examples/permitprobe.json").read_text()) == example_policy()
    assert json.loads((root / "permitprobe.schema.json").read_text()) == Policy.model_json_schema()


@pytest.mark.parametrize("slow_part", ["headers", "body"])
def test_absolute_deadline_stops_slow_drip(slow_part):
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            try:
                if slow_part == "headers":
                    self.wfile.write(b"HTTP/1.1 200 ")
                    self.wfile.flush()
                    time.sleep(0.6)
                    self.wfile.write(b"OK\r\n")
                    self.wfile.flush()
                    time.sleep(0.6)
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "20")
                    self.end_headers()
                    for _ in range(3):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.6)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = Policy.model_validate(example_policy()).api.model_copy(update={"timeout_seconds": 1})
    try:
        with pytest.raises(TimeoutError):
            asyncio.run(fetch(f"http://127.0.0.1:{server.server_port}/", {}, config))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_plan_contains_real_cross_owner_cases():
    from overstep.matrix import Matrix
    from overstep.planner import plan

    data = copy.deepcopy(example_policy())
    matrix = Matrix.model_validate(compile_matrix(Policy.model_validate(data).api))
    cases = plan(matrix)
    assert any(c.subject == "alice" and c.victim == "bob" for c in cases)
    assert any(c.subject == "bob" and c.victim == "alice" for c in cases)
