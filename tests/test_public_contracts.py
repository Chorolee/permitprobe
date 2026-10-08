import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from pydantic import ValidationError

import permitprobe.api as api_module
from permitprobe.api import check_api
from permitprobe.cli import main
from permitprobe.policy import Policy
from permitprobe.report import Report
from permitprobe.retest import run_retest

ATTACKER_COOKIE = "session=synthetic-attacker-shape"


def public_policy(base_url="https://staging.example.invalid"):
    return {
        "version": 1,
        "api": {
            "base_url": base_url,
            "timeout_seconds": 1,
            "public_resources": [
                {
                    "name": "case-survey",
                    "path": "/api/case-survey",
                    "lifecycle": "active",
                    "query": [
                        {"name": "court", "value": "seoul"},
                        {"name": "mode", "value": "current"},
                        {"name": "mode", "value": "x&admin=true"},
                    ],
                    "variants": [
                        {"name": "default"},
                        {
                            "name": "session-shaped",
                            "header_envs": {"Cookie": "PP_ATTACKER_COOKIE"},
                        },
                    ],
                    "expected_statuses": [200],
                    "max_elapsed_ms": 200,
                    "cache": "no-store",
                    "response_schema": {
                        "type": "object",
                        "required": ["state"],
                        "properties": {"state": {"const": "ready"}},
                        "additionalProperties": False,
                    },
                }
            ],
        },
    }


@contextmanager
def public_server(scenario="safe"):
    class ScenarioRequests(list):
        active_scenario = scenario

    requests = ScenarioRequests()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            active_scenario = requests.active_scenario
            headers = dict(self.headers)
            requests.append((self.path, headers))
            if active_scenario == "slow-cookie" and headers.get("Cookie"):
                time.sleep(0.35)
            status = (
                503
                if active_scenario == "bad-status"
                else 410
                if active_scenario == "retired"
                else 200
            )
            body = (
                {"state": "wrong"}
                if active_scenario == "bad-schema"
                else {"state": "ready"}
            )
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Cache-Control",
                "public, max-age=60" if active_scenario == "cacheable" else "no-store",
            )
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_public_only_contract_encodes_query_and_keeps_variant_values_out_of_report(monkeypatch):
    monkeypatch.setenv("PP_ATTACKER_COOKIE", ATTACKER_COOKIE)
    with public_server() as (url, requests):
        report = Report()
        check_api(Policy.model_validate(public_policy(url)).api, report)
    assert report.exit_code == 0, report.to_dict()
    assert len(requests) == 2
    assert all(
        path == "/api/case-survey?court=seoul&mode=current&mode=x%26admin%3Dtrue"
        for path, _ in requests
    )
    assert "Cookie" not in requests[0][1]
    assert requests[1][1]["Cookie"] == ATTACKER_COOKIE
    payload = report.to_dict()
    assert payload["coverage"] == {"planned": 2, "observed": 2, "unprobed": []}
    assert all(isinstance(item["elapsed_ms"], int) for item in payload["evidence"])
    assert ATTACKER_COOKIE not in json.dumps(payload)


@pytest.mark.parametrize(
    "scenario,code",
    [
        ("bad-status", "public.status"),
        ("bad-schema", "data.schema"),
        ("cacheable", "data.no_store"),
    ],
)
def test_public_contract_fails_closed_on_status_schema_and_cache(scenario, code, monkeypatch):
    monkeypatch.setenv("PP_ATTACKER_COOKIE", ATTACKER_COOKIE)
    with public_server(scenario) as (url, _):
        report = Report()
        check_api(Policy.model_validate(public_policy(url)).api, report)
    assert report.exit_code == 1, report.to_dict()
    assert any(check.code == code and check.outcome == "fail" for check in report.checks)


@pytest.mark.parametrize(
    "schema,body",
    [
        ({"type": "string", "pattern": "^(a+)+$"}, "a" * 34 + "!"),
        (
            {"type": "array", "uniqueItems": True},
            [{"item": index} for index in range(10_000)],
        ),
    ],
)
def test_response_validation_is_stopped_by_total_budget(schema, body, monkeypatch):
    data = public_policy()
    resource = data["api"]["public_resources"][0]
    resource["variants"] = [{"name": "default"}]
    resource["response_schema"] = schema
    config = Policy.model_validate(data).api
    # Exercise the production deadline without making the test wait for the
    # integer-valued public policy minimum.
    config.validation_timeout_ms = 50

    async def immediate_response(*_args, **_kwargs):
        return 200, json.dumps(body), {"Cache-Control": "no-store"}

    monkeypatch.setattr(api_module, "fetch", immediate_response)
    started = time.monotonic()
    report = Report()
    check_api(config, report)
    assert time.monotonic() - started < 1
    assert report.exit_code == 2
    assert any(check.code == "data.validation_budget" for check in report.checks)
    assert report.evidence[next(iter(report.evidence))].observed == "unknown"


def test_public_latency_finding_retests_with_header_free_control(monkeypatch):
    monkeypatch.setenv("PP_ATTACKER_COOKIE", ATTACKER_COOKIE)
    with public_server("slow-cookie") as (url, requests):
        original = Report()
        check_api(Policy.model_validate(public_policy(url)).api, original)
        assert len(requests) == 2
        prior = original.to_dict()
        finding = next(
            item for item in prior["findings"] if item["code"] == "availability.latency"
        )
        assert len(finding["evidence_ids"]) == 1
        requests.active_scenario = "safe"
        requests.clear()
        verdict, result = run_retest(
            Policy.model_validate(public_policy(url)).api,
            prior,
            finding["finding_id"],
            change_ref="deploy:fail-fast-123",
        )
        assert verdict == "fixed", result
        assert len(requests) == 2
        assert result["report"]["coverage"] == {
            "planned": 2,
            "observed": 2,
            "unprobed": [],
        }
        assert ATTACKER_COOKIE not in json.dumps(result)


def test_missing_variant_environment_value_sends_no_request(monkeypatch):
    monkeypatch.delenv("PP_ATTACKER_COOKIE", raising=False)
    with public_server() as (url, requests):
        report = Report()
        check_api(Policy.model_validate(public_policy(url)).api, report)
    assert not requests
    assert report.exit_code == 2
    assert any(check.code == "public.configuration" for check in report.checks)


def test_retired_route_can_declare_a_fast_terminal_status(monkeypatch):
    monkeypatch.setenv("PP_ATTACKER_COOKIE", ATTACKER_COOKIE)
    data = public_policy()
    resource = data["api"]["public_resources"][0]
    resource.update(
        lifecycle="retired",
        expected_statuses=[307, 404, 410, 503],
        response_schema=None,
        cache=None,
    )
    with public_server("retired") as (url, requests):
        data["api"]["base_url"] = url
        report = Report()
        check_api(Policy.model_validate(data).api, report)
    assert len(requests) == 2
    assert report.exit_code == 0, report.to_dict()


@pytest.mark.parametrize(
    "change",
    [
        lambda resource: resource.update(path="/api/check?mode=current"),
        lambda resource: resource.update(path="/api/{id}"),
        lambda resource: resource["variants"][1]["header_envs"].update(
            Authorization="PP_ATTACKER_COOKIE"
        ),
        lambda resource: resource["query"].append({"name": "bad name", "value": "x"}),
        lambda resource: resource["query"].append({"name": "safe", "value": "x\n"}),
    ],
)
def test_public_contract_rejects_unsafe_request_shapes(change):
    data = public_policy()
    change(data["api"]["public_resources"][0])
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


def test_public_latency_limit_cannot_exceed_transport_timeout():
    data = public_policy()
    data["api"]["public_resources"][0]["max_elapsed_ms"] = 1_001
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


def test_public_only_policy_cannot_export_an_authorization_matrix(tmp_path, capsys):
    policy = tmp_path / "public.json"
    policy.write_text(json.dumps(public_policy()))
    output = tmp_path / "matrix.json"
    assert main(["export-overstep", str(policy), "--output", str(output)]) == 2
    assert not output.exists()
    assert "INCONCLUSIVE" in capsys.readouterr().out


def test_published_public_contract_example_matches_policy_schema():
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / "examples/public-contracts.json").read_text())
    policy = Policy.model_validate(data)
    assert len(policy.api.public_resources) == 2
