import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

import permitprobe.api as api_module
import permitprobe.public_contracts as public_module
from permitprobe.api import check_api
from permitprobe.cli import main
from permitprobe.policy import CORSContract, Policy, ResponseCookieContract, api_contract_digest
from permitprobe.report import Report
from permitprobe.retest import run_retest
from permitprobe.scan import run_scan
from permitprobe.web_security import cookie_results, cors_origin_key, cors_results

ATTACKER_COOKIE = "session=synthetic-attacker-shape"
TRUSTED_ORIGIN = "https://trusted.example.invalid"
HOSTILE_ORIGIN = "https://hostile.example.invalid"
RESPONSE_COOKIE = "synthetic-browser-cookie-never-report"
LEGACY_PUBLIC_DIGEST = "c01077d0b7c69ff20ba8fd90875cd888fe2fc677d67eba1140bc7acb70137292"


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


def secured_public_policy(base_url="https://staging.example.invalid"):
    data = public_policy(base_url)
    resource = data["api"]["public_resources"][0]
    resource["variants"] = [
        {"name": "default"},
        {
            "name": "trusted-origin",
            "header_envs": {"Origin": "PP_TRUSTED_ORIGIN"},
        },
        {
            "name": "hostile-origin",
            "header_envs": {"Origin": "PP_HOSTILE_ORIGIN"},
        },
    ]
    resource["response_security"] = {
        "security_headers": {
            "hsts": {
                "min_max_age": 31_536_000,
                "include_subdomains": True,
            },
            "content_type_options": "nosniff",
            "referrer_policy": ["no-referrer", "strict-origin-when-cross-origin"],
            "frame_options": ["deny"],
            "content_security_policy": {
                "required_directives": {
                    "default-src": ["'none'"],
                    "frame-ancestors": ["'none'"],
                }
            },
            "permissions_policy": {
                "disabled_features": ["camera", "geolocation", "microphone"]
            },
            "cross_origin_opener_policy": ["same-origin"],
            "cross_origin_embedder_policy": ["require-corp"],
            "cross_origin_resource_policy": ["same-origin"],
            "origin_agent_cluster": True,
        },
        "cookies": [
            {
                "name": "__Host-session",
                "secure": True,
                "http_only": True,
                "same_site": ["strict", "lax"],
                "host_only": True,
                "path": "/",
            }
        ],
        "cors": {
            "allow_variants": ["trusted-origin"],
            "deny_variants": ["hostile-origin"],
            "allow_credentials": True,
            "require_vary_origin": True,
        },
    }
    return data


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
            raw = (
                b'{"state":"ready","sequence":9007199254740993.0}'
                if active_scenario == "rounded-number"
                else json.dumps(body).encode()
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Cache-Control",
                "public, max-age=60" if active_scenario == "cacheable" else "no-store",
            )
            if active_scenario.startswith("web-"):
                self.send_header(
                    "Strict-Transport-Security",
                    "max-age=60"
                    if active_scenario == "web-weak-hsts"
                    else 'max-age="63072000"; includeSubDomains; preload'
                    if active_scenario == "web-quoted-hsts"
                    else "max-age=" + "9" * 5_000 + "; includeSubDomains; preload"
                    if active_scenario == "web-large-hsts"
                    else "max-age=63072000; includeSubDomains; preload",
                )
                if active_scenario == "web-duplicate-hsts":
                    self.send_header(
                        "Strict-Transport-Security",
                        "max-age=63072000; includeSubDomains",
                    )
                if active_scenario != "web-missing-nosniff":
                    self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header(
                    "Referrer-Policy",
                    "unsafe-url"
                    if active_scenario == "web-bad-referrer"
                    else "strict-origin-when-cross-origin",
                )
                self.send_header(
                    "X-Frame-Options",
                    "SAMEORIGIN" if active_scenario == "web-bad-frame" else "DENY",
                )
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'"
                    if active_scenario == "web-weak-csp"
                    else "default-src 'none'; frame-ancestors 'none' https:"
                    if active_scenario == "web-broad-csp"
                    else "default-src 'none'; frame-ancestors 'none'; script-src 'self'",
                )
                permissions_policy = (
                    "camera=(self), geolocation=(), microphone=()"
                    if active_scenario == "web-permissions-enabled"
                    else "camera=(), geolocation=(), microphone=(), camera=()"
                    if active_scenario == "web-permissions-duplicate-feature"
                    else 'camera=(), geolocation=("https://media.example.invalid), microphone=()'
                    if active_scenario == "web-permissions-malformed"
                    else "Camera=(), geolocation=(), microphone=()"
                    if active_scenario == "web-permissions-case-drift"
                    else "camera=(), geolocation=(), microphone=(), future=1.2345"
                    if active_scenario == "web-permissions-invalid-extension"
                    else (
                        "camera=();report-to=security, geolocation=(), microphone=(), "
                        'fullscreen=(self "https://media.example.invalid";source=1 ?1);'
                        "extension=:YWJj:, future=?1"
                    )
                )
                self.send_header("Permissions-Policy", permissions_policy)
                if active_scenario == "web-permissions-duplicate-header":
                    self.send_header("Permissions-Policy", permissions_policy)
                self.send_header(
                    "Cross-Origin-Opener-Policy",
                    "unsafe-none"
                    if active_scenario == "web-bad-coop"
                    else 'same-origin; report-to="coop"'
                    if active_scenario != "web-malformed-coop"
                    else 'same-origin; report-to="unterminated',
                )
                self.send_header(
                    "Cross-Origin-Embedder-Policy",
                    "require-corp, require-corp"
                    if active_scenario == "web-bad-coep"
                    else 'require-corp;report-to="coep"',
                )
                self.send_header(
                    "Cross-Origin-Resource-Policy",
                    "Same-Origin"
                    if active_scenario == "web-bad-corp"
                    else "same-origin",
                )
                self.send_header(
                    "Origin-Agent-Cluster",
                    "?0" if active_scenario == "web-bad-oac" else "?1",
                )
                cookie = (
                    f"__Host-session={RESPONSE_COOKIE}; SameSite=Lax; Path=/"
                    if active_scenario == "web-cookie-flags"
                    else f"__Host-session={RESPONSE_COOKIE}; Secure=false; HttpOnly=false; SameSite=Lax; Path=/"
                    if active_scenario == "web-cookie-false-flags"
                    else f"__Host-session={RESPONSE_COOKIE}; Secure; HttpOnly; SameSite=Lax; Path=/"
                )
                if active_scenario == "web-cookie-empty-domain":
                    cookie += "; Domain="
                if active_scenario == "web-cookie-partitioned":
                    cookie += "; Partitioned"
                self.send_header("Set-Cookie", cookie)
                if active_scenario == "web-cookie-duplicate":
                    self.send_header("Set-Cookie", cookie)
                if active_scenario == "web-cookie-combined":
                    self.send_header(
                        "Set-Cookie",
                        cookie + ", unrelated=synthetic; Secure; Path=/",
                    )
                origin = headers.get("Origin")
                if origin and active_scenario in (
                    "web-cors-wildcard",
                    "web-cors-wildcard-credentials",
                ):
                    self.send_header("Access-Control-Allow-Origin", "*")
                    if active_scenario == "web-cors-wildcard-credentials":
                        self.send_header("Access-Control-Allow-Credentials", "true")
                elif origin and active_scenario == "web-cors-malformed":
                    self.send_header("Access-Control-Allow-Origin", "https://[")
                elif origin == "null" and active_scenario == "web-cors-null-only":
                    self.send_header("Access-Control-Allow-Origin", "null")
                    self.send_header("Access-Control-Allow-Credentials", "true")
                    self.send_header("Vary", "Origin")
                elif origin and (
                    origin == TRUSTED_ORIGIN or active_scenario == "web-cors-reflect"
                ):
                    allowed_origin = (
                        origin + ":443"
                        if active_scenario == "web-cors-default-port"
                        else "HTTPS" + origin[5:]
                        if active_scenario == "web-cors-origin-case"
                        else origin
                    )
                    self.send_header("Access-Control-Allow-Origin", allowed_origin)
                    if active_scenario == "web-cors-duplicate":
                        self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header(
                        "Access-Control-Allow-Credentials",
                        "True" if active_scenario == "web-cors-credentials-case" else "true",
                    )
                    if active_scenario != "web-cors-no-vary":
                        self.send_header(
                            "Vary",
                            "*" if active_scenario == "web-cors-vary-star" else "Origin",
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


def _security_environment(monkeypatch):
    monkeypatch.setenv("PP_TRUSTED_ORIGIN", TRUSTED_ORIGIN)
    monkeypatch.setenv("PP_HOSTILE_ORIGIN", HOSTILE_ORIGIN)


@pytest.mark.parametrize(
    "origin",
    [
        "https://example.invalid",
        "https://example.invalid:444",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "https://xn--bcher-kva.example",
        "https://example.invalid.",
        "null",
    ],
)
def test_cors_accepts_canonical_serialized_origins(origin):
    assert cors_origin_key(origin) is not None


@pytest.mark.parametrize("scenario", ["web-quoted-hsts", "web-large-hsts"])
def test_hsts_accepts_rfc_delta_seconds_without_fixed_width_integer_conversion(
    scenario, monkeypatch
):
    _security_environment(monkeypatch)
    with public_server(scenario) as (url, _):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
    assert report.exit_code == 0, report.to_dict()


def test_declared_response_security_contract_passes_without_retaining_values(monkeypatch):
    _security_environment(monkeypatch)
    with public_server("web-safe") as (url, requests):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
    assert report.exit_code == 0, report.to_dict()
    assert len(requests) == 3
    codes = {check.code for check in report.checks if check.code.startswith("web.")}
    assert codes == {
        "web.hsts",
        "web.content_type_options",
        "web.referrer_policy",
        "web.frame_options",
        "web.content_security_policy",
        "web.permissions_policy",
        "web.cross_origin_opener_policy",
        "web.cross_origin_embedder_policy",
        "web.cross_origin_resource_policy",
        "web.origin_agent_cluster",
        "web.cookies",
        "web.cors",
    }
    assert all(
        check.outcome == "pass" for check in report.checks if check.code.startswith("web.")
    )
    serialized = json.dumps(report.to_dict())
    assert RESPONSE_COOKIE not in serialized
    assert TRUSTED_ORIGIN not in serialized
    assert HOSTILE_ORIGIN not in serialized
    assert "media.example.invalid" not in serialized


def test_cors_can_allow_and_deny_the_opaque_null_origin(monkeypatch):
    monkeypatch.setenv("PP_TRUSTED_ORIGIN", "null")
    monkeypatch.setenv("PP_HOSTILE_ORIGIN", HOSTILE_ORIGIN)
    with public_server("web-cors-null-only") as (url, requests):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
    assert report.exit_code == 0, report.to_dict()
    assert len(requests) == 3
    assert '"null"' not in json.dumps(report.to_dict())


def test_cors_rejects_reflected_opaque_null_origin(monkeypatch):
    monkeypatch.setenv("PP_TRUSTED_ORIGIN", TRUSTED_ORIGIN)
    monkeypatch.setenv("PP_HOSTILE_ORIGIN", "null")
    with public_server("web-cors-reflect") as (url, _):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
    assert report.exit_code == 1, report.to_dict()
    assert any(
        check.code == "web.cors"
        and check.target.endswith("/hostile-origin")
        and check.outcome == "fail"
        for check in report.checks
    )


@pytest.mark.parametrize(
    "scenario,code",
    [
        ("web-weak-hsts", "web.hsts"),
        ("web-duplicate-hsts", "web.hsts"),
        ("web-missing-nosniff", "web.content_type_options"),
        ("web-bad-referrer", "web.referrer_policy"),
        ("web-bad-frame", "web.frame_options"),
        ("web-weak-csp", "web.content_security_policy"),
        ("web-broad-csp", "web.content_security_policy"),
        ("web-permissions-enabled", "web.permissions_policy"),
        ("web-permissions-duplicate-feature", "web.permissions_policy"),
        ("web-permissions-malformed", "web.permissions_policy"),
        ("web-permissions-case-drift", "web.permissions_policy"),
        ("web-permissions-invalid-extension", "web.permissions_policy"),
        ("web-permissions-duplicate-header", "web.permissions_policy"),
        ("web-bad-coop", "web.cross_origin_opener_policy"),
        ("web-malformed-coop", "web.cross_origin_opener_policy"),
        ("web-bad-coep", "web.cross_origin_embedder_policy"),
        ("web-bad-corp", "web.cross_origin_resource_policy"),
        ("web-bad-oac", "web.origin_agent_cluster"),
        ("web-cookie-flags", "web.cookies"),
        ("web-cookie-false-flags", "web.cookies"),
        ("web-cookie-empty-domain", "web.cookies"),
        ("web-cookie-duplicate", "web.cookies"),
        ("web-cookie-combined", "web.cookies"),
        ("web-cors-reflect", "web.cors"),
        ("web-cors-wildcard-credentials", "web.cors"),
        ("web-cors-duplicate", "web.cors"),
        ("web-cors-malformed", "web.cors"),
        ("web-cors-no-vary", "web.cors"),
        ("web-cors-default-port", "web.cors"),
        ("web-cors-origin-case", "web.cors"),
        ("web-cors-credentials-case", "web.cors"),
    ],
)
def test_response_security_contract_detects_declared_failures(scenario, code, monkeypatch):
    _security_environment(monkeypatch)
    with public_server(scenario) as (url, _):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
    assert report.exit_code == 1, report.to_dict()
    assert any(
        check.code == code and check.outcome == "fail" for check in report.checks
    )
    serialized = json.dumps(report.to_dict())
    assert RESPONSE_COOKIE not in serialized
    assert TRUSTED_ORIGIN not in serialized
    assert HOSTILE_ORIGIN not in serialized
    assert "unsafe-url" not in serialized


def test_public_cors_contract_can_explicitly_allow_noncredentialed_wildcard(monkeypatch):
    _security_environment(monkeypatch)
    data = secured_public_policy()
    cors = data["api"]["public_resources"][0]["response_security"]["cors"]
    cors.update(
        allow_variants=["trusted-origin", "hostile-origin"],
        deny_variants=[],
        allow_credentials=False,
        allow_wildcard=True,
    )
    with public_server("web-cors-wildcard") as (url, _):
        data["api"]["base_url"] = url
        report = Report()
        check_api(Policy.model_validate(data).api, report)
    assert report.exit_code == 0, report.to_dict()
    cors_checks = [check for check in report.checks if check.code == "web.cors"]
    assert len(cors_checks) == 2
    assert all(check.outcome == "pass" for check in cors_checks)


def test_cors_vary_wildcard_satisfies_cache_separation(monkeypatch):
    _security_environment(monkeypatch)
    with public_server("web-cors-vary-star") as (url, _):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
    assert report.exit_code == 0, report.to_dict()


@pytest.mark.parametrize(
    "vary,expected",
    [
        ("Origin", "pass"),
        ("Accept-Encoding, oRiGiN", "pass"),
        ("*", "pass"),
        ("Origin,", "pass"),
        ("Origin, @invalid", "fail"),
        ("Origin;parameter", "fail"),
        ("Accept-Encoding", "fail"),
        ("," * 33 + "Origin", "fail"),
    ],
)
def test_cors_vary_requires_a_bounded_valid_field_name_list(vary, expected):
    contract = CORSContract(allow_variants=["trusted"], allow_credentials=True)
    [(code, outcome, _)] = cors_results(
        contract,
        "trusted",
        {"Origin": TRUSTED_ORIGIN},
        httpx.Headers(
            {
                "Access-Control-Allow-Origin": TRUSTED_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
                "Vary": vary,
            }
        ),
    )
    assert code == "web.cors"
    assert outcome == expected


def test_unknown_cookie_flag_does_not_hide_declared_attributes(monkeypatch):
    _security_environment(monkeypatch)
    with public_server("web-cookie-partitioned") as (url, _):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
    assert report.exit_code == 0, report.to_dict()


@pytest.mark.parametrize(
    "value,expected",
    [
        ("session=synthetic; HttpOnly; Partitioned", "fail"),
        ("session=synthetic; Secure; HttpOnly; Partitioned", "pass"),
        ("session=synthetic; Secure; HttpOnly; Partitioned=true", "fail"),
    ],
)
def test_partitioned_cookie_must_be_valueless_and_secure(value, expected):
    contract = ResponseCookieContract(name="session", http_only=True)
    [(code, outcome, _)] = cookie_results(
        [contract], httpx.Headers({"Set-Cookie": value})
    )
    assert code == "web.cookies"
    assert outcome == expected


@pytest.mark.parametrize(
    "name,attributes",
    [
        ("__Http-session", {"secure": True, "http_only": False}),
        (
            "__Host-Http-session",
            {"secure": True, "http_only": False, "host_only": True, "path": "/"},
        ),
    ],
)
def test_http_cookie_prefixes_require_httponly(name, attributes):
    with pytest.raises(ValidationError):
        ResponseCookieContract(name=name, **attributes)


def test_http_cookie_prefixes_accept_their_complete_invariants():
    assert ResponseCookieContract(
        name="__Http-session", secure=True, http_only=True
    )
    assert ResponseCookieContract(
        name="__Host-Http-session",
        secure=True,
        http_only=True,
        host_only=True,
        path="/",
    )


def test_response_security_finding_retests_with_the_same_header_controls(monkeypatch):
    _security_environment(monkeypatch)
    with public_server("web-weak-hsts") as (url, requests):
        config = Policy.model_validate(secured_public_policy(url)).api
        original = Report()
        check_api(config, original)
        finding = next(
            item for item in original.finding_groups() if item["code"] == "web.hsts"
        )
        requests.active_scenario = "web-safe"
        requests.clear()
        verdict, result = run_retest(
            config,
            original.to_dict(),
            finding["finding_id"],
            change_ref="deploy:web-response-security",
        )
    assert verdict == "fixed", result
    assert len(requests) == 3
    assert result["report"]["exit_code"] == 0


def test_scan_attributes_response_security_failure_to_live_get_stage(tmp_path, monkeypatch):
    _security_environment(monkeypatch)
    with public_server("web-missing-nosniff") as (url, _):
        report = Report()
        run_scan(
            Policy.model_validate(secured_public_policy(url)),
            tmp_path,
            report,
        )
    assert report.exit_code == 1
    assert report.scan["stages"]["live_get_checks"]["status"] == "fail"


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


def test_public_schema_cannot_pass_a_number_rounded_to_another_integer(monkeypatch):
    monkeypatch.setenv("PP_ATTACKER_COOKIE", ATTACKER_COOKIE)
    data = public_policy()
    schema = data["api"]["public_resources"][0]["response_schema"]
    schema["required"].append("sequence")
    schema["properties"]["sequence"] = {"const": 9007199254740992}
    with public_server("rounded-number") as (url, _):
        data["api"]["base_url"] = url
        report = Report()
        check_api(Policy.model_validate(data).api, report)
    assert report.exit_code == 1, report.to_dict()
    assert any(
        check.code == "data.schema" and check.outcome == "fail"
        for check in report.checks
    )


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


def test_public_delivery_error_is_inconclusive(monkeypatch):
    monkeypatch.setenv("PP_ATTACKER_COOKIE", ATTACKER_COOKIE)

    async def failed_delivery(*_args, **_kwargs):
        raise OSError("synthetic transport failure")

    monkeypatch.setattr(api_module, "fetch", failed_delivery)
    report = Report()
    check_api(Policy.model_validate(public_policy()).api, report)

    assert report.exit_code == 2
    assert len(report.evidence) == 2
    assert all(
        evidence.delivery == "failed" and evidence.observed == "unknown"
        for evidence in report.evidence.values()
    )
    assert all(
        check.outcome == "inconclusive"
        for check in report.checks
        if check.code == "api.delivery"
    )


def test_response_security_validation_is_stopped_by_total_budget(monkeypatch):
    data = public_policy()
    resource = data["api"]["public_resources"][0]
    resource["variants"] = [{"name": "default"}]
    resource["response_security"] = {
        "security_headers": {"content_type_options": "nosniff"}
    }
    config = Policy.model_validate(data).api
    config.validation_timeout_ms = 50

    async def immediate_response(*_args, **_kwargs):
        return 200, '{"state":"ready"}', {"Cache-Control": "no-store"}

    def expensive_security_validation(*_args, **_kwargs):
        while True:
            pass

    monkeypatch.setattr(api_module, "fetch", immediate_response)
    monkeypatch.setattr(
        public_module,
        "response_security_results",
        expensive_security_validation,
    )
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


@pytest.mark.parametrize(
    "value",
    [
        "",
        "file://local",
        "https://user@example.com",
        "https://[",
        "https://example.com:99999",
        "https://example.com?",
        "https://example.com#",
        "HTTPS://example.com",
        "https://example.com:443",
        "https://EXAMPLE.com",
        "https://bücher.example",
        "http://127.000.000.001",
        "https://example.123",
    ],
)
def test_invalid_cors_origin_sends_no_request(value, monkeypatch):
    monkeypatch.setenv("PP_TRUSTED_ORIGIN", value)
    monkeypatch.setenv("PP_HOSTILE_ORIGIN", HOSTILE_ORIGIN)
    with public_server("web-safe") as (url, requests):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
    assert not requests
    assert report.exit_code == 2
    assert any(check.code == "public.configuration" for check in report.checks)


def test_duplicate_cors_origins_send_no_request(monkeypatch):
    monkeypatch.setenv("PP_TRUSTED_ORIGIN", TRUSTED_ORIGIN)
    monkeypatch.setenv("PP_HOSTILE_ORIGIN", TRUSTED_ORIGIN)
    with public_server("web-safe") as (url, requests):
        report = Report()
        check_api(Policy.model_validate(secured_public_policy(url)).api, report)
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


def test_public_contract_rejects_ignored_format_assertion():
    data = public_policy()
    schema = data["api"]["public_resources"][0]["response_schema"]
    schema["properties"]["state"]["format"] = "uri"
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


@pytest.mark.parametrize(
    "change",
    [
        lambda resource: resource.update(response_security={}),
        lambda resource: resource["response_security"]["cors"].update(
            allow_wildcard=True
        ),
        lambda resource: resource["response_security"]["cors"][
            "deny_variants"
        ].clear(),
        lambda resource: resource["response_security"]["cors"][
            "allow_variants"
        ].append("default"),
        lambda resource: resource["response_security"]["cookies"].append(
            dict(resource["response_security"]["cookies"][0])
        ),
        lambda resource: resource["response_security"]["cookies"][0].update(
            same_site=["none"], secure=None
        ),
        lambda resource: resource["response_security"]["cookies"][0].update(
            host_only=None
        ),
        lambda resource: resource["response_security"]["security_headers"][
            "content_security_policy"
        ]["required_directives"].update({"Bad-Directive": ["'none'"]}),
        lambda resource: resource["response_security"]["security_headers"].update(
            cross_origin_opener_policy=["same-origin", "same-origin"]
        ),
        lambda resource: resource["response_security"]["security_headers"][
            "permissions_policy"
        ].update(disabled_features=["camera", "camera"]),
        lambda resource: resource["response_security"]["security_headers"][
            "permissions_policy"
        ].update(disabled_features=["Camera"]),
        lambda resource: resource["response_security"]["security_headers"].update(
            origin_agent_cluster=False
        ),
    ],
)
def test_response_security_rejects_ambiguous_contracts(change):
    data = secured_public_policy()
    resource = data["api"]["public_resources"][0]
    change(resource)
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


def test_response_security_is_digest_bound_without_changing_legacy_public_digest():
    legacy = Policy.model_validate(public_policy()).api
    secured = Policy.model_validate(secured_public_policy()).api
    assert api_contract_digest(legacy) == LEGACY_PUBLIC_DIGEST
    assert api_contract_digest(secured) != LEGACY_PUBLIC_DIGEST


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
    assert policy.api.public_resources[0].response_security is not None
