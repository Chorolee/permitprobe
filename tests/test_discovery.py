import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from pydantic import ValidationError

from permitprobe.cli import main
from permitprobe.demo import example_policy
from permitprobe.discovery import discover
from permitprobe.policy import Policy, api_contract_digest
from permitprobe.report import Report


@contextmanager
def discovery_server(routes):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            path = urlsplit(self.path).path
            response = routes.get(path, (404, "text/plain", "absent", {}))
            if callable(response):
                host, port = self.server.server_address
                response = response(f"http://{host}:{port}")
            status, content_type, body, headers = response
            encoded = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", requests
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def policy_with_discovery(base_url, **overrides):
    data = example_policy(base_url)
    data["api"]["discovery"] = {
        "seed_paths": ["/"],
        "include_robots": True,
        "include_sitemap": True,
        "max_candidates": 32,
        "max_response_bytes": 16_384,
        "timeout_seconds": 1,
        **overrides,
    }
    return Policy.model_validate(data)


def public_scan_policy(base_url, *, handoff=False):
    data = {
        "version": 1,
        "api": {
            "base_url": base_url,
            "timeout_seconds": 1,
            "discovery": {
                "seed_paths": ["/"],
                "include_robots": False,
                "include_sitemap": False,
                "timeout_seconds": 1,
            },
            "public_resources": [
                {
                    "name": "health",
                    "path": "/health",
                    "expected_statuses": [200],
                    "max_elapsed_ms": 500,
                }
            ],
        },
    }
    if handoff:
        data["handoff"] = {"root": ".", "files": ["review.txt"], "allow": ["*.txt"]}
    return data


def test_discovery_proposes_sanitized_candidates_without_fetching_them(monkeypatch):
    secret_query = "synthetic-query-value-must-not-survive"
    opaque_path = "A7f9Q2m8K4v6N3x1R5t0Z9y8"
    secret_cookie = "response-cookie-must-not-survive"
    short_secret = "aB3dE5fG7h"
    person_name = "jane-smith"
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")

    def root(_):
        return (
            200,
            "text/html; charset=utf-8",
            f"""
            <a href="/documents/alice?view=summary&token={secret_query}">declared</a>
            <a href="/admin?token={secret_query}">candidate</a>
            <a href="/reset/{opaque_path}">sensitive path</a>
            <a href="/reset/{short_secret}">short sensitive path</a>
            <a href="/users/{person_name}">person path</a>
            <a href="https://outside.example.invalid/foreign">external</a>
            <form method="post" action="/admin/delete">write</form>
            """,
            {"Set-Cookie": f"session={secret_cookie}"},
        )

    def robots(base):
        return (
            200,
            "text/plain",
            f"Allow: /documents/bob\nDisallow: /private\nSitemap: {base}/nested.xml\n",
            {},
        )

    def sitemap(base):
        return (
            200,
            "application/xml",
            (
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f"<url><loc>{base}/documents/alice</loc></url>"
                f"<url><loc>{base}/billing</loc></url>"
                "</urlset>"
            ),
            {},
        )

    with discovery_server({"/": root, "/robots.txt": robots, "/sitemap.xml": sitemap}) as (
        url,
        requests,
    ):
        report = Report()
        discover(policy_with_discovery(url).api, report)

    assert [urlsplit(path).path for path, _ in requests] == [
        "/",
        "/robots.txt",
        "/sitemap.xml",
    ]
    assert all("Authorization" not in headers and "Cookie" not in headers for _, headers in requests)
    assert all(headers["Accept-Encoding"] == "identity" for _, headers in requests)
    payload = report.to_dict()
    serialized = json.dumps(payload)
    assert secret_query not in serialized
    assert opaque_path not in serialized
    assert secret_cookie not in serialized
    assert short_secret not in serialized
    assert person_name not in serialized
    assert "outside.example.invalid" not in serialized
    assert payload["discovery"]["sources"] == {
        "configured": 3,
        "planned": 3,
        "attempted": 3,
        "completed": 3,
        "failed": 0,
        "items": [
            {
                "path": "/",
                "kinds": ["html"],
                "delivery": "complete",
                "http_status": 200,
                "outcome": "pass",
            },
            {
                "path": "/robots.txt",
                "kinds": ["robots"],
                "delivery": "complete",
                "http_status": 200,
                "outcome": "pass",
            },
            {
                "path": "/sitemap.xml",
                "kinds": ["sitemap"],
                "delivery": "complete",
                "http_status": 200,
                "outcome": "pass",
            },
        ],
    }
    counts = payload["discovery"]["candidates"]
    assert counts["out_of_scope"] == 1
    assert counts["declared"] == 2
    assert counts["unsupported_method"] == 1
    assert payload["discovery"]["discovered_requests_executed"] == 0
    proposals = counts["proposals"]
    assert any(
        item["path_shape"] == "/documents/{value}"
        and item["classification"] == "declared"
        and item["policy_resources"] == ["documents"]
        for item in proposals
    )
    assert any(
        item["path_shape"] == "/{value}/{value}"
        and item["classification"] == "candidate"
        and item["observed_variants"] >= 3
        for item in proposals
    )
    assert any(
        item["method"] == "POST" and item["classification"] == "unsupported_method"
        for item in proposals
    )
    assert any(
        item["query_names"] == [] and item["redacted_query_names"] == 1
        for item in proposals
    )
    assert any(check.code == "discovery.undeclared" for check in report.checks)
    assert report.exit_code == 1


def test_optional_robots_and_sitemap_404_are_complete():
    with discovery_server({"/": (200, "text/html", "<html></html>", {})}) as (url, _):
        report = Report()
        discover(policy_with_discovery(url).api, report)
    assert report.exit_code == 0
    assert report.discovery["sources"]["completed"] == 3
    assert report.discovery["candidates"]["total"] == 0


@pytest.mark.parametrize(
    "body,headers",
    [
        ("x" * 1_025, {}),
        ("not-compressed", {"Content-Encoding": "gzip"}),
    ],
)
def test_discovery_response_limits_fail_closed(body, headers):
    with discovery_server({"/": (200, "text/html", body, headers)}) as (url, _):
        report = Report()
        discover(
            policy_with_discovery(
                url,
                include_robots=False,
                include_sitemap=False,
                max_response_bytes=1_024,
            ).api,
            report,
        )
    assert report.exit_code == 2
    assert report.discovery["state"] == "incomplete"
    assert report.discovery["sources"]["failed"] == 1
    assert any(check.code == "discovery.delivery" for check in report.checks)


@pytest.mark.parametrize(
    "sitemap",
    [
        "<urlset><url><loc>broken",
        '<!DOCTYPE urlset [<!ENTITY x "unsafe">]><urlset></urlset>',
    ],
)
def test_unsupported_sitemap_is_inconclusive(sitemap):
    routes = {
        "/": (200, "text/html", "", {}),
        "/robots.txt": (404, "text/plain", "", {}),
        "/sitemap.xml": (200, "application/xml", sitemap, {}),
    }
    with discovery_server(routes) as (url, _):
        report = Report()
        discover(policy_with_discovery(url).api, report)
    assert report.exit_code == 2
    assert any(check.code == "discovery.parse" for check in report.checks)


def test_candidate_limit_is_inconclusive():
    body = '<a href="/one">one</a><a href="/two">two</a>'
    with discovery_server({"/": (200, "text/html", body, {})}) as (url, requests):
        report = Report()
        discover(
            policy_with_discovery(
                url,
                include_robots=False,
                include_sitemap=False,
                max_candidates=1,
                report_path_literals=["one", "two"],
            ).api,
            report,
        )
    assert [path for path, _ in requests] == ["/"]
    assert report.exit_code == 2
    assert report.discovery["candidates"]["total"] == 1
    assert report.discovery["candidates"]["truncated"] == 1
    assert any(check.code == "discovery.limit" for check in report.checks)


def test_redirect_is_proposed_without_following():
    routes = {"/": (302, "text/plain", "", {"Location": "/landing"})}
    with discovery_server(routes) as (url, requests):
        report = Report()
        discover(
            policy_with_discovery(url, include_robots=False, include_sitemap=False).api,
            report,
        )
    assert [path for path, _ in requests] == ["/"]
    assert report.discovery["candidates"]["proposals"][0]["path_shape"] == "/{value}"
    assert report.exit_code == 1


def test_one_shot_counts_fixed_sources_and_declared_checks(tmp_path, capsys):
    routes = {
        "/": (200, "text/html", '<a href="/health">health</a>', {}),
        "/health": (200, "application/json", "{}", {}),
    }
    with discovery_server(routes) as (url, requests):
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(public_scan_policy(url)))
        assert main(["scan", str(policy_path), "--format", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
    assert [path for path, _ in requests] == ["/", "/health"]
    assert payload["scan"]["stages"]["passive_discovery"] == {
        "configured": True,
        "status": "pass",
    }
    assert payload["scan"]["requests"] == {
        "planned": 2,
        "observed": 2,
        "completed": 2,
        "failed": 0,
        "writes": 0,
    }
    assert payload["scan"]["scope"]["proposal_discovery"] is True
    assert payload["scan"]["scope"]["discovered_requests_executed"] == 0


def test_discovery_failure_does_not_skip_declared_checks(tmp_path, capsys):
    routes = {
        "/": (500, "text/plain", "temporary", {}),
        "/health": (200, "application/json", "{}", {}),
    }
    with discovery_server(routes) as (url, requests):
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(public_scan_policy(url)))
        assert main(["scan", str(policy_path), "--format", "json"]) == 2
        payload = json.loads(capsys.readouterr().out)
    assert [path for path, _ in requests] == ["/", "/health"]
    assert payload["scan"]["stages"]["passive_discovery"]["status"] == "inconclusive"
    assert payload["scan"]["stages"]["live_get_checks"]["status"] == "pass"


def test_incomplete_handoff_blocks_discovery_and_declared_requests(tmp_path, capsys):
    with discovery_server({}) as (url, requests):
        data = public_scan_policy(url, handoff=True)
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(data))
        (tmp_path / "review.txt").write_text("Synthetic review.\n")
        assert (
            main(
                [
                    "scan",
                    str(policy_path),
                    "--gitleaks",
                    "/nonexistent/permitprobe-gitleaks",
                    "--format",
                    "json",
                ]
            )
            == 2
        )
        payload = json.loads(capsys.readouterr().out)
    assert requests == []
    assert payload["discovery"]["state"] == "blocked_by_handoff"
    assert payload["scan"]["requests"]["planned"] == 0
    assert payload["scan"]["stages"]["passive_discovery"]["status"] == "inconclusive"


@pytest.mark.parametrize(
    "discovery",
    [
        {"seed_paths": ["/", "/"]},
        {"seed_paths": ["/{id}"]},
        {"seed_paths": ["/?token=value"]},
        {"seed_paths": ["/%2e%2e/private"]},
        {"seed_paths": ["/1", "/2", "/3", "/4", "/5"]},
        {"timeout_seconds": 16},
        {"max_response_bytes": 1_001},
        {"max_candidates": 513},
        {"report_path_literals": ["safe", "safe"]},
        {"report_path_literals": ["unsafe/path"]},
        {"report_query_names": ["safe", "safe"]},
        {"report_query_names": ["bad name"]},
    ],
)
def test_discovery_contract_rejects_unsafe_or_unbounded_configuration(discovery):
    data = example_policy()
    data["api"]["discovery"] = discovery
    with pytest.raises(ValidationError):
        Policy.model_validate(data)


def test_api_digest_binds_origin_but_not_operational_limits():
    first = Policy.model_validate(example_policy("https://one.example.invalid")).api
    same = Policy.model_validate(example_policy("https://ONE.example.invalid:443")).api
    other = Policy.model_validate(example_policy("https://two.example.invalid")).api
    tuned = Policy.model_validate(example_policy("https://one.example.invalid")).api
    tuned.timeout_seconds = 30
    tuned.validation_timeout_ms = 30_000
    tuned.max_response_bytes = 2_000_000
    tuned.max_cases = 512
    assert api_contract_digest(first) == api_contract_digest(same)
    assert api_contract_digest(first) == api_contract_digest(tuned)
    assert api_contract_digest(first) != api_contract_digest(other)


def test_only_policy_approved_discovery_labels_survive():
    body = '<a href="/admin/jane-smith?mode=x&secretName=y">candidate</a>'
    with discovery_server({"/": (200, "text/html", body, {})}) as (url, _):
        report = Report()
        discover(
            policy_with_discovery(
                url,
                include_robots=False,
                include_sitemap=False,
                report_path_literals=["admin"],
                report_query_names=["mode"],
            ).api,
            report,
        )
    proposal = report.discovery["candidates"]["proposals"][0]
    assert proposal["path_shape"] == "/admin/{value}"
    assert proposal["query_names"] == ["mode"]
    assert proposal["redacted_query_names"] == 1
    assert "jane-smith" not in json.dumps(report.to_dict())
    assert "secretName" not in json.dumps(report.to_dict())


def test_same_origin_linked_route_is_a_declared_discovery_template():
    body = '<a href="/objects/alice">linked</a>'
    with discovery_server({"/": (200, "text/html", body, {})}) as (url, _):
        data = example_policy(url)
        data["api"]["linked_resources"] = [
            {
                "name": "direct-documents",
                "source_resource": "documents",
                "origin": url,
                "path": "/objects/{id}",
            }
        ]
        data["api"]["discovery"] = {
            "seed_paths": ["/"],
            "include_robots": False,
            "include_sitemap": False,
        }
        report = Report()
        discover(Policy.model_validate(data).api, report)
    proposal = report.discovery["candidates"]["proposals"][0]
    assert proposal["classification"] == "declared"
    assert proposal["policy_resources"] == ["direct-documents"]
    assert proposal["path_shape"] == "/objects/{value}"


def test_published_discovery_example_is_valid():
    root = Path(__file__).resolve().parents[1]
    policy = Policy.model_validate_json((root / "examples/discovery.json").read_text())
    assert policy.api.discovery.seed_paths == ["/", "/account"]
