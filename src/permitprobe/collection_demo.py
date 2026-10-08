"""Synthetic private-collection fixture, independent of any service implementation."""

import json
import os
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from permitprobe.api import check_api
from permitprobe.policy import Policy
from permitprobe.report import Report

DEMO_COOKIES = {
    "PP_ALICE_COOKIE": "session=synthetic-alice; theme=light",
    "PP_BOB_COOKIE": "session=synthetic-bob; theme=light",
}


def collection_policy(base_url: str = "https://staging.example.invalid") -> dict:
    return {
        "version": 1,
        "api": {
            "base_url": base_url,
            "probe_victims": "all",
            "subjects": [
                {"name": "anon", "role": "anonymous"},
                *[
                    {
                        "name": name,
                        "role": "user",
                        "cookie_env": f"PP_{name.upper()}_COOKIE",
                        "attributes": {"user_id": name},
                    }
                    for name in ("alice", "bob")
                ],
            ],
            "resources": [
                {
                    "name": "saved-searches",
                    "kind": "function",
                    "path": "/saved-searches",
                    "allow": [{"role": "user", "scope": "any"}],
                    "collection": {
                        "items_pointer": "/items",
                        "owner_pointer": "/ownerId",
                        "owner_attr": "user_id",
                    },
                    "response_schema": {
                        "type": "object",
                        "required": ["items"],
                        "additionalProperties": False,
                        "properties": {
                            "items": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["id", "ownerId", "name"],
                                    "additionalProperties": False,
                                    "properties": {
                                        "id": {"type": "string"},
                                        "ownerId": {"type": "string"},
                                        "name": {"type": "string"},
                                    },
                                },
                            }
                        },
                    },
                    "denial_schema": {
                        "type": "object",
                        "required": ["error"],
                        "additionalProperties": False,
                        "properties": {"error": {"const": "denied"}},
                    },
                }
            ],
        },
    }


@contextmanager
def collection_server(scenario: str = "safe"):
    requests = []
    rows = [
        {"id": f"search-{name}", "ownerId": name, "name": "Synthetic saved search"}
        for name in ("alice", "bob")
    ]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            subject = next(
                (
                    name
                    for name in ("alice", "bob")
                    if self.headers.get("Cookie") == DEMO_COOKIES[f"PP_{name.upper()}_COOKIE"]
                    or self.headers.get("Authorization") == f"Bearer synthetic-{name}"
                ),
                None,
            )
            if scenario in ("expired", "leaky-and-expired") and subject == "alice":
                subject = None
            requests.append((subject, self.path, dict(self.headers)))
            status = 200 if subject or scenario == "anonymous-leak" else 401
            if self.path != "/saved-searches":
                status = 404
            if scenario == "server-error" and subject:
                status = 500
            items = [row.copy() for row in rows if row["ownerId"] == subject]
            if scenario in ("leaky", "anonymous-leak", "leaky-and-expired"):
                items = [row.copy() for row in rows]
            if scenario == "empty":
                items = []
            if scenario == "malformed-and-foreign":
                items = [{}, {"id": "foreign", "ownerId": "third-user", "name": "Synthetic"}]
            body = {"items": items} if status == 200 else {"error": "denied"}
            raw = json.dumps(body).encode()
            if scenario == "duplicate-owner" and status == 200:
                raw = raw.replace(b'"ownerId":', b'"ownerId": "foreign", "ownerId":', 1)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Set-Cookie", "injected=must-not-be-reused; Path=/")
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def collection_environment():
    old = {key: os.environ.get(key) for key in DEMO_COOKIES}
    os.environ.update(DEMO_COOKIES)
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def run_collection_demo(scenario: str) -> Report:
    report = Report()
    with collection_server(scenario) as (url, _), collection_environment():
        check_api(Policy.model_validate(collection_policy(url)).api, report)
    return report
