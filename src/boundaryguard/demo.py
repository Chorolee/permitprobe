"""Synthetic, loopback-only fixtures; no product data or live service dependency."""

import json
import os
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from boundaryguard.api import check_api
from boundaryguard.handoff import check_handoff
from boundaryguard.policy import Policy
from boundaryguard.report import Report

DEMO_TOKENS = {"BG_ALICE_TOKEN": "demo-only-alice-token", "BG_BOB_TOKEN": "demo-only-bob-token"}


def example_policy(base_url: str = "https://staging.example.invalid") -> dict:
    return {
        "version": 1,
        "api": {
            "base_url": base_url,
            "subjects": [
                {"name": "anon", "role": "anonymous"},
                {
                    "name": "alice",
                    "role": "user",
                    "token_env": "BG_ALICE_TOKEN",
                    "attributes": {"document_id": "alice"},
                    "marker": "alice",
                },
                {
                    "name": "bob",
                    "role": "user",
                    "token_env": "BG_BOB_TOKEN",
                    "attributes": {"document_id": "bob"},
                    "marker": "bob",
                },
            ],
            "resources": [
                {
                    "name": "documents",
                    "kind": "object",
                    "path": "/documents/{id}",
                    "owner_param": "id",
                    "owner_attr": "document_id",
                    "identity_pointer": "/id",
                    "allow": [{"role": "user", "scope": "own"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["id", "title"],
                        "properties": {"id": {"type": "string"}, "title": {"type": "string"}},
                        "additionalProperties": False,
                    },
                    "denial_schema": {
                        "type": "object",
                        "required": ["error"],
                        "properties": {"error": {"enum": ["denied"]}},
                        "additionalProperties": False,
                    },
                }
            ],
        },
        "handoff": {"root": ".", "files": ["review.txt"], "allow": ["*.txt", "docs/*.md"]},
    }


@contextmanager
def fixture_server(scenario: str = "safe"):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            owner = urlsplit(self.path).path.rsplit("/", 1)[-1]
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            subject = {v: k.split("_")[1].lower() for k, v in DEMO_TOKENS.items()}.get(token)
            if scenario == "expired" and subject == "alice":
                subject = None
            requests.append((subject, owner, dict(self.headers)))
            status = 200 if subject and (subject == owner or scenario == "leaky") else 403
            if scenario == "server-error" and subject and subject != owner:
                status = 500
            if scenario == "redirect" and subject and subject != owner:
                status = 302
            if scenario == "cookie" and self.headers.get("Cookie"):
                status = 200
            body = (
                {"id": owner, "title": "Synthetic document"}
                if status == 200
                else {"error": "denied"}
            )
            if scenario == "denied-leak" and status == 403:
                body["private_email"] = "synthetic@example.invalid"
            if scenario in ("leaky", "schema-leak") and status == 200:
                body["private_email"] = "synthetic@example.invalid"
            if scenario == "wrong-object" and status == 200:
                body["id"] = "unrelated"
            if scenario == "nested-leak" and status == 200:
                body["metadata"] = {"private": "synthetic-sensitive-value"}
            raw = json.dumps(body).encode()
            if scenario == "html" and status == 200:
                raw = b"<html>login page</html>"
            if scenario == "oversize" and status == 200:
                raw = b"x" * 2048
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if scenario == "cookie":
                self.send_header("Set-Cookie", "privileged=alice; Path=/")
            if status == 302:
                self.send_header("Location", "http://127.0.0.1:1/never-follow")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def demo_environment():
    old = {key: os.environ.get(key) for key in DEMO_TOKENS}
    os.environ.update(DEMO_TOKENS)
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def run_demo(scenario: str, binary: str | None = None) -> Report:
    report = Report()
    with (
        fixture_server(scenario) as (url, _),
        demo_environment(),
        tempfile.TemporaryDirectory() as tmp,
    ):
        directory = Path(tmp)
        text = "Review only these synthetic notes.\n"
        if scenario == "leaky":
            # Intentionally fake credential assembled for an actual scanner test.
            text += "github_token = '" + "ghp_" + "7Qx4Kp9Vn2Ms8Rt6Wj3Yz5Bc1Df0Ha9Lu4Se" + "'\n"
        (directory / "review.txt").write_text(text)
        policy = Policy.model_validate(example_policy(url))
        check_api(policy.api, report)
        check_handoff(policy.handoff, directory, report, binary)
    return report
