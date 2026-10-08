"""Synthetic linked API/storage fixtures for anonymous and same-origin reads."""

import json
import os
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from permitprobe.api import check_api
from permitprobe.policy import Policy
from permitprobe.report import Report

TOKENS = {
    "PP_LINKED_ALICE_TOKEN": "synthetic-linked-alice",
    "PP_LINKED_BOB_COOKIE": "session=synthetic-linked-bob",
}
PRIVATE_BODY = "synthetic-linked-private-body-never-report"
REDIRECT_SENTINEL = "synthetic-linked-redirect-never-follow"
SCENARIOS = (
    "safe",
    "public-leak",
    "source-missing",
    "redirect",
    "server-error",
    "authenticated-safe",
    "authenticated-leak",
)


def linked_policy(
    base_url: str = "https://api.example.invalid",
    storage_origin: str = "https://objects.example.invalid",
    authentication: str = "anonymous",
) -> dict:
    denial = {
        "type": "object",
        "required": ["error"],
        "additionalProperties": False,
        "properties": {"error": {"const": "denied"}},
    }
    return {
        "version": 1,
        "api": {
            "base_url": base_url,
            "subjects": [
                {"name": "anon", "role": "anonymous"},
                {
                    "name": "alice",
                    "role": "member",
                    "token_env": "PP_LINKED_ALICE_TOKEN",
                    "attributes": {"document_id": "alice"},
                },
                {
                    "name": "bob",
                    "role": "member",
                    "cookie_env": "PP_LINKED_BOB_COOKIE",
                    "attributes": {"document_id": "bob"},
                },
            ],
            "resources": [
                {
                    "name": "private-documents",
                    "path": "/documents/{id}",
                    "kind": "object",
                    "owner_param": "id",
                    "owner_attr": "document_id",
                    "identity_pointer": "/id",
                    "allow": [{"role": "member", "scope": "own"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["id", "title"],
                        "additionalProperties": False,
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                        },
                    },
                    "denial_schema": denial,
                }
            ],
            "linked_resources": [
                {
                    "name": "direct-private-documents",
                    "source_resource": "private-documents",
                    "origin": base_url if authentication == "source_subjects" else storage_origin,
                    "path": (
                        "/alternate/{id}.pdf"
                        if authentication == "source_subjects"
                        else "/objects/{id}.pdf"
                    ),
                    "authentication": authentication,
                    "denial_statuses": [403, 404],
                }
            ],
        },
    }


@contextmanager
def linked_environment():
    previous = {name: os.environ.get(name) for name in TOKENS}
    os.environ.update(TOKENS)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextmanager
def linked_servers(scenario: str = "safe"):
    class ScenarioRequests(list):
        active_scenario = scenario

    class APIRequests(list):
        pass

    api_requests = APIRequests()
    api_requests.linked_requests = []
    storage_requests = ScenarioRequests()

    class APIHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            subject = "alice" if token == TOKENS["PP_LINKED_ALICE_TOKEN"] else None
            if self.headers.get("Cookie") == TOKENS["PP_LINKED_BOB_COOKIE"]:
                subject = "bob"
            owner = self.path.rsplit("/", 1)[-1]
            if self.path.startswith("/alternate/"):
                owner = owner.removesuffix(".pdf")
                api_requests.linked_requests.append((subject, self.path, dict(self.headers)))
                active = storage_requests.active_scenario
                allowed = active == "authenticated-public-leak" or (
                    subject is not None
                    and (
                        active == "authenticated-leak"
                        or (subject == owner and active != "authenticated-deny-all")
                    )
                )
                status = 200 if allowed else 403
                raw = PRIVATE_BODY.encode() if allowed else b"denied"
                self.send_response(status)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Length",
                    str(len(raw) + (100 if allowed else 0)),
                )
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            api_requests.append((subject, self.path, dict(self.headers)))
            allowed = subject is not None and subject == owner
            if (
                storage_requests.active_scenario == "source-missing"
                and subject == owner == "alice"
            ):
                allowed = False
            status = 200 if allowed else 403
            body = (
                {"id": owner, "title": "Synthetic private document"}
                if allowed
                else {"error": "denied"}
            )
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    class StorageHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            storage_requests.append((self.path, dict(self.headers)))
            active = storage_requests.active_scenario
            status = 404
            raw = b"not found"
            if active == "public-leak":
                status = 200
                raw = PRIVATE_BODY.encode()
            elif active == "redirect":
                status = 302
                raw = b""
            elif active == "server-error":
                status = 500
                raw = b"server error"
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header(
                "Content-Length",
                str(len(raw) + (100 if active == "public-leak" else 0)),
            )
            self.send_header("Set-Cookie", "linked-secret=never-reuse")
            if status == 302:
                self.send_header(
                    "Location",
                    "http://127.0.0.1:1/never-follow?token=" + REDIRECT_SENTINEL,
                )
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

    api_server = ThreadingHTTPServer(("127.0.0.1", 0), APIHandler)
    storage_server = ThreadingHTTPServer(("127.0.0.1", 0), StorageHandler)
    threads = [
        threading.Thread(target=api_server.serve_forever, daemon=True),
        threading.Thread(target=storage_server.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        yield (
            f"http://127.0.0.1:{api_server.server_port}",
            f"http://127.0.0.1:{storage_server.server_port}",
            api_requests,
            storage_requests,
        )
    finally:
        api_server.shutdown()
        storage_server.shutdown()
        api_server.server_close()
        storage_server.server_close()
        for thread in threads:
            thread.join(timeout=5)


def run_linked_demo(scenario: str) -> Report:
    report = Report()
    with linked_servers(scenario) as (api, storage, _, _), linked_environment():
        authentication = (
            "source_subjects" if scenario.startswith("authenticated-") else "anonymous"
        )
        check_api(
            Policy.model_validate(linked_policy(api, storage, authentication)).api,
            report,
        )
    return report
