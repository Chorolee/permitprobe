"""Independent synthetic fixtures for file grants, roles and ownerless collections."""

import json
import os
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from permitprobe.api import check_api
from permitprobe.policy import Policy
from permitprobe.report import Report

ROLES = {"alice": "member", "bob": "member", "moderator": "moderator", "admin": "admin"}
COOKIES = {f"PP_{name.upper()}_COOKIE": f"session=synthetic-{name}" for name in ROLES}
DESTINATION = "https://storage.example.invalid"
SIGNED_SENTINEL = "synthetic-signed-token-do-not-report"
SCENARIOS = (
    "safe",
    "private-leak",
    "selective-owner-leak",
    "moderator-leak",
    "collection-leak",
    "cache-leak",
    "expired-auth",
    "wrong-location",
    "empty",
    "server-error",
)


def read_policy(base_url: str = "https://staging.example.invalid") -> dict:
    own = [{"role": role, "scope": "own"} for role in dict.fromkeys(ROLES.values())]
    all_members = [{"role": role, "scope": "any"} for role in dict.fromkeys(ROLES.values())]
    denial = {
        "type": "object",
        "required": ["error"],
        "additionalProperties": False,
        "properties": {"error": {"const": "denied"}},
    }
    resources = []
    for name, path, rules in [
        ("private-attachments", "/attachments/{id}/private.png", own),
        ("published-attachments", "/attachments/{id}/published.png", all_members),
        (
            "applications",
            "/applications/{id}/document.pdf",
            [
                {"role": "member", "scope": "own"},
                {"role": "moderator", "scope": "own"},
                {"role": "admin", "scope": "any"},
            ],
        ),
        (
            "verifications",
            "/verifications/{id}/document.pdf",
            [
                {"role": "member", "scope": "own"},
                {"role": "moderator", "scope": "any"},
                {"role": "admin", "scope": "any"},
            ],
        ),
    ]:
        resources.append(
            {
                "name": name,
                "path": path,
                "kind": "object",
                "owner_param": "id",
                "owner_attr": "user_id",
                "allow": rules,
                "redirect": {
                    "status": 302,
                    "origin": DESTINATION,
                    "path": "/signed" + path,
                    "required_query": ["token"],
                },
                "private_cache": True,
                "denial_schema": denial,
            }
        )
    resources.append(
        {
            "name": "requests",
            "path": "/requests",
            "kind": "function",
            "allow": all_members,
            "collection": {
                "items_pointer": "/items",
                "item_pointer": "/id",
                "items_attr": "requests",
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
                            "required": ["id", "detail"],
                            "additionalProperties": False,
                            "properties": {"id": {"type": "string"}, "detail": {"type": "string"}},
                        },
                    }
                },
            },
            "denial_schema": denial,
        }
    )
    return {
        "version": 1,
        "api": {
            "base_url": base_url,
            "probe_victims": "all",
            "subjects": [{"name": "anon", "role": "anonymous"}]
            + [
                {
                    "name": name,
                    "role": role,
                    "cookie_env": f"PP_{name.upper()}_COOKIE",
                    "attributes": {"user_id": name},
                    "owned_items": {"requests": [f"request-{name}"]},
                }
                for name, role in ROLES.items()
            ],
            "resources": resources,
        },
    }


@contextmanager
def read_environment():
    old = {key: os.environ.get(key) for key in COOKIES}
    os.environ.update(COOKIES)
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def read_server(scenario: str = "safe"):
    class ScenarioRequests(list):
        active_scenario = scenario

    requests = ScenarioRequests()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            active_scenario = requests.active_scenario
            subject = next(
                (
                    name
                    for name in ROLES
                    if self.headers.get("Cookie") == COOKIES[f"PP_{name.upper()}_COOKIE"]
                ),
                None,
            )
            if active_scenario == "expired-auth" and subject == "alice":
                subject = None
            requests.append((subject, self.path, dict(self.headers)))
            parts = self.path.strip("/").split("/")
            status, body = 401, {"error": "denied"}
            location = None
            if subject and self.path == "/requests":
                status = 200
                items = [
                    {"id": f"request-{name}", "detail": "synthetic-private-detail"}
                    for name in ROLES
                    if name == subject or active_scenario == "collection-leak"
                ]
                if active_scenario == "empty":
                    items = []
                if active_scenario == "invalid-item-id":
                    items[0]["id"] = "\0"
                if active_scenario == "malformed-and-foreign":
                    items = [{}, {"id": "unlisted", "detail": "synthetic-private-detail"}]
                body = {"items": items}
            elif (
                subject
                and len(parts) == 3
                and parts[0] in {"attachments", "applications", "verifications"}
            ):
                section, owner, filename = parts
                allowed = owner == subject
                if section == "attachments":
                    allowed |= (
                        filename == "published.png"
                        or active_scenario == "private-leak"
                        or (
                            active_scenario == "selective-owner-leak"
                            and subject == "bob"
                            and owner == "moderator"
                            and filename == "private.png"
                        )
                        or active_scenario.startswith("grant-body-")
                    )
                elif section == "applications":
                    allowed |= subject == "admin" or (
                        subject == "moderator" and active_scenario == "moderator-leak"
                    )
                else:
                    allowed |= subject in {"moderator", "admin"}
                status = 302 if allowed else 403
                if allowed:
                    location = DESTINATION + "/signed" + self.path + "?token=" + SIGNED_SENTINEL
                    if active_scenario == "wrong-location":
                        location = location.replace(DESTINATION, "https://wrong.example.invalid")
                    if active_scenario == "wrong-object":
                        location = location.replace(f"/{owner}/", "/unrelated/")
                    if active_scenario == "login-redirect":
                        location = DESTINATION + "/login"
                    if active_scenario == "unexpected-200":
                        status, location = 200, None
            if active_scenario == "server-error" and subject:
                status, location, body = 500, None, {"error": "denied"}
            raw = b"" if status == 302 else json.dumps(body).encode()
            if status == 302 and active_scenario.startswith("grant-body-"):
                raw = (
                    b"\xff"
                    if active_scenario != "grant-body-oversize"
                    else b"x" * 100_000
                )
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Content-Length",
                str(
                    len(raw)
                    + (
                        100
                        if active_scenario == "grant-body-interrupted" and status == 302
                        else 0
                    )
                ),
            )
            if location:
                self.send_header("Location", location)
                if active_scenario == "duplicate-location":
                    self.send_header("Location", location)
                self.send_header(
                    "Cache-Control",
                    "public, max-age=60"
                    if active_scenario == "cache-leak"
                    else "private, max-age=60",
                )
                self.send_header("Vary", "Cookie")
                if active_scenario == "grant-body-encoded":
                    self.send_header("Content-Encoding", "gzip")
            self.send_header("Set-Cookie", "injected=never-reuse; Path=/")
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


def run_read_demo(scenario: str) -> Report:
    report = Report()
    with read_server(scenario) as (url, _), read_environment():
        check_api(Policy.model_validate(read_policy(url)).api, report)
    return report
