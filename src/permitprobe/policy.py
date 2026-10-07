"""Small, strict JSON contract. Credentials are environment references, never literals."""

import ipaddress
import json
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

NAME = r"^[A-Za-z][A-Za-z0-9_-]{0,63}$"
ENV = r"^[A-Z][A-Z0-9_]{0,127}$"
ID_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.~-]{0,127}$")
MAX_POLICY_BYTES = 1_000_000


class PolicyError(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Subject(Strict):
    name: str = Field(pattern=NAME)
    role: str = Field(pattern=NAME)
    token_env: str | None = Field(default=None, pattern=ENV)
    attributes: dict[str, str] = Field(default_factory=dict)
    marker: str | None = Field(default=None, min_length=1, max_length=128)


class Allow(Strict):
    role: str = Field(pattern=NAME)
    scope: Literal["own", "any"] = "any"


class Resource(Strict):
    name: str = Field(pattern=NAME)
    path: str = Field(min_length=1, max_length=512)
    kind: Literal["object", "function"] = "object"
    owner_param: str | None = Field(default=None, pattern=NAME)
    owner_attr: str | None = Field(default=None, pattern=NAME)
    identity_pointer: str | None = None
    allow: list[Allow] = Field(min_length=1, max_length=16)
    response_schema: dict
    denial_schema: dict

    @model_validator(mode="after")
    def valid(self):
        if (
            not re.fullmatch(r"/[A-Za-z0-9_/{\}.~-]*", self.path)
            or "//" in self.path
            or any(p in (".", "..") for p in self.path.split("/"))
        ):
            raise ValueError("path must be origin-relative without traversal, query or encoding")
        params = re.findall(r"\{([^}]+)\}", self.path)
        if self.kind == "object":
            if not self.owner_param or not self.owner_attr or not self.identity_pointer:
                raise ValueError("object resources need ownership and response identity")
            if params != [self.owner_param]:
                raise ValueError("object path must contain exactly one owner placeholder")
            if not self.identity_pointer.startswith("/"):
                raise ValueError("identity_pointer must be a JSON pointer")
        elif params or self.owner_param or self.owner_attr or self.identity_pointer:
            raise ValueError("function resources cannot declare object ownership")
        if "{" in re.sub(r"\{[^}]+\}", "", self.path) or "}" in re.sub(r"\{[^}]+\}", "", self.path):
            raise ValueError("malformed path template")
        if self.kind == "function" and any(a.scope == "own" for a in self.allow):
            raise ValueError("own scope requires an object resource")
        try:
            for schema in (self.response_schema, self.denial_schema):
                if not schema:
                    raise ValueError("empty schema")
                Draft202012Validator.check_schema(schema)
        except Exception:
            raise ValueError("invalid or empty response JSON Schema") from None
        stack = [self.response_schema, self.denial_schema]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                if any(k in node for k in ("$ref", "$dynamicRef", "$recursiveRef")):
                    raise ValueError("v0.1 schemas must be inline; references are not resolved")
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        return self


class API(Strict):
    base_url: str
    subjects: list[Subject] = Field(min_length=3, max_length=16)
    resources: list[Resource] = Field(min_length=1, max_length=32)
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    max_response_bytes: int = Field(default=1_000_000, ge=64, le=5_000_000)
    max_cases: int = Field(default=256, ge=1, le=1024)

    @model_validator(mode="after")
    def valid(self):
        u = urlsplit(self.base_url)
        try:
            loopback = bool(u.hostname) and ipaddress.ip_address(u.hostname).is_loopback
        except ValueError:
            loopback = False
        if (
            u.scheme not in ("http", "https")
            or not u.hostname
            or u.username
            or u.password
            or u.query
            or u.fragment
            or u.path not in ("", "/")
            or (u.scheme == "http" and not loopback)
        ):
            raise ValueError("base_url must be an HTTPS origin or literal loopback HTTP origin")
        if any(ord(c) < 33 or ord(c) > 126 for c in self.base_url) or "\\" in self.base_url:
            raise ValueError("invalid origin")
        try:
            u.port
        except ValueError:
            raise ValueError("invalid origin port") from None
        if len({s.name for s in self.subjects}) != len(self.subjects):
            raise ValueError("duplicate subject")
        if len({r.name for r in self.resources}) != len(self.resources):
            raise ValueError("duplicate resource")
        anonymous = [s for s in self.subjects if s.role == "anonymous"]
        authenticated = [s for s in self.subjects if s.role != "anonymous"]
        if len(anonymous) != 1 or anonymous[0].token_env:
            raise ValueError("exactly one anonymous subject, without a token, is required")
        if any(not s.token_env for s in authenticated):
            raise ValueError("every authenticated subject needs token_env")
        if len({s.token_env for s in authenticated}) != len(authenticated):
            raise ValueError("authenticated subjects must use different token references")
        roles = {s.role for s in self.subjects}
        for r in self.resources:
            if any(a.role not in roles for a in r.allow):
                raise ValueError("policy references an unknown role")
            if r.kind == "object":
                ids = [s.attributes.get(r.owner_attr, "") for s in authenticated]
                if any(not ID_VALUE.fullmatch(i) for i in ids) or len(set(ids)) != len(ids):
                    raise ValueError("each authenticated subject needs a distinct safe object ID")
        return self


class Handoff(Strict):
    root: str = Field(min_length=1, max_length=4096)
    files: list[str] = Field(min_length=1, max_length=256)
    allow: list[str] = Field(min_length=1, max_length=64)
    deny: list[str] = Field(default_factory=list, max_length=64)
    max_file_bytes: int = Field(default=1_000_000, ge=1, le=5_000_000)
    max_total_bytes: int = Field(default=10_000_000, ge=1, le=50_000_000)

    @model_validator(mode="after")
    def valid(self):
        if len(set(self.files)) != len(self.files):
            raise ValueError("duplicate handoff file")
        if any(
            not p or len(p) > 1024 or any(ord(c) < 32 for c in p)
            for p in [*self.files, *self.allow, *self.deny]
        ):
            raise ValueError("invalid handoff path or pattern")
        return self


class Policy(Strict):
    version: Literal[1]
    api: API | None = None
    handoff: Handoff | None = None

    @model_validator(mode="after")
    def valid(self):
        if not self.api and not self.handoff:
            raise ValueError("at least one surface must be configured")
        return self


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def load_policy(path: Path) -> Policy:
    try:
        with path.open("rb") as f:
            raw = f.read(MAX_POLICY_BYTES + 1)
        if len(raw) > MAX_POLICY_BYTES:
            raise PolicyError("policy is too large")
        data = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(data, dict) or type(data.get("version")) is not int:
            raise PolicyError("policy version must be the integer 1")
        return Policy.model_validate(data)
    except ValidationError as e:
        # Pydantic's normal error includes input values, possibly pasted credentials.
        locations = sorted(
            {".".join(map(str, item["loc"])) or "policy" for item in e.errors(include_input=False)}
        )
        raise PolicyError("invalid policy at: " + ", ".join(locations)) from None
    except PolicyError:
        raise
    except (OSError, ValueError, RecursionError):
        raise PolicyError("cannot read a valid UTF-8 JSON policy") from None
