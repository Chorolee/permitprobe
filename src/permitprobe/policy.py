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


def origin_key(value: str) -> tuple[str, str, int]:
    u = urlsplit(value)
    try:
        loopback = bool(u.hostname) and ipaddress.ip_address(u.hostname).is_loopback
    except ValueError:
        loopback = False
    if (
        u.scheme not in ("http", "https")
        or not u.hostname
        or "@" in u.netloc
        or u.query
        or u.fragment
        or u.path not in ("", "/")
        or (u.scheme == "http" and not loopback)
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
        or "\\" in value
        or "%" in u.netloc
        or u.netloc.endswith(":")
        or "?" in value
        or "#" in value
        or u.port == 0
    ):
        raise ValueError("expected an HTTPS origin or literal loopback HTTP origin")
    return u.scheme, u.hostname.lower(), u.port or (443 if u.scheme == "https" else 80)


def path_params(path: str) -> list[str]:
    if (
        not re.fullmatch(r"/[A-Za-z0-9_/{\}.~-]*", path)
        or "//" in path
        or any(p in (".", "..") for p in path.split("/"))
        or any(c in re.sub(r"\{[^}]+\}", "", path) for c in "{}")
    ):
        raise ValueError("path must be origin-relative without traversal, query or encoding")
    return re.findall(r"\{([^}]+)\}", path)


class PolicyError(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Subject(Strict):
    name: str = Field(pattern=NAME)
    role: str = Field(pattern=NAME)
    token_env: str | None = Field(default=None, pattern=ENV)
    cookie_env: str | None = Field(default=None, pattern=ENV)
    attributes: dict[str, str] = Field(default_factory=dict)
    owned_items: dict[str, list[str]] = Field(default_factory=dict, max_length=32)
    marker: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def valid(self):
        for name, ids in self.owned_items.items():
            if (
                not re.fullmatch(NAME, name)
                or not 1 <= len(ids) <= 256
                or any(not ID_VALUE.fullmatch(i) for i in ids)
                or len(ids) != len(set(ids))
            ):
                raise ValueError("owned_items requires named, nonempty distinct safe ID lists")
        return self


class Allow(Strict):
    role: str = Field(pattern=NAME)
    scope: Literal["own", "any"] = "any"


def valid_pointer(pointer: str) -> bool:
    return bool(re.fullmatch(r"(?:/(?:[^~/]|~[01])*)*", pointer))


class Collection(Strict):
    items_pointer: str = Field(max_length=512)
    owner_pointer: str | None = Field(default=None, min_length=1, max_length=512)
    owner_attr: str | None = Field(default=None, pattern=NAME)
    item_pointer: str | None = Field(default=None, max_length=512)
    items_attr: str | None = Field(default=None, pattern=NAME)

    @model_validator(mode="after")
    def valid(self):
        owner = self.owner_pointer is not None and self.owner_attr is not None
        items = self.item_pointer is not None and self.items_attr is not None
        if (
            owner == items
            or (owner and (self.item_pointer is not None or self.items_attr is not None))
            or (items and (self.owner_pointer is not None or self.owner_attr is not None))
        ):
            raise ValueError("collection needs exactly one complete ownership mode")
        if any(
            not valid_pointer(p)
            for p in (self.items_pointer, self.owner_pointer, self.item_pointer)
            if p is not None
        ):
            raise ValueError("collection locations must be JSON pointers")
        return self


class Redirect(Strict):
    status: Literal[302, 303, 307, 308] = 302
    origin: str = Field(max_length=512)
    path: str = Field(min_length=1, max_length=512)
    required_query: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def valid(self):
        origin_key(self.origin)
        path_params(self.path)
        if any(not re.fullmatch(NAME, key) for key in self.required_query) or len(
            set(self.required_query)
        ) != len(self.required_query):
            raise ValueError("redirect query names must be safe and distinct")
        return self


class Resource(Strict):
    name: str = Field(pattern=NAME)
    path: str = Field(min_length=1, max_length=512)
    kind: Literal["object", "function"] = "object"
    owner_param: str | None = Field(default=None, pattern=NAME)
    owner_attr: str | None = Field(default=None, pattern=NAME)
    identity_pointer: str | None = None
    collection: Collection | None = None
    redirect: Redirect | None = None
    private_cache: bool = False
    allow: list[Allow] = Field(min_length=1, max_length=16)
    response_schema: dict | None = None
    denial_schema: dict

    @model_validator(mode="after")
    def valid(self):
        params = path_params(self.path)
        if self.kind == "object":
            if not self.owner_param or not self.owner_attr:
                raise ValueError("object resources need ownership")
            if params != [self.owner_param]:
                raise ValueError("object path must contain exactly one owner placeholder")
            if not self.redirect and (
                not self.identity_pointer or not valid_pointer(self.identity_pointer)
            ):
                raise ValueError("identity_pointer must be a JSON pointer")
        elif params or self.owner_param or self.owner_attr or self.identity_pointer:
            raise ValueError("function resources cannot declare object ownership")
        if self.redirect:
            if (
                self.kind != "object"
                or self.identity_pointer is not None
                or self.response_schema is not None
                or path_params(self.redirect.path) != [self.owner_param]
            ):
                raise ValueError(
                    "redirect resources need the same owner placeholder and no JSON success contract"
                )
        elif self.response_schema is None:
            raise ValueError("JSON resources need a response schema")
        if self.private_cache and any(a.role == "anonymous" for a in self.allow):
            raise ValueError("private_cache requires a protected resource")
        if self.kind == "function" and any(a.scope == "own" for a in self.allow):
            raise ValueError("own scope requires an object resource")
        if self.collection and (
            self.kind != "function" or any(a.role == "anonymous" for a in self.allow)
        ):
            raise ValueError("collection rules require a protected function resource")
        try:
            for schema in (self.response_schema, self.denial_schema):
                if schema is None:
                    continue
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
    # Additional fully contracted surfaces authorized for the active explorer.
    # Ordinary `check` ignores them; `explore` exposes them as bounded capabilities.
    exploration_resources: list[Resource] = Field(default_factory=list, max_length=32)
    # Probe every declared owner by default. A single representative victim can
    # miss a conditional authorization bug that affects only one owner pair.
    probe_victims: Literal["one", "all"] = "all"
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    max_response_bytes: int = Field(default=1_000_000, ge=64, le=5_000_000)
    max_cases: int = Field(default=256, ge=1, le=1024)

    @model_validator(mode="after")
    def valid(self):
        origin_key(self.base_url)
        if len({s.name for s in self.subjects}) != len(self.subjects):
            raise ValueError("duplicate subject")
        all_resources = [*self.resources, *self.exploration_resources]
        if len({r.name for r in all_resources}) != len(all_resources):
            raise ValueError("duplicate resource")
        anonymous = [s for s in self.subjects if s.role == "anonymous"]
        authenticated = [s for s in self.subjects if s.role != "anonymous"]
        if len(anonymous) != 1 or anonymous[0].token_env or anonymous[0].cookie_env:
            raise ValueError("exactly one anonymous subject, without credentials, is required")
        if any(bool(s.token_env) == bool(s.cookie_env) for s in authenticated):
            raise ValueError("each authenticated subject needs exactly one credential reference")
        if len({s.token_env or s.cookie_env for s in authenticated}) != len(authenticated):
            raise ValueError("authenticated subjects must use different credential references")
        roles = {s.role for s in self.subjects}
        for r in all_resources:
            if any(a.role not in roles for a in r.allow):
                raise ValueError("policy references an unknown role")
            if r.kind == "object":
                ids = [s.attributes.get(r.owner_attr, "") for s in authenticated]
                if any(not ID_VALUE.fullmatch(i) for i in ids) or len(set(ids)) != len(ids):
                    raise ValueError("each authenticated subject needs a distinct safe object ID")
            if r.collection and r.collection.owner_attr:
                owners = [s.attributes.get(r.collection.owner_attr, "") for s in authenticated]
                if any(not ID_VALUE.fullmatch(i) for i in owners) or len(set(owners)) != len(
                    owners
                ):
                    raise ValueError("each authenticated subject needs a distinct collection owner")
            if r.collection and r.collection.items_attr:
                ids = []
                for s in authenticated:
                    owned = s.owned_items.get(r.collection.items_attr)
                    if not owned:
                        raise ValueError("each authenticated subject needs seeded collection IDs")
                    ids.extend(owned)
                if len(ids) != len(set(ids)):
                    raise ValueError("collection item IDs must be disjoint across subjects")
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
