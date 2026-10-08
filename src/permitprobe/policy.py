"""Small, strict JSON contract. Credentials are environment references, never literals."""

import hashlib
import ipaddress
import json
import re
import warnings
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from permitprobe.local_files import read_bounded_regular
from permitprobe.validation import (
    MAX_JSON_NUMBER_DIGITS,
    MAX_JSON_NUMBER_EXPONENT,
    bounded_json_decimal,
    bounded_json_int,
)

NAME = r"^[A-Za-z][A-Za-z0-9_-]{0,63}$"
ENV = r"^[A-Z][A-Z0-9_]{0,127}$"
ID_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.~-]{0,127}$")
QUERY_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.~-]{0,63}$")
PUBLIC_HEADER_NAMES = {
    "cookie",
    "origin",
    "referer",
    "user-agent",
    "x-forwarded-for",
    "x-real-ip",
}
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


_SINGLE_SUBSCHEMAS = {
    "additionalProperties",
    "contains",
    "else",
    "if",
    "items",
    "not",
    "propertyNames",
    "then",
    "unevaluatedItems",
    "unevaluatedProperties",
}
_ARRAY_SUBSCHEMAS = {"allOf", "anyOf", "oneOf", "prefixItems"}
_MAPPED_SUBSCHEMAS = {"$defs", "dependentSchemas", "patternProperties", "properties"}
_UNRESOLVED_REFERENCES = {"$ref", "$dynamicRef", "$recursiveRef"}
_SUPPORTED_SCHEMA_KEYWORDS = {
    "$anchor",
    "$comment",
    "$defs",
    "$dynamicAnchor",
    "$dynamicRef",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "contains",
    "default",
    "dependentRequired",
    "dependentSchemas",
    "deprecated",
    "description",
    "else",
    "enum",
    "examples",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "format",
    "if",
    "items",
    "maxContains",
    "maxItems",
    "maxLength",
    "maxProperties",
    "maximum",
    "minContains",
    "minItems",
    "minLength",
    "minProperties",
    "minimum",
    "multipleOf",
    "not",
    "oneOf",
    "pattern",
    "patternProperties",
    "prefixItems",
    "properties",
    "propertyNames",
    "readOnly",
    "required",
    "then",
    "title",
    "type",
    "unevaluatedItems",
    "unevaluatedProperties",
    "uniqueItems",
    "writeOnly",
}
_DRAFT_2020_12_SCHEMAS = {
    "https://json-schema.org/draft/2020-12/schema",
    "https://json-schema.org/draft/2020-12/schema#",
}


def _schema_nodes(schema: dict):
    """Yield actual schema objects without treating property names or constants as keywords."""

    stack = [schema]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        yield node
        stack.extend(node[key] for key in _SINGLE_SUBSCHEMAS if key in node)
        for key in _ARRAY_SUBSCHEMAS:
            value = node.get(key)
            if isinstance(value, list):
                stack.extend(value)
        for key in _MAPPED_SUBSCHEMAS:
            value = node.get(key)
            if isinstance(value, dict):
                stack.extend(value.values())


def _check_supported_schema(schema: dict) -> None:
    for node in _schema_nodes(schema):
        if _UNRESOLVED_REFERENCES & node.keys():
            raise ValueError("response schemas must be inline; references are not resolved")
        if "format" in node:
            raise ValueError("response schema format assertions are not enforced")
        if set(node) - _SUPPORTED_SCHEMA_KEYWORDS:
            raise ValueError("response schema contains an unsupported keyword")
        dialect = node.get("$schema")
        if dialect is not None and dialect not in _DRAFT_2020_12_SCHEMAS:
            raise ValueError("response schema must use Draft 2020-12")


def _check_response_schema(schema: dict) -> None:
    # Python rejects some nonportable regular expressions outright and warns when
    # a character set has ambiguous future semantics. Neither can be an assertion.
    with warnings.catch_warnings():
        warnings.simplefilter("error", FutureWarning)
        Draft202012Validator.check_schema(schema)
    _check_supported_schema(schema)


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


class QueryParameter(Strict):
    name: str = Field(min_length=1, max_length=64)
    value: str = Field(max_length=512)

    @model_validator(mode="after")
    def valid(self):
        if not QUERY_NAME.fullmatch(self.name) or any(
            ord(char) < 32 or ord(char) == 127 for char in self.value
        ):
            raise ValueError("query parameters require a safe name and value")
        return self


class RequestVariant(Strict):
    name: str = Field(pattern=NAME)
    header_envs: dict[str, str] = Field(default_factory=dict, max_length=8)

    @model_validator(mode="after")
    def valid(self):
        lowered = [name.lower() for name in self.header_envs]
        if (
            len(lowered) != len(set(lowered))
            or any(name not in PUBLIC_HEADER_NAMES for name in lowered)
            or any(not re.fullmatch(ENV, env) for env in self.header_envs.values())
        ):
            raise ValueError("request variant headers must be allowlisted environment references")
        return self


class HSTSContract(Strict):
    min_max_age: int = Field(default=31_536_000, ge=0, le=63_072_000)
    include_subdomains: bool = False
    preload: bool = False

    @model_validator(mode="after")
    def valid(self):
        if self.preload and (not self.include_subdomains or self.min_max_age < 31_536_000):
            raise ValueError("HSTS preload requires one year and includeSubDomains")
        return self


class CSPContract(Strict):
    required_directives: dict[str, list[str]] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def valid(self):
        for name, values in self.required_directives.items():
            if (
                not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name)
                or len(values) > 32
                or len(values) != len(set(values))
                or any(
                    not 1 <= len(value) <= 256
                    or any(char.isspace() or char in ";," for char in value)
                    or any(ord(char) < 33 or ord(char) > 126 for char in value)
                    for value in values
                )
            ):
                raise ValueError("CSP directives and source tokens must be safe and distinct")
        return self


class PermissionsPolicyContract(Strict):
    disabled_features: list[str] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def valid(self):
        if len(self.disabled_features) != len(set(self.disabled_features)) or any(
            not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", feature)
            for feature in self.disabled_features
        ):
            raise ValueError("disabled Permissions-Policy features must be safe and distinct")
        return self


class SecurityHeadersContract(Strict):
    hsts: HSTSContract | None = None
    content_type_options: Literal["nosniff"] | None = None
    referrer_policy: list[
        Literal[
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        ]
    ] = Field(default_factory=list, max_length=8)
    frame_options: list[Literal["deny", "sameorigin"]] = Field(
        default_factory=list, max_length=2
    )
    content_security_policy: CSPContract | None = None
    permissions_policy: PermissionsPolicyContract | None = None
    cross_origin_opener_policy: list[
        Literal["same-origin", "same-origin-allow-popups", "noopener-allow-popups"]
    ] = Field(default_factory=list, max_length=3)
    cross_origin_embedder_policy: list[Literal["require-corp", "credentialless"]] = Field(
        default_factory=list, max_length=2
    )
    cross_origin_resource_policy: list[
        Literal["same-origin", "same-site", "cross-origin"]
    ] = Field(default_factory=list, max_length=3)
    origin_agent_cluster: Literal[True] | None = None

    @model_validator(mode="after")
    def valid(self):
        if (
            self.hsts is None
            and self.content_type_options is None
            and not self.referrer_policy
            and not self.frame_options
            and self.content_security_policy is None
            and self.permissions_policy is None
            and not self.cross_origin_opener_policy
            and not self.cross_origin_embedder_policy
            and not self.cross_origin_resource_policy
            and self.origin_agent_cluster is None
        ):
            raise ValueError("security_headers needs at least one declared response contract")
        accepted_lists = (
            self.referrer_policy,
            self.frame_options,
            self.cross_origin_opener_policy,
            self.cross_origin_embedder_policy,
            self.cross_origin_resource_policy,
        )
        if any(len(values) != len(set(values)) for values in accepted_lists):
            raise ValueError("accepted security header values must be distinct")
        return self


class ResponseCookieContract(Strict):
    name: str = Field(min_length=1, max_length=128)
    secure: bool | None = None
    http_only: bool | None = None
    same_site: list[Literal["strict", "lax", "none"]] = Field(
        default_factory=list, max_length=3
    )
    host_only: bool | None = None
    path: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def valid(self):
        if not re.fullmatch(r"[!#$%&'*+.^_`|~A-Za-z0-9-]+", self.name):
            raise ValueError("response cookie name must be an HTTP token")
        if len(self.same_site) != len(set(self.same_site)):
            raise ValueError("accepted SameSite values must be distinct")
        if self.path is not None and (
            not self.path.startswith("/")
            or any(ord(char) < 32 or ord(char) > 126 or char == ";" for char in self.path)
        ):
            raise ValueError("cookie path must be a safe absolute path")
        if "none" in self.same_site and self.secure is not True:
            raise ValueError("SameSite=None requires an explicit Secure contract")
        if self.name.startswith("__Host-") and (
            self.secure is not True or self.host_only is not True or self.path != "/"
        ):
            raise ValueError("__Host- cookies require Secure, host-only, and Path=/")
        if self.name.startswith("__Secure-") and self.secure is not True:
            raise ValueError("__Secure- cookies require Secure")
        if self.name.startswith("__Http-") and (
            self.secure is not True or self.http_only is not True
        ):
            raise ValueError("__Http- cookies require Secure and HttpOnly")
        if self.name.startswith("__Host-Http-") and self.http_only is not True:
            raise ValueError("__Host-Http- cookies also require HttpOnly")
        return self


class CORSContract(Strict):
    allow_variants: list[str] = Field(default_factory=list, max_length=8)
    deny_variants: list[str] = Field(default_factory=list, max_length=8)
    allow_credentials: bool = False
    allow_wildcard: bool = False
    require_vary_origin: bool = True

    @model_validator(mode="after")
    def valid(self):
        names = [*self.allow_variants, *self.deny_variants]
        if (
            not names
            or len(names) != len(set(names))
            or any(not re.fullmatch(NAME, name) for name in names)
            or (self.allow_credentials and self.allow_wildcard)
        ):
            raise ValueError("CORS variants must be distinct and credentials cannot use wildcard")
        return self


class ResponseSecurityContract(Strict):
    security_headers: SecurityHeadersContract | None = None
    cookies: list[ResponseCookieContract] = Field(default_factory=list, max_length=16)
    cors: CORSContract | None = None

    @model_validator(mode="after")
    def valid(self):
        if self.security_headers is None and not self.cookies and self.cors is None:
            raise ValueError("response_security needs headers, cookies, or CORS")
        names = [cookie.name for cookie in self.cookies]
        if len(names) != len(set(names)):
            raise ValueError("response cookie contracts must have distinct names")
        return self


class PublicResource(Strict):
    name: str = Field(pattern=NAME)
    path: str = Field(min_length=1, max_length=512)
    lifecycle: Literal["active", "retired"] = "active"
    query: list[QueryParameter] = Field(default_factory=list, max_length=32)
    variants: list[RequestVariant] = Field(
        default_factory=lambda: [RequestVariant(name="default")],
        min_length=1,
        max_length=8,
    )
    expected_statuses: list[int] = Field(default_factory=lambda: [200], min_length=1, max_length=16)
    max_elapsed_ms: int = Field(default=5_000, ge=1, le=30_000)
    cache: Literal["no-store"] | None = None
    response_schema: dict | None = None
    response_security: ResponseSecurityContract | None = None

    @model_validator(mode="after")
    def valid(self):
        if path_params(self.path):
            raise ValueError("public resource paths cannot contain placeholders")
        if len({variant.name for variant in self.variants}) != len(self.variants):
            raise ValueError("public request variant names must be distinct")
        if self.response_security and self.response_security.cors:
            cors = self.response_security.cors
            configured = {*cors.allow_variants, *cors.deny_variants}
            origin_variants = {
                variant.name
                for variant in self.variants
                if "origin" in {name.lower() for name in variant.header_envs}
            }
            if configured != origin_variants:
                raise ValueError("CORS must classify every and only Origin request variant")
        if (
            len(set(self.expected_statuses)) != len(self.expected_statuses)
            or any(status < 200 or status > 599 for status in self.expected_statuses)
        ):
            raise ValueError("expected statuses must be distinct HTTP final-response codes")
        if self.response_schema is not None:
            try:
                if not self.response_schema:
                    raise ValueError
                _check_response_schema(self.response_schema)
            except Exception:
                raise ValueError("invalid or empty public response JSON Schema") from None
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
                _check_response_schema(schema)
        except Exception:
            raise ValueError("invalid or empty response JSON Schema") from None
        return self


class LinkedResource(Strict):
    """Status-only alternate read tied to a protected source object."""

    name: str = Field(pattern=NAME)
    source_resource: str = Field(pattern=NAME)
    origin: str = Field(max_length=512)
    path: str = Field(min_length=1, max_length=512)
    authentication: Literal["anonymous", "source_subjects"] = "anonymous"
    denial_statuses: list[Literal[401, 403, 404, 410]] = Field(
        default_factory=lambda: [401, 403, 404],
        min_length=1,
        max_length=4,
    )

    @model_validator(mode="after")
    def valid(self):
        origin_key(self.origin)
        path_params(self.path)
        if len(set(self.denial_statuses)) != len(self.denial_statuses):
            raise ValueError("linked denial statuses must be distinct")
        return self


class Discovery(Strict):
    """Fixed anonymous sources used only to propose same-origin GET coverage."""

    seed_paths: list[str] = Field(default_factory=lambda: ["/"], min_length=1, max_length=4)
    include_robots: bool = True
    include_sitemap: bool = True
    # Only policy-approved response-derived labels may survive in reports.
    # All other path segments and query names are replaced with placeholders.
    report_path_literals: list[str] = Field(default_factory=list, max_length=128)
    report_query_names: list[str] = Field(default_factory=list, max_length=64)
    max_candidates: int = Field(default=128, ge=1, le=512)
    max_response_bytes: int = Field(default=262_144, ge=1_024, le=1_000_000)
    timeout_seconds: int = Field(default=5, ge=1, le=15)

    @model_validator(mode="after")
    def valid(self):
        if len(set(self.seed_paths)) != len(self.seed_paths):
            raise ValueError("discovery seed paths must be distinct")
        for path in self.seed_paths:
            if len(path) > 512 or path_params(path):
                raise ValueError("discovery seeds must be concrete origin-relative paths")
        if (
            len(set(self.report_path_literals)) != len(self.report_path_literals)
            or any(not ID_VALUE.fullmatch(item) for item in self.report_path_literals)
        ):
            raise ValueError("discovery report path literals must be safe and distinct")
        if (
            len(set(self.report_query_names)) != len(self.report_query_names)
            or any(not QUERY_NAME.fullmatch(item) for item in self.report_query_names)
        ):
            raise ValueError("discovery report query names must be safe and distinct")
        return self


class API(Strict):
    base_url: str
    subjects: list[Subject] = Field(default_factory=list, max_length=16)
    resources: list[Resource] = Field(default_factory=list, max_length=32)
    # Anonymous direct reads at an explicitly pinned origin. Each is tied to a
    # protected primary object whose successful self-case proves the fixture.
    linked_resources: list[LinkedResource] = Field(default_factory=list, max_length=32)
    # Anonymous GET contracts are independent of the authorization matrix. They
    # cover response integrity, browser-facing security, cache behavior and latency.
    public_resources: list[PublicResource] = Field(default_factory=list, max_length=32)
    # Additional fully contracted surfaces authorized for the active explorer.
    # Ordinary `check` ignores them; `explore` exposes them as bounded capabilities.
    exploration_resources: list[Resource] = Field(default_factory=list, max_length=32)
    # Discovery fetches only fixed anonymous sources and emits proposals. A
    # discovered location never becomes an executable request.
    discovery: Discovery | None = None
    # Probe every declared owner by default. A single representative victim can
    # miss a conditional authorization bug that affects only one owner pair.
    probe_victims: Literal["one", "all"] = "all"
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    # Total wall-clock budget for response parsing and contract validation in
    # one deterministic API/public execution batch.
    validation_timeout_ms: int = Field(default=5_000, ge=10, le=30_000)
    max_response_bytes: int = Field(default=1_000_000, ge=64, le=5_000_000)
    max_cases: int = Field(default=256, ge=1, le=1024)

    @model_validator(mode="after")
    def valid(self):
        origin_key(self.base_url)
        if not self.resources and not self.public_resources:
            raise ValueError("at least one ordinary or public resource is required")
        if self.exploration_resources and not self.resources:
            raise ValueError("exploration resources require an ordinary baseline resource")
        if self.linked_resources and not self.resources:
            raise ValueError("linked resources require an ordinary source resource")
        if len({s.name for s in self.subjects}) != len(self.subjects):
            raise ValueError("duplicate subject")
        all_resources = [*self.resources, *self.exploration_resources]
        all_names = [
            resource.name
            for resource in [*all_resources, *self.public_resources, *self.linked_resources]
        ]
        if len(set(all_names)) != len(all_names):
            raise ValueError("duplicate resource")
        if len({r.name for r in all_resources}) != len(all_resources):
            raise ValueError("duplicate resource")
        anonymous = [s for s in self.subjects if s.role == "anonymous"]
        authenticated = [s for s in self.subjects if s.role != "anonymous"]
        if all_resources:
            if len(self.subjects) < 3:
                raise ValueError("authorization resources require at least three subjects")
            if len(anonymous) != 1 or anonymous[0].token_env or anonymous[0].cookie_env:
                raise ValueError("exactly one anonymous subject, without credentials, is required")
            if any(bool(s.token_env) == bool(s.cookie_env) for s in authenticated):
                raise ValueError("each authenticated subject needs exactly one credential reference")
            if len({s.token_env or s.cookie_env for s in authenticated}) != len(authenticated):
                raise ValueError("authenticated subjects must use different credential references")
        elif self.subjects and (
            len(self.subjects) != 1
            or len(anonymous) != 1
            or anonymous[0].token_env
            or anonymous[0].cookie_env
        ):
            raise ValueError("public-only policies may omit subjects or declare one anonymous subject")
        if any(resource.max_elapsed_ms > self.timeout_seconds * 1_000 for resource in self.public_resources):
            raise ValueError("public max_elapsed_ms cannot exceed the API timeout")
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
        primary_by_name = {resource.name: resource for resource in self.resources}
        for linked in self.linked_resources:
            source = primary_by_name.get(linked.source_resource)
            if (
                source is None
                or source.kind != "object"
                or any(rule.role == "anonymous" for rule in source.allow)
                or path_params(linked.path) != [source.owner_param]
                or (
                    linked.authentication == "source_subjects"
                    and origin_key(linked.origin) != origin_key(self.base_url)
                )
            ):
                raise ValueError(
                    "linked resources need a protected source, matching placeholder, and same-origin credentials"
                )
        return self


def api_contract_digest(
    config: API,
    *,
    include_exploration: bool = False,
    include_public: bool = True,
    include_linked: bool = True,
) -> str:
    contract = config.model_dump(mode="python")
    # Bind evidence to the exact normalized origin without retaining the URL in
    # reports. Moving a baseline or retest to another environment must change
    # the digest and therefore fail closed.
    contract["target_origin"] = list(origin_key(config.base_url))
    for operational in (
        "base_url",
        "timeout_seconds",
        "validation_timeout_ms",
        "max_response_bytes",
        "max_cases",
    ):
        contract.pop(operational, None)
    if not include_exploration:
        contract.pop("exploration_resources", None)
    if include_public and contract.get("public_resources"):
        for item, resource in zip(contract["public_resources"], config.public_resources):
            if resource.response_security is None:
                # Preserve digests from policies written before response security contracts.
                item.pop("response_security", None)
    else:
        contract.pop("public_resources", None)
    if include_linked and contract.get("linked_resources"):
        for item, linked in zip(contract["linked_resources"], config.linked_resources):
            item["origin"] = list(origin_key(linked.origin))
            if linked.authentication == "anonymous":
                # Preserve digests from the first anonymous linked-read contract.
                item.pop("authentication", None)
    else:
        # Preserve existing/scoped digests when linked reads are absent or not executed.
        contract.pop("linked_resources", None)
    # Preserve digests for policies written before optional proposal discovery
    # existed. Once configured, the complete discovery contract is digest-bound.
    if contract.get("discovery") is None:
        contract.pop("discovery", None)
    return hashlib.sha256(_canonical_json(contract).encode()).hexdigest()


class Handoff(Strict):
    root: str = Field(min_length=1, max_length=4096)
    files: list[str] = Field(min_length=1, max_length=256)
    allow: list[str] = Field(min_length=1, max_length=64)
    deny: list[str] = Field(default_factory=list, max_length=64)
    max_file_bytes: int = Field(default=1_000_000, ge=1, le=5_000_000)
    max_total_bytes: int = Field(default=10_000_000, ge=1, le=50_000_000)

    @model_validator(mode="after")
    def valid(self):
        root = PurePosixPath(self.root)
        if (
            self.root != "."
            and (
                root.is_absolute()
                or not root.parts
                or ".." in root.parts
                or "\\" in self.root
                or str(root) != self.root
                or self.root.endswith("/")
                or ":" in self.root
                or any(not char.isprintable() for char in self.root)
                or any(part.endswith((".", " ")) for part in root.parts)
            )
        ):
            raise ValueError("handoff root must be a canonical relative directory")
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


def _canonical_json(value) -> str:
    """Serialize JSON-native policy data without rounding Decimal values."""

    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return json.dumps(value, allow_nan=False)
    if type(value) is float:
        return json.dumps(value, allow_nan=False)
    if isinstance(value, Decimal):
        parts = value.as_tuple()
        if (
            not value.is_finite()
            or len(parts.digits) > MAX_JSON_NUMBER_DIGITS
            or abs(value.adjusted()) > MAX_JSON_NUMBER_EXPONENT
            or abs(parts.exponent) > MAX_JSON_NUMBER_EXPONENT
        ):
            raise ValueError("policy number is too large")
        return str(value)
    if isinstance(value, str):
        value.encode("utf-8")
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        return "{" + ",".join(
            _canonical_json(key) + ":" + _canonical_json(value[key])
            for key in sorted(value)
        ) + "}"
    raise TypeError("unsupported policy JSON value")


def load_policy(path: Path) -> Policy:
    try:
        raw = read_bounded_regular(path, MAX_POLICY_BYTES)
        data = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_float=bounded_json_decimal,
            parse_int=bounded_json_int,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        _canonical_json(data)
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
