"""Offline OpenAPI-to-policy coverage inventory. No target requests are sent."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from permitprobe.local_files import read_bounded_regular
from permitprobe.policy import API, PolicyError, _unique, api_contract_digest, origin_key
from permitprobe.report import Report

MAX_OPENAPI_BYTES = 5_000_000
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
OPENAPI_VERSION = re.compile(r"^3\.[0-2]\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
PATH_PARAMETER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_.-]*\}")


@dataclass(frozen=True)
class Operation:
    path: str
    normalized_path: str
    access: str
    required_query: frozenset[str]


@dataclass(frozen=True)
class Surface:
    name: str
    normalized_path: str
    access: str
    query: frozenset[str]


def _load(path: Path) -> tuple[dict, str]:
    try:
        raw = read_bounded_regular(path, MAX_OPENAPI_BYTES)
        document = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (OSError, ValueError, RecursionError, UnicodeError):
        raise PolicyError("cannot read a bounded OpenAPI JSON document") from None
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("openapi"), str)
        or not OPENAPI_VERSION.fullmatch(document["openapi"])
        or not isinstance(document.get("paths"), dict)
    ):
        raise PolicyError("expected an OpenAPI 3.0, 3.1 or 3.2 JSON document")
    return document, hashlib.sha256(raw).hexdigest()


def _pointer(document: dict, reference: str):
    if not reference.startswith("#/") or len(reference) > 1_024:
        raise PolicyError("only bounded local OpenAPI parameter references are supported")
    value = document
    for raw in reference[2:].split("/"):
        if "%" in raw or re.search(r"~(?![01])", raw):
            raise PolicyError("invalid local OpenAPI reference")
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", key):
            index = int(key)
            if index >= len(value):
                raise PolicyError("invalid local OpenAPI reference")
            value = value[index]
        else:
            raise PolicyError("invalid local OpenAPI reference")
    return value


def _resolve_parameter(document: dict, value) -> dict:
    seen = set()
    for _ in range(8):
        if not isinstance(value, dict):
            break
        reference = value.get("$ref")
        if reference is None:
            return value
        if not isinstance(reference, str) or reference in seen:
            break
        seen.add(reference)
        value = _pointer(document, reference)
    raise PolicyError("invalid or recursive OpenAPI parameter reference")


def _parameters(document: dict, path_item: dict, operation: dict) -> frozenset[str]:
    merged = {}
    for source in (path_item.get("parameters", []), operation.get("parameters", [])):
        if not isinstance(source, list) or len(source) > 256:
            raise PolicyError("OpenAPI parameters must be a bounded array")
        local = set()
        for raw in source:
            parameter = _resolve_parameter(document, raw)
            name = parameter.get("name")
            location = parameter.get("in")
            required = parameter.get("required", False)
            if (
                not isinstance(name, str)
                or not 1 <= len(name) <= 128
                or any(ord(char) < 33 or ord(char) > 126 for char in name)
                or not isinstance(location, str)
                or location not in {"query", "header", "path", "cookie"}
                or type(required) is not bool
                or (location == "path" and not required)
            ):
                raise PolicyError("invalid OpenAPI parameter object")
            key = (location, name)
            if key in local:
                raise PolicyError("duplicate OpenAPI parameter")
            local.add(key)
            merged[key] = required
    return frozenset(
        name for (location, name), required in merged.items() if location == "query" and required
    )


def _access(document: dict, operation: dict) -> str:
    security = operation.get("security", document.get("security", []))
    if not isinstance(security, list) or len(security) > 64:
        raise PolicyError("OpenAPI security must be a bounded array")
    if not security:
        return "public"
    public_alternative = False
    components = document.get("components", {})
    schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    for requirement in security:
        if not isinstance(requirement, dict) or len(requirement) > 64:
            raise PolicyError("invalid OpenAPI security requirement")
        if not requirement:
            public_alternative = True
            continue
        if any(
            not isinstance(name, str)
            or not 1 <= len(name) <= 128
            or not isinstance(scopes, list)
            or len(scopes) > 256
            or any(not isinstance(scope, str) for scope in scopes)
            for name, scopes in requirement.items()
        ):
            raise PolicyError("invalid OpenAPI security requirement")
        if not isinstance(schemes, dict) or any(name not in schemes for name in requirement):
            raise PolicyError("OpenAPI security requirement references an unknown scheme")
    return "public" if public_alternative else "protected"


def _normalize_path(path: str) -> str:
    if (
        not isinstance(path, str)
        or not 1 <= len(path) <= 512
        or not path.startswith("/")
        or not re.fullmatch(r"/[A-Za-z0-9_/{\}.~-]*", path)
        or "?" in path
        or "#" in path
        or "\\" in path
        or any(ord(char) < 32 or ord(char) > 126 for char in path)
        or any(part in {".", ".."} for part in path.split("/"))
    ):
        raise PolicyError("invalid OpenAPI path")
    without_parameters = PATH_PARAMETER.sub("", path)
    if "{" in without_parameters or "}" in without_parameters or "//" in path:
        raise PolicyError("invalid OpenAPI path template")
    return PATH_PARAMETER.sub("{}", path)


def _operations(document: dict) -> tuple[list[Operation], int]:
    operations = []
    non_get = 0
    seen = set()
    if len(document["paths"]) > 4_096:
        raise PolicyError("OpenAPI path inventory exceeds the operation budget")
    for path, raw_item in document["paths"].items():
        normalized = _normalize_path(path)
        if not isinstance(raw_item, dict):
            raise PolicyError("OpenAPI path items must be objects")
        if "$ref" in raw_item:
            raise PolicyError("referenced OpenAPI path items are not supported")
        for method in HTTP_METHODS:
            if method not in raw_item:
                continue
            operation = raw_item[method]
            if not isinstance(operation, dict):
                raise PolicyError("OpenAPI operations must be objects")
            key = (method, normalized)
            if key in seen:
                raise PolicyError("duplicate structural OpenAPI operation")
            seen.add(key)
            if method != "get":
                non_get += 1
                continue
            operations.append(
                Operation(
                    path,
                    normalized,
                    _access(document, operation),
                    _parameters(document, raw_item, operation),
                )
            )
    return operations, non_get


def _surfaces(config: API) -> list[Surface]:
    ordinary = [
        Surface(
            resource.name,
            _normalize_path(resource.path),
            "public" if any(rule.role == "anonymous" for rule in resource.allow) else "protected",
            frozenset(),
        )
        for resource in config.resources
    ]
    public = [
        Surface(
            resource.name,
            _normalize_path(resource.path),
            "public",
            frozenset(item.name for item in resource.query),
        )
        for resource in config.public_resources
    ]
    origin = origin_key(config.base_url)
    linked = [
        Surface(
            resource.name,
            _normalize_path(resource.path),
            "protected",
            frozenset(),
        )
        for resource in config.linked_resources
        if origin_key(resource.origin) == origin
    ]
    return [*ordinary, *public, *linked]


def inventory_openapi(config: API, path: Path, report: Report) -> None:
    """Compare locally declared GET operations with executable check resources."""

    document, document_digest = _load(path)
    operations, non_get = _operations(document)
    surfaces = _surfaces(config)
    if "api" not in report.configured:
        report.configured.append("api")
    report.policy_digest = api_contract_digest(config)
    covered = 0
    structural_matches = set()
    if not operations:
        report.add(
            "inventory.coverage",
            "inconclusive",
            "openapi",
            "The OpenAPI document declares no GET operations.",
        )
    for operation in operations:
        target = f"openapi/GET {operation.path}"
        same_path = [
            surface for surface in surfaces if surface.normalized_path == operation.normalized_path
        ]
        structural_matches.update(surface.name for surface in same_path)
        if not same_path:
            report.add(
                "inventory.coverage",
                "fail",
                target,
                "No ordinary, public or same-origin linked check covers this GET operation.",
            )
            continue
        same_access = [surface for surface in same_path if surface.access == operation.access]
        if not same_access:
            report.add(
                "inventory.security",
                "fail",
                target,
                "The OpenAPI security requirement and declared check surface disagree.",
            )
            continue
        query_match = [
            surface for surface in same_access if operation.required_query.issubset(surface.query)
        ]
        if not query_match:
            report.add(
                "inventory.query",
                "fail",
                target,
                "The declared check omits one or more required OpenAPI query parameters.",
            )
            continue
        covered += 1
        report.add(
            "inventory.coverage",
            "pass",
            target,
            "A declared GET check matches the path, security requirement and required query names.",
        )
    stale = [surface for surface in surfaces if surface.name not in structural_matches]
    for surface in stale:
        report.add(
            "inventory.stale_policy",
            "fail",
            surface.name,
            "The declared check resource has no matching GET operation in the OpenAPI document.",
        )
    report.inventory = {
        "format": "openapi",
        "version": document["openapi"],
        "document_sha256": document_digest,
        "operations": len(operations) + non_get,
        "get_operations": len(operations),
        "covered_get_operations": covered,
        "uncovered_get_operations": len(operations) - covered,
        "unsupported_non_get_operations": non_get,
        "declared_check_resources": len(surfaces),
        "stale_check_resources": len(stale),
    }
