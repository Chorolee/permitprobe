"""Value-free checks for declared browser-facing response security contracts."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from permitprobe.policy import (
    CORSContract,
    HSTSContract,
    ResponseCookieContract,
    ResponseSecurityContract,
    SecurityHeadersContract,
)

COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~A-Za-z0-9-]+")
COOKIE_VALUE = re.compile(
    r'(?:"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*"|'
    r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*)"
)


def _values(headers: httpx.Headers, name: str) -> list[str]:
    return headers.get_list(name)


def _one(headers: httpx.Headers, name: str) -> str | None:
    values = _values(headers, name)
    return values[0].strip() if len(values) == 1 else None


def _result(code: str, passed: bool, noun: str) -> tuple[str, str, str]:
    return (
        code,
        "pass" if passed else "fail",
        f"Response matches the declared {noun} contract."
        if passed
        else f"Response does not match the declared {noun} contract; values omitted.",
    )


def _hsts_matches(value: str | None, contract: HSTSContract) -> bool:
    if value is None:
        return False
    directives: dict[str, str | None] = {}
    for raw in value.split(";"):
        part = raw.strip()
        if not part:
            continue
        name, separator, argument = part.partition("=")
        lowered = name.strip().lower()
        if not re.fullmatch(r"[a-z][a-z-]*", lowered) or lowered in directives:
            return False
        directives[lowered] = argument.strip() if separator else None
    maximum = directives.get("max-age")
    if maximum is None or not maximum.isdecimal() or int(maximum) < contract.min_max_age:
        return False
    if contract.include_subdomains and directives.get("includesubdomains", "missing") is not None:
        return False
    if contract.preload and directives.get("preload", "missing") is not None:
        return False
    return True


def _csp_matches(value: str | None, required: dict[str, list[str]]) -> bool:
    if value is None:
        return False
    directives: dict[str, list[str]] = {}
    for raw in value.split(";"):
        tokens = raw.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) or name in directives:
            return False
        directives[name] = tokens[1:]
    return all(
        name in directives and set(values) == set(directives[name])
        for name, values in required.items()
    )


def security_header_results(
    contract: SecurityHeadersContract, headers: httpx.Headers
) -> list[tuple[str, str, str]]:
    results = []
    if contract.hsts is not None:
        results.append(
            _result(
                "web.hsts",
                _hsts_matches(_one(headers, "Strict-Transport-Security"), contract.hsts),
                "HSTS",
            )
        )
    if contract.content_type_options is not None:
        value = _one(headers, "X-Content-Type-Options")
        results.append(
            _result(
                "web.content_type_options",
                value is not None and value.lower() == contract.content_type_options,
                "content-type-options",
            )
        )
    if contract.referrer_policy:
        value = _one(headers, "Referrer-Policy")
        results.append(
            _result(
                "web.referrer_policy",
                value is not None and value.lower() in contract.referrer_policy,
                "referrer-policy",
            )
        )
    if contract.frame_options:
        value = _one(headers, "X-Frame-Options")
        results.append(
            _result(
                "web.frame_options",
                value is not None and value.lower() in contract.frame_options,
                "frame-options",
            )
        )
    if contract.content_security_policy is not None:
        results.append(
            _result(
                "web.content_security_policy",
                _csp_matches(
                    _one(headers, "Content-Security-Policy"),
                    contract.content_security_policy.required_directives,
                ),
                "content-security-policy",
            )
        )
    return results


def _cookie_jar(
    headers: httpx.Headers,
) -> tuple[dict[str, list[dict[str, str | None]]], bool]:
    result: dict[str, list[dict[str, str | None]]] = {}
    valid = True
    for raw in _values(headers, "Set-Cookie"):
        parts = raw.split(";")
        name, separator, value = parts[0].strip().partition("=")
        if (
            not separator
            or not COOKIE_NAME.fullmatch(name)
            or not COOKIE_VALUE.fullmatch(value)
        ):
            valid = False
            continue
        attributes: dict[str, str | None] = {}
        for raw_attribute in parts[1:]:
            attribute = raw_attribute.strip()
            attr_name, has_value, attr_value = attribute.partition("=")
            lowered = attr_name.strip().lower()
            argument = attr_value.strip() if has_value else None
            if (
                not attribute
                or not COOKIE_NAME.fullmatch(attr_name.strip())
                or lowered in attributes
                or (
                    argument is not None
                    and any(
                        ord(char) < 32 or ord(char) > 126 or char == ";"
                        for char in argument
                    )
                )
            ):
                valid = False
                break
            attributes[lowered] = argument
        else:
            if any(attributes.get(flag) is not None for flag in ("secure", "httponly")):
                valid = False
                continue
            result.setdefault(name, []).append(attributes)
    return result, valid


def _cookie_matches(
    contract: ResponseCookieContract, attributes: dict[str, str | None]
) -> bool:
    secure = "secure" in attributes
    http_only = "httponly" in attributes
    same_site = (attributes.get("samesite") or "").lower()
    domain_present = "domain" in attributes
    path = attributes.get("path")
    checks = [same_site != "none" or secure]
    if contract.secure is not None:
        checks.append(secure is contract.secure)
    if contract.http_only is not None:
        checks.append(http_only is contract.http_only)
    if contract.same_site:
        checks.append(same_site in contract.same_site)
    if contract.host_only is not None:
        checks.append((not domain_present) is contract.host_only)
    if contract.path is not None:
        checks.append(path == contract.path)
    return all(checks)


def cookie_results(
    contracts: list[ResponseCookieContract], headers: httpx.Headers
) -> list[tuple[str, str, str]]:
    if not contracts:
        return []
    jar, valid = _cookie_jar(headers)
    passed = valid and all(
        len(jar.get(contract.name, [])) == 1
        and _cookie_matches(contract, jar[contract.name][0])
        for contract in contracts
    )
    return [_result("web.cookies", passed, "response-cookie")]


def cors_origin_key(value: str) -> tuple[str, str, int] | None:
    if value != value.strip() or len(value) > 512 or any(
        ord(char) < 33 or ord(char) > 126 for char in value
    ):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
    except ValueError:
        return None
    if (
        parsed.scheme not in ("http", "https")
        or not hostname
        or "@" in parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or "%" in parsed.netloc
        or parsed.netloc.endswith(":")
        or "?" in value
        or "#" in value
        or port == 0
    ):
        return None
    return parsed.scheme, hostname.lower(), port or (443 if parsed.scheme == "https" else 80)


def _header_value(headers: dict[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


def _vary_has_origin(headers: httpx.Headers) -> bool:
    return any(
        token.strip().lower() in ("origin", "*")
        for value in _values(headers, "Vary")
        for token in value.split(",")
    )


def cors_results(
    contract: CORSContract,
    variant: str,
    request_headers: dict[str, str],
    response_headers: httpx.Headers,
) -> list[tuple[str, str, str]]:
    if variant not in {*contract.allow_variants, *contract.deny_variants}:
        return []
    request_origin = _header_value(request_headers, "Origin")
    request_key = cors_origin_key(request_origin or "")
    values = _values(response_headers, "Access-Control-Allow-Origin")
    credentials = _values(response_headers, "Access-Control-Allow-Credentials")
    if request_key is None or len(values) > 1 or len(credentials) > 1:
        return [_result("web.cors", False, "CORS")]
    allowed_origin = values[0].strip() if values else None
    credentials_true = bool(credentials) and credentials[0].strip().lower() == "true"
    wildcard = allowed_origin == "*"
    reflected = (
        allowed_origin is not None
        and not wildcard
        and cors_origin_key(allowed_origin) == request_key
    )
    malformed_wildcard = wildcard and credentials_true
    if variant in contract.deny_variants:
        passed = not malformed_wildcard and not wildcard and not reflected
        return [_result("web.cors", passed, "CORS")]
    origin_ok = reflected or (wildcard and contract.allow_wildcard)
    credentials_ok = credentials_true if contract.allow_credentials else not credentials
    vary_ok = (
        not reflected or not contract.require_vary_origin or _vary_has_origin(response_headers)
    )
    return [
        _result(
            "web.cors",
            not malformed_wildcard and origin_ok and credentials_ok and vary_ok,
            "CORS",
        )
    ]


def response_security_results(
    contract: ResponseSecurityContract,
    variant: str,
    request_headers: dict[str, str],
    response_headers: httpx.Headers,
) -> list[tuple[str, str, str]]:
    results = []
    if contract.security_headers is not None:
        results.extend(security_header_results(contract.security_headers, response_headers))
    results.extend(cookie_results(contract.cookies, response_headers))
    if contract.cors is not None:
        results.extend(
            cors_results(
                contract.cors,
                variant,
                request_headers,
                response_headers,
            )
        )
    return results
