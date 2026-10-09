"""Header-only contracts. Signed locations never leave this in-memory validator."""

import re
from urllib.parse import parse_qsl, urlsplit

import httpx

from permitprobe.policy import Redirect, origin_key


def _http_values(headers: httpx.Headers, name: str) -> list[str] | None:
    values = headers.get_list(name)
    if any(
        char != "\t" and not 0x20 <= ord(char) <= 0x7E
        for value in values
        for char in value
    ):
        return None
    return values


def _cache_directives(headers: httpx.Headers) -> dict[str, str | None] | None:
    values = _http_values(headers, "cache-control")
    if not values:
        return None
    directives: dict[str, str | None] = {}
    for raw_value in values:
        for raw_part in raw_value.lower().split(","):
            part = raw_part.strip(" \t")
            name, separator, value = part.partition("=")
            if not name or name in directives:
                return None
            argument = value if separator else None
            if name == "max-age":
                if argument is None or not re.fullmatch(r"[0-9]+", argument):
                    return None
            elif (
                name not in {"private", "no-store", "no-cache", "must-revalidate", "no-transform"}
                or argument is not None
            ):
                return None
            directives[name] = argument
    return directives


def redirect_matches(
    rule: Redirect, headers: httpx.Headers, owner_param: str, owner_id: str
) -> bool:
    locations = headers.get_list("location")
    if len(locations) != 1:
        return False
    location = locations[0]
    if (
        not location
        or len(location) > 8192
        or "\\" in location
        or "#" in location
        or any(ord(c) < 33 or ord(c) > 126 for c in location)
        or re.search(r"%(?![0-9a-fA-F]{2})", location)
    ):
        return False
    try:
        u = urlsplit(location)
        if origin_key(f"{u.scheme}://{u.netloc}") != origin_key(rule.origin):
            return False
        if u.path != rule.path.replace("{" + owner_param + "}", owner_id):
            return False
        query = parse_qsl(
            u.query, keep_blank_values=True, strict_parsing=True, errors="strict", max_num_fields=16
        )
        if len(query) != len(rule.required_query) or {k for k, _ in query} != set(
            rule.required_query
        ):
            return False
        return all(v.strip() and all(32 <= ord(c) <= 126 for c in v) for _, v in query)
    except (ValueError, UnicodeError):
        return False


def private_cache_matches(headers: httpx.Headers, auth_header: str) -> bool:
    # Intentionally a small unambiguous subset, not a complete HTTP cache parser.
    directives = _cache_directives(headers)
    if directives is None:
        return False
    if "no-store" in directives:
        return True
    vary_values = _http_values(headers, "vary")
    if vary_values is None:
        return False
    vary = [part.strip(" \t").lower() for value in vary_values for part in value.split(",")]
    if "*" in vary and len(vary) != 1:
        return False
    if any(not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", s) for s in vary):
        return False
    return "private" in directives and (auth_header.lower() in vary or "*" in vary)


def no_store_matches(headers: httpx.Headers) -> bool:
    # Reuse the same strict directive subset while requiring no-store itself.
    directives = _cache_directives(headers)
    return directives is not None and "no-store" in directives
