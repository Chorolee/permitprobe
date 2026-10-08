"""Header-only contracts. Signed locations never leave this in-memory validator."""

import re
from urllib.parse import parse_qsl, urlsplit

import httpx

from permitprobe.policy import Redirect, origin_key


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
    directives = {}
    for part in headers.get("cache-control", "").lower().split(","):
        parts = part.strip().split("=", 1)
        name = parts[0]
        if name in directives:
            return False
        value = parts[1] if len(parts) == 2 else None
        if name == "max-age":
            if value is None or not re.fullmatch(r"[0-9]+", value):
                return False
        elif (
            name not in {"private", "no-store", "no-cache", "must-revalidate", "no-transform"}
            or value is not None
        ):
            return False
        directives[name] = value
    if "no-store" in directives:
        return True
    vary = [s.strip().lower() for s in headers.get("vary", "").split(",")]
    if "*" in vary and len(vary) != 1:
        return False
    if any(not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", s) for s in vary):
        return False
    return "private" in directives and (auth_header.lower() in vary or "*" in vary)


def no_store_matches(headers: httpx.Headers) -> bool:
    # Reuse the same strict directive subset while requiring no-store itself.
    names = {
        part.strip().split("=", 1)[0]
        for part in headers.get("cache-control", "").lower().split(",")
    }
    return "no-store" in names and private_cache_matches(headers, "")
