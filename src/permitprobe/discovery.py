"""Bounded same-origin discovery that emits proposals and never follows them."""

import asyncio
import hashlib
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit
from xml.etree import ElementTree

import httpx

from permitprobe.policy import (
    API,
    QUERY_NAME,
    Discovery,
    api_contract_digest,
    origin_key,
    path_params,
)
from permitprobe.report import Report

_SAFE_METHODS = {"GET", "POST"}
_NAVIGATION_RELS = {"alternate", "canonical", "next", "prev"}


@dataclass(frozen=True)
class _Reference:
    value: str
    method: str
    source: dict[str, str]


@dataclass(frozen=True)
class _SourcePlan:
    path: str
    kinds: tuple[str, ...]


@dataclass(frozen=True)
class _Response:
    status: int
    text: str
    headers: httpx.Headers


class _HTMLReferences(HTMLParser):
    def __init__(self, source_path: str, limit: int):
        super().__init__(convert_charrefs=True)
        self.source_path = source_path
        self.limit = limit
        self.references: list[_Reference] = []
        self.truncated = False

    def _append(self, value: str | None, method: str, tag: str, attribute: str) -> None:
        if not value:
            return
        if len(self.references) >= self.limit:
            self.truncated = True
            return
        self.references.append(
            _Reference(
                value,
                method,
                {
                    "kind": "html",
                    "source_path": self.source_path,
                    "element": tag,
                    "attribute": attribute,
                },
            )
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {name.lower(): value for name, value in attrs}
        if tag in {"a", "area"}:
            self._append(values.get("href"), "GET", tag, "href")
        elif tag == "link":
            rels = set((values.get("rel") or "").lower().split())
            if rels & _NAVIGATION_RELS:
                self._append(values.get("href"), "GET", tag, "href")
        elif tag in {"iframe", "frame"}:
            self._append(values.get("src"), "GET", tag, "src")
        elif tag == "form":
            method = (values.get("method") or "GET").upper()
            self._append(
                values.get("action"),
                method if method in _SAFE_METHODS else "OTHER",
                tag,
                "action",
            )


def _source_plans(config: Discovery) -> list[_SourcePlan]:
    paths: dict[str, list[str]] = {}
    for path in config.seed_paths:
        paths.setdefault(path, []).append("html")
    if config.include_robots:
        paths.setdefault("/robots.txt", []).append("robots")
    if config.include_sitemap:
        paths.setdefault("/sitemap.xml", []).append("sitemap")
    return [_SourcePlan(path, tuple(kinds)) for path, kinds in paths.items()]


def _template_regex(path: str) -> re.Pattern[str]:
    parts = re.split(r"(\{[^{}]+\})", path)
    pattern = "".join(r"[^/]+" if part.startswith("{") else re.escape(part) for part in parts)
    return re.compile("^" + pattern + "$")


def _normalized_template(path: str) -> str:
    return re.sub(r"\{[^{}]+\}", "{value}", path)


def _literal_segments(path: str) -> set[str]:
    return {segment for segment in path.split("/") if segment and "{" not in segment}


def _shape_path(path: str, approved: set[str]) -> str:
    if path == "/":
        return path
    trailing = path.endswith("/")
    shaped = "/".join(
        part if part in approved else "{value}" for part in path.split("/")[1:] if part
    )
    return "/" + shaped + ("/" if trailing else "")


class _Candidates:
    def __init__(self, config: API):
        assert config.discovery is not None
        self.config = config.discovery
        self.base_url = config.base_url.rstrip("/")
        self.origin = origin_key(config.base_url)
        declared = [*config.resources, *config.public_resources]
        declared.extend(
            resource
            for resource in config.linked_resources
            if origin_key(resource.origin) == self.origin
        )
        self.templates = [
            (resource.name, resource.path, _template_regex(resource.path))
            for resource in declared
        ]
        self.report_path_literals = set(self.config.report_path_literals)
        for _, path, _ in self.templates:
            self.report_path_literals.update(_literal_segments(path))
        self.report_query_names = set(self.config.report_query_names)
        for resource in config.public_resources:
            self.report_query_names.update(item.name for item in resource.query)
        self.items: dict[tuple[str, str, tuple[str, ...], int], dict] = {}
        self.extracted = 0
        self.rejected = 0
        self.out_of_scope = 0
        self.truncated = 0
        self._raw_limit = min(4_096, self.config.max_candidates * 8)

    def mark_truncated(self) -> None:
        self.truncated += 1

    def _normalize(self, raw: str, source_path: str) -> tuple[str, tuple[str, ...]] | None:
        value = raw.strip()
        if (
            not value
            or len(value) > 4_096
            or "\\" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            self.rejected += 1
            return None
        try:
            parsed = urlsplit(urljoin(self.base_url + source_path, value))
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            candidate_origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(), port)
        except ValueError:
            self.rejected += 1
            return None
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "%" in parsed.netloc
        ):
            self.rejected += 1
            return None
        if candidate_origin != self.origin:
            self.out_of_scope += 1
            return None
        path = parsed.path or "/"
        try:
            placeholders = path_params(path)
        except ValueError:
            self.rejected += 1
            return None
        if placeholders or len(path) > 512 or any(ord(char) > 126 for char in path):
            self.rejected += 1
            return None
        try:
            pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=17,
            )
        except ValueError:
            self.rejected += 1
            return None
        query_names = tuple(sorted({name for name, _ in pairs}))
        if (
            len(pairs) > 16
            or len(query_names) > 16
            or any(not QUERY_NAME.fullmatch(name) for name in query_names)
        ):
            self.rejected += 1
            return None
        return path, query_names

    def add(self, reference: _Reference, source_path: str) -> None:
        self.extracted += 1
        if self.extracted > self._raw_limit:
            self.truncated += 1
            return
        normalized = self._normalize(reference.value, source_path)
        if normalized is None:
            return
        path, query_names = normalized
        reported_query_names = tuple(
            name for name in query_names if name in self.report_query_names
        )
        redacted_query_names = len(query_names) - len(reported_query_names)
        matches = sorted(name for name, _, pattern in self.templates if pattern.fullmatch(path))
        if reference.method != "GET":
            classification = "unsupported_method"
            path_shape = _shape_path(path, self.report_path_literals)
        elif matches:
            classification = "declared"
            matched_paths = sorted(
                path for name, path, _ in self.templates if name in matches
            )
            path_shape = _normalized_template(matched_paths[0])
        else:
            classification = "candidate"
            path_shape = _shape_path(path, self.report_path_literals)
        key = (
            reference.method,
            path_shape,
            reported_query_names,
            redacted_query_names,
        )
        item = self.items.get(key)
        if item is None:
            if len(self.items) >= self.config.max_candidates:
                self.truncated += 1
                return
            item = {
                "method": reference.method,
                "path_shape": path_shape,
                "query_names": list(reported_query_names),
                "redacted_query_names": redacted_query_names,
                "classification": classification,
                "policy_resources": matches,
                "sources": [],
                "executable": False,
                "_variants": set(),
            }
            self.items[key] = item
        else:
            item["policy_resources"] = sorted(set(item["policy_resources"]) | set(matches))
            if item["classification"] == "declared" and classification == "candidate":
                item["classification"] = "candidate"
        if reference.source not in item["sources"]:
            item["sources"].append(reference.source)
        item["_variants"].add((path, query_names))

    def proposals(self) -> list[dict]:
        result = []
        for key in sorted(self.items):
            item = self.items[key]
            item["sources"].sort(key=lambda source: tuple(sorted(source.items())))
            identity = "\0".join(
                [
                    item["method"],
                    item["path_shape"],
                    *item["query_names"],
                    str(item["redacted_query_names"]),
                ]
            )
            result.append(
                {
                    "proposal_id": "ppd-" + hashlib.sha256(identity.encode()).hexdigest()[:16],
                    **{name: value for name, value in item.items() if name != "_variants"},
                    "observed_variants": len(item["_variants"]),
                }
            )
        return result


async def _fetch(base_url: str, path: str, config: Discovery) -> _Response:
    headers = {
        "Accept": "text/html, application/xhtml+xml, application/xml, text/plain",
        "Accept-Encoding": "identity",
    }
    async with asyncio.timeout(config.timeout_seconds):
        async with httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            timeout=config.timeout_seconds,
        ) as client:
            async with client.stream("GET", base_url.rstrip("/") + path, headers=headers) as response:
                if not 200 <= response.status_code < 300:
                    return _Response(response.status_code, "", response.headers)
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("encoded response")
                body = bytearray()
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > config.max_response_bytes:
                        raise ValueError("response budget exceeded")
                    body.extend(chunk)
                return _Response(response.status_code, body.decode("utf-8"), response.headers)


def _html_references(text: str, path: str, limit: int) -> tuple[list[_Reference], bool]:
    parser = _HTMLReferences(path, limit)
    parser.feed(text)
    parser.close()
    return parser.references, parser.truncated


def _robots_references(text: str, path: str, limit: int) -> tuple[list[_Reference], bool]:
    references = []
    truncated = False
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        name, value = (part.strip() for part in line.split(":", 1))
        lowered = name.lower()
        if lowered not in {"allow", "disallow", "sitemap"} or not value:
            continue
        if lowered in {"allow", "disallow"} and ("*" in value or "$" in value):
            continue
        if len(references) >= limit:
            truncated = True
            continue
        references.append(
            _Reference(
                value,
                "GET",
                {
                    "kind": "robots",
                    "source_path": path,
                    "directive": lowered,
                },
            )
        )
    return references, truncated


def _sitemap_references(text: str, path: str, limit: int) -> tuple[list[_Reference], bool]:
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise ValueError("unsupported XML declaration")
    root = ElementTree.fromstring(text)
    root_name = root.tag.rsplit("}", 1)[-1].lower()
    if root_name not in {"urlset", "sitemapindex"}:
        raise ValueError("unsupported sitemap root")
    references = []
    truncated = False
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() != "loc" or not element.text:
            continue
        if len(references) >= limit:
            truncated = True
            continue
        references.append(
            _Reference(
                element.text,
                "GET",
                {
                    "kind": "sitemap",
                    "source_path": path,
                    "document": root_name,
                    "element": "loc",
                },
            )
        )
    return references, truncated


def _source_target(kind: str, path: str) -> str:
    return f"discovery/{kind} {path}"


def _record_source(
    kind: str,
    plan: _SourcePlan,
    response: _Response,
    candidates: _Candidates,
    report: Report,
) -> str:
    target = _source_target(kind, plan.path)
    status = response.status
    if 300 <= status < 400:
        locations = response.headers.get_list("location")
        if len(locations) != 1 or not locations[0]:
            report.add(
                "discovery.source",
                "inconclusive",
                target,
                f"HTTP {status} had no single usable Location; redirects were not followed.",
            )
            return "inconclusive"
        candidates.add(
            _Reference(
                locations[0],
                "GET",
                {
                    "kind": "redirect",
                    "source_path": plan.path,
                    "attribute": "location",
                },
            ),
            plan.path,
        )
        report.add(
            "discovery.source",
            "pass",
            target,
            f"HTTP {status} destination was proposed without following the redirect.",
        )
        return "pass"
    if status == 404 and kind in {"robots", "sitemap"}:
        report.add(
            "discovery.source",
            "pass",
            target,
            "Optional discovery source was absent (HTTP 404).",
        )
        return "pass"
    if not 200 <= status < 300:
        outcome = "fail" if kind == "html" and 400 <= status < 500 else "inconclusive"
        report.add(
            "discovery.source",
            outcome,
            target,
            f"Fixed discovery source returned HTTP {status}.",
        )
        return outcome
    try:
        if kind == "html":
            content_type = response.headers.get("content-type", "").lower()
            if content_type and not (
                content_type.startswith("text/html")
                or content_type.startswith("application/xhtml+xml")
            ):
                references, truncated = [], False
            else:
                references, truncated = _html_references(
                    response.text, plan.path, candidates._raw_limit
                )
        elif kind == "robots":
            references, truncated = _robots_references(
                response.text, plan.path, candidates._raw_limit
            )
        else:
            references, truncated = _sitemap_references(
                response.text, plan.path, candidates._raw_limit
            )
    except (ElementTree.ParseError, UnicodeError, ValueError, RecursionError):
        report.add(
            "discovery.parse",
            "inconclusive",
            target,
            "Fixed discovery source could not be parsed within the supported format.",
        )
        return "inconclusive"
    for reference in references:
        candidates.add(reference, plan.path)
    if truncated:
        candidates.mark_truncated()
    report.add(
        "discovery.source",
        "pass",
        target,
        f"Fixed discovery source completed with HTTP {status}; content was not retained.",
    )
    return "pass"


def _empty_discovery(config: API, state: str, *, planned: int) -> dict:
    assert config.discovery is not None
    return {
        "schema_version": 1,
        "mode": "bounded_same_origin_proposals",
        "state": state,
        "sources": {
            "configured": len(_source_plans(config.discovery)),
            "planned": planned,
            "attempted": 0,
            "completed": 0,
            "failed": 0,
            "items": [],
        },
        "candidates": {
            "total": 0,
            "declared": 0,
            "undeclared": 0,
            "unsupported_method": 0,
            "out_of_scope": 0,
            "rejected": 0,
            "truncated": 0,
            "proposals": [],
        },
        "limits": {
            "max_candidates": config.discovery.max_candidates,
            "max_response_bytes": config.discovery.max_response_bytes,
            "timeout_seconds": config.discovery.timeout_seconds,
        },
        "discovered_requests_executed": 0,
    }


def record_discovery_blocked(config: API, report: Report) -> None:
    """Record that handoff preflight prevented every discovery request."""

    if config.discovery is None:
        return
    report.discovery = _empty_discovery(config, "blocked_by_handoff", planned=0)


def discover(config: API, report: Report) -> None:
    """Fetch only fixed configured sources, then emit non-executable proposals."""

    if config.discovery is None:
        return
    digest = api_contract_digest(config)
    if report.policy_digest is not None and report.policy_digest != digest:
        raise ValueError("inconsistent API policy digest")
    report.policy_digest = digest
    candidates = _Candidates(config)
    plans = _source_plans(config.discovery)
    metadata = _empty_discovery(config, "complete", planned=len(plans))
    sources = metadata["sources"]

    for plan in plans:
        sources["attempted"] += 1
        item = {"path": plan.path, "kinds": list(plan.kinds)}
        try:
            response = asyncio.run(_fetch(config.base_url, plan.path, config.discovery))
        except Exception:
            sources["failed"] += 1
            item["delivery"] = "failed"
            item["outcome"] = "inconclusive"
            for kind in plan.kinds:
                report.add(
                    "discovery.delivery",
                    "inconclusive",
                    _source_target(kind, plan.path),
                    "Fixed discovery request failed, used unsupported encoding, or exceeded a limit.",
                )
        else:
            sources["completed"] += 1
            item["delivery"] = "complete"
            item["http_status"] = response.status
            outcomes = [
                _record_source(kind, plan, response, candidates, report) for kind in plan.kinds
            ]
            item["outcome"] = (
                "inconclusive"
                if "inconclusive" in outcomes
                else "fail"
                if "fail" in outcomes
                else "pass"
            )
        sources["items"].append(item)

    if any(item["outcome"] == "inconclusive" for item in sources["items"]):
        metadata["state"] = "incomplete"

    proposals = candidates.proposals()
    undeclared = [item for item in proposals if item["classification"] == "candidate"]
    for item in undeclared:
        query_names = [
            *item["query_names"],
            *("{name}" for _ in range(item["redacted_query_names"])),
        ]
        query = "?" + "&".join(query_names) if query_names else ""
        report.add(
            "discovery.undeclared",
            "fail",
            f"discovery/GET {item['path_shape']}{query}",
            "Same-origin GET proposal has no matching declared check resource; it was not requested.",
        )
    if not undeclared:
        report.add(
            "discovery.coverage",
            "pass",
            "discovery",
            "Every accepted GET proposal matches a declared check resource.",
        )
    if candidates.truncated:
        report.add(
            "discovery.limit",
            "inconclusive",
            "discovery",
            "Candidate or extraction limit was reached; discovery coverage is incomplete.",
        )
        metadata["state"] = "incomplete"

    counts = metadata["candidates"]
    counts.update(
        {
            "total": len(proposals),
            "declared": sum(item["classification"] == "declared" for item in proposals),
            "undeclared": len(undeclared),
            "unsupported_method": sum(
                item["classification"] == "unsupported_method" for item in proposals
            ),
            "out_of_scope": candidates.out_of_scope,
            "rejected": candidates.rejected,
            "truncated": candidates.truncated,
            "proposals": proposals,
        }
    )
    report.discovery = metadata
