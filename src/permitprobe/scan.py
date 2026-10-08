"""One-shot orchestration of every deterministic, declared PermitProbe stage."""

from pathlib import Path

from permitprobe.api import check_api
from permitprobe.baseline import Baseline, apply_baseline
from permitprobe.discovery import discover, record_discovery_blocked
from permitprobe.handoff import check_handoff
from permitprobe.openapi_inventory import inventory_openapi
from permitprobe.policy import Policy, PolicyError
from permitprobe.report import Report


def _stage_status(report: Report, prefixes: tuple[str, ...], configured: bool) -> str:
    if not configured:
        return "skipped"
    outcomes = [check.outcome for check in report.checks if check.code.startswith(prefixes)]
    if not outcomes or "inconclusive" in outcomes:
        return "inconclusive"
    if "fail" in outcomes:
        return "fail"
    return "pass"


def run_scan(
    policy: Policy,
    policy_dir: Path,
    report: Report,
    *,
    openapi: Path | None = None,
    gitleaks: str | None = None,
    baseline: Baseline | None = None,
) -> None:
    """Run inventory, handoff, fixed proposal discovery, and declared GET checks once."""

    if policy.api is None:
        raise PolicyError("one-shot scan requires an API policy")
    if openapi is not None:
        inventory_openapi(policy.api, openapi, report)
    if policy.handoff is not None:
        check_handoff(policy.handoff, policy_dir, report, gitleaks)
    handoff_incomplete = any(
        check.code.startswith("handoff.") and check.outcome == "inconclusive"
        for check in report.checks
    )
    if not handoff_incomplete:
        discover(policy.api, report)
        check_api(policy.api, report)
    else:
        record_discovery_blocked(policy.api, report)
    if baseline is not None:
        apply_baseline(report, baseline)

    evidence = list(report.evidence.values())
    discovery_sources = (
        report.discovery["sources"]
        if report.discovery is not None
        else {"planned": 0, "attempted": 0, "completed": 0, "failed": 0}
    )
    linked_same_origin_credentials_used = any(
        case_id in report.evidence
        and item.get("case_type") == "linked_read"
        and item.get("authentication") == "source_subjects"
        and item.get("role") != "anonymous"
        for case_id, item in report.planned_cases.items()
    )
    report.scan = {
        "schema_version": 2,
        "mode": "declared_get_one_shot",
        "stages": {
            "openapi_inventory": {
                "configured": openapi is not None,
                "status": _stage_status(report, ("inventory.",), openapi is not None),
            },
            "passive_discovery": {
                "configured": policy.api.discovery is not None,
                "status": _stage_status(
                    report,
                    ("discovery.",),
                    policy.api.discovery is not None,
                ),
            },
            "live_get_checks": {
                "configured": True,
                "status": _stage_status(
                    report,
                    ("api.", "data.", "public.", "availability.", "web."),
                    True,
                ),
            },
            "linked_reads": {
                "configured": bool(policy.api.linked_resources),
                "status": _stage_status(
                    report,
                    ("linked.",),
                    bool(policy.api.linked_resources),
                ),
            },
            "handoff": {
                "configured": policy.handoff is not None,
                "status": _stage_status(report, ("handoff.",), policy.handoff is not None),
            },
            "known_finding_baseline": {
                "configured": baseline is not None,
                "status": (
                    "inconclusive"
                    if baseline is not None
                    and report.baseline is not None
                    and not report.baseline["policy_match"]
                    else "applied"
                    if baseline is not None
                    else "skipped"
                ),
            },
        },
        "requests": {
            "planned": len(report.planned_cases) + discovery_sources["planned"],
            "observed": len(evidence) + discovery_sources["attempted"],
            "completed": sum(item.delivery == "complete" for item in evidence)
            + discovery_sources["completed"],
            "failed": sum(item.delivery == "failed" for item in evidence)
            + discovery_sources["failed"],
            "writes": 0,
        },
        "scope": {
            "methods": ["GET"],
            "automatic_discovery": False,
            "proposal_discovery": policy.api.discovery is not None,
            "discovered_requests_executed": 0,
            "redirects_followed": False,
            "linked_read_contracts": len(policy.api.linked_resources),
            "linked_credentials_forwarded": linked_same_origin_credentials_used,
            "linked_same_origin_credentials_used": linked_same_origin_credentials_used,
            "linked_cross_origin_credentials_forwarded": False,
            "linked_response_bodies_consumed": False,
        },
    }
