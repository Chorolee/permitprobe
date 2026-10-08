"""Sanitized manifests for deterministic replay of bounded exploration cases."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from permitprobe import __version__
from permitprobe.api import case_descriptor, execute_api_cases, finalize_api, prepare_api
from permitprobe.artifacts import write_private_json
from permitprobe.exploration import baseline_cases
from permitprobe.local_files import read_bounded_regular
from permitprobe.policy import API, PolicyError, _unique, api_contract_digest
from permitprobe.report import Report
from permitprobe.retest import _validate_prior_report

FORMAT_VERSION = 1
MAX_REPLAY_BYTES = 1_000_000
MAX_SOURCE_BYTES = 10_000_000
MAX_REPLAY_CASES = 1_024
MAX_CASE_ID_BYTES = 512
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@~-]{0,511}$")


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def _read_json(path: Path, limit: int):
    try:
        raw = read_bounded_regular(path, limit)
        return json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except PolicyError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise PolicyError("cannot read a valid bounded replay JSON file") from None


def _valid_case_ids(value, *, allow_empty: bool = False) -> bool:
    if (
        not isinstance(value, list)
        or not (allow_empty or value)
        or len(value) > MAX_REPLAY_CASES
        or any(
            not isinstance(item, str)
            or not 1 <= len(item.encode()) <= MAX_CASE_ID_BYTES
            or not CASE_ID.fullmatch(item)
            for item in value
        )
    ):
        return False
    return len(value) == len(set(value))


def load_replay_source(path: Path) -> dict:
    """Load either an exploration report or its private checkpoint wrapper."""

    data = _read_json(path, MAX_SOURCE_BYTES)
    if isinstance(data, dict) and data.get("schema_version") == 1 and "report" in data:
        if set(data) != {"schema_version", "status", "policy_digest", "exploration", "report"}:
            raise PolicyError("exploration checkpoint has an unsupported shape")
        status = data.get("status")
        outer_exploration = data.get("exploration")
        report = data.get("report")
        nested_exploration = report.get("exploration") if isinstance(report, dict) else None
        consistent_exploration = (
            nested_exploration in (None, outer_exploration)
            if status == "running"
            else nested_exploration == outer_exploration
        )
        if (
            status not in ("running", "complete")
            or not isinstance(report, dict)
            or data.get("policy_digest") != report.get("policy_digest")
            or not consistent_exploration
        ):
            raise PolicyError("exploration checkpoint is internally inconsistent")
        data = dict(report)
        data["exploration"] = outer_exploration
    try:
        validated = _validate_prior_report(data)
    except ValueError:
        raise PolicyError("source is not a compatible PermitProbe report") from None
    if not isinstance(validated.get("exploration"), dict):
        raise PolicyError("replay creation requires an exploration report")
    return validated


def _scheduled_case_ids(report: dict) -> tuple[list[str], list[str]]:
    trace = report["exploration"]
    baseline = trace.get("baseline")
    rounds = trace.get("rounds")
    tail = trace.get("deterministic_tail")
    if (
        trace.get("protocol_version") != 1
        or not _valid_case_ids(baseline)
        or not isinstance(rounds, list)
        or len(rounds) > 20
        or not _valid_case_ids(tail, allow_empty=True)
    ):
        raise PolicyError("exploration trace cannot produce a bounded replay")
    scheduled = list(baseline)
    for round_item in rounds:
        accepted = round_item.get("accepted") if isinstance(round_item, dict) else None
        if not isinstance(accepted, list) or len(accepted) > 64:
            raise PolicyError("exploration trace contains an invalid provider batch")
        for candidate in accepted:
            case_id = candidate.get("case_id") if isinstance(candidate, dict) else None
            if not _valid_case_ids([case_id]):
                raise PolicyError("exploration trace contains an invalid case ID")
            scheduled.append(case_id)
    scheduled.extend(tail)
    if (
        len(scheduled) > MAX_REPLAY_CASES
        or len(scheduled) != len(set(scheduled))
        or scheduled[: len(baseline)] != baseline
    ):
        raise PolicyError("exploration trace contains duplicate or excessive cases")
    evidence = {
        item.get("evidence_id"): item
        for item in report["evidence"]
        if isinstance(item, dict)
    }
    if set(evidence) != set(scheduled) or any(
        evidence[case_id].get("delivery") != "complete" for case_id in scheduled
    ):
        raise PolicyError("every scheduled case must have complete source evidence")
    return baseline, scheduled


@dataclass(frozen=True)
class ReplayManifest:
    permitprobe_version: str
    policy_digest: str
    source_report_digest: str
    baseline_case_ids: tuple[str, ...]
    case_ids: tuple[str, ...]

    def unsigned_dict(self) -> dict:
        return {
            "format_version": FORMAT_VERSION,
            "permitprobe_version": self.permitprobe_version,
            "policy_digest": self.policy_digest,
            "source_report_digest": self.source_report_digest,
            "baseline_case_ids": list(self.baseline_case_ids),
            "case_ids": list(self.case_ids),
        }

    @property
    def manifest_id(self) -> str:
        return "ppr-" + hashlib.sha256(_canonical(self.unsigned_dict())).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {"manifest_id": self.manifest_id, **self.unsigned_dict()}

    def write(self, path: Path) -> None:
        write_private_json(path, self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data):
        expected = {
            "format_version",
            "manifest_id",
            "permitprobe_version",
            "policy_digest",
            "source_report_digest",
            "baseline_case_ids",
            "case_ids",
        }
        if not isinstance(data, dict) or set(data) != expected:
            raise ValueError
        baseline = data["baseline_case_ids"]
        cases = data["case_ids"]
        if (
            data["format_version"] != FORMAT_VERSION
            or not isinstance(data["permitprobe_version"], str)
            or not VERSION.fullmatch(data["permitprobe_version"])
            or not isinstance(data["policy_digest"], str)
            or not HEX_DIGEST.fullmatch(data["policy_digest"])
            or not isinstance(data["source_report_digest"], str)
            or not HEX_DIGEST.fullmatch(data["source_report_digest"])
            or not _valid_case_ids(baseline)
            or not _valid_case_ids(cases)
            or cases[: len(baseline)] != baseline
        ):
            raise ValueError
        manifest = cls(
            data["permitprobe_version"],
            data["policy_digest"],
            data["source_report_digest"],
            tuple(baseline),
            tuple(cases),
        )
        if data["manifest_id"] != manifest.manifest_id:
            raise ValueError
        return manifest

    @classmethod
    def load(cls, path: Path):
        try:
            return cls.from_dict(_read_json(path, MAX_REPLAY_BYTES))
        except PolicyError:
            raise
        except (KeyError, TypeError, ValueError, RecursionError):
            raise PolicyError("cannot read a valid replay manifest") from None


def build_replay_manifest(source_report: dict) -> ReplayManifest:
    try:
        report = _validate_prior_report(source_report)
    except ValueError:
        raise PolicyError("source is not a compatible PermitProbe report") from None
    if not isinstance(report.get("exploration"), dict):
        raise PolicyError("replay creation requires an exploration report")
    baseline, scheduled = _scheduled_case_ids(report)
    return ReplayManifest(
        __version__,
        report["policy_digest"],
        hashlib.sha256(_canonical(report)).hexdigest(),
        tuple(baseline),
        tuple(scheduled),
    )


def run_replay(config: API, manifest: ReplayManifest, report: Report) -> None:
    """Execute only manifest case IDs after binding them to the current policy catalog."""

    current_digest = api_contract_digest(
        config,
        include_exploration=True,
        include_public=False,
        include_linked=False,
    )
    report.policy_digest = current_digest
    report.replay = {
        "format_version": FORMAT_VERSION,
        "manifest_id": manifest.manifest_id,
        "source_report_digest": manifest.source_report_digest,
        "baseline_cases": len(manifest.baseline_case_ids),
        "planned_cases": len(manifest.case_ids),
        "observed_cases": 0,
        "delivery": "blocked",
        "writes": 0,
    }
    if manifest.policy_digest != current_digest:
        report.add(
            "replay.policy",
            "inconclusive",
            "replay",
            "The replay manifest belongs to a different policy or target origin.",
        )
        return
    prepared = prepare_api(
        config,
        report,
        include_exploration=True,
        include_public=False,
        include_linked=False,
    )
    if prepared is None:
        report.replay["delivery"] = "precheck"
        return
    report.planned_cases = {}
    by_id = {case.id: case for case in prepared.cases}
    expected_baseline = tuple(
        case.id
        for case in baseline_cases(
            prepared.cases,
            {resource.name for resource in config.resources},
        )
    )
    if manifest.baseline_case_ids != expected_baseline:
        raise PolicyError("replay manifest does not contain the exact deterministic baseline")
    try:
        selected = [by_id[case_id] for case_id in manifest.case_ids]
    except KeyError:
        raise PolicyError("replay manifest contains a case outside the current policy") from None
    if len(selected) > config.max_cases:
        raise PolicyError("replay manifest exceeds the current request budget")
    report.plan([case_descriptor(case) for case in selected])
    report.add(
        "replay.manifest",
        "pass",
        "replay",
        "Manifest matched the current target-bound policy and deterministic baseline.",
    )
    observations = execute_api_cases(prepared, selected, report)
    finalize_api(
        prepared,
        selected,
        observations,
        report,
        require_full_coverage=False,
    )
    observed = set(report.evidence)
    complete = observed == set(manifest.case_ids) and all(
        item.delivery == "complete" for item in report.evidence.values()
    )
    report.replay["observed_cases"] = len(observed)
    report.replay["delivery"] = "complete" if complete else "incomplete"
    if not complete:
        report.add(
            "replay.delivery",
            "inconclusive",
            "replay",
            "Not every replay case produced complete evidence.",
        )
