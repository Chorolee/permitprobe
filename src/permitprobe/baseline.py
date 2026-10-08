"""Explicit known-finding baselines that never suppress incomplete evidence."""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from permitprobe import __version__
from permitprobe.artifacts import write_private_json
from permitprobe.policy import PolicyError, _unique
from permitprobe.report import Report
from permitprobe.retest import _validate_prior_report

FORMAT_VERSION = 1
MAX_BASELINE_BYTES = 5_000_000
MAX_ENTRIES = 4_096
CODE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
INELIGIBLE_PREFIXES = ("availability.", "discovery.", "handoff.")

FailureKey = tuple[str, str]


def is_eligible(code: str) -> bool:
    return bool(CODE.fullmatch(code)) and not code.startswith(INELIGIBLE_PREFIXES)


def _valid_target(target: str) -> bool:
    return (
        isinstance(target, str)
        and 1 <= len(target) <= 1_024
        and all(char.isprintable() and char not in "\r\n" for char in target)
    )


def _date(value: str) -> date:
    if not isinstance(value, str) or not DATE.fullmatch(value):
        raise ValueError
    return date.fromisoformat(value)


def baseline_entry_id(policy_digest: str, code: str, target: str) -> str:
    key = f"{policy_digest}\0{code}\0{target}"
    return "ppb-" + hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class BaselineEntry:
    code: str
    target: str
    first_seen: str
    last_seen: str
    expires: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> FailureKey:
        return self.code, self.target

    def entry_id(self, policy_digest: str) -> str:
        return baseline_entry_id(policy_digest, self.code, self.target)

    def is_expired(self, today: date) -> bool:
        return self.expires is not None and _date(self.expires) < today

    def to_dict(self, policy_digest: str) -> dict:
        data = {
            "id": self.entry_id(policy_digest),
            "code": self.code,
            "target": self.target,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }
        if self.expires is not None:
            data["expires"] = self.expires
        data.update(self.extra)
        return data

    @classmethod
    def from_dict(cls, data, policy_digest: str):
        if not isinstance(data, dict) or len(data) > 40:
            raise ValueError
        code = data.get("code")
        target = data.get("target")
        first_seen = data.get("first_seen")
        last_seen = data.get("last_seen")
        expires = data.get("expires")
        if (
            not isinstance(code, str)
            or not is_eligible(code)
            or not _valid_target(target)
            or not isinstance(first_seen, str)
            or not isinstance(last_seen, str)
        ):
            raise ValueError
        first = _date(first_seen)
        last = _date(last_seen)
        if last < first or (expires is not None and not isinstance(expires, str)):
            raise ValueError
        if expires is not None:
            _date(expires)
        expected_id = baseline_entry_id(policy_digest, code, target)
        if data.get("id") != expected_id:
            raise ValueError
        reserved = {"id", "code", "target", "first_seen", "last_seen", "expires"}
        extra = {key: value for key, value in data.items() if key not in reserved}
        if any(
            not isinstance(key, str)
            or not 1 <= len(key) <= 64
            or not all(char.isprintable() for char in key)
            for key in extra
        ):
            raise ValueError
        return cls(code, target, first_seen, last_seen, expires, extra)


@dataclass
class Baseline:
    policy_digest: str
    entries: list[BaselineEntry]

    def require_policy(self, policy_digest: str) -> None:
        if self.policy_digest != policy_digest:
            raise PolicyError("baseline policy digest does not match the current API policy")

    def to_dict(self) -> dict:
        return {
            "format_version": FORMAT_VERSION,
            "permitprobe_version": __version__,
            "policy_digest": self.policy_digest,
            "entries": [
                entry.to_dict(self.policy_digest)
                for entry in sorted(self.entries, key=lambda item: item.key)
            ],
        }

    def write(self, path: Path) -> None:
        write_private_json(path, self.to_dict(), ensure_ascii=False)

    @classmethod
    def load(cls, path: Path):
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_BASELINE_BYTES + 1)
            if len(raw) > MAX_BASELINE_BYTES:
                raise ValueError
            data = json.loads(
                raw,
                object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            if not isinstance(data, dict) or set(data) != {
                "format_version",
                "permitprobe_version",
                "policy_digest",
                "entries",
            }:
                raise ValueError
            digest = data.get("policy_digest")
            entries = data.get("entries")
            if (
                data.get("format_version") != FORMAT_VERSION
                or not isinstance(data.get("permitprobe_version"), str)
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not isinstance(entries, list)
                or len(entries) > MAX_ENTRIES
            ):
                raise ValueError
            parsed = [BaselineEntry.from_dict(entry, digest) for entry in entries]
            if len({entry.key for entry in parsed}) != len(parsed):
                raise ValueError
            return cls(digest, parsed)
        except (OSError, ValueError, RecursionError, UnicodeError):
            raise PolicyError("cannot read a compatible PermitProbe baseline") from None


def build_baseline(
    report_data: dict,
    previous: Baseline | None = None,
    *,
    today: date | None = None,
) -> tuple[Baseline, dict]:
    try:
        report_data = _validate_prior_report(report_data)
    except ValueError:
        raise PolicyError("cannot baseline an incompatible PermitProbe report") from None
    coverage = report_data.get("coverage")
    if (
        not isinstance(coverage, dict)
        or type(coverage.get("planned")) is not int
        or type(coverage.get("observed")) is not int
        or not isinstance(coverage.get("unprobed"), list)
        or coverage["planned"] != coverage["observed"]
        or coverage["observed"] != len(report_data["evidence"])
        or coverage["unprobed"]
        or report_data.get("exit_code") not in (0, 1)
        or any(check["outcome"] == "inconclusive" for check in report_data["checks"])
    ):
        raise PolicyError("inconclusive reports cannot be baselined")
    failures = {
        (check["code"], check["target"])
        for check in report_data["checks"]
        if check["outcome"] == "fail"
    }
    if not failures or any(
        not is_eligible(code) or not _valid_target(target) for code, target in failures
    ):
        raise PolicyError("report has no eligible failures or contains a non-baselineable failure")
    digest = report_data["policy_digest"]
    if previous is not None:
        previous.require_policy(digest)
    stamp = (today or date.today()).isoformat()
    existing = {entry.key: entry for entry in previous.entries} if previous else {}
    entries = dict(existing)
    recorded = 0
    for code, target in sorted(failures):
        prior = existing.get((code, target))
        if prior is None:
            entries[(code, target)] = BaselineEntry(code, target, stamp, stamp)
            recorded += 1
        else:
            entries[(code, target)] = BaselineEntry(
                prior.code,
                prior.target,
                prior.first_seen,
                stamp,
                prior.expires,
                prior.extra,
            )
    if len(entries) > MAX_ENTRIES:
        raise PolicyError("baseline entry budget exceeded")
    baseline = Baseline(digest, list(entries.values()))
    return baseline, {
        "entries": len(entries),
        "observed": len(failures),
        "recorded": recorded,
        "carried_unobserved": len(set(existing) - failures),
    }


def apply_baseline(report: Report, baseline: Baseline, *, today: date | None = None) -> None:
    now = today or date.today()
    failures = {(check.code, check.target) for check in report.checks if check.outcome == "fail"}
    if report.policy_digest != baseline.policy_digest:
        report.baseline = {
            "policy_match": False,
            "known": 0,
            "new": len(failures),
            "unobserved": len(baseline.entries),
            "expired": 0,
            "known_ids": [],
            "new_ids": sorted(baseline_entry_id(baseline.policy_digest, *key) for key in failures),
            "unobserved_ids": sorted(
                entry.entry_id(baseline.policy_digest) for entry in baseline.entries
            ),
            "expired_ids": [],
        }
        report.add(
            "baseline.policy",
            "inconclusive",
            "baseline",
            "The baseline policy digest does not match this run.",
        )
        return
    active = {entry.key: entry for entry in baseline.entries if not entry.is_expired(now)}
    expired = [entry for entry in baseline.entries if entry.is_expired(now)]
    known = failures & set(active)
    new = failures - known
    unobserved = set(active) - failures
    report._known_failure_keys = known
    report.baseline = {
        "policy_match": True,
        "known": len(known),
        "new": len(new),
        "unobserved": len(unobserved),
        "expired": len(expired),
        "known_ids": sorted(active[key].entry_id(baseline.policy_digest) for key in known),
        "new_ids": sorted(baseline_entry_id(baseline.policy_digest, *key) for key in new),
        "unobserved_ids": sorted(
            active[key].entry_id(baseline.policy_digest) for key in unobserved
        ),
        "expired_ids": sorted(entry.entry_id(baseline.policy_digest) for entry in expired),
    }
