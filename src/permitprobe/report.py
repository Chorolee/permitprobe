"""Reports contain normalized facts, never response bodies, credentials or file contents."""

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Literal

Outcome = Literal["pass", "fail", "inconclusive"]


@dataclass
class Check:
    code: str
    outcome: Outcome
    target: str
    detail: str
    evidence_id: str | None = None


@dataclass(frozen=True)
class Evidence:
    """One delivered case, reduced to the fields needed for lineage and retests."""

    evidence_id: str
    resource: str
    subject: str
    owner: str | None
    variant: str
    expected: str
    observed: str
    status: int
    delivery: Literal["complete", "failed", "skipped"]
    elapsed_ms: int | None = None


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    configured: list[str] = field(default_factory=list)
    engines: dict[str, str] = field(default_factory=dict)
    policy_digest: str | None = None
    planned_cases: dict[str, dict] = field(default_factory=dict)
    evidence: dict[str, Evidence] = field(default_factory=dict)
    exploration: dict | None = None
    inventory: dict | None = None
    baseline: dict | None = None
    _known_failure_keys: set[tuple[str, str]] = field(default_factory=set, repr=False)

    def add(
        self,
        code: str,
        outcome: Outcome,
        target: str,
        detail: str,
        evidence_id: str | None = None,
    ) -> None:
        self.checks.append(Check(code, outcome, target, detail, evidence_id))

    def plan(self, cases: list[dict]) -> None:
        for case in cases:
            case_id = case["case_id"]
            if case_id in self.planned_cases:
                raise ValueError("duplicate planned case")
            self.planned_cases[case_id] = case

    def observe(self, item: Evidence) -> None:
        if item.evidence_id not in self.planned_cases or item.evidence_id in self.evidence:
            raise ValueError("unknown or duplicate evidence")
        self.evidence[item.evidence_id] = item

    def finding_groups(self) -> list[dict]:
        groups: dict[tuple[str, str], list[Check]] = {}
        for check in self.checks:
            if check.outcome != "fail":
                continue
            resource = check.target.split("/", 1)[0]
            groups.setdefault((check.code, resource), []).append(check)
        findings = []
        for (code, resource), checks in sorted(groups.items()):
            key = f"{self.policy_digest or 'no-policy'}\0{code}\0{resource}"
            findings.append(
                {
                    "finding_id": "pp-" + hashlib.sha256(key.encode()).hexdigest()[:16],
                    "code": code,
                    "resource": resource,
                    "state": "open",
                    "occurrences": len(checks),
                    "evidence_ids": sorted(
                        {check.evidence_id for check in checks if check.evidence_id}
                    ),
                    "targets": sorted({check.target for check in checks}),
                }
            )
        return findings

    @property
    def exit_code(self) -> int:
        incomplete = bool(self.planned_cases) and set(self.evidence) != set(self.planned_cases)
        if (
            not self.checks
            or incomplete
            or any(c.outcome == "inconclusive" for c in self.checks)
        ):
            return 2
        failures = {(check.code, check.target) for check in self.checks if check.outcome == "fail"}
        return 1 if failures - self._known_failure_keys else 0

    def to_dict(self) -> dict:
        observed = set(self.evidence)
        planned = set(self.planned_cases)
        status = {0: "pass", 1: "fail", 2: "inconclusive"}[self.exit_code]
        if self.exit_code == 0 and any(check.outcome == "fail" for check in self.checks):
            status = "known_findings"
        return {
            "schema_version": 2,
            "status": status,
            "exit_code": self.exit_code,
            "policy_digest": self.policy_digest,
            "configured_surfaces": self.configured,
            "unconfigured_surfaces": [
                s for s in ("api", "data", "handoff") if s not in self.configured
            ],
            "engines": self.engines,
            "counts": {
                s: sum(c.outcome == s for c in self.checks)
                for s in ("pass", "fail", "inconclusive")
            },
            "coverage": {
                "planned": len(planned),
                "observed": len(observed),
                "unprobed": sorted(planned - observed),
            },
            "evidence": [asdict(self.evidence[key]) for key in self.planned_cases if key in observed],
            "findings": self.finding_groups(),
            "exploration": self.exploration,
            "inventory": self.inventory,
            "baseline": self.baseline,
            "checks": [asdict(c) for c in self.checks],
        }
