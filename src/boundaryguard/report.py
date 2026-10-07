"""Reports deliberately contain no response bodies, credentials, or file contents."""

from dataclasses import asdict, dataclass, field
from typing import Literal

Outcome = Literal["pass", "fail", "inconclusive"]


@dataclass
class Check:
    code: str
    outcome: Outcome
    target: str
    detail: str


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    configured: list[str] = field(default_factory=list)
    engines: dict[str, str] = field(default_factory=dict)

    def add(self, code: str, outcome: Outcome, target: str, detail: str) -> None:
        self.checks.append(Check(code, outcome, target, detail))

    @property
    def exit_code(self) -> int:
        if not self.checks or any(c.outcome == "inconclusive" for c in self.checks):
            return 2
        return 1 if any(c.outcome == "fail" for c in self.checks) else 0

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "status": {0: "pass", 1: "fail", 2: "inconclusive"}[self.exit_code],
            "exit_code": self.exit_code,
            "configured_surfaces": self.configured,
            "unconfigured_surfaces": [
                s for s in ("api", "data", "handoff") if s not in self.configured
            ],
            "engines": self.engines,
            "counts": {
                s: sum(c.outcome == s for c in self.checks)
                for s in ("pass", "fail", "inconclusive")
            },
            "checks": [asdict(c) for c in self.checks],
        }
