"""Public CLI. Inspect, test and bundle; never deploy, upload or alter a target."""

import argparse
import json
from pathlib import Path

from permitprobe import __version__
from permitprobe.api import check_api, compile_matrix
from permitprobe.collection_demo import run_collection_demo
from permitprobe.demo import example_policy, run_demo
from permitprobe.handoff import check_handoff, write_bundle
from permitprobe.policy import Policy, PolicyError, load_policy
from permitprobe.report import Report


def emit(report: Report, fmt: str, output: str | None = None) -> int:
    payload = report.to_dict()
    if output:
        try:
            with Path(output).open("x", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.write("\n")
        except OSError:
            report.add(
                "report.write",
                "inconclusive",
                "report",
                "Cannot create report; no file overwritten.",
            )
            payload = report.to_dict()
    if fmt == "json":
        print(json.dumps(payload, indent=2))
    else:
        c = payload["counts"]
        print(
            f"PermitProbe {payload['status'].upper()}: "
            f"{c['pass']} passed, {c['fail']} failed, {c['inconclusive']} inconclusive"
        )
        for item in report.checks:
            if item.outcome != "pass":
                print(f"  {item.outcome.upper()} {item.code} [{item.target}]: {item.detail}")
        if payload["unconfigured_surfaces"]:
            print("  Not configured: " + ", ".join(payload["unconfigured_surfaces"]))
    return report.exit_code


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Check declared API, data and AI handoff boundaries."
    )
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("check", "bundle"):
        p = commands.add_parser(name)
        p.add_argument("policy", type=Path)
        p.add_argument("--gitleaks", help="Path to Gitleaks 8.30.1; defaults to PATH lookup")
        p.add_argument("--format", choices=("text", "json"), default="text")
        p.add_argument("--report", help="Create a new JSON report (never overwrite)")
        if name == "bundle":
            p.add_argument(
                "--output", required=True, type=Path, help="Create a checked ZIP locally"
            )
    demo = commands.add_parser("demo", help="Run synthetic fixtures on loopback")
    demo.add_argument(
        "--scenario",
        choices=("safe", "leaky", "schema-leak", "expired", "server-error"),
        default="safe",
    )
    demo.add_argument("--gitleaks")
    demo.add_argument("--format", choices=("text", "json"), default="text")
    demo.add_argument("--report")
    collection = commands.add_parser("demo-collection", help="Run a synthetic private collection")
    collection.add_argument(
        "--scenario", choices=("safe", "leaky", "empty", "expired", "server-error"), default="safe"
    )
    collection.add_argument("--format", choices=("text", "json"), default="text")
    collection.add_argument("--report")
    init = commands.add_parser("init", help="Create a starter in a NEW directory")
    init.add_argument("directory", type=Path)
    export = commands.add_parser(
        "export-overstep", help="Export an auth-only matrix, without secrets"
    )
    export.add_argument("policy", type=Path)
    export.add_argument("--output", required=True, type=Path)
    commands.add_parser("schema", help="Print the policy JSON Schema")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "schema":
            print(json.dumps(Policy.model_json_schema(), indent=2))
            return 0
        if args.command == "init":
            args.directory.mkdir(parents=True, exist_ok=False)
            (args.directory / "permitprobe.json").write_text(
                json.dumps(example_policy(), indent=2) + "\n"
            )
            (args.directory / "review.txt").write_text(
                "Replace with the text you intend to hand off.\n"
            )
            print(
                "Starter created. Set your staging origin, object IDs, response schema and token environment variables."
            )
            return 0
        if args.command == "demo":
            return emit(run_demo(args.scenario, args.gitleaks), args.format, args.report)
        if args.command == "demo-collection":
            return emit(run_collection_demo(args.scenario), args.format, args.report)
        policy = load_policy(args.policy)
        if args.command == "export-overstep":
            if not policy.api:
                raise PolicyError("policy has no API surface")
            matrix = compile_matrix(policy.api)
            with args.output.open("x", encoding="utf-8") as f:
                json.dump(matrix, f, indent=2)
                f.write("\n")
            print(
                "Auth-only matrix exported. PermitProbe data/control checks are not part of this export."
            )
            return 0
        report = Report()
        snapshot = {}
        if args.command == "check" and policy.api:
            check_api(policy.api, report)
        if policy.handoff:
            snapshot = check_handoff(policy.handoff, args.policy.parent, report, args.gitleaks)
        elif args.command == "bundle":
            raise PolicyError("policy has no handoff surface")
        if args.command == "bundle" and report.exit_code == 0:
            try:
                write_bundle(snapshot, args.output)
                report.add(
                    "handoff.bundle",
                    "pass",
                    "handoff",
                    "Checked bytes written to a local ZIP; nothing sent.",
                )
            except OSError:
                report.add(
                    "handoff.bundle",
                    "inconclusive",
                    "handoff",
                    "Cannot create bundle; no existing file overwritten.",
                )
        return emit(report, args.format, args.report)
    except (PolicyError, OSError, ValueError, RecursionError):
        # No exception text: parsers and network libraries may quote secret input.
        report = Report()
        report.add(
            "configuration",
            "inconclusive",
            "policy",
            "Invalid or unreadable policy, unsupported operation, or existing output path.",
        )
        return emit(report, getattr(args, "format", "text"))
