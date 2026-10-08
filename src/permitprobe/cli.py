"""Public CLI. Inspect, test and bundle; never deploy, upload or alter a target."""

import argparse
import json
from pathlib import Path

from permitprobe import __version__
from permitprobe.api import check_api, compile_matrix
from permitprobe.collection_demo import run_collection_demo
from permitprobe.demo import example_policy, run_demo
from permitprobe.exploration import ExternalProvider, StateWriter, explore_api
from permitprobe.handoff import check_handoff, write_bundle
from permitprobe.openapi_inventory import inventory_openapi
from permitprobe.policy import Policy, PolicyError, load_policy
from permitprobe.read_demo import SCENARIOS, run_read_demo
from permitprobe.report import Report
from permitprobe.retest import load_prior_report, run_retest


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
        if payload["inventory"]:
            inventory = payload["inventory"]
            print(
                "  OpenAPI GET coverage: "
                f"{inventory['covered_get_operations']}/{inventory['get_operations']}; "
                f"non-GET not executed: {inventory['unsupported_non_get_operations']}"
            )
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
    reads = commands.add_parser("demo-read-paths", help="Run synthetic file-grant and role cases")
    reads.add_argument("--scenario", choices=SCENARIOS, default="safe")
    reads.add_argument("--format", choices=("text", "json"), default="text")
    reads.add_argument("--report")
    explore = commands.add_parser(
        "explore", help="Run bounded active exploration through a model-neutral provider"
    )
    explore.add_argument("policy", type=Path)
    explore.add_argument("--provider-command", required=True, type=Path)
    explore.add_argument("--provider-arg", action="append", default=[])
    explore.add_argument("--provider-env", action="append", default=[])
    explore.add_argument("--provider-name", default="external")
    explore.add_argument("--state", required=True, type=Path)
    explore.add_argument("--max-rounds", type=int, default=4)
    explore.add_argument("--batch-size", type=int, default=16)
    explore.add_argument("--max-requests", type=int)
    explore.add_argument("--provider-timeout", type=int, default=120)
    explore.add_argument("--max-seconds", type=int, default=600)
    explore.add_argument(
        "--complete",
        action="store_true",
        help="After AI-selected rounds, run the remaining declared cases deterministically",
    )
    explore.add_argument("--format", choices=("text", "json"), default="text")
    explore.add_argument("--report")
    retest = commands.add_parser("retest", help="Rerun one retained finding with controls")
    retest.add_argument("policy", type=Path)
    retest.add_argument("--prior-report", required=True, type=Path)
    retest.add_argument("--finding", required=True)
    retest.add_argument("--output", required=True, type=Path)
    retest.add_argument("--change-ref")
    retest.add_argument("--format", choices=("text", "json"), default="text")
    init = commands.add_parser("init", help="Create a starter in a NEW directory")
    init.add_argument("directory", type=Path)
    export = commands.add_parser(
        "export-overstep", help="Export an auth-only matrix, without secrets"
    )
    export.add_argument("policy", type=Path)
    export.add_argument("--output", required=True, type=Path)
    inventory = commands.add_parser(
        "inventory-openapi",
        help="Compare a local OpenAPI JSON document with declared GET checks",
    )
    inventory.add_argument("policy", type=Path)
    inventory.add_argument("--openapi", required=True, type=Path)
    inventory.add_argument("--format", choices=("text", "json"), default="text")
    inventory.add_argument("--report", help="Create a new JSON report (never overwrite)")
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
        if args.command == "demo-read-paths":
            return emit(run_read_demo(args.scenario), args.format, args.report)
        policy = load_policy(args.policy)
        if args.command == "explore":
            if not policy.api or args.state.exists():
                raise PolicyError("explore needs an API policy and a new state path")
            provider = ExternalProvider(
                args.provider_name,
                [str(args.provider_command), *args.provider_arg],
                args.provider_env,
            )
            report = Report()
            explore_api(
                policy.api,
                report,
                provider,
                max_rounds=args.max_rounds,
                max_candidates_per_round=args.batch_size,
                max_requests_total=args.max_requests,
                provider_timeout_seconds=args.provider_timeout,
                max_seconds_total=args.max_seconds,
                complete=args.complete,
                checkpoint=StateWriter(args.state).write,
            )
            return emit(report, args.format, args.report)
        if args.command == "retest":
            if not policy.api or args.output.exists():
                raise PolicyError("retest needs an API policy and a new output path")
            verdict, result = run_retest(
                policy.api,
                load_prior_report(args.prior_report),
                args.finding,
                change_ref=args.change_ref,
            )
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2)
                handle.write("\n")
            if args.format == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"PermitProbe retest {verdict.upper()}: {args.finding}")
            return {"fixed": 0, "reproduced": 1, "not_reproduced": 2, "inconclusive": 2}[
                verdict
            ]
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
        if args.command == "inventory-openapi":
            if not policy.api:
                raise PolicyError("inventory-openapi needs an API policy")
            report = Report()
            inventory_openapi(policy.api, args.openapi, report)
            return emit(report, args.format, args.report)
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
