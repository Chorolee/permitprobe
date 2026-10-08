"""Public CLI. Inspect, test and bundle; never deploy, upload or alter a target."""

import argparse
import json
from pathlib import Path

from permitprobe import __version__
from permitprobe.api import check_api, compile_matrix
from permitprobe.artifacts import write_private_bytes, write_private_json
from permitprobe.baseline import Baseline, apply_baseline, build_baseline
from permitprobe.collection_demo import run_collection_demo
from permitprobe.demo import example_policy, run_demo
from permitprobe.exploration import ExternalProvider, StateWriter, explore_api
from permitprobe.handoff import check_handoff, write_bundle
from permitprobe.linked_demo import SCENARIOS as LINKED_SCENARIOS
from permitprobe.linked_demo import run_linked_demo
from permitprobe.openapi_inventory import inventory_openapi
from permitprobe.policy import Policy, PolicyError, api_contract_digest, load_policy
from permitprobe.read_demo import SCENARIOS, run_read_demo
from permitprobe.replay import (
    ReplayManifest,
    build_replay_manifest,
    load_replay_source,
    run_replay,
)
from permitprobe.report import Report
from permitprobe.retest import load_prior_report, run_retest
from permitprobe.scan import run_scan


def _target_request_envs(policy: Policy) -> set[str]:
    if policy.api is None:
        return set()
    names = {
        reference
        for subject in policy.api.subjects
        for reference in (subject.token_env, subject.cookie_env)
        if reference is not None
    }
    names.update(
        reference
        for resource in policy.api.public_resources
        for variant in resource.variants
        for reference in variant.header_envs.values()
    )
    return names


def emit(report: Report, fmt: str, output: str | None = None) -> int:
    payload = report.to_dict()
    if output:
        try:
            write_private_json(Path(output), payload)
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
        if payload["baseline"]:
            baseline = payload["baseline"]
            print(
                "  Baseline: "
                f"{baseline['known']} known, {baseline['new']} new, "
                f"{baseline['unobserved']} unobserved, {baseline['expired']} expired"
            )
        if payload["inventory"]:
            inventory = payload["inventory"]
            print(
                "  OpenAPI GET coverage: "
                f"{inventory['covered_get_operations']}/{inventory['get_operations']}; "
                f"non-GET not executed: {inventory['unsupported_non_get_operations']}"
            )
        if payload["discovery"]:
            candidates = payload["discovery"]["candidates"]
            sources = payload["discovery"]["sources"]
            print(
                "  Discovery proposals: "
                f"{candidates['total']} total, {candidates['undeclared']} undeclared; "
                f"fixed sources: {sources['completed']}/{sources['planned']} completed; "
                "discovered requests executed: 0"
            )
        if payload["scan"]:
            scan = payload["scan"]
            stages = scan["stages"]
            requests = scan["requests"]
            print(
                "  One-shot stages: "
                + ", ".join(f"{name}={item['status']}" for name, item in stages.items())
            )
            print(
                "  One-shot requests: "
                f"{requests['observed']}/{requests['planned']} observed, "
                f"{requests['writes']} writes"
            )
        if payload["replay"]:
            replay = payload["replay"]
            print(
                "  Replay cases: "
                f"{replay['observed_cases']}/{replay['planned_cases']} observed, "
                f"delivery={replay['delivery']}, {replay['writes']} writes"
            )
        if payload["unconfigured_surfaces"]:
            print("  Not configured: " + ", ".join(payload["unconfigured_surfaces"]))
    return report.exit_code


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Scan declared website, API, data and AI handoff boundaries."
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
        else:
            p.add_argument("--baseline", type=Path, help="Apply a reviewed known-finding baseline")
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
    linked = commands.add_parser(
        "demo-linked", help="Run synthetic linked API/storage read cases"
    )
    linked.add_argument("--scenario", choices=LINKED_SCENARIOS, default="safe")
    linked.add_argument("--format", choices=("text", "json"), default="text")
    linked.add_argument("--report")
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
    replay_create = commands.add_parser(
        "replay-create",
        help="Create a sanitized deterministic manifest from an exploration report or state",
    )
    replay_create.add_argument("source", type=Path)
    replay_create.add_argument("--output", required=True, type=Path)
    replay_create.add_argument("--format", choices=("text", "json"), default="text")
    replay = commands.add_parser(
        "replay",
        help="Run an exact sanitized exploration manifest without an AI provider",
    )
    replay.add_argument("policy", type=Path)
    replay.add_argument("--manifest", required=True, type=Path)
    replay.add_argument("--format", choices=("text", "json"), default="text")
    replay.add_argument("--report", help="Create a new JSON report (never overwrite)")
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
    inventory.add_argument("--baseline", type=Path, help="Apply a reviewed known-finding baseline")
    baseline = commands.add_parser(
        "baseline",
        help="Create a reviewed known-finding baseline from a report",
    )
    baseline.add_argument("report", type=Path)
    baseline.add_argument("--output", required=True, type=Path)
    baseline.add_argument("--previous", type=Path)
    baseline.add_argument("--format", choices=("text", "json"), default="text")
    scan = commands.add_parser(
        "scan",
        help="Run every deterministic declared website check in one assessment",
    )
    scan.add_argument("policy", type=Path)
    scan.add_argument("--openapi", type=Path)
    scan.add_argument("--baseline", type=Path)
    scan.add_argument("--gitleaks", help="Path to Gitleaks 8.30.1; defaults to PATH lookup")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--report", help="Create a new JSON report (never overwrite)")
    commands.add_parser("schema", help="Print the policy JSON Schema")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "schema":
            print(json.dumps(Policy.model_json_schema(), indent=2))
            return 0
        if args.command == "init":
            args.directory.mkdir(parents=True, mode=0o700, exist_ok=False)
            write_private_json(
                args.directory / "permitprobe.json",
                example_policy(),
            )
            write_private_bytes(
                args.directory / "review.txt",
                b"Replace with the text you intend to hand off.\n",
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
        if args.command == "demo-linked":
            return emit(run_linked_demo(args.scenario), args.format, args.report)
        if args.command == "baseline":
            previous = Baseline.load(args.previous) if args.previous else None
            baseline, summary = build_baseline(load_prior_report(args.report), previous)
            baseline.write(args.output)
            if args.format == "json":
                print(json.dumps(summary, indent=2))
            else:
                print(
                    "PermitProbe baseline created: "
                    f"{summary['entries']} entries, {summary['recorded']} recorded, "
                    f"{summary['carried_unobserved']} carried unobserved"
                )
            return 0
        if args.command == "replay-create":
            manifest = build_replay_manifest(load_replay_source(args.source))
            manifest.write(args.output)
            if args.format == "json":
                print(json.dumps(manifest.to_dict(), indent=2))
            else:
                print(
                    "PermitProbe replay created: "
                    f"{len(manifest.case_ids)} cases, "
                    f"{len(manifest.baseline_case_ids)} deterministic baseline cases"
                )
            return 0
        policy_path = args.policy.resolve(strict=True)
        policy = load_policy(policy_path)
        policy_dir = policy_path.parent
        if args.command == "replay":
            if not policy.api:
                raise PolicyError("replay needs an API policy")
            report = Report()
            run_replay(policy.api, ReplayManifest.load(args.manifest), report)
            return emit(report, args.format, args.report)
        known = None
        if getattr(args, "baseline", None):
            if not policy.api:
                raise PolicyError("a known-finding baseline requires an API policy")
            known = Baseline.load(args.baseline)
            known.require_policy(api_contract_digest(policy.api))
        if args.command == "explore":
            if not policy.api or args.state.exists():
                raise PolicyError("explore needs an API policy and a new state path")
            if set(args.provider_env) & _target_request_envs(policy):
                raise PolicyError("provider environment cannot include target request values")
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
            write_private_json(args.output, result)
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
            write_private_json(args.output, matrix)
            print(
                "Auth-only matrix exported. PermitProbe data/control checks are not part of this export."
            )
            return 0
        if args.command == "inventory-openapi":
            if not policy.api:
                raise PolicyError("inventory-openapi needs an API policy")
            report = Report()
            inventory_openapi(policy.api, args.openapi, report)
            if known:
                apply_baseline(report, known)
            return emit(report, args.format, args.report)
        if args.command == "scan":
            if not policy.api:
                raise PolicyError("scan needs an API policy")
            report = Report(policy_digest=known.policy_digest if known else None)
            run_scan(
                policy,
                policy_dir,
                report,
                openapi=args.openapi,
                gitleaks=args.gitleaks,
                baseline=known,
            )
            return emit(report, args.format, args.report)
        report = Report(policy_digest=known.policy_digest if known else None)
        snapshot = {}
        if args.command == "check" and policy.api:
            check_api(policy.api, report)
        if policy.handoff:
            snapshot = check_handoff(policy.handoff, policy_dir, report, args.gitleaks)
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
        if known:
            apply_baseline(report, known)
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
