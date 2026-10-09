#!/usr/bin/env python3
"""Install a built wheel in a new environment and exercise its packaged CLI."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(command: list[str], *, cwd: Path, timeout: int = 300) -> str:
    # Callers construct argv from fixed module names and resolved release paths.
    result = subprocess.run(  # noqa: S603
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("isolated wheel smoke command failed")
    return result.stdout


def smoke(wheel: Path, requirements: Path, gitleaks: Path) -> dict[str, str]:
    wheel = wheel.resolve(strict=True)
    requirements = requirements.resolve(strict=True)
    gitleaks = gitleaks.resolve(strict=True)
    match = re.fullmatch(r"permitprobe-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl", wheel.name)
    if not match or not wheel.is_file() or not requirements.is_file() or not gitleaks.is_file():
        raise ValueError("expected a stable PermitProbe wheel, locked requirements and scanner")
    expected_version = match.group(1)

    with tempfile.TemporaryDirectory(prefix="permitprobe-wheel-") as temporary:
        root = Path(temporary)
        environment = root / "venv"
        # Isolated mode ignores PYTHONPATH, user-site packages and other
        # PYTHON* settings inherited from the release runner. Every Python
        # process in this smoke test must resolve modules from the interpreter
        # or the newly installed virtual environment.
        _run([sys.executable, "-I", "-m", "venv", str(environment)], cwd=root)
        python = environment / "bin" / "python"
        command = [str(python), "-I", "-m", "permitprobe"]
        _run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "--isolated",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--require-hashes",
                "--only-binary=:all:",
                "--requirement",
                str(requirements),
            ],
            cwd=root,
        )
        _run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "--isolated",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--no-deps",
                str(wheel),
            ],
            cwd=root,
        )
        _run([str(python), "-I", "-m", "pip", "--isolated", "check"], cwd=root)
        observed_version = _run([*command, "--version"], cwd=root).strip()
        if observed_version != expected_version:
            raise ValueError("installed CLI version does not match the wheel")
        schema = json.loads(_run([*command, "schema"], cwd=root))
        if schema.get("title") != "Policy" or schema.get("additionalProperties") is not False:
            raise ValueError("installed CLI emitted an incompatible policy schema")
        demo = json.loads(
            _run(
                [
                    *command,
                    "demo",
                    "--scenario",
                    "safe",
                    "--gitleaks",
                    str(gitleaks),
                    "--format",
                    "json",
                ],
                cwd=root,
            )
        )
        if demo.get("status") != "pass" or demo.get("exit_code") != 0:
            raise ValueError("installed CLI safe demo did not pass")
    return {"version": expected_version, "schema": "valid", "safe_demo": "pass"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument(
        "--requirements",
        "--constraint",
        dest="requirements",
        type=Path,
        default=Path("requirements.lock"),
    )
    parser.add_argument("--gitleaks", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = smoke(args.wheel, args.requirements, args.gitleaks)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError):
        parser.exit(2, "Wheel smoke test failed.\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
