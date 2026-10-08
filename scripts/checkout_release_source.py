#!/usr/bin/env python3
"""Check out a release tag only when its commit belongs to trusted main history."""

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def _git(repository: Path, *arguments: str, output: bool = False) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("git is required")
    env = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }
    result = subprocess.run(  # noqa: S603
        [
            executable,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(repository),
            *arguments,
        ],
        env=env,
        stdout=subprocess.PIPE if output else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("git rejected the requested release source")
    return result.stdout.strip() if output else ""


def checkout_release_source(repository: Path, tag: str, output: Path) -> str:
    repository = repository.resolve(strict=True)
    output = output.absolute()
    if not TAG.fullmatch(tag) or output.exists() or output.is_symlink():
        raise ValueError("expected a stable tag and a new output path")
    commit = _git(
        repository,
        "rev-parse",
        "--verify",
        f"refs/tags/{tag}^{{commit}}",
        output=True,
    )
    if not COMMIT.fullmatch(commit):
        raise ValueError("tag did not resolve to a commit")
    _git(repository, "merge-base", "--is-ancestor", commit, "HEAD")
    _git(repository, "worktree", "add", "--detach", str(output), commit)
    return commit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        commit = checkout_release_source(args.repository, args.tag, args.output)
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(2, "Release source checkout failed.\n")
    print(f"Checked out trusted release commit {commit}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
