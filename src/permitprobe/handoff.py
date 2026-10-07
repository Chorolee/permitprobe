"""Check explicit text-file handoffs and export exactly the bytes that were scanned."""

import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from permitprobe.policy import Handoff
from permitprobe.report import Report

GITLEAKS_VERSION = "8.30.1"
RECEIPT_NAME = "PERMITPROBE-MANIFEST.json"
PRIVATE_DIRS = {".git", ".ssh", ".aws", ".azure", ".kube", ".memory", ".venv"}
PRIVATE_FILES = {".gitleaks.toml", ".gitleaksignore", "credentials", "id_rsa", "id_ed25519"}


def _denied(name: str, policy: Handoff) -> bool:
    parts = PurePosixPath(name).parts
    lowered = [p.lower() for p in parts]
    if any(p in PRIVATE_DIRS for p in lowered):
        return True
    leaf = lowered[-1]
    if (
        leaf == ".env"
        or leaf.startswith(".env.")
        or leaf.endswith(".env")
        or leaf in PRIVATE_FILES
        or leaf.endswith((".pem", ".key", ".p12", ".pfx"))
        or name == RECEIPT_NAME
    ):
        return True
    return not any(fnmatch.fnmatchcase(name, p) for p in policy.allow) or any(
        fnmatch.fnmatchcase(name, p) for p in policy.deny
    )


def _read_under(root_fd: int, parts: tuple[str, ...], limit: int) -> bytes:
    """Resolve every component relative to an open directory without following links."""
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        with os.fdopen(fd, "rb") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise ValueError("not a bounded regular, unlinked file")
            body = f.read(limit + 1)
            if len(body) > limit:
                raise ValueError("oversized file")
        body.decode("utf-8")
        if b"\x00" in body:
            raise ValueError("binary content")
        return body
    finally:
        os.close(current)


def collect(policy: Handoff, policy_dir: Path, report: Report) -> dict[str, bytes]:
    snapshot = {}
    total = 0
    root = policy_dir / policy.root
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        report.add("handoff.root", "inconclusive", "handoff", "Cannot open handoff directory.")
        return snapshot
    try:
        for name in policy.files:
            path = PurePosixPath(name)
            if (
                path.is_absolute()
                or not path.parts
                or ".." in path.parts
                or "\\" in name
                or str(path) != name
                or name.endswith("/")
                or ":" in name
                or any(p.endswith((".", " ")) for p in path.parts)
            ):
                report.add("handoff.path", "fail", "handoff", "Non-canonical relative file path.")
                continue
            if _denied(name, policy):
                report.add(
                    "handoff.policy", "fail", name, "File is outside the declared handoff boundary."
                )
                continue
            try:
                body = _read_under(fd, path.parts, policy.max_file_bytes)
            except (OSError, ValueError):
                report.add(
                    "handoff.read",
                    "inconclusive",
                    name,
                    "Not a readable bounded UTF-8 regular file; links are not followed.",
                )
                continue
            total += len(body)
            if total > policy.max_total_bytes:
                report.add(
                    "handoff.budget", "inconclusive", "handoff", "Total byte budget exceeded."
                )
                break
            snapshot[name] = body
            report.add("handoff.path", "pass", name, "Explicit file captured within boundary.")
    finally:
        os.close(fd)
    return snapshot


def scan(snapshot: dict[str, bytes], report: Report, binary: str | None = None) -> None:
    executable = shutil.which(binary or "gitleaks")
    if not executable:
        report.add("handoff.scanner", "inconclusive", "handoff", "Gitleaks 8.30.1 is required.")
        return
    executable = str(Path(executable).resolve())
    # No cloud/database/agent credentials, scanner config overrides, or proxy vars.
    env = {"PATH": os.defpath, "LANG": "C.UTF-8"}
    try:
        result = subprocess.run(
            [executable, "version"], env=env, capture_output=True, timeout=10, check=False
        )
        if (
            result.returncode
            or result.stdout.decode().strip().removeprefix("v") != GITLEAKS_VERSION
        ):
            raise ValueError("unsupported scanner")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        report.add("handoff.scanner", "inconclusive", "handoff", "Cannot verify Gitleaks 8.30.1.")
        return
    report.engines["gitleaks"] = GITLEAKS_VERSION
    with tempfile.TemporaryDirectory(prefix="permitprobe-scan-") as directory:
        work = Path(directory)
        source = work / "files"
        source.mkdir()
        names = {}
        for n, (name, body) in enumerate(snapshot.items()):
            # Neutral paths prevent an example/test filename from suppressing a rule.
            neutral = f"file-{n:04d}.txt"
            (source / neutral).write_bytes(body)
            names[neutral] = name
        (work / "scanner.toml").write_text("[extend]\nuseDefault = true\n")
        (work / "ignore").write_text("")
        output = work / "findings.json"
        try:
            result = subprocess.run(
                [
                    executable,
                    "dir",
                    str(source),
                    "--config",
                    str(work / "scanner.toml"),
                    "--gitleaks-ignore-path",
                    str(work / "ignore"),
                    "--ignore-gitleaks-allow",
                    "--redact=100",
                    "--no-banner",
                    "--no-color",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(output),
                    "--exit-code",
                    "1",
                    "--timeout",
                    "45",
                    "--max-target-megabytes",
                    "6",
                    "--max-decode-depth",
                    "2",
                ],
                env=env,
                cwd=work,
                capture_output=True,
                timeout=50,
                check=False,
            )
            if not output.is_file() or output.stat().st_size > 10_000_000:
                raise ValueError("missing or oversized scanner report")
            findings = json.loads(output.read_text())
            if (
                type(findings) is not list
                or result.returncode not in (0, 1)
                or (result.returncode == 0) != (len(findings) == 0)
            ):
                raise ValueError("inconsistent scanner result")
            for finding in findings:
                if not isinstance(finding, dict):
                    raise ValueError("invalid scanner finding")
                name = names.get(Path(finding.get("File", "")).name)
                rule = finding.get("RuleID", "")
                if (
                    not name
                    or not isinstance(rule, str)
                    or not re.fullmatch(r"[a-zA-Z0-9_-]+", rule)
                ):
                    raise ValueError("unmapped scanner finding")
                report.add(
                    "handoff.secret",
                    "fail",
                    name,
                    f"Gitleaks rule {rule} matched; content omitted.",
                )
            if not findings:
                report.add(
                    "handoff.secrets",
                    "pass",
                    "handoff",
                    f"Gitleaks scanned {len(snapshot)} captured text files; no matches.",
                )
        except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
            report.add(
                "handoff.scanner",
                "inconclusive",
                "handoff",
                "Scanner failed or returned an unverifiable result; output omitted.",
            )


def check_handoff(
    policy: Handoff, policy_dir: Path, report: Report, binary: str | None = None
) -> dict[str, bytes]:
    report.configured.append("handoff")
    snapshot = collect(policy, policy_dir, report)
    if len(snapshot) != len(policy.files):
        report.add(
            "handoff.coverage",
            "inconclusive",
            "handoff",
            "Not all declared files were captured; no bundle can be issued.",
        )
    if snapshot:
        scan(snapshot, report, binary)
    return snapshot


def write_bundle(snapshot: dict[str, bytes], destination: Path) -> None:
    manifest = {
        "schema_version": 1,
        "scope": "Exact text bytes checked by PermitProbe; not an authorization to send.",
        "files": [
            {"path": name, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
            for name, body in sorted(snapshot.items())
        ],
        "scanner": {"name": "gitleaks", "version": GITLEAKS_VERSION},
    }
    # Assemble privately; link into place only on completion. A partial ZIP is
    # never published at the requested path, and existing files are not replaced.
    fd, temporary = tempfile.mkstemp(prefix=".permitprobe-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, body in sorted(snapshot.items()):
                    archive.writestr(name, body)
                archive.writestr(RECEIPT_NAME, json.dumps(manifest, indent=2) + "\n")
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)
