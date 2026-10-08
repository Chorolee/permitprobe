"""Check explicit text-file handoffs and export exactly the bytes that were scanned."""

import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import unicodedata
import zipfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath

from permitprobe.policy import Handoff
from permitprobe.report import Report

GITLEAKS_VERSION = "8.30.1"
GITLEAKS_BINARIES = {
    "linux_x64": (
        "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",
        21_958_840,
    ),
    "linux_arm64": (
        "00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b",
        20_775_096,
    ),
    "darwin_x64": (
        "cee01fea7173f1b779dff188e1c26ecbcb4027d394acc573b23aaf0be260e291",
        22_398_576,
    ),
    "darwin_arm64": (
        "ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f",
        21_324_882,
    ),
}
RECEIPT_NAME = "PERMITPROBE-MANIFEST.json"
PRIVATE_DIRS = {".git", ".ssh", ".aws", ".azure", ".kube", ".memory", ".venv"}
PRIVATE_FILES = {".gitleaks.toml", ".gitleaksignore", "credentials", "id_rsa", "id_ed25519"}
WINDOWS_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "conin$",
    "conout$",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
    "com¹",
    "com²",
    "com³",
    "lpt¹",
    "lpt²",
    "lpt³",
}
WINDOWS_INVALID_NAME_CHARACTERS = frozenset('<>:"\\|?*')


def _portable_path_key(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def _windows_device_path(parts: tuple[str, ...]) -> bool:
    return any(
        _portable_path_key(part).split(".", 1)[0].rstrip(" .") in WINDOWS_DEVICE_NAMES
        for part in parts
    )


def _canonical_handoff_path(name: str) -> bool:
    if not isinstance(name, str):
        return False
    path = PurePosixPath(name)
    return not (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or str(path) != name
        or name.endswith("/")
        or any(char in WINDOWS_INVALID_NAME_CHARACTERS for char in name)
        or any(not char.isprintable() for char in name)
        or any(part.endswith((".", " ")) for part in path.parts)
        or _windows_device_path(path.parts)
    )


def _has_private_directory(parts: tuple[str, ...]) -> bool:
    return any(part.casefold() in PRIVATE_DIRS for part in parts)


def _denied(name: str, policy: Handoff) -> bool:
    root_parts = () if policy.root == "." else PurePosixPath(policy.root).parts
    parts = (*root_parts, *PurePosixPath(name).parts)
    lowered = [part.casefold() for part in parts]
    if _has_private_directory(parts):
        return True
    leaf = lowered[-1]
    if (
        leaf == ".env"
        or leaf.startswith(".env.")
        or leaf.endswith(".env")
        or leaf in PRIVATE_FILES
        or leaf.endswith((".pem", ".key", ".p12", ".pfx"))
        or _portable_path_key(name) == _portable_path_key(RECEIPT_NAME)
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


def _open_root(policy_dir: Path, root: str) -> int:
    """Open a relative root one directory component at a time without following links."""

    current = os.open(policy_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if root != ".":
            for part in PurePosixPath(root).parts:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                os.close(current)
                current = child
        return current
    except OSError:
        os.close(current)
        raise


def collect(policy: Handoff, policy_dir: Path, report: Report) -> dict[str, bytes]:
    snapshot = {}
    total = 0
    root_parts = () if policy.root == "." else PurePosixPath(policy.root).parts
    if _has_private_directory(root_parts):
        report.add(
            "handoff.policy",
            "fail",
            "handoff",
            "Handoff root is a built-in private directory.",
        )
        return snapshot
    try:
        fd = _open_root(policy_dir, policy.root)
    except OSError:
        report.add("handoff.root", "inconclusive", "handoff", "Cannot open handoff directory.")
        return snapshot
    try:
        portable_names = {_portable_path_key(RECEIPT_NAME)}
        for name in policy.files:
            if not _canonical_handoff_path(name):
                report.add(
                    "handoff.path",
                    "fail",
                    "handoff",
                    "Non-canonical or non-portable relative file path.",
                )
                continue
            portable = _portable_path_key(name)
            if portable in portable_names:
                report.add(
                    "handoff.path",
                    "fail",
                    "handoff",
                    "Non-canonical or non-portable relative file path.",
                )
                continue
            portable_names.add(portable)
            path = PurePosixPath(name)
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


def _scanner_target() -> str:
    architecture = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower(), "unsupported")
    return platform.system().lower() + "_" + architecture


def _stage_verified_scanner(executable: str, work: Path) -> str:
    expected = GITLEAKS_BINARIES.get(_scanner_target())
    if expected is None:
        raise ValueError("unsupported scanner platform")
    expected_digest, expected_size = expected
    source_path = Path(executable).resolve(strict=True)
    staged_path = work / "gitleaks"
    digest = hashlib.sha256()
    try:
        with ExitStack() as stack:
            source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            source = stack.enter_context(os.fdopen(source_fd, "rb"))
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
                raise ValueError("unexpected scanner file")
            staged_fd = os.open(staged_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
            staged = stack.enter_context(os.fdopen(staged_fd, "wb"))
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                staged.write(chunk)
            os.fchmod(staged.fileno(), 0o500)
    except Exception:
        staged_path.unlink(missing_ok=True)
        raise
    if digest.hexdigest() != expected_digest:
        staged_path.unlink(missing_ok=True)
        raise ValueError("unexpected scanner digest")
    return str(staged_path)


def scan(snapshot: dict[str, bytes], report: Report, binary: str | None = None) -> None:
    executable = shutil.which(binary or "gitleaks")
    if not executable:
        report.add("handoff.scanner", "inconclusive", "handoff", "Gitleaks 8.30.1 is required.")
        return
    with tempfile.TemporaryDirectory(prefix="permitprobe-scan-") as directory:
        work = Path(directory)
        # Copy only a hash-pinned official binary into the private work directory.
        # Later path replacement cannot change the executable used for this scan.
        try:
            executable = _stage_verified_scanner(executable, work)
            env = {"PATH": os.defpath, "LANG": "C.UTF-8"}
            result = subprocess.run(  # noqa: S603
                [executable, "version"],
                env=env,
                capture_output=True,
                timeout=10,
                check=False,
            )
            if (
                result.returncode
                or result.stdout.decode().strip().removeprefix("v") != GITLEAKS_VERSION
            ):
                raise ValueError("unsupported scanner")
        except (OSError, ValueError, subprocess.TimeoutExpired):
            report.add(
                "handoff.scanner",
                "inconclusive",
                "handoff",
                "Cannot verify the official Gitleaks 8.30.1 binary.",
            )
            return
        report.engines["gitleaks"] = GITLEAKS_VERSION
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
            # Only the previously resolved and version-pinned scanner is executed.
            result = subprocess.run(  # noqa: S603
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
    portable_names = {_portable_path_key(RECEIPT_NAME)}
    for name in snapshot:
        if not _canonical_handoff_path(name):
            raise ValueError("bundle paths must be canonical and portable")
        portable = _portable_path_key(name)
        if portable in portable_names:
            raise ValueError("bundle paths must be canonical and portable")
        portable_names.add(portable)
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
