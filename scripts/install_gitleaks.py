#!/usr/bin/env python3
"""Install the tested scanner from a pinned release with pinned archive hashes."""

import argparse
import hashlib
import io
import os
import platform
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "8.30.1"
HASHES = {
    "linux_x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "linux_arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    "darwin_x64": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    "darwin_arm64": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
}
BINARY_HASHES = {
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


def publish_binary(binary: bytes, output: Path) -> None:
    """Publish complete executable bytes at a new path without exposing a partial final file."""

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".permitprobe-gitleaks-", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(binary)
            os.fchmod(handle.fileno(), 0o755)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".tools/gitleaks"))
    args = parser.parse_args()
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine().lower(), "unsupported"
    )
    target = platform.system().lower() + "_" + arch
    if target not in HASHES:
        parser.error("Supported targets: Linux/macOS on x64/arm64.")
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists; it was not modified.")
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_{target}.tar.gz"
    with urllib.request.urlopen(url, timeout=30) as response:
        archive_bytes = response.read(30_000_001)
    if hashlib.sha256(archive_bytes).hexdigest() != HASHES[target]:
        parser.error("Archive SHA256 does not match the pinned release.")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        member = archive.getmember("gitleaks")
        if not member.isfile() or member.size > 100_000_000:
            parser.error("Unexpected archive member.")
        binary = archive.extractfile(member).read()
    binary_digest, binary_size = BINARY_HASHES[target]
    if len(binary) != binary_size or hashlib.sha256(binary).hexdigest() != binary_digest:
        parser.error("Scanner binary SHA256 does not match the pinned release.")
    try:
        publish_binary(binary, args.output)
    except OSError:
        parser.error("Cannot publish the verified scanner at a new output path.")
    print(f"Installed Gitleaks {VERSION}; pinned archive and binary SHA256 verified.")


if __name__ == "__main__":
    main()
