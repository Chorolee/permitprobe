#!/usr/bin/env python3
"""Install the tested scanner from a pinned release with pinned archive hashes."""

import argparse
import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

VERSION = "8.30.1"
HASHES = {
    "linux_x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "linux_arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    "darwin_x64": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    "darwin_arm64": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
}


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
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as f:
        f.write(binary)
    args.output.chmod(0o755)
    print(f"Installed Gitleaks {VERSION}; pinned archive SHA256 verified.")


if __name__ == "__main__":
    main()
