#!/usr/bin/env python3
"""Validate the exact GitHub release distributions before registry publication."""

import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path


def package_identity(raw: bytes, version: str) -> None:
    metadata = BytesParser().parsebytes(raw)
    for field, value in (("Name", "permitprobe"), ("Version", version)):
        if metadata.get_all(field) != [value]:
            raise ValueError("Distribution identity does not match the requested release.")


def verify_release(release: dict, directory: Path, requested_tag: str) -> dict[str, str]:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", requested_tag):
        raise ValueError("Expected a stable vX.Y.Z release tag.")
    if (
        release.get("tag_name") != requested_tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
    ):
        raise ValueError("Only the requested published, non-prerelease release can be uploaded.")
    version = requested_tag[1:]
    names = {f"permitprobe-{version}-py3-none-any.whl", f"permitprobe-{version}.tar.gz"}
    assets = release.get("assets", [])
    records = {a["name"]: a for a in assets if a.get("name") in names}
    if len([a for a in assets if a.get("name") in names]) != 2 or set(records) != names:
        raise ValueError("The release must contain exactly the two expected distribution assets.")
    if {p.name for p in directory.iterdir()} != names:
        raise ValueError("The upload directory must contain exactly the expected wheel and sdist.")
    digests = {}
    for name in sorted(names):
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 20_000_000:
            raise ValueError("Invalid release artifact file.")
        digest = records[name].get("digest", "")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("GitHub did not provide a verifiable SHA256 digest.")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest[7:]:
            raise ValueError("Downloaded artifact does not match its published GitHub digest.")
        digests[name] = digest
        if name.endswith(".whl"):
            with zipfile.ZipFile(path) as archive:
                if "permitprobe/__init__.py" not in archive.namelist():
                    raise ValueError("Wheel has no PermitProbe module.")
                if any(n.startswith("boundaryguard/") for n in archive.namelist()):
                    raise ValueError("Wheel still contains the conflicting old namespace.")
                package_identity(archive.read(f"permitprobe-{version}.dist-info/METADATA"), version)
        else:
            with tarfile.open(path, "r:gz") as archive:
                member = archive.getmember(f"permitprobe-{version}/PKG-INFO")
                if not member.isfile() or member.size > 1_000_000:
                    raise ValueError("Invalid source distribution metadata.")
                package_identity(archive.extractfile(member).read(), version)
    return digests


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        digests = verify_release(json.loads(args.metadata.read_text()), args.dist, args.tag)
    except Exception:
        parser.exit(2, "Release validation failed; nothing should be uploaded.\n")
    print(json.dumps({"tag": args.tag, "verified_sha256": digests}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
