#!/usr/bin/env python3
"""Validate the exact GitHub release distributions before registry publication."""

import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import re
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.requirements import Requirement

MAX_ARCHIVE_MEMBER = 5_000_000
MAX_ARCHIVE_CONTENT = 50_000_000
MAX_ARCHIVE_MEMBERS = 4_096
MAX_TAR_STREAM = 64_000_000


def _bounded_tar(path: Path) -> tarfile.TarFile:
    """Open a gzip sdist only after bounding its complete decompressed stream."""

    try:
        with gzip.open(path, "rb") as compressed:
            payload = compressed.read(MAX_TAR_STREAM + 1)
    except (EOFError, OSError):
        raise ValueError("Source archive is not a valid bounded gzip stream.") from None
    if len(payload) > MAX_TAR_STREAM:
        raise ValueError("Source archive expands beyond the verification limit.")
    try:
        return tarfile.open(fileobj=io.BytesIO(payload), mode="r:")
    except tarfile.TarError:
        raise ValueError("Source archive is not a valid tar stream.") from None


def _bounded_tar_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = []
    for member in archive:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise ValueError("Source archive has too many members.")
        members.append(member)
    return members


def package_identity(raw: bytes, version: str) -> None:
    metadata = BytesParser().parsebytes(raw)
    for field, value in (("Name", "permitprobe"), ("Version", version)):
        if metadata.get_all(field) != [value]:
            raise ValueError("Distribution identity does not match the requested release.")


def _canonical(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and "\\" not in name
        and not path.is_absolute()
        and ".." not in path.parts
        and path.as_posix() == name.rstrip("/")
    )


def _local_release_files(source_root: Path) -> dict[str, bytes]:
    names = {
        "AGENTS.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "MANIFEST.in",
        "NOTICE",
        "README.md",
        "SECURITY.md",
        "setup.cfg",
        "permitprobe.schema.json",
        "pyproject.toml",
        "requirements.lock",
    }
    patterns = {
        "docs": ("*.md",),
        "examples": ("*.json", "*.txt"),
        "scripts": ("*.py",),
        "src/permitprobe": ("*.py",),
        "tests": ("*.py",),
    }
    for directory, globs in patterns.items():
        for pattern in globs:
            names.update(
                path.relative_to(source_root).as_posix()
                for path in (source_root / directory).rglob(pattern)
            )
    result = {}
    for name in sorted(names):
        path = source_root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5_000_000:
            raise ValueError("Invalid checked-out release source.")
        result[name] = path.read_bytes()
    return result


def _entry_points(project: dict) -> bytes:
    scripts = project.get("scripts", {})
    if project.get("gui-scripts") or project.get("entry-points"):
        raise ValueError("Release verifier does not support additional entry-point groups.")
    if not scripts:
        return b""
    return (
        "[console_scripts]\n"
        + "".join(f"{name} = {target}\n" for name, target in sorted(scripts.items()))
    ).encode()


def _normalized_requirement(value: str) -> str:
    return str(Requirement(value))


def _expected_requirements(project: dict) -> list[str]:
    expected = [_normalized_requirement(item) for item in project.get("dependencies", [])]
    for extra, requirements in project.get("optional-dependencies", {}).items():
        for requirement in requirements:
            if ";" in requirement:
                raise ValueError("Release verifier does not support marked optional dependencies.")
            expected.append(
                _normalized_requirement(f'{requirement}; extra == "{extra}"')
            )
    return expected


def _expected_requires_file(project: dict) -> bytes:
    lines = [_normalized_requirement(item) for item in project.get("dependencies", [])]
    for extra, requirements in project.get("optional-dependencies", {}).items():
        lines.extend(("", f"[{extra}]"))
        lines.extend(_normalized_requirement(item) for item in requirements)
    return ("\n".join(lines) + "\n").encode()


def _validate_metadata(raw: bytes, source_root: Path, project: dict, version: str) -> None:
    metadata = BytesParser().parsebytes(raw)
    maintainer = project.get("maintainers", [{}])[0].get("name")
    expected = {
        "Metadata-Version": ["2.4"],
        "Name": [project.get("name")],
        "Version": [version],
        "Summary": [project.get("description")],
        "Maintainer": [maintainer],
        "License-Expression": [project.get("license")],
        "Project-URL": [
            f"{name}, {url}" for name, url in project.get("urls", {}).items()
        ],
        "Keywords": [",".join(project.get("keywords", []))],
        "Requires-Python": [project.get("requires-python")],
        "Description-Content-Type": ["text/markdown"],
        "License-File": list(project.get("license-files", [])),
        "Requires-Dist": _expected_requirements(project),
        "Provides-Extra": list(project.get("optional-dependencies", {})),
        "Dynamic": ["license-file"],
    }
    if any(
        metadata.get_all(name)
        for name in ("Author", "Author-email", "Maintainer-email")
    ):
        raise ValueError("Distribution contains undeclared identity metadata.")
    if (
        metadata.defects
        or set(metadata.keys()) != set(expected)
        or any(metadata.get_all(name) != values for name, values in expected.items())
    ):
        raise ValueError("Distribution metadata differs from the release tag.")
    if metadata.get_payload().encode() != (source_root / "README.md").read_bytes():
        raise ValueError("Distribution description differs from the release tag.")


def _validate_record(archive: zipfile.ZipFile, record_name: str, allowed: set[str]) -> None:
    rows = list(csv.reader(archive.read(record_name).decode().splitlines()))
    if len(rows) != len(allowed) or {row[0] for row in rows} != allowed:
        raise ValueError("Wheel RECORD does not cover the exact archive.")
    for row in rows:
        if len(row) != 3:
            raise ValueError("Wheel RECORD row is malformed.")
        name, digest, size = row
        if name == record_name:
            if digest or size:
                raise ValueError("Wheel RECORD self-entry is malformed.")
            continue
        content = archive.read(name)
        encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        if digest != "sha256=" + encoded or size != str(len(content)):
            raise ValueError("Wheel RECORD digest or size mismatch.")


def verify_executable_sources(
    wheel: Path, source: Path, source_root: Path, version: str
) -> None:
    """Bind every installable distribution byte to the checked-out release source."""

    source_root = source_root.resolve(strict=True)
    local = _local_release_files(source_root)
    project = tomllib.loads(local["pyproject.toml"].decode())["project"]
    if project.get("version") != version or project.get("name") != "permitprobe":
        raise ValueError("Checked-out project identity differs from the requested release.")
    package = {
        name.removeprefix("src/"): content
        for name, content in local.items()
        if name.startswith("src/permitprobe/")
    }
    dist_info = f"permitprobe-{version}.dist-info"
    generated_wheel = {
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/licenses/NOTICE",
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/top_level.txt",
        f"{dist_info}/RECORD",
    }
    allowed_wheel = set(package) | generated_wheel
    with zipfile.ZipFile(wheel) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        if (
            len(names) != len(set(names))
            or len(entries) > MAX_ARCHIVE_MEMBERS
            or set(names) != allowed_wheel
            or any(not _canonical(name) for name in names)
            or any(item.is_dir() for item in entries)
            or any(((item.external_attr >> 16) & 0o170000) == 0o120000 for item in entries)
            or any(item.file_size > MAX_ARCHIVE_MEMBER for item in entries)
            or sum(item.file_size for item in entries) > MAX_ARCHIVE_CONTENT
        ):
            raise ValueError("Wheel contains an unexpected, duplicate or noncanonical entry.")
        for name, expected in package.items():
            if archive.read(name) != expected:
                raise ValueError("Wheel package code differs from the release tag.")
        if archive.read(f"{dist_info}/licenses/LICENSE") != local["LICENSE"] or archive.read(
            f"{dist_info}/licenses/NOTICE"
        ) != local["NOTICE"]:
            raise ValueError("Wheel license bytes differ from the release tag.")
        metadata = archive.read(f"{dist_info}/METADATA")
        _validate_metadata(metadata, source_root, project, version)
        if archive.read(f"{dist_info}/entry_points.txt") != _entry_points(project):
            raise ValueError("Wheel entry points differ from the release tag.")
        if archive.read(f"{dist_info}/top_level.txt") != b"permitprobe\n":
            raise ValueError("Wheel top-level package metadata is invalid.")
        wheel_metadata = BytesParser().parsebytes(archive.read(f"{dist_info}/WHEEL"))
        if (
            wheel_metadata.get_all("Wheel-Version") != ["1.0"]
            or wheel_metadata.get_all("Root-Is-Purelib") != ["true"]
            or wheel_metadata.get_all("Tag") != ["py3-none-any"]
        ):
            raise ValueError("Wheel compatibility metadata is invalid.")
        _validate_record(archive, f"{dist_info}/RECORD", allowed_wheel)

    prefix = f"permitprobe-{version}/"
    egg_info = "src/permitprobe.egg-info"
    generated_source = {
        "PKG-INFO",
        f"{egg_info}/PKG-INFO",
        f"{egg_info}/SOURCES.txt",
        f"{egg_info}/dependency_links.txt",
        f"{egg_info}/entry_points.txt",
        f"{egg_info}/requires.txt",
        f"{egg_info}/top_level.txt",
    }
    allowed_source = set(local) | generated_source
    with _bounded_tar(source) as archive:
        members = _bounded_tar_members(archive)
        root_name = prefix.rstrip("/")
        relative_names = []
        files = {}
        directories = set()
        invalid_member = False
        for member in members:
            if member.name == root_name:
                relative = ""
            elif member.name.startswith(prefix):
                relative = member.name[len(prefix) :]
            else:
                invalid_member = True
                relative = member.name
            relative = relative.rstrip("/")
            relative_names.append(relative)
            if not (member.isfile() or member.isdir()):
                invalid_member = True
            elif (
                member.uid != 0
                or member.gid != 0
                or member.uname != "root"
                or member.gname != "root"
            ):
                invalid_member = True
            elif member.isfile():
                files[relative] = member
            else:
                directories.add(relative)
        expected_directories = {""}
        for name in allowed_source:
            parent = PurePosixPath(name).parent
            while parent != PurePosixPath("."):
                expected_directories.add(parent.as_posix())
                parent = parent.parent
        if (
            len(relative_names) != len(set(relative_names))
            or any(not _canonical(member.name) for member in members)
            or invalid_member
            or any(member.size > MAX_ARCHIVE_MEMBER for member in members)
            or sum(member.size for member in members) > MAX_ARCHIVE_CONTENT
            or set(files) != allowed_source
            or directories != expected_directories
        ):
            raise ValueError("Source archive contains an unexpected, linked or duplicate entry.")

        def read(name: str) -> bytes:
            handle = archive.extractfile(files[name])
            if handle is None:
                raise ValueError("Cannot read source archive entry.")
            return handle.read()

        for name, expected in local.items():
            if read(name) != expected:
                raise ValueError("Source archive file differs from the release tag.")
        if read("PKG-INFO") != metadata or read(f"{egg_info}/PKG-INFO") != metadata:
            raise ValueError("Source and wheel metadata differ.")
        if read("setup.cfg") != local["setup.cfg"]:
            raise ValueError("Source archive setup configuration is unexpected.")
        if read(f"{egg_info}/dependency_links.txt") != b"\n":
            raise ValueError("Source archive dependency links are unexpected.")
        if read(f"{egg_info}/entry_points.txt") != _entry_points(project):
            raise ValueError("Source archive entry points differ from the release tag.")
        if read(f"{egg_info}/requires.txt") != _expected_requires_file(project):
            raise ValueError("Source archive dependencies differ from the release tag.")
        if read(f"{egg_info}/top_level.txt") != b"permitprobe\n":
            raise ValueError("Source archive top-level package metadata is invalid.")
        source_names = read(f"{egg_info}/SOURCES.txt").decode().splitlines()
        expected_names = set(local) | {
            f"{egg_info}/PKG-INFO",
            f"{egg_info}/SOURCES.txt",
            f"{egg_info}/dependency_links.txt",
            f"{egg_info}/entry_points.txt",
            f"{egg_info}/requires.txt",
            f"{egg_info}/top_level.txt",
        }
        if len(source_names) != len(set(source_names)) or set(source_names) != expected_names:
            raise ValueError("Source archive manifest differs from the release tag.")


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
    if (
        not isinstance(assets, list)
        or len(assets) != 2
        or any(not isinstance(asset, dict) for asset in assets)
    ):
        raise ValueError("The release must contain exactly the two expected distribution assets.")
    records = {asset.get("name"): asset for asset in assets}
    if len(records) != 2 or set(records) != names:
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
                entries = archive.infolist()
                if (
                    len(entries) > MAX_ARCHIVE_MEMBERS
                    or any(item.file_size > MAX_ARCHIVE_MEMBER for item in entries)
                    or sum(item.file_size for item in entries) > MAX_ARCHIVE_CONTENT
                ):
                    raise ValueError("Wheel expands beyond the release verification limit.")
                if "permitprobe/__init__.py" not in archive.namelist():
                    raise ValueError("Wheel has no PermitProbe module.")
                if any(n.startswith("boundaryguard/") for n in archive.namelist()):
                    raise ValueError("Wheel still contains the conflicting old namespace.")
                package_identity(archive.read(f"permitprobe-{version}.dist-info/METADATA"), version)
        else:
            with _bounded_tar(path) as archive:
                expected = f"permitprobe-{version}/PKG-INFO"
                members = _bounded_tar_members(archive)
                member = next((item for item in members if item.name == expected), None)
                if member is None:
                    raise ValueError("Source distribution has no package metadata.")
                if not member.isfile() or member.size > 1_000_000:
                    raise ValueError("Invalid source distribution metadata.")
                package_identity(archive.extractfile(member).read(), version)
    return digests


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        digests = verify_release(json.loads(args.metadata.read_text()), args.dist, args.tag)
        version = args.tag[1:]
        verify_executable_sources(
            args.dist / f"permitprobe-{version}-py3-none-any.whl",
            args.dist / f"permitprobe-{version}.tar.gz",
            args.source_root,
            version,
        )
    except Exception:
        parser.exit(2, "Release validation failed; nothing should be uploaded.\n")
    print(json.dumps({"tag": args.tag, "verified_sha256": digests}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
