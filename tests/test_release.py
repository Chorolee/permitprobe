import base64
import copy
import csv
import gzip
import hashlib
import importlib.util
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from permitprobe import __version__
from permitprobe.handoff import GITLEAKS_BINARIES

VERSION = __version__

spec = importlib.util.spec_from_file_location(
    "verify_release", Path(__file__).resolve().parents[1] / "scripts/verify_release.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

checkout_spec = importlib.util.spec_from_file_location(
    "checkout_release_source",
    Path(__file__).resolve().parents[1] / "scripts/checkout_release_source.py",
)
checkout_module = importlib.util.module_from_spec(checkout_spec)
checkout_spec.loader.exec_module(checkout_module)

installer_spec = importlib.util.spec_from_file_location(
    "install_gitleaks",
    Path(__file__).resolve().parents[1] / "scripts/install_gitleaks.py",
)
installer_module = importlib.util.module_from_spec(installer_spec)
installer_spec.loader.exec_module(installer_module)

smoke_spec = importlib.util.spec_from_file_location(
    "smoke_wheel", Path(__file__).resolve().parents[1] / "scripts/smoke_wheel.py"
)
smoke_module = importlib.util.module_from_spec(smoke_spec)
smoke_spec.loader.exec_module(smoke_module)


@pytest.fixture
def release_pair(tmp_path):
    metadata = f"Metadata-Version: 2.4\nName: permitprobe\nVersion: {VERSION}\n\nExample.".encode()
    wheel = tmp_path / f"permitprobe-{VERSION}-py3-none-any.whl"
    source = tmp_path / f"permitprobe-{VERSION}.tar.gz"
    with zipfile.ZipFile(wheel, "w") as z:
        z.writestr("permitprobe/__init__.py", "")
        z.writestr(f"permitprobe-{VERSION}.dist-info/METADATA", metadata)
    with tarfile.open(source, "w:gz") as t:
        member = tarfile.TarInfo(f"permitprobe-{VERSION}/PKG-INFO")
        member.size = len(metadata)
        t.addfile(member, io.BytesIO(metadata))
    release = {
        "tag_name": f"v{VERSION}",
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": p.name, "digest": "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in (wheel, source)
        ],
    }
    return release, tmp_path


def test_verifies_exact_distribution_bytes(release_pair):
    release, path = release_pair
    assert len(module.verify_release(release, path, f"v{VERSION}")) == 2


def test_release_verification_bounds_expanded_wheel_before_read(
    monkeypatch, release_pair
):
    release, path = release_pair
    monkeypatch.setattr(module, "MAX_ARCHIVE_MEMBER", 1)
    with pytest.raises(ValueError, match="expands"):
        module.verify_release(release, path, f"v{VERSION}")


def test_release_verification_bounds_sdist_decompression(monkeypatch, tmp_path):
    source = tmp_path / "oversized.tar.gz"
    source.write_bytes(gzip.compress(b"x" * 33))
    monkeypatch.setattr(module, "MAX_TAR_STREAM", 32)
    with pytest.raises(ValueError, match="expands"):
        module._bounded_tar(source)


def test_release_verification_bounds_sdist_member_count(monkeypatch, release_pair):
    release, path = release_pair
    monkeypatch.setattr(module, "MAX_ARCHIVE_MEMBERS", 0)
    with pytest.raises(ValueError, match="too many members"):
        with module._bounded_tar(path / f"permitprobe-{VERSION}.tar.gz") as archive:
            module._bounded_tar_members(archive)


def test_release_verification_bounds_wheel_member_count(monkeypatch, release_pair):
    release, path = release_pair
    monkeypatch.setattr(module, "MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(ValueError, match="expands"):
        module.verify_release(release, path, f"v{VERSION}")


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(prerelease=True),
        lambda r: r.update(draft=True),
        lambda r: r.update(tag_name="v0.1.0"),
        lambda r: r["assets"].pop(),
        lambda r: r["assets"].append(copy.deepcopy(r["assets"][0])),
        lambda r: r["assets"].append(
            {"name": "unverified-installer.exe", "digest": "sha256:" + "0" * 64}
        ),
        lambda r: r["assets"][0].update(digest="sha256:" + "0" * 64),
        lambda r: r["assets"][0].pop("digest"),
    ],
)
def test_refuses_unverifiable_release(release_pair, change):
    release, path = release_pair
    change(release)
    with pytest.raises(ValueError):
        module.verify_release(release, path, f"v{VERSION}")


def test_refuses_unrelated_file_in_upload_directory(release_pair):
    release, path = release_pair
    (path / "unrelated.whl").write_bytes(b"not the release")
    with pytest.raises(ValueError):
        module.verify_release(release, path, f"v{VERSION}")


@pytest.mark.parametrize(
    "metadata",
    [
        f"Name: boundaryguard\nVersion: {VERSION}\n".encode(),
        b"Name: permitprobe\nVersion: 0.1.0\n",
        f"Name: permitprobe\nName: other\nVersion: {VERSION}\n".encode(),
    ],
)
def test_distribution_identity_cannot_drift(metadata):
    with pytest.raises(ValueError):
        module.package_identity(metadata, VERSION)


def test_project_and_import_versions_match():
    import tomllib

    root = Path(__file__).resolve().parents[1]
    with (root / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    assert project["version"] == VERSION
    assert f"## [{VERSION}] - " in (root / "CHANGELOG.md").read_text()
    assert (root / "docs" / "releases" / f"v{VERSION}.md").is_file()
    assert f"default: v{VERSION}" in (
        root / ".github" / "workflows" / "publish-pypi.yml"
    ).read_text()
    assert f"dist/permitprobe-{VERSION}-py3-none-any.whl" in (
        root / ".github" / "workflows" / "ci.yml"
    ).read_text()


def test_dependency_installation_is_complete_and_hash_locked():
    root = Path(__file__).resolve().parents[1]
    lines = (root / "requirements.lock").read_text().splitlines()
    packages = set()
    for index, line in enumerate(lines):
        match = re.fullmatch(
            r'([A-Za-z0-9][A-Za-z0-9_.-]*)==[^ ]+(?: ; python_version < "3\.12")? \\',
            line,
        )
        if match is None:
            continue
        packages.add(match.group(1).lower().replace("_", "-"))
        hashes = []
        for follower in lines[index + 1 :]:
            if not follower.startswith("    --hash="):
                break
            hashes.append(follower)
        assert hashes
        assert all(
            re.fullmatch(r"    --hash=sha256:[a-f0-9]{64}(?: \\)?", item)
            for item in hashes
        )
    assert {
        "build",
        "httpx",
        "jsonschema",
        "overstep",
        "pydantic",
        "pytest",
        "ruff",
        "setuptools",
        "twine",
        "wheel",
    } <= packages
    assert "boundaryguard" not in packages
    for name in ("backports-tarfile", "importlib-metadata", "zipp"):
        assert any(
            line.startswith(name + "==") and '; python_version < "3.12"' in line
            for line in lines
        )
    ci = (root / ".github" / "workflows" / "ci.yml").read_text()
    publish = (root / ".github" / "workflows" / "publish-pypi.yml").read_text()
    assert "--require-hashes\n          --only-binary=:all:\n          -r requirements.lock" in ci
    assert "python -m pip install --no-deps -e ." in ci
    assert "python -m build --no-isolation" in ci
    scanner_install = ci.index("python scripts/install_gitleaks.py")
    source_scan = ci.index(".tools/gitleaks dir .")
    dependency_install = ci.index("Install hash-locked dependencies")
    assert scanner_install < source_scan < dependency_install
    assert "GITLEAKS_CONFIG_TOML" in ci
    assert "--gitleaks-ignore-path /dev/null" in ci
    assert "--ignore-gitleaks-allow" in ci
    assert (
        "--require-hashes\n          --only-binary=:all:\n          -r verifier/requirements.lock"
        in publish
    )


def test_installer_and_runtime_pin_the_same_scanner_binaries():
    assert installer_module.BINARY_HASHES == GITLEAKS_BINARIES


def test_publication_executes_only_the_main_branch_verifier():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "publish-pypi.yml").read_text()
    assert "path: verifier" in workflow
    assert "fetch-depth: 0" in workflow
    assert "fetch-tags: true" in workflow
    assert "python verifier/scripts/checkout_release_source.py" in workflow
    assert "ref: refs/tags/" not in workflow
    assert "-r verifier/requirements.lock" in workflow
    assert "python verifier/scripts/verify_release.py" in workflow
    assert "--source-root release-source" in workflow
    assert "python verifier/scripts/smoke_wheel.py" in workflow
    assert "python scripts/verify_release.py" not in workflow
    assert "python scripts/smoke_wheel.py" not in workflow


def test_release_source_checkout_requires_a_tag_in_main_history(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    git_executable = shutil.which("git")
    assert git_executable is not None

    def git(*arguments):
        subprocess.run(
            [git_executable, "-C", str(repository), *arguments],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )

    git("init", "--initial-branch=main")
    git("config", "user.name", "Synthetic Maintainer")
    git("config", "user.email", "maintainer@example.invalid")
    (repository / "source.txt").write_text("reviewed\n")
    git("add", "source.txt")
    git("commit", "-m", "reviewed release")
    git("tag", "-a", "v1.2.3", "-m", "reviewed")

    trusted = tmp_path / "trusted-source"
    commit = checkout_module.checkout_release_source(repository, "v1.2.3", trusted)
    assert re.fullmatch(r"[0-9a-f]{40}", commit)
    assert (trusted / "source.txt").read_text() == "reviewed\n"

    git("switch", "--orphan", "unreviewed")
    (repository / "source.txt").write_text("unreviewed\n")
    git("add", "source.txt")
    git("commit", "-m", "unreviewed release")
    git("tag", "v2.0.0")
    git("switch", "main")
    rejected = tmp_path / "rejected-source"
    with pytest.raises(ValueError, match="rejected"):
        checkout_module.checkout_release_source(repository, "v2.0.0", rejected)
    assert not rejected.exists()


def test_scanner_binary_publication_is_complete_exclusive_and_executable(
    tmp_path, monkeypatch
):
    output = tmp_path / "tools" / "gitleaks"
    binary = b"synthetic verified scanner bytes"
    real_link = os.link
    real_fsync = os.fsync
    synced = set()
    observed = []

    def track_fsync(descriptor):
        info = os.fstat(descriptor)
        synced.add((info.st_dev, info.st_ino))
        real_fsync(descriptor)

    def inspect_before_publish(source, destination):
        source = Path(source)
        info = source.stat()
        observed.append(
            (
                output.exists(),
                source.read_bytes(),
                stat.S_IMODE(info.st_mode),
                (info.st_dev, info.st_ino) in synced,
            )
        )
        real_link(source, destination)

    monkeypatch.setattr(installer_module.os, "fsync", track_fsync)
    monkeypatch.setattr(installer_module.os, "link", inspect_before_publish)
    previous_umask = os.umask(0)
    try:
        installer_module.publish_binary(binary, output)
    finally:
        os.umask(previous_umask)

    assert observed == [(False, binary, 0o755, True)]
    assert output.read_bytes() == binary
    assert stat.S_IMODE(output.stat().st_mode) == 0o755
    with pytest.raises(FileExistsError):
        installer_module.publish_binary(b"replacement", output)
    assert output.read_bytes() == binary

    victim = tmp_path / "victim"
    victim.write_bytes(b"private")
    symlink = tmp_path / "tools" / "linked-gitleaks"
    symlink.symlink_to(victim)
    with pytest.raises(FileExistsError):
        installer_module.publish_binary(b"replacement", symlink)
    assert symlink.is_symlink()
    assert victim.read_bytes() == b"private"
    assert not list(output.parent.glob(".permitprobe-gitleaks-*"))


def test_security_workflows_pin_the_runner_operating_system():
    root = Path(__file__).resolve().parents[1]
    workflows = list((root / ".github" / "workflows").glob("*.yml"))
    assert workflows
    for path in workflows:
        workflow = path.read_text()
        assert "ubuntu-latest" not in workflow
        assert workflow.count("runs-on:") == workflow.count("runs-on: ubuntu-24.04")


@pytest.fixture(scope="module")
def built_distributions(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    dist = tmp_path_factory.mktemp("release-provenance")
    result = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    return (
        dist / f"permitprobe-{VERSION}-py3-none-any.whl",
        dist / f"permitprobe-{VERSION}.tar.gz",
        root,
    )


def _wheel_record(files: dict[str, bytes], record_name: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(files):
        digest = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b"=")
        writer.writerow((name, "sha256=" + digest.decode(), len(files[name])))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode()


def _mutate_wheel(source: Path, target: Path, mutation) -> None:
    with zipfile.ZipFile(source) as archive:
        files = {item.filename: archive.read(item) for item in archive.infolist()}
    record_name = f"permitprobe-{VERSION}.dist-info/RECORD"
    files.pop(record_name)
    mutation(files)
    files[record_name] = _wheel_record(files, record_name)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def _mutate_source(source: Path, target: Path, mutation) -> None:
    entries = []
    with tarfile.open(source, "r:gz") as archive:
        for member in archive.getmembers():
            handle = archive.extractfile(member) if member.isfile() else None
            entries.append((copy.copy(member), handle.read() if handle else None))
    mutation(entries)
    with tarfile.open(target, "w:gz") as archive:
        for member, content in entries:
            if content is not None:
                member.size = len(content)
            archive.addfile(member, io.BytesIO(content) if content is not None else None)


def _source_checkout(root: Path, target: Path) -> Path:
    for name, content in module._local_release_files(root).items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return target


def test_distribution_is_bound_to_every_checked_out_release_file(built_distributions):
    wheel, source, root = built_distributions
    module.verify_executable_sources(wheel, source, root, VERSION)


def test_wheel_smoke_ignores_parent_pythonpath(tmp_path, monkeypatch, built_distributions):
    wheel, _, root = built_distributions
    fake = tmp_path / "untrusted" / "permitprobe"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("")
    (fake / "__main__.py").write_text("print('parent-path-module-ran')\n")
    monkeypatch.setenv("PYTHONPATH", str(fake.parent))
    scanner = Path(os.environ.get("PERMITPROBE_GITLEAKS", root / ".tools" / "gitleaks"))

    assert smoke_module.smoke(wheel, root / "requirements.lock", scanner) == {
        "version": VERSION,
        "schema": "valid",
        "safe_demo": "pass",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Author", "Synthetic Person"),
        ("Author-email", "synthetic@example.invalid"),
        ("Maintainer-email", "synthetic@example.invalid"),
    ],
)
def test_distribution_rejects_undeclared_identity_metadata(
    tmp_path, built_distributions, field, value
):
    original_wheel, original_source, root = built_distributions
    wheel = tmp_path / original_wheel.name
    source = tmp_path / original_source.name
    metadata_name = f"permitprobe-{VERSION}.dist-info/METADATA"

    def inject(raw):
        return raw.replace(b"\n\n", f"\n{field}: {value}\n\n".encode(), 1)

    _mutate_wheel(
        original_wheel,
        wheel,
        lambda files: files.__setitem__(metadata_name, inject(files[metadata_name])),
    )

    def mutate_source(entries):
        for index, (member, content) in enumerate(entries):
            if member.name.endswith("/PKG-INFO"):
                entries[index] = (copy.copy(member), inject(content))

    _mutate_source(original_source, source, mutate_source)
    with pytest.raises(ValueError, match="identity metadata"):
        module.verify_executable_sources(wheel, source, root, VERSION)


@pytest.mark.parametrize("artifact", ["wheel", "source", "tag", "extra"])
def test_distribution_source_drift_is_rejected(tmp_path, built_distributions, artifact):
    original_wheel, original_source, root = built_distributions
    wheel = tmp_path / original_wheel.name
    source = tmp_path / original_source.name
    shutil.copy2(original_wheel, wheel)
    shutil.copy2(original_source, source)
    checkout = root
    if artifact == "wheel":
        _mutate_wheel(
            original_wheel,
            wheel,
            lambda files: files.__setitem__("permitprobe/api.py", b"raise SystemExit\n"),
        )
    elif artifact == "source":
        name = f"permitprobe-{VERSION}/src/permitprobe/api.py"
        _mutate_source(
            original_source,
            source,
            lambda entries: entries.__setitem__(
                next(index for index, item in enumerate(entries) if item[0].name == name),
                (next(item[0] for item in entries if item[0].name == name), b"raise SystemExit\n"),
            ),
        )
    elif artifact == "tag":
        checkout = _source_checkout(root, tmp_path / "checkout")
        (checkout / "src" / "permitprobe" / "api.py").write_bytes(b"raise SystemExit\n")
    else:
        name = f"permitprobe-{VERSION}/setup.py"

        def add_setup(entries):
            member = tarfile.TarInfo(name)
            entries.append((member, b"raise SystemExit\n"))

        _mutate_source(original_source, source, add_setup)
    with pytest.raises(ValueError):
        module.verify_executable_sources(wheel, source, checkout, VERSION)


@pytest.mark.parametrize("attack", ["pth", "module", "data", "entry_points"])
def test_wheel_install_bypasses_are_rejected(tmp_path, built_distributions, attack):
    original_wheel, source, root = built_distributions
    wheel = tmp_path / original_wheel.name

    def mutate(files):
        if attack == "pth":
            files["bootstrap.pth"] = b"import os\n"
        elif attack == "module":
            files["bootstrap.py"] = b"raise SystemExit\n"
        elif attack == "data":
            files[f"permitprobe-{VERSION}.data/purelib/permitprobe/api.py"] = (
                b"raise SystemExit\n"
            )
        else:
            files[f"permitprobe-{VERSION}.dist-info/entry_points.txt"] = (
                b"[console_scripts]\npermitprobe = os:path\n"
            )

    _mutate_wheel(original_wheel, wheel, mutate)
    with pytest.raises(ValueError):
        module.verify_executable_sources(wheel, source, root, VERSION)


@pytest.mark.parametrize("attack", ["special", "duplicate", "requires"])
def test_source_archive_structure_and_dependencies_are_exact(
    tmp_path, built_distributions, attack
):
    wheel, original_source, root = built_distributions
    source = tmp_path / original_source.name

    def mutate(entries):
        if attack == "special":
            member = tarfile.TarInfo(f"permitprobe-{VERSION}/unexpected-fifo")
            member.type = tarfile.FIFOTYPE
            entries.append((member, None))
        elif attack == "duplicate":
            member, content = next(
                item for item in entries if item[0].name.endswith("/README.md")
            )
            entries.append((copy.copy(member), content))
        else:
            name = f"permitprobe-{VERSION}/src/permitprobe.egg-info/requires.txt"
            index = next(i for i, item in enumerate(entries) if item[0].name == name)
            entries[index] = (entries[index][0], b"malicious-package\n")

    _mutate_source(original_source, source, mutate)
    with pytest.raises(ValueError):
        module.verify_executable_sources(wheel, source, root, VERSION)


def test_unpacked_archive_member_size_is_bounded(monkeypatch, built_distributions):
    wheel, source, root = built_distributions
    monkeypatch.setattr(module, "MAX_ARCHIVE_MEMBER", 1)
    with pytest.raises(ValueError):
        module.verify_executable_sources(wheel, source, root, VERSION)
