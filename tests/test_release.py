import base64
import copy
import csv
import hashlib
import importlib.util
import io
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from permitprobe import __version__

VERSION = __version__

spec = importlib.util.spec_from_file_location(
    "verify_release", Path(__file__).resolve().parents[1] / "scripts/verify_release.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


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


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(prerelease=True),
        lambda r: r.update(draft=True),
        lambda r: r.update(tag_name="v0.1.0"),
        lambda r: r["assets"].pop(),
        lambda r: r["assets"].append(copy.deepcopy(r["assets"][0])),
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
