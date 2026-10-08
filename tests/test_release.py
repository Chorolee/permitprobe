import copy
import hashlib
import importlib.util
import io
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
