import copy
import hashlib
import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "verify_release", Path(__file__).resolve().parents[1] / "scripts/verify_release.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def release_pair(tmp_path):
    metadata = b"Metadata-Version: 2.4\nName: permitprobe\nVersion: 0.1.1\n\nExample."
    wheel = tmp_path / "permitprobe-0.1.1-py3-none-any.whl"
    source = tmp_path / "permitprobe-0.1.1.tar.gz"
    with zipfile.ZipFile(wheel, "w") as z:
        z.writestr("permitprobe/__init__.py", "")
        z.writestr("permitprobe-0.1.1.dist-info/METADATA", metadata)
    with tarfile.open(source, "w:gz") as t:
        member = tarfile.TarInfo("permitprobe-0.1.1/PKG-INFO")
        member.size = len(metadata)
        t.addfile(member, io.BytesIO(metadata))
    release = {
        "tag_name": "v0.1.1",
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
    assert len(module.verify_release(release, path, "v0.1.1")) == 2


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
        module.verify_release(release, path, "v0.1.1")


def test_refuses_unrelated_file_in_upload_directory(release_pair):
    release, path = release_pair
    (path / "unrelated.whl").write_bytes(b"not the release")
    with pytest.raises(ValueError):
        module.verify_release(release, path, "v0.1.1")


@pytest.mark.parametrize(
    "metadata",
    [
        b"Name: boundaryguard\nVersion: 0.1.1\n",
        b"Name: permitprobe\nVersion: 0.1.0\n",
        b"Name: permitprobe\nName: other\nVersion: 0.1.1\n",
    ],
)
def test_distribution_identity_cannot_drift(metadata):
    with pytest.raises(ValueError):
        module.package_identity(metadata, "0.1.1")
