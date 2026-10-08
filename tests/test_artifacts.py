import json
import os
import stat
from pathlib import Path

import pytest

from permitprobe.artifacts import write_private_json


def test_private_json_is_complete_owner_only_and_independent_of_umask(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    payload = {"status": "pass", "labels": ["private-resource", "한글"]}
    real_link = os.link
    observed = []

    def inspect_before_publish(source, destination):
        observed.append((output.exists(), json.loads(Path(source).read_text())))
        real_link(source, destination)

    monkeypatch.setattr(os, "link", inspect_before_publish)
    previous_umask = os.umask(0)
    try:
        write_private_json(output, payload, ensure_ascii=False)
    finally:
        os.umask(previous_umask)

    assert observed == [(False, payload)]
    assert json.loads(output.read_text()) == payload
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".permitprobe-*"))


def test_private_json_never_replaces_an_existing_path_or_leaves_a_temporary(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("existing")
    with pytest.raises(FileExistsError):
        write_private_json(output, {"replacement": True})
    assert output.read_text() == "existing"

    victim = tmp_path / "victim.json"
    victim.write_text("private")
    symlink = tmp_path / "linked-report.json"
    symlink.symlink_to(victim)
    with pytest.raises(FileExistsError):
        write_private_json(symlink, {"replacement": True})
    assert symlink.is_symlink()
    assert victim.read_text() == "private"
    assert not list(tmp_path.glob(".permitprobe-*"))
