import os
import time

import pytest

from permitprobe.baseline import Baseline
from permitprobe.local_files import read_bounded_regular
from permitprobe.openapi_inventory import _load as load_openapi
from permitprobe.policy import load_policy
from permitprobe.replay import ReplayManifest
from permitprobe.retest import load_prior_report


@pytest.mark.parametrize(
    "loader",
    [
        load_policy,
        Baseline.load,
        load_prior_report,
        ReplayManifest.load,
        load_openapi,
    ],
)
def test_json_loaders_reject_fifo_without_blocking(loader, tmp_path):
    fifo = tmp_path / "input.json"
    os.mkfifo(fifo)
    started = time.monotonic()
    with pytest.raises(ValueError):
        loader(fifo)
    assert time.monotonic() - started < 1


def test_bounded_regular_reader_accepts_symlink_to_regular_file(tmp_path):
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert read_bounded_regular(link, 2) == b"{}"


@pytest.mark.parametrize("kind", ["directory", "oversized"])
def test_bounded_regular_reader_rejects_nonregular_or_oversized_input(kind, tmp_path):
    path = tmp_path / "input"
    if kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"123")
    with pytest.raises(ValueError):
        read_bounded_regular(path, 2)
