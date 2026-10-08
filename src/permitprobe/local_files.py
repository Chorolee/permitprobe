"""Bounded reads from regular local files."""

import os
import stat
from pathlib import Path


def read_bounded_regular(path: Path, limit: int) -> bytes:
    """Read at most ``limit`` bytes without blocking on a pipe or device."""

    if limit < 0:
        raise ValueError("file limit must be nonnegative")
    resolved = path.resolve(strict=True)
    descriptor = os.open(
        resolved,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("expected a bounded regular file")
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        with handle:
            body = handle.read(limit + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(body) > limit:
        raise ValueError("file grew beyond its byte limit")
    return body
