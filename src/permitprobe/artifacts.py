"""Exclusive, owner-only publication for local security artifacts."""

import json
import os
import tempfile
from pathlib import Path


def write_private_json(path: Path, payload: object, *, ensure_ascii: bool = True) -> None:
    """Publish complete JSON at a new path with owner-only permissions."""

    body = (
        json.dumps(payload, indent=2, ensure_ascii=ensure_ascii, allow_nan=False) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".permitprobe-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        # Linking is an atomic no-overwrite publication. The mkstemp inode keeps mode 0600.
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
