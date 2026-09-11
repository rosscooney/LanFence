# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Symlink-safe filesystem helpers.

LAN Fence typically runs unattended (cron / systemd, often as root for raw
ARP sockets) and writes to predictable paths (the device database, the
allowlist, JSON reports). :func:`atomic_write` creates a fresh file and
renames it into place, so a symlink planted at the destination name is
swapped, never followed - it can't be used to redirect a privileged write onto
an arbitrary file.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

#: Owner-only. The database and reports carry MAC addresses and hostnames.
PRIVATE_FILE_MODE = 0o600


def atomic_write(path: Path | str, text: str, *, mode: int = PRIVATE_FILE_MODE) -> Path:
    """Write ``text`` to ``path`` atomically, without ever following a symlink."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, mode)
            except OSError:  # pragma: no cover - unusual filesystems
                pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:  # pragma: no cover
            pass
        raise
    return path
