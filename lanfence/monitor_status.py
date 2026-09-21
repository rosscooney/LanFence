# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Whether `lanfence monitor` is currently running, checked from a
*separate* process - e.g. `lanfence digest` reporting monitor's status in
a delivered digest.

Tracked via a pidfile `monitor` itself writes on startup and removes on a
clean shutdown - the same convention ``lanfence/web.py`` uses for
`lanfence web`, kept here as its own tiny module since it's used by two
otherwise-unrelated commands (`monitor`, which writes it, and `digest`,
which only reads it) and neither should import the other's module for it.
A pidfile (rather than only asking systemd) works the same way whether
`monitor` was started manually, in a screen/tmux session, or via the
packaged systemd unit - the OS process is the same either way.
"""

from __future__ import annotations

import os
from pathlib import Path

from lanfence.config import expand_operator_path

#: Sudo-aware, same state directory convention as db_path/allowlist_file's
#: own defaults (see Config) - resolved against the *operator's* home even
#: under sudo, not root's.
_PID_FILE = Path("~/.local/share/lanfence/monitor.pid")


def _resolved_pid_file() -> Path:
    return expand_operator_path(_PID_FILE)


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just owned by someone else (e.g. root via sudo)
    return True


def running_pid() -> int | None:
    """The PID of a running `lanfence monitor` process, tracked via its
    own pidfile - ``None`` if not running (or the pidfile is stale, in
    which case it's cleaned up)."""

    path = _resolved_pid_file()
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if _process_alive(pid):
        return pid
    path.unlink(missing_ok=True)
    return None


def is_running() -> bool:
    return running_pid() is not None


def write_pid_file() -> None:
    path = _resolved_pid_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()), encoding="utf-8")


def remove_pid_file() -> None:
    _resolved_pid_file().unlink(missing_ok=True)
