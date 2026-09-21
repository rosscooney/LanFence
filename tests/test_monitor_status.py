# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from lanfence import monitor_status


def test_running_pid_none_when_no_pidfile(tmp_path: Path):
    with patch("lanfence.monitor_status._resolved_pid_file", return_value=tmp_path / "monitor.pid"):
        assert monitor_status.running_pid() is None
        assert monitor_status.is_running() is False


def test_write_and_read_own_pid(tmp_path: Path):
    pid_file = tmp_path / "monitor.pid"
    with patch("lanfence.monitor_status._resolved_pid_file", return_value=pid_file):
        monitor_status.write_pid_file()
        assert monitor_status.running_pid() == os.getpid()
        assert monitor_status.is_running() is True
        monitor_status.remove_pid_file()
        assert not pid_file.exists()
        assert monitor_status.is_running() is False


def test_running_pid_cleans_up_stale_pidfile(tmp_path: Path):
    pid_file = tmp_path / "monitor.pid"
    pid_file.write_text("999999999")  # exceedingly unlikely to be a live PID
    with patch("lanfence.monitor_status._resolved_pid_file", return_value=pid_file):
        assert monitor_status.running_pid() is None
        assert not pid_file.exists()


def test_running_pid_none_for_malformed_pidfile(tmp_path: Path):
    pid_file = tmp_path / "monitor.pid"
    pid_file.write_text("not-a-pid")
    with patch("lanfence.monitor_status._resolved_pid_file", return_value=pid_file):
        assert monitor_status.running_pid() is None
