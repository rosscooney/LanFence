from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from lanfence.cli import _reexec_with_sudo, _sudo_hints, _trusted_to_run_as_root, app

runner = CliRunner()


def test_reexec_with_sudo_fails_clean_instead_of_looping_if_still_not_root():
    """Regression test: a `sudo` that "succeeds" without actually elevating
    (a non-standard wrapper, misconfiguration, etc.) must not cause an
    infinite re-exec / password-prompt loop - it should fail once with a
    clear error instead."""

    with patch("lanfence.cli._is_root", return_value=False), \
         patch.dict(os.environ, {"LANFENCE_SUDO_REEXEC_ATTEMPTED": "1"}), \
         patch("lanfence.cli.os.execvpe") as exec_mock:
        with pytest.raises(typer.Exit) as excinfo:
            _reexec_with_sudo()
    assert excinfo.value.exit_code == 1
    exec_mock.assert_not_called()


def test_reexec_with_sudo_execs_sudo_with_marker_env(tmp_path: Path):
    launcher = tmp_path / "lanfence"
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)

    with patch("lanfence.cli._is_root", return_value=False), \
         patch.dict(os.environ, {}, clear=False), \
         patch("lanfence.cli.shutil.which", return_value="/usr/bin/sudo"), \
         patch("lanfence.cli.sys.stdin.isatty", return_value=True), \
         patch("lanfence.cli._launcher_path", return_value=launcher), \
         patch("lanfence.cli.os.execvpe") as exec_mock:
        os.environ.pop("LANFENCE_SUDO_REEXEC_ATTEMPTED", None)
        _reexec_with_sudo()

    exec_mock.assert_called_once()
    args, kwargs = exec_mock.call_args
    program, argv, env = args
    assert program == "sudo"
    assert argv[0] == "sudo"
    assert str(launcher) in argv
    assert env.get("LANFENCE_SUDO_REEXEC_ATTEMPTED") == "1"


def test_reexec_with_sudo_noop_when_already_root():
    with patch("lanfence.cli._is_root", return_value=True), \
         patch("lanfence.cli.os.execvpe") as exec_mock:
        _reexec_with_sudo()
    exec_mock.assert_not_called()


def test_reexec_with_sudo_noop_when_opted_out():
    with patch("lanfence.cli._is_root", return_value=False), \
         patch.dict(os.environ, {"LANFENCE_NO_SUDO_REEXEC": "1"}), \
         patch("lanfence.cli.os.execvpe") as exec_mock:
        _reexec_with_sudo()
    exec_mock.assert_not_called()


def test_reexec_with_sudo_noop_when_no_tty():
    with patch("lanfence.cli._is_root", return_value=False), \
         patch.dict(os.environ, {}, clear=False), \
         patch("lanfence.cli.shutil.which", return_value="/usr/bin/sudo"), \
         patch("lanfence.cli.sys.stdin.isatty", return_value=False), \
         patch("lanfence.cli.os.execvpe") as exec_mock:
        os.environ.pop("LANFENCE_SUDO_REEXEC_ATTEMPTED", None)
        _reexec_with_sudo()
    exec_mock.assert_not_called()


def test_trusted_to_run_as_root_true_for_owner_only_paths(tmp_path: Path):
    launcher = tmp_path / "lanfence"
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)
    assert _trusted_to_run_as_root(launcher) is True


def test_trusted_to_run_as_root_false_for_group_writable_dir(tmp_path: Path):
    launcher = tmp_path / "lanfence"
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)
    tmp_path.chmod(tmp_path.stat().st_mode | stat.S_IWGRP)
    try:
        assert _trusted_to_run_as_root(launcher) is False
    finally:
        tmp_path.chmod(0o700)


def test_trusted_to_run_as_root_false_for_missing_path(tmp_path: Path):
    assert _trusted_to_run_as_root(tmp_path / "nope") is False


def test_sudo_hints_plain_when_launcher_on_root_secure_path():
    with patch("lanfence.cli._launcher_path", return_value=Path("/usr/local/bin/lanfence")):
        assert _sudo_hints("scan") == ["sudo lanfence scan"]


def test_sudo_hints_plain_when_launcher_unknown():
    with patch("lanfence.cli._launcher_path", return_value=None):
        assert _sudo_hints("scan") == ["sudo lanfence scan"]


def test_sudo_hints_full_path_when_launcher_off_secure_path():
    launcher = Path("/home/alice/.local/bin/lanfence")
    with patch("lanfence.cli._launcher_path", return_value=launcher):
        hints = _sudo_hints("monitor")
    assert hints == [
        "sudo /home/alice/.local/bin/lanfence monitor",
        'sudo env "PATH=$PATH" lanfence monitor',
    ]


def test_link_creates_and_removes_symlink(tmp_path: Path):
    launcher = tmp_path / "src" / "lanfence"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)
    bin_dir = tmp_path / "bin"

    with patch("lanfence.cli._launcher_path", return_value=launcher):
        result = runner.invoke(app, ["link", "--bin-dir", str(bin_dir), "--no-sudo"])
    assert result.exit_code == 0, result.output
    target = bin_dir / "lanfence"
    assert target.is_symlink()
    assert target.resolve() == launcher.resolve()

    # running again is a no-op, not an error
    with patch("lanfence.cli._launcher_path", return_value=launcher):
        result = runner.invoke(app, ["link", "--bin-dir", str(bin_dir), "--no-sudo"])
    assert result.exit_code == 0
    assert "already points at" in result.output

    result = runner.invoke(app, ["link", "--bin-dir", str(bin_dir), "--remove", "--no-sudo"])
    assert result.exit_code == 0
    assert not target.exists()


def test_link_refuses_untrusted_launcher(tmp_path: Path):
    launcher = tmp_path / "src" / "lanfence"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\n")
    launcher.chmod(0o755)
    launcher.parent.chmod(launcher.parent.stat().st_mode | stat.S_IWOTH)
    bin_dir = tmp_path / "bin"
    try:
        with patch("lanfence.cli._launcher_path", return_value=launcher):
            result = runner.invoke(app, ["link", "--bin-dir", str(bin_dir), "--no-sudo"])
    finally:
        launcher.parent.chmod(0o700)
    assert result.exit_code == 2
    assert "refusing to link" in result.output


def test_link_missing_launcher_errors(tmp_path: Path):
    with patch("lanfence.cli._launcher_path", return_value=None):
        result = runner.invoke(app, ["link", "--bin-dir", str(tmp_path / "bin"), "--no-sudo"])
    assert result.exit_code == 2
    assert "could not locate" in result.output


def test_link_remove_when_nothing_there(tmp_path: Path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    result = runner.invoke(app, ["link", "--bin-dir", str(bin_dir), "--remove", "--no-sudo"])
    assert result.exit_code == 0
    assert "nothing to remove" in result.output
