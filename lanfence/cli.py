# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""LAN Fence command-line interface (Typer)."""

from __future__ import annotations

import json
import os
import queue
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import typer

from lanfence import __version__, alerts, scanner
from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.engine import build_findings, process_sighting, run_active_sweep
from lanfence.fingerprint import SignatureSet, fingerprint_device
from lanfence.logging_config import setup_logging
from lanfence.models import Finding
from lanfence.report import (
    exit_code_for,
    exit_code_for_findings,
    render_events,
    render_findings,
    render_scan_result,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "LAN Fence - defensive LAN device monitor.\n\n"
        "Scans for connected devices via ARP, tracks them against an allowlist "
        "of devices you trust, and alerts when something unknown joins your "
        "network. Observation only; LAN Fence never modifies the network."
    ),
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"lanfence {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


def _load_config(config_path: Optional[Path]) -> Config:
    try:
        return Config.load(config_path)
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"error: could not load config: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


#: Directories on root's default ``secure_path`` (see ``sudo -V``). If the
#: launcher lives here, a bare ``sudo lanfence`` works; otherwise (pipx /
#: ``pip install --user`` put it in ``~/.local/bin``) it does not.
_ROOT_SECURE_PATH = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/snap/bin",
)


def _launcher_path() -> Optional[Path]:
    """Absolute path to the installed ``lanfence`` launcher script, if any.

    Ignores ``sys.argv[0]`` when it is not actually the ``lanfence`` console
    script (e.g. ``python -m lanfence.cli`` during development).
    """

    argv0 = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    candidates = []
    if argv0 is not None and argv0.name == "lanfence":
        candidates.append(argv0)
    which = shutil.which("lanfence")
    candidates.append(Path(which) if which else None)
    for path in candidates:
        if path is not None and path.is_absolute() and path.exists():
            # resolve symlinks so callers see (and can vet) the real target
            try:
                return Path(os.path.realpath(path))
            except OSError:
                return path
    return None


def _group_write_is_self_only(st: os.stat_result) -> bool:
    """True if the current user is the *only* account in ``st``'s group.

    Debian and Raspberry Pi OS default new users to ``umask 002``, so a fresh
    pipx venv (``~/.local/share/pipx/venvs/...``) is group-writable by the
    user's own primary group - typically a group nobody else belongs to. That
    is not a real tampering risk the way an arbitrary other account would be,
    so it should not fail the trust check the way world-writable does.
    """

    try:
        import grp
        import pwd

        me = pwd.getpwuid(os.geteuid()).pw_name
        members = set(grp.getgrgid(st.st_gid).gr_mem)
        # anyone whose *primary* group is this one is a member too, even
        # though getgrgid() only lists supplementary members.
        members.update(entry.pw_name for entry in pwd.getpwall() if entry.pw_gid == st.st_gid)
        return members <= {me}
    except (KeyError, ImportError, OSError):
        return False


def _trusted_to_run_as_root(path: Path) -> bool:
    """True if a third party could not have swapped out ``path``.

    ``_launcher_path()`` can fall back to ``$PATH`` (``shutil.which``), which is
    the *invoking* user's ``PATH``. Before we ask ``sudo`` to run that file as
    root - or symlink it onto root's ``PATH`` - make sure another account could
    not have replaced it. World-writable always fails this; group-writable
    only fails it when the group actually has other members (see
    :func:`_group_write_is_self_only`) - otherwise every umask-002 pipx
    install on Debian/Raspberry Pi OS would be rejected.
    """

    try:
        for target in (path, path.parent):
            st = target.stat()
            mode = st.st_mode
            if mode & stat.S_IWOTH:
                return False
            if mode & stat.S_IWGRP and not _group_write_is_self_only(st):
                return False
    except OSError:
        return False
    return True


def _sudo_hints(subcommand: str) -> list[str]:
    """Copy-pasteable ways to re-run ``subcommand`` as root, best first.

    ``sudo`` resets ``PATH`` to a fixed ``secure_path``, so a bare
    ``sudo lanfence`` fails with "command not found" for the common pipx /
    ``pip install --user`` layout. Detect that and offer commands that work.
    """

    launcher = _launcher_path()
    on_root_path = launcher is not None and str(launcher.parent) in _ROOT_SECURE_PATH

    if on_root_path or launcher is None:
        return [f"sudo lanfence {subcommand}"]

    quoted = shlex.quote(str(launcher))
    return [
        f"sudo {quoted} {subcommand}",
        f'sudo env "PATH=$PATH" lanfence {subcommand}',
    ]


def _permanent_link_hint() -> Optional[str]:
    """One-liner that makes ``sudo lanfence`` work for good, or None if the
    launcher is already on root's PATH."""

    launcher = _launcher_path()
    if launcher is None or str(launcher.parent) in _ROOT_SECURE_PATH:
        return None
    return "lanfence link          # prompts for your sudo password"


def _warn_not_root(subcommand: str) -> None:
    """Print a not-root warning with copy-pasteable ways to fix it.

    ARP scanning/sniffing needs raw-socket access (``CAP_NET_RAW``), so
    ``scan``/``monitor`` see little or nothing without root.
    """

    hint = "\n    ".join(_sudo_hints(subcommand))
    typer.secho(
        "warning: not running as root - ARP scanning needs raw-socket access.\n"
        f"  re-run as:\n    {hint}",
        fg="yellow", err=True,
    )
    permanent = _permanent_link_hint()
    if permanent is not None:
        typer.secho(
            f"  or, so a bare `sudo lanfence` works from now on:\n    {permanent}",
            fg="bright_black", err=True,
        )


_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def _parse_since(value: str) -> datetime:
    """Parse a duration like ``24h``, ``30m``, ``7d`` into a UTC cutoff datetime."""

    value = value.strip().lower()
    if value and value[-1] in _UNIT_SECONDS and value[:-1].replace(".", "", 1).isdigit():
        amount = float(value[:-1])
        seconds = amount * _UNIT_SECONDS[value[-1]]
        return datetime.now(timezone.utc) - timedelta(seconds=seconds)
    typer.secho(
        f"error: could not parse --since {value!r} (expected e.g. 24h, 30m, 7d)",
        fg="red", err=True,
    )
    raise typer.Exit(code=2)


@app.command()
def scan(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to scan."),
    subnet: Optional[str] = typer.Option(None, "--subnet", "-s", help="CIDR subnet to scan (default: auto-detect)."),
    output_format: str = typer.Option("table", "--format", "-f", help="table | json"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    alert: bool = typer.Option(False, "--alert", help="Dispatch alerts for findings via configured channels."),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings", help="Exit non-zero when medium+ findings are present."
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True),
) -> None:
    """One-time active ARP scan; shows connected devices and any findings."""

    setup_logging(verbose)
    cfg = _load_config(config)

    if not _is_root():
        _warn_not_root("scan")

    signatures = SignatureSet.load(cfg.rogue_signatures_file)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())

    with DeviceStore(cfg.resolved_db_path()) as store:
        result = run_active_sweep(cfg, store, allowlist, signatures, interface=interface, subnet=subnet)

    if alert:
        alerts.dispatch(result.findings, cfg.alerts)

    if output_format == "json":
        typer.echo(result.to_json())
    else:
        render_scan_result(result)

    if fail_on_findings:
        raise typer.Exit(code=exit_code_for(result))


def _emit_findings(findings: list[Finding], *, alert: bool, cfg: Config) -> None:
    colour = {"high": "red", "medium": "yellow", "info": "cyan"}
    for finding in findings:
        typer.secho(
            f"[{finding.severity.upper()}] {finding.title} (mac={finding.mac})",
            fg=colour.get(finding.severity, "white"), bold=(finding.severity == "high"),
        )
        if finding.rationale:
            typer.echo(f"    {finding.rationale}")
        if finding.recommendation:
            typer.secho(f"    Recommendation: {finding.recommendation}", fg="cyan")
    if alert and findings:
        alerts.dispatch(findings, cfg.alerts)


@app.command()
def monitor(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to monitor."),
    subnet: Optional[str] = typer.Option(None, "--subnet", "-s", help="CIDR subnet to actively sweep."),
    interval: Optional[float] = typer.Option(None, "--interval", help="Active-sweep interval override (seconds)."),
    passive: Optional[bool] = typer.Option(
        None, "--passive/--no-passive", help="Also passively sniff ARP traffic between sweeps."
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    alert: bool = typer.Option(True, "--alert/--no-alert", help="Dispatch alerts for findings as they occur."),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True),
) -> None:
    """Continuously watch for new/changed devices until interrupted (Ctrl+C)."""

    setup_logging(verbose)
    cfg = _load_config(config)
    if interval is not None:
        cfg.scan.scan_interval_seconds = interval
    if passive is not None:
        cfg.scan.passive = passive

    if not _is_root():
        _warn_not_root("monitor")

    signatures = SignatureSet.load(cfg.rogue_signatures_file)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    store = DeviceStore(cfg.resolved_db_path())

    iface = interface or cfg.scan.interface or scanner.default_interface()
    net = subnet or cfg.scan.subnet

    typer.secho(f"LAN Fence {__version__} - monitoring (Ctrl+C to stop)", fg="green", bold=True)
    typer.echo(
        f"interface: {iface or '(auto)'}   scan interval: {cfg.scan.scan_interval_seconds:.0f}s   "
        f"passive: {cfg.scan.passive}"
    )

    stop_event = threading.Event()
    passive_queue: "queue.Queue[scanner.ArpSighting]" = queue.Queue()

    def _run_passive() -> None:
        try:
            scanner.passive_sniff(on_sighting=passive_queue.put, interface=iface, stop_event=stop_event)
        except scanner.ScannerUnavailable as exc:
            typer.secho(f"passive monitoring unavailable: {exc}", fg="yellow", err=True)

    passive_thread: threading.Thread | None = None
    if cfg.scan.passive:
        passive_thread = threading.Thread(target=_run_passive, daemon=True)
        passive_thread.start()

    try:
        last_sweep = 0.0
        while True:
            now = time.monotonic()
            if now - last_sweep >= cfg.scan.scan_interval_seconds:
                result = run_active_sweep(cfg, store, allowlist, signatures, interface=iface, subnet=net)
                last_sweep = now
                for err in result.errors:
                    typer.secho(f"error: {err}", fg="red", err=True)
                _emit_findings(result.findings, alert=alert, cfg=cfg)

            drained = 0
            while drained < 200:
                try:
                    sighting = passive_queue.get_nowait()
                except queue.Empty:
                    break
                drained += 1
                _, _event_type, findings = process_sighting(
                    mac=sighting.mac, ip=sighting.ip, seen_at=sighting.seen_at,
                    store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
                )
                _emit_findings(findings, alert=alert, cfg=cfg)

            time.sleep(1.0)
    except KeyboardInterrupt:
        typer.echo("\nstopping monitor...")
    finally:
        stop_event.set()
        store.close()


@app.command()
def report(
    since: str = typer.Option("24h", "--since", help="How far back to report, e.g. 30m, 24h, 7d."),
    output_format: str = typer.Option("table", "--format", "-f", help="table | json"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings", help="Exit non-zero when medium+ findings are present in the window."
    ),
) -> None:
    """Summarize device activity (connects/disconnects/reappearances) since a point in time."""

    cfg = _load_config(config)
    since_dt = _parse_since(since)
    signatures = SignatureSet.load(cfg.rogue_signatures_file)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())

    with DeviceStore(cfg.resolved_db_path()) as store:
        events = store.events_since(since_dt)
        devices_by_mac = {d.mac: d for d in store.all_devices()}

    findings: list[Finding] = []
    for event in events:
        if event.event_type == "disconnected":
            continue
        device = devices_by_mac.get(event.mac)
        if device is None:
            continue
        allow_entry = allowlist.match(event.mac)
        device = device.model_copy(
            update={
                "allowlisted": allow_entry is not None,
                "allowlist_name": allow_entry.name if allow_entry else None,
            }
        )
        _, matches = fingerprint_device(
            event.mac, device.hostname, signatures=signatures, vendor_file=cfg.vendor_file
        )
        findings.extend(build_findings(device, event.event_type, matches))

    if output_format == "json":
        payload = {
            "since": since_dt.isoformat(),
            "events": [e.model_dump(mode="json") for e in events],
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        typer.echo(json.dumps(payload, indent=2))
    else:
        typer.secho(f"LAN Fence report - since {since_dt.isoformat()}", fg="cyan", bold=True)
        render_events(events)
        typer.echo("")
        render_findings(findings)

    if fail_on_findings:
        raise typer.Exit(code=exit_code_for_findings(findings))


@app.command()
def allow(
    mac: Optional[str] = typer.Argument(None, help="MAC address to trust."),
    name: Optional[str] = typer.Option(None, "--name", help="Label for this device."),
    notes: Optional[str] = typer.Option(None, "--notes", help="Freeform notes."),
    list_entries: bool = typer.Option(False, "--list", help="Show current allowlist entries."),
    remove: Optional[str] = typer.Option(None, "--remove", help="MAC address to remove from the allowlist."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Manage the allowlist of devices you trust.

    Findings about an allowlisted device are downgraded to *info*, so your own
    hardware stops shouting every time it reconnects. With no MAC and no
    options, lists the current entries.
    """

    cfg = _load_config(config)
    path = cfg.resolved_allowlist_file()
    al = Allowlist.load(path)
    al.path = path

    if remove is not None:
        entry = al.remove(remove)
        if entry is None:
            typer.secho(f"error: {remove} is not on the allowlist", fg="red", err=True)
            raise typer.Exit(code=2)
        al.save()
        typer.secho(f"removed: {entry.name} ({entry.mac})", fg="green")
        return

    if list_entries or mac is None:
        if not al.entries:
            typer.echo(f"allowlist is empty ({path})")
            return
        typer.secho(f"Allowlist ({path}):\n", fg="cyan", bold=True)
        for i, e in enumerate(al.entries, start=1):
            tail = f"  {e.notes}" if e.notes else ""
            typer.echo(f"  {i:>3}. {e.name:<28}  {e.mac}{tail}")
        return

    entry = al.add(mac, name or mac, notes or "")
    al.save()
    typer.secho(f"added: {entry.name}  ({entry.mac})", fg="green")


#: Set in the child's environment across the ``execvpe`` below so a second
#: attempt (still not root after ``sudo`` supposedly ran - wrong password,
#: a wrapped/non-standard ``sudo``, or similar) reports an error instead of
#: re-prompting forever.
_SUDO_REEXEC_MARKER = "LANFENCE_SUDO_REEXEC_ATTEMPTED"


def _reexec_with_sudo() -> None:
    """Re-run this exact command under ``sudo`` (which prompts for a password).

    Returns only if that is not possible (no sudo, no TTY, or already elevated);
    otherwise it replaces the current process and never returns.
    """

    if _is_root() or os.environ.get("LANFENCE_NO_SUDO_REEXEC"):
        return
    if os.environ.get(_SUDO_REEXEC_MARKER):
        typer.secho(
            "error: still not root after re-running under sudo - check your "
            "sudo configuration and try again with an explicit `sudo`.",
            fg="red", err=True,
        )
        raise typer.Exit(code=1)
    if shutil.which("sudo") is None or not sys.stdin.isatty():
        return
    launcher = _launcher_path()
    if launcher is None:
        return
    if not _trusted_to_run_as_root(launcher):
        typer.secho(
            f"not auto-escalating: {launcher} or its directory is writable by "
            "other users. Re-run as root explicitly if you trust it.",
            fg="yellow", err=True,
        )
        return
    argv = ["sudo", str(launcher), *sys.argv[1:]]
    typer.secho(f"re-running with sudo: {shlex.join(argv)}", fg="bright_black")
    env = {**os.environ, _SUDO_REEXEC_MARKER: "1"}
    try:
        os.execvpe("sudo", argv, env)  # noqa: S606 - deliberate privilege escalation
    except OSError:
        return


@app.command()
def link(
    bin_dir: Path = typer.Option(
        Path("/usr/local/bin"), "--bin-dir",
        help="Directory on root's PATH to link the launcher into.",
    ),
    remove: bool = typer.Option(False, "--remove", help="Remove the link instead of creating it."),
    sudo: bool = typer.Option(
        True, "--sudo/--no-sudo",
        help="Re-run under sudo (prompting for a password) if writing needs root.",
    ),
) -> None:
    """Make `sudo lanfence` work by symlinking the launcher into root's PATH.

    A pipx / ``pip install --user`` install puts ``lanfence`` in
    ``~/.local/bin``, which ``sudo`` does not see. Run ``lanfence link`` once
    (no ``sudo`` needed - it re-runs itself under ``sudo`` and prompts for your
    password) and afterwards ``sudo lanfence scan`` / ``sudo lanfence monitor``
    work without a full path. ``--no-sudo`` skips the escalation; ``--remove``
    deletes the link.
    """

    target = bin_dir / "lanfence"
    need_root = not os.access(bin_dir if bin_dir.is_dir() else bin_dir.parent, os.W_OK)
    if need_root and not _is_root() and sudo:
        _reexec_with_sudo()  # replaces the process on success

    if remove:
        if target.is_symlink() or target.exists():
            try:
                target.unlink()
            except OSError as exc:
                typer.secho(f"error: could not remove {target}: {exc}", fg="red", err=True)
                raise typer.Exit(code=1) from exc
            typer.secho(f"removed {target}", fg="green")
        else:
            typer.echo(f"nothing to remove at {target}")
        return

    launcher = _launcher_path()
    if launcher is None:
        typer.secho(
            "error: could not locate the lanfence launcher to link.", fg="red", err=True
        )
        raise typer.Exit(code=2)

    if not _trusted_to_run_as_root(launcher):
        typer.secho(
            f"error: refusing to link {target} -> {launcher}: the launcher or its "
            "directory is writable by other users, so the link would let them run "
            "code as root via `sudo lanfence`.",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)

    if target.is_symlink() and target.resolve() == launcher.resolve():
        typer.secho(f"{target} already points at {launcher}", fg="green")
        return

    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.exists():
            target.unlink()
        target.symlink_to(launcher)
    except OSError as exc:
        typer.secho(f"error: could not write {target}: {exc}", fg="red", err=True)
        if not _is_root():
            typer.secho(
                f"  run it as root:  sudo {shlex.quote(str(launcher))} link",
                fg="bright_black",
            )
        raise typer.Exit(code=1) from exc

    typer.secho(f"linked {target} -> {launcher}", fg="green")
    typer.echo("`sudo lanfence scan` / `sudo lanfence monitor` now work without a full path.")


@app.command()
def check(
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Check that this host can run LAN Fence (permissions, scapy, interface)."""

    cfg = _load_config(config)

    typer.secho("Host", fg="cyan", bold=True)
    typer.echo(f"  root:        {_is_root()}")
    typer.echo(f"  platform:    {sys.platform}")

    typer.secho("\nScanning", fg="cyan", bold=True)
    try:
        import scapy  # noqa: F401

        typer.secho("  ok       scapy is installed", fg="green")
    except ImportError:
        typer.secho(
            "  MISSING  scapy is not installed - run: pipx inject lanfence scapy "
            "(or pip install 'lanfence[scan]')",
            fg="yellow",
        )

    iface = cfg.scan.interface or scanner.default_interface()
    typer.echo(f"  interface:   {iface or '(could not auto-detect)'}")
    net = cfg.scan.subnet or scanner.local_subnet(iface)
    typer.echo(f"  subnet:      {net or '(could not auto-detect)'}")

    typer.secho("\nStorage", fg="cyan", bold=True)
    db_path = cfg.resolved_db_path()
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        DeviceStore(db_path).close()
        typer.secho(f"  ok       database writable: {db_path}", fg="green")
        db_ok = True
    except OSError as exc:
        typer.secho(f"  FAIL     database not writable: {db_path} ({exc})", fg="red")
        db_ok = False

    allowlist_file = cfg.resolved_allowlist_file()
    if not allowlist_file.is_file():
        allowlist = Allowlist.load(allowlist_file)
        allowlist.path = allowlist_file
        try:
            allowlist.save()
            typer.echo(f"  allowlist:   {allowlist_file} (created)")
        except OSError as exc:
            typer.secho(f"  allowlist:   {allowlist_file} (could not create: {exc})", fg="yellow")
    else:
        typer.echo(f"  allowlist:   {allowlist_file} (exists)")

    if not _is_root():
        typer.echo("")
        _warn_not_root("check")

    raise typer.Exit(code=0 if db_ok else 1)


_PYPI_JSON_URL = "https://pypi.org/pypi/lanfence/json"


def _pypi_latest_version(timeout: float = 6.0) -> Optional[str]:
    """The newest lanfence version on PyPI, queried directly (no local pip
    index cache involved), or ``None`` if PyPI could not be reached."""

    req = urllib.request.Request(_PYPI_JSON_URL, headers={"User-Agent": f"lanfence/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https literal
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    return (data.get("info") or {}).get("version")


def _version_key(value: str) -> tuple:
    key: list = []
    for part in value.replace("-", ".").replace("+", ".").split("."):
        key.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(key)


def _is_editable_install() -> bool:
    try:
        from importlib.metadata import distribution

        raw = distribution("lanfence").read_text("direct_url.json")
        if raw:
            return bool(json.loads(raw).get("dir_info", {}).get("editable"))
    except (ImportError, OSError, ValueError):  # metadata absent / malformed
        pass
    return False


#: Conservative POSIX login-name shape; also bounds what we hand to ``sudo -u``.
_USERNAME_RE = re.compile(r"\A[a-z_][a-z0-9_-]{0,31}\Z")


def _valid_local_user(name: Optional[str]) -> Optional[str]:
    """Return ``name`` (canonicalised) only if it is a well-formed login name
    of a real local account. Guards values passed to ``sudo -u`` - notably
    ``$SUDO_USER``, which is attacker-influenceable if root's environment is
    already tainted."""

    if not name or not _USERNAME_RE.match(name):
        return None
    try:
        import pwd

        return pwd.getpwnam(name).pw_name
    except (KeyError, ImportError):  # not a local account / non-POSIX
        return None


def _path_owner(path: str) -> Optional[str]:
    """Login name that owns ``path`` (a pipx venv is owned by its installer)."""

    try:
        import pwd

        return pwd.getpwuid(Path(path).stat().st_uid).pw_name
    except (OSError, KeyError, ImportError):  # stat failure / unknown uid / non-POSIX
        return None


def _is_pipx_install() -> bool:
    prefix = str(Path(sys.prefix).resolve())
    return "/pipx/" in prefix or os.path.basename(os.path.dirname(prefix)) == "venvs"


def _upgrade_command() -> Optional[list[str]]:
    """The command that upgrades *this* install, or ``None`` if that can't be
    guessed (a source checkout, or an install this doesn't recognize)."""

    if __version__.endswith("+dev") or _is_editable_install():
        return None  # source checkout - `git pull`
    if _is_pipx_install():
        # `--pip-args=--no-cache-dir` bypasses pip's wheel/index cache for this
        # one upgrade (rather than purging the shared pip cache outright, which
        # would affect every other package too) - the point is a release that
        # just published on PyPI is never masked by a stale cached wheel.
        cmd = ["pipx", "upgrade", "lanfence", "--pip-args=--no-cache-dir"]
        # `sudo lanfence upgrade` runs as root, but a pipx install lives in the
        # *user's* home - pipx as root can't see it. Drop back to the invoking
        # user. Both candidate names are validated as real local accounts
        # before they reach `sudo -u`.
        owner = _valid_local_user(os.environ.get("SUDO_USER")) or _valid_local_user(
            _path_owner(str(Path(sys.prefix).resolve()))
        )
        if _is_root() and owner and owner != "root":
            return ["sudo", "-u", owner, "-H", *cmd]
        return cmd
    return [sys.executable, "-m", "pip", "install", "--upgrade", "--no-cache-dir", "lanfence"]


@app.command()
def upgrade(
    check: bool = typer.Option(
        False, "--check", help="Only report whether an update is available; do not install."
    ),
) -> None:
    """Check PyPI for a newer lanfence and (unless --check) install it.

    Queries PyPI directly rather than trusting a local pip index cache, and
    for a pipx install runs the upgrade with `--pip-args=--no-cache-dir` so a
    release that just published can't be masked by a stale cached wheel.
    """

    typer.echo(f"installed: {__version__}")
    latest = _pypi_latest_version()
    if latest is None:
        typer.secho("could not reach PyPI to check for updates.", fg="red", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"latest on PyPI: {latest}")

    if __version__.endswith("+dev") or _is_editable_install():
        typer.secho(
            "this is a source / editable checkout - `git pull` to update.",
            fg="bright_black",
        )
        raise typer.Exit(code=0)

    if _version_key(latest) <= _version_key(__version__):
        typer.secho("lanfence is up to date.", fg="green")
        raise typer.Exit(code=0)

    typer.secho(f"\nlanfence {latest} is available.", fg="yellow", bold=True)
    cmd = _upgrade_command()
    if cmd and cmd[0] == "sudo":
        typer.secho(
            f"(this is a pipx install owned by {cmd[2]}; upgrading as that user)",
            fg="bright_black",
        )
    if check or cmd is None:
        if cmd is None:
            typer.echo(
                "this install is managed elsewhere - upgrade it the same way you installed it."
            )
        else:
            typer.echo(f"to upgrade:  {shlex.join(cmd)}")
        raise typer.Exit(code=10)

    typer.secho(f"running: {shlex.join(cmd)}\n", fg="bright_black")
    try:
        result = subprocess.run(cmd, check=False)  # noqa: S603 - argv list, no shell
    except FileNotFoundError:
        typer.secho(f"error: {cmd[0]} not found on PATH.", fg="red", err=True)
        raise typer.Exit(code=1) from None
    if result.returncode != 0:
        typer.secho("upgrade command failed - see its output above.", fg="red", err=True)
        raise typer.Exit(code=result.returncode)
    typer.secho("\nupgraded. run `lanfence --version` to confirm.", fg="green")


def main() -> None:  # pragma: no cover - entry point shim
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
