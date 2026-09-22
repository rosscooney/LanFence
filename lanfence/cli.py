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
import socket
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

from lanfence import __version__, active_inspect, alerts, discovery, monitor_status, monitor_ui, scanner, web
from lanfence.alert_worker import AlertDeliveryWorker
from lanfence.allowlist import Allowlist
from lanfence.channels import (
    CHANNEL_FIELDS,
    CHANNEL_NAMES,
    CLEAR,
    KEEP,
    ConcurrentModificationError,
    ConfigFileError,
    apply_channel_values,
    apply_digest_selection,
    check_insecure_permissions,
    list_channel_statuses,
    load_channels_config_file,
    resolve_channels_config_path,
    save_channels_config_file,
    send_channel_test_message,
    supports_digest,
    validate_channel_values,
)
from lanfence.config import DIGEST_CHANNELS, Config, expand_operator_path
from lanfence.db import DeviceStore
from lanfence.device_metadata import validate_metadata_value
from lanfence.dhcp_server import (
    dhcp_server_detection_active,
    dhcp_server_inventory,
    process_dhcp_server_sighting,
)
from lanfence.digest import build_digest, dispatch_digest
from lanfence.dossier import TriageSummary, build_device_dossier, build_triage_summary, review_priority
from lanfence.engine import (
    apply_self_trust,
    build_device,
    build_findings,
    build_inventory,
    coalesce_sightings,
    enrich_missing_hostnames,
    filter_rate_limited,
    filter_snoozed,
    is_review_needed,
    process_sighting,
    run_active_sweep,
    utcnow,
)
from lanfence.fingerprint import SignatureSet, fingerprint_device
from lanfence.fsutil import atomic_write
from lanfence.logging_config import setup_logging
from lanfence.models import Finding, format_datetime
from lanfence.netutil import normalize_mac
from lanfence.safe_errors import summarize_error
from lanfence.report import (
    exit_code_for,
    exit_code_for_findings,
    render_advertised_services,
    render_channels_table,
    render_device_detail,
    render_device_inventory,
    render_dossier_compact,
    render_digest,
    render_events,
    render_findings,
    render_inspection_result,
    render_scan_result,
    render_triage_summary,
)
from lanfence.vendor import format_vendor_table, parse_ieee_oui_csv

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


#: Matches DeviceStore's own "owned by uid X, not the expected uid Y" text
#: (see lanfence/db.py's _check_fd_owner_and_mode) - used only to add a
#: copy-pasteable `chown` fix to the error below, never to change whether
#: the error is treated as fatal.
_OWNERSHIP_MISMATCH_RE = re.compile(r"owned by uid \d+, not the expected uid (\d+)")


def _ownership_fix_hint(exc: BaseException, path: Path) -> Optional[str]:
    """A copy-pasteable ``sudo chown ...`` command if ``exc`` is
    specifically the "wrong owner" error :func:`_open_store`/`lanfence
    check` can hit opening the database directory/file (see
    ``lanfence.db._check_fd_owner_and_mode``) - ``None`` for any other
    error, where there's nothing this specific to suggest."""

    match = _OWNERSHIP_MISMATCH_RE.search(str(exc))
    if not match:
        return None
    try:
        import pwd

        username = pwd.getpwuid(int(match.group(1))).pw_name
    except (KeyError, ValueError, ImportError):
        return None
    return f"sudo chown -R {username}:{username} {path}"


def _open_store(db_path: Path, **kwargs) -> DeviceStore:
    """Open the device database, translating a directory/file ownership,
    permission, or symlink problem (see ``lanfence.db._ensure_secure_directory``)
    into a clear, actionable CLI error - with a copy-pasteable `chown` fix
    when it's specifically an ownership mismatch - instead of a raw
    Python traceback. The same boundary role `_load_config` already plays
    for a broken config file, applied to the database for the same reason:
    an environment problem outside this process's control should never
    surface as an unhandled exception.
    """

    try:
        return DeviceStore(db_path, **kwargs)
    except (OSError, RuntimeError) as exc:
        typer.secho(f"error: could not open the database at {db_path}: {exc}", fg="red", err=True)
        hint = _ownership_fix_hint(exc, db_path.parent)
        if hint:
            typer.secho(f"fix: {hint}", fg="yellow", err=True)
        raise typer.Exit(code=1) from exc


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


def _invoking_uid() -> int:
    """The UID of the human actually running this command, even once
    :func:`_reexec_with_sudo` has escalated the process to root.

    ``sudo`` sets ``SUDO_UID`` to the invoking user before exec'ing as root -
    without consulting it here, a post-escalation check would see euid 0 and
    (correctly, but for the wrong question) find "root" absent from the
    original user's own group, wrongly treating a perfectly normal umask-002
    pipx install as shared with a stranger. Falls back to the real euid when
    not running under sudo (already root, or invoked directly).
    """

    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is not None:
        try:
            return int(sudo_uid)
        except ValueError:
            pass
    return os.geteuid()


def _group_write_is_self_only(st: os.stat_result) -> bool:
    """True if the invoking user is the *only* account in ``st``'s group.

    Debian and Raspberry Pi OS default new users to ``umask 002``, so a fresh
    pipx venv (``~/.local/share/pipx/venvs/...``) is group-writable by the
    user's own primary group - typically a group nobody else belongs to. That
    is not a real tampering risk the way an arbitrary other account would be,
    so it should not fail the trust check the way world-writable does.
    """

    try:
        import grp
        import pwd

        me = pwd.getpwuid(_invoking_uid()).pw_name
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


def _duration_seconds(value: str) -> Optional[float]:
    """Parse a duration like ``24h``, ``30m``, ``7d`` into seconds, or
    ``None`` if it isn't well-formed. The one duration grammar shared by
    ``--since`` and ``--snooze``."""

    value = value.strip().lower()
    if value and value[-1] in _UNIT_SECONDS and value[:-1].replace(".", "", 1).isdigit():
        return float(value[:-1]) * _UNIT_SECONDS[value[-1]]
    return None


def _parse_since(value: str) -> datetime:
    """Parse a duration like ``24h``, ``30m``, ``7d`` into a UTC cutoff datetime."""

    seconds = _duration_seconds(value)
    if seconds is None:
        typer.secho(
            f"error: could not parse --since {value!r} (expected e.g. 24h, 30m, 7d)",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


def _parse_snooze_duration(value: str) -> timedelta:
    """Parse a duration like ``24h`` for ``--snooze``. Exits(2) on bad input -
    for the *noninteractive* path; the interactive prompt uses
    :func:`_duration_seconds` directly so one bad answer doesn't abort the
    whole review session."""

    seconds = _duration_seconds(value)
    if seconds is None:
        typer.secho(
            f"error: could not parse --snooze {value!r} (expected e.g. 24h, 30m, 7d)",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)
    return timedelta(seconds=seconds)


@app.command()
def scan(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to scan."),
    subnet: Optional[str] = typer.Option(None, "--subnet", "-s", help="CIDR subnet to scan (default: auto-detect)."),
    ipv6: Optional[bool] = typer.Option(
        None, "--ipv6/--no-ipv6", help="Also discover devices via IPv6 neighbor discovery."
    ),
    output_format: str = typer.Option("table", "--format", "-f", help="table | json"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    alert: bool = typer.Option(False, "--alert", help="Dispatch alerts for findings via configured channels."),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings", help="Exit non-zero when medium+ findings are present."
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True),
) -> None:
    """One-time active scan (ARP + IPv6 neighbor discovery); shows connected devices and any findings."""

    setup_logging(verbose)
    cfg = _load_config(config)
    if ipv6 is not None:
        cfg.scan.ipv6 = ipv6

    if not _is_root():
        _warn_not_root("scan")

    signatures = SignatureSet.load(cfg.rogue_signatures_file)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    apply_self_trust(allowlist, interface=interface or cfg.scan.interface)

    triage: Optional[TriageSummary] = None
    with _open_store(cfg.resolved_db_path()) as store:
        result = run_active_sweep(cfg, store, allowlist, signatures, interface=interface, subnet=subnet)
        if alert:
            not_snoozed = filter_snoozed(result.findings, store, now=utcnow())
            to_send = filter_rate_limited(not_snoozed, store, cfg.alerts, now=utcnow())
            alerts.dispatch(to_send, cfg.alerts, store=store)

        if output_format != "json":
            # First-run/ongoing triage orientation over the *whole* known
            # inventory (not just devices seen in this sweep) - see
            # lanfence.dossier.build_triage_summary. Deliberately not part
            # of the JSON payload: it's a derived, human-facing summary,
            # not new scan data, and JSON output stays exactly ScanResult.
            now = utcnow()
            inventory = build_inventory(store, allowlist)
            dossiers = [
                build_device_dossier(
                    store, allowlist, d.mac, signatures=signatures, vendor_file=cfg.vendor_file,
                    now=now, device=d,
                )
                for d in inventory
            ]
            triage = build_triage_summary(dossiers, now=now)

    if output_format == "json":
        typer.echo(result.to_json())
    else:
        typer.secho(
            "note: this is a single, short active scan - a mobile/WiFi device that's asleep or "
            "power-saving may not respond in time and won't appear here, even though it's on the "
            "network. Run `lanfence monitor` for a complete picture: it repeats this sweep over time "
            "and passively listens in between, so a device only needs to be caught once.",
            fg="yellow",
        )
        typer.echo("")
        render_scan_result(result)
        summary_text = render_triage_summary(triage) if triage is not None else ""
        if summary_text:
            typer.echo("")
            typer.echo(summary_text)

    if fail_on_findings:
        raise typer.Exit(code=exit_code_for(result))


#: `lanfence run` is an exact alias for `lanfence scan` - same function, same
#: options, same behavior, just a second name for anyone who reaches for
#: "run" instead of "scan". Hidden from --help (scan is the documented
#: name) but still works exactly as before - never removed outright.
app.command(name="run", hidden=True)(scan)


def _finding_identity(finding: Finding) -> str:
    """Best available identity for a compact activity line - prefers an
    allowlist name already baked into the finding's title (see
    ``engine.build_findings``'s ``"...connected: {label}"``/``"...
    reappeared: {label}"`` titles for a trusted device), then a hostname
    from its evidence lines, then the MAC/subject id."""

    if "allowlisted" in finding.title.lower() and ":" in finding.title:
        return finding.title.split(":", 1)[1].strip()
    for ev in finding.evidence:
        if ev.startswith("Hostname: ") and not ev.endswith("[unknown]"):
            return ev.removeprefix("Hostname: ")
    return finding.mac or finding.subject_id or "[no device]"


def _finding_ip(finding: Finding) -> Optional[str]:
    for ev in finding.evidence:
        if ev.startswith("IP: ") and not ev.endswith("[unknown]"):
            return ev.removeprefix("IP: ")
    return None


def _finding_activity_label(finding: Finding) -> str:
    if finding.kind == "availability":
        base = "AVAILABILITY"
    elif finding.kind == "network_service":
        base = "NETWORK"
    elif "connected" in finding.title.lower():
        base = "NEW"
    elif "reappeared" in finding.title.lower():
        base = "RETURNED"
    else:
        base = "FINDING"
    if finding.severity != "info":
        base = f"{base} ({finding.severity})"
    return base


def _finding_activity_entry(finding: Finding) -> "monitor_ui.ActivityEntry":
    identity = _finding_identity(finding)
    ip = _finding_ip(finding)
    detail = f"{identity} · {ip}" if ip else identity
    level: "monitor_ui.ActivityLevel" = "info" if finding.severity == "info" else "finding"
    return monitor_ui.ActivityEntry(
        timestamp=monitor_ui.local_now(), level=level, label=_finding_activity_label(finding), detail=detail,
    )


def _emit_findings(
    findings: list[Finding], *, alert: bool, cfg: Config, store: DeviceStore,
    activity: "monitor_ui.ActivityLog | None" = None, stats: "monitor_ui.MonitorStats | None" = None,
    alert_worker: "AlertDeliveryWorker | None" = None,
) -> None:
    """Report ``findings`` to the operator, then dispatch alerts as usual.

    ``activity`` is given only by `lanfence monitor` in live mode - when
    present, each finding becomes one activity-log line instead of a
    `typer.secho` call, so the same finding is never shown twice (once
    live, once via the old console renderer). ``stats`` (also given only
    by `monitor`, live or not - its session summary needs an accurate
    count either way) has its finding counter incremented regardless of
    which rendering path was used. Every other caller (`scan`/`run`) leaves
    both ``None`` and gets the exact console output this function has
    always produced.

    ``alert_worker`` (given only by `monitor`) moves the actual network
    delivery onto a bounded background thread (see
    :mod:`lanfence.alert_worker`) so a slow/failing channel never blocks
    this thread's ongoing sighting processing; the filtering
    (snoozed/rate-limited) immediately below always happens here, on the
    thread that owns ``store``, regardless of whether delivery itself is
    backgrounded. ``None`` (the default, and always the case for `scan`)
    dispatches synchronously exactly as before.
    """

    if stats is not None:
        for _finding in findings:
            stats.record_finding()

    if activity is not None:
        for finding in findings:
            activity.add(_finding_activity_entry(finding))
    else:
        colour = {"high": "red", "medium": "yellow", "info": "cyan"}
        for finding in findings:
            subject = finding.mac or finding.subject_id or "[no device]"
            typer.secho(
                f"[{finding.severity.upper()}] {finding.title} (mac={subject})",
                fg=colour.get(finding.severity, "white"), bold=(finding.severity == "high"),
            )
            if finding.rationale:
                typer.echo(f"    {finding.rationale}")
            if finding.recommendation:
                typer.secho(f"    Recommendation: {finding.recommendation}", fg="cyan")

    if alert and findings:
        not_snoozed = filter_snoozed(findings, store, now=utcnow())
        to_send = filter_rate_limited(not_snoozed, store, cfg.alerts, now=utcnow())
        if not to_send:
            pass
        elif alert_worker is not None:
            alert_worker.submit(to_send, cfg.alerts)
        else:
            alerts.dispatch(to_send, cfg.alerts, store=store)


class _DropCountingQueue(queue.Queue):
    """A bounded queue whose producer side (the passive-sniffing thread)
    never blocks: :meth:`put_dropping` uses a nonblocking put and silently
    counts an overflow instead of stalling packet capture or raising.
    ``dropped`` is read only from `monitor`'s own main-loop thread; written
    only by the single passive-sniffing thread that owns this queue's
    producer side - safe without a lock under CPython's GIL for this
    single-writer/single-reader access pattern."""

    def __init__(self, maxsize: int) -> None:
        super().__init__(maxsize=maxsize)
        self.dropped = 0

    def put_dropping(self, item: object) -> None:
        try:
            self.put_nowait(item)
        except queue.Full:
            self.dropped += 1


@app.command()
def monitor(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to monitor."),
    subnet: Optional[str] = typer.Option(None, "--subnet", "-s", help="CIDR subnet to actively sweep."),
    interval: Optional[float] = typer.Option(None, "--interval", help="Active-sweep interval override (seconds)."),
    passive: Optional[bool] = typer.Option(
        None, "--passive/--no-passive", help="Also passively sniff ARP/ND traffic between sweeps."
    ),
    ipv6: Optional[bool] = typer.Option(
        None, "--ipv6/--no-ipv6", help="Also discover devices via IPv6 neighbor discovery."
    ),
    dhcp: Optional[bool] = typer.Option(
        None, "--dhcp/--no-dhcp",
        help="While passive monitoring, also snoop DHCP for a device's self-reported hostname.",
    ),
    mdns: Optional[bool] = typer.Option(
        None, "--mdns/--no-mdns",
        help="While passive monitoring, also parse mDNS/DNS-SD service advertisements.",
    ),
    ssdp: Optional[bool] = typer.Option(
        None, "--ssdp/--no-ssdp",
        help="While passive monitoring, also parse SSDP/UPnP service advertisements.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    alert: bool = typer.Option(True, "--alert/--no-alert", help="Dispatch alerts for findings as they occur."),
    live: Optional[bool] = typer.Option(
        None, "--live/--no-live",
        help="Live bordered dashboard vs. plain append-only output. Default: auto-detect an "
        "interactive terminal.",
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True),
) -> None:
    """Continuously watch for new/changed devices until interrupted (Ctrl+C)."""

    setup_logging(verbose)
    cfg = _load_config(config)
    if interval is not None:
        cfg.scan.scan_interval_seconds = interval
    if passive is not None:
        cfg.scan.passive = passive
    if ipv6 is not None:
        cfg.scan.ipv6 = ipv6
    if dhcp is not None:
        cfg.scan.dhcp_snooping = dhcp
    if mdns is not None:
        cfg.discovery.mdns = mdns
    if ssdp is not None:
        cfg.discovery.ssdp = ssdp

    if not _is_root():
        _warn_not_root("monitor")

    monitor_status.write_pid_file()

    signatures = SignatureSet.load(cfg.rogue_signatures_file)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    store = _open_store(
        cfg.resolved_db_path(),
        max_evidence_rows_per_mac=cfg.retention.max_evidence_rows_per_mac,
        max_dhcp_server_findings=cfg.retention.max_dhcp_server_findings,
        max_discovery_rows_per_table=cfg.retention.max_discovery_rows_per_table,
    )
    alert_worker = AlertDeliveryWorker(cfg.resolved_db_path())

    iface = interface or cfg.scan.interface or scanner.default_interface()
    net = subnet or cfg.scan.subnet
    apply_self_trust(allowlist, interface=iface)

    dhcp_active = cfg.scan.passive and cfg.scan.dhcp_snooping
    dhcp_server_active = dhcp_server_detection_active(cfg)
    mdns_active = cfg.scan.passive and cfg.discovery.mdns
    ssdp_active = cfg.scan.passive and cfg.discovery.ssdp

    console = monitor_ui.make_console()
    use_live, fallback_reason = monitor_ui.should_use_live(live, console)
    if fallback_reason:
        typer.secho(f"note: {fallback_reason}", fg="yellow", err=True)

    header = monitor_ui.HeaderInfo(
        version=__version__, interface=iface or "(auto)", network=net or "(auto)",
        scan_interval_seconds=cfg.scan.scan_interval_seconds, passive=cfg.scan.passive,
        ipv6=cfg.scan.ipv6, dhcp=dhcp_active, mdns=mdns_active, ssdp=ssdp_active,
        dhcp_server_detection=dhcp_server_active,
    )
    stats = monitor_ui.MonitorStats(
        scan_interval_seconds=cfg.scan.scan_interval_seconds, passive_enabled=cfg.scan.passive,
        now_monotonic=time.monotonic(),
        expected_sweep_seconds=cfg.scan.active_scan_timeout_seconds * (2 if cfg.scan.ipv6 else 1),
    )
    activity_log = monitor_ui.ActivityLog() if use_live else None

    def _report_warning(text: str) -> None:
        if activity_log is not None:
            activity_log.add(monitor_ui.ActivityEntry(
                timestamp=monitor_ui.local_now(), level="warning", label="WARNING", detail=text,
            ))
        else:
            typer.secho(f"warning: {text}", fg="yellow", err=True)

    def _report_error(text: str, *, label: str = "ERROR") -> None:
        if activity_log is not None:
            activity_log.add(monitor_ui.ActivityEntry(
                timestamp=monitor_ui.local_now(), level="error", label=label, detail=text,
            ))
        else:
            typer.secho(f"error: {text}", fg="red", err=True)

    def _report_lifecycle(label: str, *, mac: str, hostname: str | None, ip: str | None) -> None:
        # Purely informational lines with no corresponding Finding
        # (disconnects never produce one; an intermittent-presence device's
        # "reappeared" finding is deliberately suppressed - see
        # `engine.build_findings`) - shown only in the live activity feed,
        # never in append-only mode, to leave its existing output
        # (unchanged by this feature) exactly as it was.
        if activity_log is None:
            return
        identity = hostname or mac
        detail = f"{identity} · {ip}" if ip else identity
        activity_log.add(monitor_ui.ActivityEntry(timestamp=monitor_ui.local_now(), level="info", label=label, detail=detail))

    if not use_live:
        typer.secho(f"LAN Fence {__version__} - monitoring (Ctrl+C to stop)", fg="green", bold=True)
        typer.echo(
            f"interface: {iface or '(auto)'}   scan interval: {cfg.scan.scan_interval_seconds:.0f}s   "
            f"passive: {cfg.scan.passive}   ipv6: {cfg.scan.ipv6}   dhcp: {dhcp_active}   "
            f"dhcp-server-detection: {dhcp_server_active}   mdns: {mdns_active}   ssdp: {ssdp_active}"
        )
    if cfg.dhcp_servers.enabled and not dhcp_server_active:
        _report_warning(
            "dhcp_servers.enabled is true, but passive DHCP capture is off "
            "(scan.passive/scan.dhcp_snooping) - no unexpected-DHCP-server findings will be "
            "produced until it is. This is not silently \"protected\" in the meantime."
        )
    if dhcp_server_active and not cfg.dhcp_servers.approved:
        _report_warning(
            "dhcp_servers.enabled is true with no dhcp_servers.approved entries - "
            "every DHCP server observed will be treated as unexpected."
        )
    if (cfg.discovery.mdns or cfg.discovery.ssdp) and not cfg.scan.passive:
        _report_warning(
            "discovery.mdns/ssdp is enabled, but passive monitoring (scan.passive) is off - "
            "no service advertisements will be parsed until it is. This combination is enabled but "
            "inactive, not silently \"working anyway\"."
        )

    stop_event = threading.Event()
    queue_maxsize = cfg.scan.passive_queue_maxsize
    passive_queue: "_DropCountingQueue" = _DropCountingQueue(maxsize=queue_maxsize)
    dhcp_server_queue: "_DropCountingQueue" = _DropCountingQueue(maxsize=queue_maxsize)
    mdns_queue: "_DropCountingQueue" = _DropCountingQueue(maxsize=queue_maxsize)
    ssdp_queue: "_DropCountingQueue" = _DropCountingQueue(maxsize=queue_maxsize)
    passive_error_queue: "queue.Queue[str]" = queue.Queue()

    def _run_passive() -> None:
        try:
            scanner.passive_sniff(
                on_sighting=passive_queue.put_dropping, interface=iface, stop_event=stop_event,
                dhcp=cfg.scan.dhcp_snooping,
                on_dhcp_server=dhcp_server_queue.put_dropping if cfg.dhcp_servers.enabled else None,
                mdns=cfg.discovery.mdns, ssdp=cfg.discovery.ssdp,
                on_mdns_records=mdns_queue.put_dropping if cfg.discovery.mdns else None,
                on_ssdp=ssdp_queue.put_dropping if cfg.discovery.ssdp else None,
            )
        except scanner.ScannerUnavailable as exc:
            # Reported via a queue (like every other cross-thread message
            # here), drained on the main loop's own thread below - never
            # printed directly from this background thread, which would
            # otherwise be unsafe alongside a live alternate-screen display.
            passive_error_queue.put(str(exc))

    passive_thread: threading.Thread | None = None
    if cfg.scan.passive:
        passive_thread = threading.Thread(target=_run_passive, daemon=True)
        passive_thread.start()

    def _refresh_inventory_counts() -> None:
        known, _online = store.device_counts()
        review = sum(1 for d in build_inventory(store, allowlist) if is_review_needed(d, now=utcnow()))
        stats.set_inventory_counts(known=known, review=review)

    def _loop() -> None:
        nonlocal net
        last_sweep = 0.0
        last_stats_refresh = 0.0
        if use_live:
            _refresh_inventory_counts()
        while True:
            if use_live:
                display.check_quit()
            now = time.monotonic()

            # Drain any queued passive sightings *before* this tick's active
            # sweep gets a chance to evaluate offline transitions - a device
            # already positively sighted (but not yet drained from the
            # queue) must not be wrongly counted as a missed sweep and then,
            # moments later, flagged reappeared once its queued sighting is
            # finally processed. The passive thread only ever calls
            # `passive_queue.put` (see `_run_passive` above) - all database
            # access, here, stays on this single owning thread.
            batch: list[scanner.ArpSighting] = []
            while len(batch) < 200:
                try:
                    batch.append(passive_queue.get_nowait())
                except queue.Empty:
                    break
            # Safe coalescing: a burst of pure duplicate observations (same
            # mac/ip/hostname/source) collapses to the single latest one -
            # every distinct piece of evidence in the batch is still
            # processed, just not once per identical packet.
            for sighting in coalesce_sightings(batch):
                device, event_type, findings = process_sighting(
                    mac=sighting.mac, ip=sighting.ip, seen_at=sighting.seen_at,
                    store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
                    hostname_hint=sighting.hostname, interface=iface, subnet=net,
                    source=sighting.source,
                )
                stats.record_event(device.mac, event_type)
                if event_type == "disconnected":
                    _report_lifecycle("DISCONNECTED", mac=device.mac, hostname=device.hostname, ip=device.ip)
                elif event_type == "reappeared" and not findings:
                    _report_lifecycle("RETURNED", mac=device.mac, hostname=device.hostname, ip=device.ip)
                _emit_findings(
                    findings, alert=alert, cfg=cfg, store=store,
                    activity=activity_log, stats=stats, alert_worker=alert_worker,
                )

            # DHCP server observations are processed the same way, from
            # their own queue - kept separate from `passive_queue` since a
            # server reply is not a device sighting (see
            # `scanner.DhcpServerSighting`). Bounded for the same reason:
            # one burst of DHCP traffic must not starve active sweeps or
            # ARP/ND passive processing.
            drained_dhcp_servers = 0
            while drained_dhcp_servers < 200:
                try:
                    server_sighting = dhcp_server_queue.get_nowait()
                except queue.Empty:
                    break
                drained_dhcp_servers += 1
                finding = process_dhcp_server_sighting(server_sighting, store, cfg)
                if finding is not None:
                    _emit_findings(
                        [finding], alert=alert, cfg=cfg, store=store,
                        activity=activity_log, stats=stats, alert_worker=alert_worker,
                    )

            # Advertised-service evidence, same bounded-drain shape as
            # above - a burst of mDNS/SSDP traffic must never starve device
            # sightings or active sweeps. Never produces findings/alerts or
            # touches device presence/reachability (see
            # `lanfence/discovery.py`), so nothing is passed to
            # `_emit_findings` here.
            drained_mdns = 0
            while drained_mdns < 200:
                try:
                    records = mdns_queue.get_nowait()
                except queue.Empty:
                    break
                drained_mdns += 1
                for record in records:
                    discovery.process_mdns_record_sighting(record, store)

            drained_ssdp = 0
            while drained_ssdp < 200:
                try:
                    ssdp_sighting = ssdp_queue.get_nowait()
                except queue.Empty:
                    break
                drained_ssdp += 1
                discovery.process_ssdp_sighting(ssdp_sighting, store)

            total_dropped = (
                passive_queue.dropped + dhcp_server_queue.dropped + mdns_queue.dropped + ssdp_queue.dropped
            )
            if total_dropped > stats.dropped_observations:
                newly_dropped = total_dropped - stats.dropped_observations
                stats.dropped_observations = total_dropped
                _report_warning(
                    f"dropped {newly_dropped} observation(s) - a processing queue filled up "
                    "faster than it could be drained; some evidence from this burst may be "
                    "incomplete. Consider raising scan.passive_queue_maxsize if this recurs."
                )

            try:
                passive_err = passive_error_queue.get_nowait()
            except queue.Empty:
                pass
            else:
                stats.mark_passive_failed()
                _report_error(passive_err, label="PASSIVE")

            if now - last_sweep >= cfg.scan.scan_interval_seconds:
                # Reload on the same cadence as active sweeps, so a `lanfence
                # allow` / `review --trust` made while this monitor is
                # already running takes effect without a restart - review
                # state itself needs no such reload, since it's read fresh
                # from the database on every finding via filter_snoozed.
                try:
                    allowlist_reloaded = Allowlist.load(cfg.resolved_allowlist_file())
                    apply_self_trust(allowlist_reloaded, interface=iface)
                    allowlist.entries[:] = allowlist_reloaded.entries
                    allowlist.path = allowlist_reloaded.path
                except Exception as exc:  # noqa: BLE001 - a bad edit must not crash monitoring
                    _report_warning(f"could not reload allowlist: {exc}")
                stats.record_sweep_start(now)
                if use_live:
                    display.update(stats, activity_log, now_monotonic=time.monotonic())
                else:
                    # No live dashboard to show "scanning now" - say so
                    # immediately, since the sweep below blocks for up to
                    # scan.active_scan_timeout_seconds (doubled with IPv6)
                    # and would otherwise look like nothing is happening.
                    typer.echo("scanning...")
                result = run_active_sweep(cfg, store, allowlist, signatures, interface=iface, subnet=net)
                # Keep using the just-resolved subnet for passive sightings
                # drained between now and the next sweep, so their coverage
                # provenance (see DeviceStore.observe) matches what this
                # sweep actually covered rather than staying unresolved.
                net = result.subnet or net
                last_sweep = now
                stats.record_sweep_end(ok=not result.errors, now_monotonic=time.monotonic())
                event_type_by_mac = {e.mac: e.event_type for e in result.events}
                for swept_device in result.devices:
                    stats.record_event(swept_device.mac, event_type_by_mac.get(swept_device.mac))
                for event in result.events:
                    if event.event_type == "disconnected":
                        _report_lifecycle("DISCONNECTED", mac=event.mac, hostname=event.hostname, ip=event.ip)
                for err in result.errors:
                    _report_error(err, label="SCAN")
                _emit_findings(
                    result.findings, alert=alert, cfg=cfg, store=store,
                    activity=activity_log, stats=stats, alert_worker=alert_worker,
                )
                if use_live:
                    _refresh_inventory_counts()
                    last_stats_refresh = now

            if use_live and now - last_stats_refresh >= 5.0:
                _refresh_inventory_counts()
                last_stats_refresh = now

            if use_live:
                display.update(stats, activity_log, now_monotonic=time.monotonic())

            if use_live:
                display.check_quit()
            time.sleep(1.0)

    if use_live:
        display = monitor_ui.MonitorDisplay(
            header, activity_log, passive_enabled=cfg.scan.passive, console=console,
        )
    try:
        if use_live:
            with display:
                _loop()
        else:
            _loop()
    except KeyboardInterrupt:
        typer.echo("\nstopping monitor...")
        elapsed = monitor_ui.format_duration(time.monotonic() - stats.session_start_monotonic)
        typer.echo(
            f"Monitoring stopped after {elapsed}.\n"
            f"Seen this session: {len(stats.seen)} devices · "
            f"Newly discovered: {len(stats.new_macs)} · Findings: {stats.findings_count}"
        )
    finally:
        stop_event.set()
        alert_worker.shutdown()
        store.close()
        monitor_status.remove_pid_file()


@app.command()
def digest(
    since: str = typer.Option("24h", "--since", help="Rolling window to summarize, e.g. 24h, 7d."),
    output_format: str = typer.Option("table", "--format", "-f", help="table | json"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Also show detailed device activity (connects/disconnects/reappearances) and findings for the window.",
    ),
    send: bool = typer.Option(
        False, "--send", help="Also send through configured digest destinations (default: preview only)."
    ),
    channel: list[str] = typer.Option(
        [], "--channel", help=f"Repeatable: limit --send to these channels ({', '.join(DIGEST_CHANNELS)})."
    ),
    send_empty: bool = typer.Option(
        False, "--send-empty", help="With --send, send even if the digest is empty (overrides digest.send_when_empty)."
    ),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings",
        help="With --verbose, exit non-zero when medium+ findings are present in the window.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Preview - or, with --send, deliver - a summary of recent network activity.

    A rolling window ending now (default 24h): new devices, devices needing
    review or under investigation, missing always-on devices, and a compact
    activity summary. A pure database read - never scans the network, and
    never changes trust, review, snooze, or lifecycle state. Independent of
    the immediate-alert pipeline (`alerts.min_severity`, per-MAC cooldowns,
    `scan --alert`) - sending a digest never affects those, and vice versa.

    `--verbose` additionally lists every connect/disconnect/reappearance
    event in the window plus their findings (the detail formerly shown by
    the separate `lanfence report` command).
    """

    if output_format not in ("table", "json"):
        typer.secho(f"error: --format must be 'table' or 'json', got {output_format!r}", fg="red", err=True)
        raise typer.Exit(code=2)

    cfg = _load_config(config)
    until = utcnow()
    duration_seconds = _duration_seconds(since)
    if duration_seconds is None:
        typer.secho(
            f"error: could not parse --since {since!r} (expected e.g. 24h, 30m, 7d)", fg="red", err=True
        )
        raise typer.Exit(code=2)
    since_dt = until - timedelta(seconds=duration_seconds)

    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    apply_self_trust(allowlist, interface=cfg.scan.interface)
    signatures = SignatureSet.load(cfg.rogue_signatures_file) if verbose else None
    portal_url = web.build_portal_url(cfg)
    monitor_running = monitor_status.is_running()
    try:
        generated_by_host = socket.gethostname() or None
    except OSError:
        generated_by_host = None

    with _open_store(cfg.resolved_db_path()) as store:
        digest_obj = build_digest(
            store, allowlist, since=since_dt, until=until, portal_url=portal_url, monitor_running=monitor_running,
            generated_by_host=generated_by_host, resolve_missing_hostnames=cfg.scan.resolve_hostnames,
            dns_timeout_seconds=cfg.scan.dns_timeout_seconds,
        )
        events = store.events_since(since_dt) if verbose else []
        devices_by_mac = {d.mac: d for d in store.all_devices()} if verbose else {}

    findings: list[Finding] = []
    if verbose:
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
        payload = digest_obj.model_dump(mode="json")
        if verbose:
            payload["events"] = [e.model_dump(mode="json") for e in events]
            payload["findings"] = [f.model_dump(mode="json") for f in findings]
        typer.echo(json.dumps(payload, indent=2))
    else:
        render_digest(digest_obj)
        if verbose:
            typer.echo("")
            typer.secho(f"Detailed activity - since {format_datetime(since_dt)}", fg="cyan", bold=True)
            render_events(events)
            typer.echo("")
            render_findings(findings)

    if verbose and fail_on_findings:
        raise typer.Exit(code=exit_code_for_findings(findings))

    if not send:
        return

    requested = list(dict.fromkeys(channel)) if channel else list(cfg.digest.channels)
    if not requested:
        typer.secho(
            "error: --send needs at least one digest channel - configure digest.channels "
            "or pass --channel explicitly",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)

    unsupported = [c for c in requested if c not in DIGEST_CHANNELS]
    if unsupported:
        if any(c in ("sms", "twilio", "syslog") for c in unsupported):
            typer.secho(
                f"error: {', '.join(unsupported)} not supported for digest delivery "
                f"(SMS and syslog are excluded from digest delivery) - use one of: "
                f"{', '.join(DIGEST_CHANNELS)}",
                fg="red", err=True,
            )
        else:
            typer.secho(
                f"error: unknown digest channel(s): {', '.join(unsupported)} - "
                f"use one of: {', '.join(DIGEST_CHANNELS)}",
                fg="red", err=True,
            )
        raise typer.Exit(code=2)

    channel_enabled = {
        "email": cfg.alerts.email.enabled, "webhook": cfg.alerts.webhook.enabled,
        "slack": cfg.alerts.slack.enabled, "discord": cfg.alerts.discord.enabled,
        "teams": cfg.alerts.teams.enabled, "ntfy": cfg.alerts.ntfy.enabled,
    }
    not_enabled = [c for c in requested if not channel_enabled[c]]
    if not_enabled:
        typer.secho(
            f"error: channel(s) not enabled in config: {', '.join(not_enabled)} "
            f"(enable under alerts.<channel>.enabled first)",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)

    if digest_obj.is_empty and not (send_empty or cfg.digest.send_when_empty):
        typer.echo("digest is empty - not sending (use --send-empty to override).")
        return

    results = dispatch_digest(digest_obj, cfg, channels=requested)
    failed = [name for name, ok in results.items() if not ok]
    for name, ok in results.items():
        typer.secho(f"  {name}: {'sent' if ok else 'FAILED'}", fg="green" if ok else "red")
    if failed:
        raise typer.Exit(code=1)


@app.command(name="dhcp-servers")
def dhcp_servers_cmd(
    output_format: str = typer.Option("table", "--format", "-f", help="table | json"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """List DHCP servers observed via passive capture, with approval status.

    A read-only database query - never scans the network or sends packets,
    and works whether or not `dhcp_servers.enabled` is on (that setting only
    controls whether an *unexpected* server also produces a finding). An
    empty list means no DHCP server reply has been observed at this capture
    point yet, not that no DHCP server exists on the network - a switched
    network can hide unicast replies from other segments entirely (see
    README's "Visibility limitations").
    """

    if output_format not in ("table", "json"):
        typer.secho(f"error: --format must be 'table' or 'json', got {output_format!r}", fg="red", err=True)
        raise typer.Exit(code=2)

    cfg = _load_config(config)
    with _open_store(cfg.resolved_db_path()) as store:
        records = dhcp_server_inventory(store, cfg)

    if output_format == "json":
        typer.echo(json.dumps([r.model_dump(mode="json") for r in records], indent=2))
        return

    if not records:
        typer.secho("No DHCP server replies observed yet.", fg="yellow")
        return

    typer.secho(f"DHCP servers ({len(records)}):\n", fg="cyan", bold=True)
    for r in records:
        approval = f"approved ({r.name})" if r.approved and r.name else ("approved" if r.approved else "NOT approved")
        typer.echo(
            f"  {r.interface:<10} {r.server_id:<16} {approval:<20} "
            f"seen {r.observation_count}x, {format_datetime(r.first_seen)} - "
            f"{format_datetime(r.last_seen)}"
        )
        detail = f"    last: {r.last_message_type or '?'}"
        if r.last_source_ip:
            detail += f"  source={r.last_source_ip}"
        if r.last_source_mac:
            detail += f"  source_mac={r.last_source_mac}"
        if r.last_relay_ip:
            detail += f"  relay={r.last_relay_ip}"
        typer.echo(detail)


@app.command()
def services(
    protocol: Optional[str] = typer.Option(None, "--protocol", help="Filter by protocol: mdns | ssdp."),
    unassociated: bool = typer.Option(
        False, "--unassociated", help="Only services that could not be confidently matched to a device."
    ),
    include_expired: bool = typer.Option(
        False, "--include-expired", help="Also include expired/withdrawn history (default: current only)."
    ),
    output_format: str = typer.Option("table", "--format", "-f", help="table | json"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """List advertised services observed via passive mDNS/DNS-SD or SSDP/UPnP capture.

    A read-only database query - never scans the network, never sends an
    mDNS query or SSDP M-SEARCH request. An advertised service is a claim
    the advertising device makes about itself, not a verified capability or
    proof it's reachable; an empty (or missing) result means nothing
    advertising it has been observed at this capture point, never that no
    such service exists on the network - see README's discovery section.
    Works whether or not `discovery.mdns`/`discovery.ssdp` are currently
    enabled (they only gate what's captured going forward, not this read).

    Attribution to a device is deliberately conservative: `--unassociated`
    shows services that could not be confidently matched to any inventory
    device (an mDNS proxy/reflector, or an ambiguous/stale IP association,
    never produces a guessed match - see `lanfence device <MAC>` for a
    per-device view of that device's own attributed services).

    Filters combine with AND. `--format json` additionally always includes
    each service's full evidence (attributes, target, expiry, association
    basis).
    """

    if output_format not in ("table", "json"):
        typer.secho(f"error: --format must be 'table' or 'json', got {output_format!r}", fg="red", err=True)
        raise typer.Exit(code=2)
    if protocol is not None and protocol not in ("mdns", "ssdp"):
        typer.secho(f"error: --protocol must be 'mdns' or 'ssdp', got {protocol!r}", fg="red", err=True)
        raise typer.Exit(code=2)

    cfg = _load_config(config)
    now = utcnow()
    with _open_store(cfg.resolved_db_path()) as store:
        total_count = len(store.advertised_services(include_expired=True, now=now))
        records = store.advertised_services(
            protocol=protocol, include_expired=include_expired, unassociated_only=unassociated, now=now,
        )

    if output_format == "json":
        typer.echo(json.dumps([r.model_dump(mode="json") for r in records], indent=2))
        return

    render_advertised_services(records, now=now, total_count=total_count)


@app.command()
def allow(
    mac: Optional[str] = typer.Argument(None, help="MAC address to trust."),
    name: Optional[str] = typer.Option(None, "--name", help="Label for this device."),
    notes: Optional[str] = typer.Option(None, "--notes", help="Freeform notes."),
    list_entries: bool = typer.Option(False, "--list", help="Show current allowlist entries."),
    remove: Optional[str] = typer.Option(None, "--remove", help="MAC address to remove from the allowlist."),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the device-context confirmation prompt (for scripted use)."
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Manage the allowlist of devices you trust.

    Findings about an allowlisted device are downgraded to *info*, so your own
    hardware stops shouting every time it reconnects. With no MAC and no
    options, lists the current entries.

    When run at an interactive terminal for a MAC LAN Fence has already
    observed, shows a compact device dossier (what it likely is, and why)
    before asking you to confirm - the same context `lanfence review`
    shows, so you're not trusting a device on the strength of its MAC
    address alone. Pass `--yes` to skip this (or simply run
    noninteractively, e.g. from a script or cron job - no prompt ever
    appears there, exactly as before).
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

    if not yes and _stdin_is_interactive():
        try:
            norm_mac = normalize_mac(mac)
        except ValueError:
            norm_mac = None
        if norm_mac is not None:
            with _open_store(cfg.resolved_db_path()) as store:
                already_known = store.get_device(norm_mac) is not None
                dossier = None
                if already_known:
                    dossier = build_device_dossier(
                        store, al, norm_mac, signatures=SignatureSet.load(cfg.rogue_signatures_file),
                        vendor_file=cfg.vendor_file,
                    )
            if dossier is not None:
                typer.echo(render_dossier_compact(dossier))
                typer.echo("")
                if not typer.confirm(f"Trust {norm_mac}?", default=True):
                    typer.echo("cancelled - nothing changed.")
                    return

    entry = al.add(mac, name or mac, notes or "")
    al.save()
    typer.secho(f"added: {entry.name}  ({entry.mac})", fg="green")


@app.command()
def reset(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    keep_allowlist: bool = typer.Option(
        False, "--keep-allowlist", help="Only clear scanned device history; leave the allowlist untouched."
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Permanently delete all previously scanned devices and their history.

    Clears every device, its lifecycle events, alert-dispatch cooldowns, and
    review/snooze state from the database - and, unless `--keep-allowlist` is
    given, the allowlist too, so trust decisions start over from scratch as
    well. This cannot be undone. Requires a terminal to confirm unless
    `--yes` is given.
    """

    cfg = _load_config(config)
    db_path = cfg.resolved_db_path()
    allowlist_path = cfg.resolved_allowlist_file()

    if not yes:
        if not _stdin_is_interactive():
            typer.secho(
                "error: `lanfence reset` needs confirmation - pass --yes to run noninteractively.",
                fg="red", err=True,
            )
            raise typer.Exit(code=2)
        warning = f"This will permanently delete all scanned device history in {db_path}"
        if not keep_allowlist:
            warning += f", and the allowlist at {allowlist_path}"
        typer.secho(warning + ". This cannot be undone.", fg="yellow")
        if not typer.confirm("Are you sure?", default=False):
            typer.echo("aborted - nothing changed.")
            return

    with _open_store(db_path) as store:
        store.reset_all()

    if not keep_allowlist:
        Allowlist([], allowlist_path).save()

    summary = "erased all scanned device history"
    summary += "; allowlist untouched." if keep_allowlist else " and cleared the allowlist."
    typer.secho(summary, fg="green")


_PRESENCE_POLICIES = ("unspecified", "intermittent", "always-on")


def _list_devices(
    *,
    status: Optional[str],
    untrusted: bool,
    review_needed: bool,
    presence: Optional[str],
    owner: Optional[str],
    group: Optional[str],
    location: Optional[str],
    details: bool,
    output_format: str,
    config: Optional[Path],
) -> None:
    """List every previously observed device from the database - no scan.

    This is `lanfence device`'s no-MAC behavior (formerly the standalone
    `lanfence devices` command). Filters combine with AND: `--status online
    --untrusted` shows only devices that are both online and not on the
    allowlist. Allowlist membership is applied fresh from the current
    allowlist file, not whatever it was the last time a scan ran.

    `--owner`/`--group`/`--location` match a device's user-provided
    metadata exactly (after trimming whitespace, case-insensitive) - a
    device with that field unset never matches. `--details` adds those
    metadata fields as extra table columns; JSON output always includes
    them (nested under `metadata`) regardless of `--details`.
    """

    if status is not None and status not in ("online", "offline"):
        typer.secho(f"error: --status must be 'online' or 'offline', got {status!r}", fg="red", err=True)
        raise typer.Exit(code=2)
    if presence is not None and presence not in _PRESENCE_POLICIES:
        typer.secho(
            f"error: --presence must be one of {', '.join(_PRESENCE_POLICIES)}, got {presence!r}",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)
    if output_format not in ("table", "json"):
        typer.secho(f"error: --format must be 'table' or 'json', got {output_format!r}", fg="red", err=True)
        raise typer.Exit(code=2)

    cfg = _load_config(config)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    apply_self_trust(allowlist, interface=cfg.scan.interface)
    now = utcnow()

    with _open_store(cfg.resolved_db_path()) as store:
        inventory = build_inventory(store, allowlist)

    total_count = len(inventory)
    if status is not None:
        inventory = [d for d in inventory if d.status == status]
    if untrusted:
        inventory = [d for d in inventory if not d.allowlisted]
    if review_needed:
        inventory = [d for d in inventory if is_review_needed(d, now=now)]
    if presence is not None:
        inventory = [d for d in inventory if d.presence_policy == presence]
    if owner is not None:
        needle = owner.strip().casefold()
        inventory = [d for d in inventory if (d.metadata.owner or "").strip().casefold() == needle]
    if group is not None:
        needle = group.strip().casefold()
        inventory = [d for d in inventory if (d.metadata.group or "").strip().casefold() == needle]
    if location is not None:
        needle = location.strip().casefold()
        inventory = [d for d in inventory if (d.metadata.location or "").strip().casefold() == needle]

    # Best-effort, unpersisted DNS lookup for shown devices still missing a
    # hostname - after filtering, so this only ever costs lookups for rows
    # actually displayed. See enrich_missing_hostnames's own docstring for
    # why it's online-only and never written back to the database.
    inventory = enrich_missing_hostnames(
        inventory, resolve=cfg.scan.resolve_hostnames, timeout=cfg.scan.dns_timeout_seconds
    )

    if output_format == "json":
        typer.echo(json.dumps([d.model_dump(mode="json") for d in inventory], indent=2))
    else:
        render_device_inventory(
            inventory, now=now, total_count=total_count,
            default_offline_after_seconds=cfg.scan.offline_grace_seconds,
            show_metadata=details,
        )


def _delete_new_offline_devices(*, config: Optional[Path], yes: bool) -> None:
    """`lanfence device --delete-new-offline` - see that command's own
    docstring for exactly what "new" means here. Permanently deletes each
    matching device via :meth:`lanfence.db.DeviceStore.delete_device`;
    never touches the allowlist (a matching device is never on it, by
    definition - ``allowlisted`` is part of the filter)."""

    cfg = _load_config(config)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    apply_self_trust(allowlist, interface=cfg.scan.interface)

    with _open_store(cfg.resolved_db_path()) as store:
        inventory = build_inventory(store, allowlist)
        targets = [
            d for d in inventory
            if d.review_state == "pending" and d.status == "offline" and not d.allowlisted
        ]
        if not targets:
            typer.echo("No new, offline devices to delete.")
            return

        typer.secho(f"{len(targets)} device(s) will be permanently deleted:", fg="yellow")
        for d in targets:
            label = d.hostname or "[unknown]"
            typer.echo(f"  {d.mac}  {label}  {d.vendor or '[unknown]'}")

        if not yes:
            if not _stdin_is_interactive():
                typer.secho(
                    "error: this needs confirmation - pass --yes to run noninteractively.",
                    fg="red", err=True,
                )
                raise typer.Exit(code=2)
            if not typer.confirm("Permanently delete these devices? This cannot be undone.", default=False):
                typer.echo("aborted - nothing changed.")
                return

        for d in targets:
            store.delete_device(d.mac)

    typer.secho(f"deleted {len(targets)} device(s).", fg="green")


@app.command()
def device(
    mac: Optional[str] = typer.Argument(
        None, help="MAC address to show. Omit to list every observed device instead (see --status etc.)."
    ),
    since: str = typer.Option("30d", "--since", help="How far back to show the lifecycle timeline, e.g. 24h, 7d."),
    presence: Optional[str] = typer.Option(
        None, "--presence", help="With a MAC: set presence policy: unspecified | intermittent | always-on."
    ),
    offline_after: Optional[str] = typer.Option(
        None, "--offline-after",
        help="Always-on only: override how long an absence may last before an availability "
        "finding fires, e.g. 10m. Default: the configured global offline grace period.",
    ),
    clear_offline_after: bool = typer.Option(
        False, "--clear-offline-after", help="Remove the --offline-after override; restore the global default."
    ),
    owner: Optional[str] = typer.Option(None, "--owner", help="With a MAC: set the owner metadata field."),
    purpose: Optional[str] = typer.Option(None, "--purpose", help="With a MAC: set the purpose metadata field."),
    group: Optional[str] = typer.Option(None, "--group", help="With a MAC: set the group metadata field."),
    location: Optional[str] = typer.Option(None, "--location", help="With a MAC: set the location metadata field."),
    clear_owner: bool = typer.Option(False, "--clear-owner", help="Clear the owner metadata field."),
    clear_purpose: bool = typer.Option(False, "--clear-purpose", help="Clear the purpose metadata field."),
    clear_group: bool = typer.Option(False, "--clear-group", help="Clear the group metadata field."),
    clear_location: bool = typer.Option(False, "--clear-location", help="Clear the location metadata field."),
    status: Optional[str] = typer.Option(
        None, "--status", help="Without a MAC: filter the list by status: online | offline."
    ),
    untrusted: bool = typer.Option(
        False, "--untrusted", help="Without a MAC: only list devices not on the allowlist."
    ),
    review_needed: bool = typer.Option(
        False, "--review-needed",
        help="Without a MAC: only list devices needing review (untrusted, not snoozed, not investigating).",
    ),
    details: bool = typer.Option(
        False, "--details", help="Without a MAC: also show owner/purpose/group/location columns (table format only)."
    ),
    delete_new_offline: bool = typer.Option(
        False, "--delete-new-offline",
        help="Without a MAC: permanently delete every never-reviewed, currently-offline, "
        "untrusted device. Lists them and asks for confirmation first.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the confirmation prompt for --delete-new-offline."
    ),
    output_format: str = typer.Option("table", "--format", "-f", help="table | json"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Show one device's details, or (with no MAC) list every observed device.

    With a MAC address: "current details" (IP/hostname/vendor/status)
    reflect only the most recent sighting; the timeline below is a
    separate, append-only log of connect/reappear/disconnect transitions -
    not a complete history of every address this MAC has ever held (see the
    timeline's own caveat).

    With `--presence`/`--offline-after`/`--clear-offline-after`, also edits
    that device's presence policy - see `lanfence device <MAC> --presence
    always-on --offline-after 10m`. Presence is separate from trust: it
    never changes the allowlist, and a policy edit alone never fabricates a
    lifecycle event or fires an alert.

    With `--owner`/`--purpose`/`--group`/`--location` (or their
    `--clear-*` counterparts), also edits operator-provided inventory
    metadata - separate from observed hostname, vendor, trust, review, and
    presence. Any combination of presence and metadata options may be
    given in one call; an omitted field is left unchanged, and after a
    successful update the device's resulting details are shown, same as a
    plain `lanfence device <MAC>`. Metadata edits never scan, alert, or
    create a lifecycle event, and never create a device that hasn't
    actually been observed.

    Without a MAC address: lists every previously observed device from the
    database (no scan) - `--status`/`--untrusted`/`--review-needed`/
    `--details` filter and shape that listing; see `lanfence device --help`.

    `--delete-new-offline` (also without a MAC) permanently deletes every
    device that has never been reviewed at all (still "pending" - never
    trusted, snoozed, or flagged investigating), is currently offline, and
    is not on the allowlist - a bulk cleanup for one-off devices that
    showed up once and aren't coming back. It never touches a device
    that's been snoozed or flagged investigating, since that reflects a
    deliberate decision already made about it. Lists the matching devices
    and asks for confirmation before deleting anything (`--yes` skips
    this for scripted use); this cannot be undone, and does not touch the
    allowlist (a device this matches is by definition not on it).
    """

    if delete_new_offline:
        _delete_new_offline_devices(config=config, yes=yes)
        return

    if mac is None:
        _list_devices(
            status=status, untrusted=untrusted, review_needed=review_needed,
            presence=presence, owner=owner, group=group, location=location,
            details=details, output_format=output_format, config=config,
        )
        return

    if output_format not in ("table", "json"):
        typer.secho(f"error: --format must be 'table' or 'json', got {output_format!r}", fg="red", err=True)
        raise typer.Exit(code=2)
    if presence is not None and presence not in _PRESENCE_POLICIES:
        typer.secho(
            f"error: --presence must be one of {', '.join(_PRESENCE_POLICIES)}, got {presence!r}",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)
    if offline_after is not None and clear_offline_after:
        typer.secho("error: --offline-after and --clear-offline-after are contradictory", fg="red", err=True)
        raise typer.Exit(code=2)
    for field, set_value, clear_flag in (
        ("owner", owner, clear_owner), ("purpose", purpose, clear_purpose),
        ("group", group, clear_group), ("location", location, clear_location),
    ):
        if set_value is not None and clear_flag:
            typer.secho(f"error: --{field} and --clear-{field} are contradictory", fg="red", err=True)
            raise typer.Exit(code=2)

    try:
        norm_mac = normalize_mac(mac)
    except ValueError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc

    # Validate every requested metadata change before writing any of them.
    metadata_updates: dict[str, Optional[str]] = {}
    try:
        if owner is not None:
            metadata_updates["owner"] = validate_metadata_value("owner", owner)
        if purpose is not None:
            metadata_updates["purpose"] = validate_metadata_value("purpose", purpose)
        if group is not None:
            metadata_updates["group"] = validate_metadata_value("group", group)
        if location is not None:
            metadata_updates["location"] = validate_metadata_value("location", location)
    except ValueError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc
    if clear_owner:
        metadata_updates["owner"] = None
    if clear_purpose:
        metadata_updates["purpose"] = None
    if clear_group:
        metadata_updates["group"] = None
    if clear_location:
        metadata_updates["location"] = None

    cfg = _load_config(config)

    mutating = presence is not None or offline_after is not None or clear_offline_after or metadata_updates
    if mutating:
        with _open_store(cfg.resolved_db_path()) as store:
            if store.get_device(norm_mac) is None:
                typer.secho(f"error: no device with MAC {norm_mac} has been observed", fg="red", err=True)
                raise typer.Exit(code=2)

            current = store.get_presence(norm_mac)
            effective_policy = presence if presence is not None else current.policy
            if offline_after is not None and effective_policy != "always-on":
                typer.secho(
                    "error: --offline-after only applies when the effective policy is always-on",
                    fg="red", err=True,
                )
                raise typer.Exit(code=2)

            now = utcnow()
            if presence is not None:
                store.set_presence_policy(norm_mac, presence, updated_at=now)
                typer.secho(f"presence policy for {norm_mac} set to {presence}", fg="green")
            if offline_after is not None:
                seconds = _duration_seconds(offline_after)
                if seconds is None or seconds <= 0:
                    typer.secho(
                        f"error: could not parse --offline-after {offline_after!r} "
                        "(expected a positive duration, e.g. 10m, 1h)",
                        fg="red", err=True,
                    )
                    raise typer.Exit(code=2)
                store.set_offline_after(norm_mac, seconds, updated_at=now)
                typer.secho(f"offline-after for {norm_mac} set to {offline_after}", fg="green")
            if clear_offline_after:
                store.set_offline_after(norm_mac, None, updated_at=now)
                typer.secho(f"offline-after for {norm_mac} cleared - using the global default", fg="green")
            if metadata_updates:
                store.update_device_metadata(norm_mac, updated_at=now, **metadata_updates)
                typer.secho(f"metadata for {norm_mac} updated: {', '.join(metadata_updates)}", fg="green")

    since_dt = _parse_since(since)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    apply_self_trust(allowlist, interface=cfg.scan.interface)
    now = utcnow()

    with _open_store(cfg.resolved_db_path()) as store:
        dev = build_device(store, allowlist, norm_mac)
        if dev is None:
            typer.secho(f"error: no device with MAC {norm_mac} has been observed", fg="red", err=True)
            raise typer.Exit(code=2)
        dev = enrich_missing_hostnames([dev], resolve=cfg.scan.resolve_hostnames, timeout=cfg.scan.dns_timeout_seconds)[0]
        events = store.events_for(norm_mac, since=since_dt)
        addresses = store.address_evidence_for(norm_mac)
        names = store.name_evidence_for(norm_mac)
        services = store.advertised_services(mac=norm_mac, now=now)
        dossier = build_device_dossier(
            store, allowlist, norm_mac, signatures=SignatureSet.load(cfg.rogue_signatures_file),
            vendor_file=cfg.vendor_file, now=now, device=dev, addresses=addresses, names=names, services=services,
        )

    if output_format == "json":
        payload = {
            "device": dev.model_dump(mode="json"),
            "since": since_dt.isoformat(),
            "timeline": [e.model_dump(mode="json") for e in events],
            "addresses": [a.model_dump(mode="json") for a in addresses],
            "names": [n.model_dump(mode="json") for n in names],
            "services": [s.model_dump(mode="json") for s in services],
            # Additive - existing keys/shapes above are unchanged. A
            # conservative, confidence-labeled guess (see
            # lanfence.classify) and the fingerprint signatures currently
            # matching this device, never presented as verified fact.
            "classification": dossier.classification.model_dump(mode="json"),
            "fingerprint_matches": [m.model_dump(mode="json") for m in dossier.fingerprint_matches],
            # None when never actively inspected (see `lanfence inspect`) -
            # distinct from an inspection that ran and found nothing.
            "inspection": dossier.inspection.model_dump(mode="json") if dossier.inspection else None,
        }
        typer.echo(json.dumps(payload, indent=2))
    else:
        render_device_detail(
            dev, events, since_dt, now=now, default_offline_after_seconds=cfg.scan.offline_grace_seconds,
            addresses=addresses, names=names, services=services, classification=dossier.classification,
            inspection=dossier.inspection,
        )


@app.command()
def inspect(
    mac: str = typer.Argument(..., help="MAC address of an already-known device to actively inspect."),
    nmap: bool = typer.Option(
        True, "--nmap/--no-nmap",
        help="Prefer the optional nmap binary when available (falls back to a built-in scan either way).",
    ),
    output_format: str = typer.Option("table", "--format", "-f", help="table | json"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Actively inspect one already-known device: a bounded TCP connect-scan
    of a short list of common service ports, plus a conservative platform
    guess from which ports responded.

    Unlike every other LAN Fence command, this sends probe traffic directly
    to the device - never run automatically by `scan`/`monitor`/passive
    discovery/`review`. Confirmed open ports are a fact (the connection
    succeeded); the service label next to each one and the overall platform
    guess are inferences, never verified capabilities or OS fingerprinting.
    Results are persisted (one row per MAC, replacing any earlier run) so
    `lanfence device <MAC>` and `lanfence review` can show them again later,
    labeled with their age.
    """

    if output_format not in ("table", "json"):
        typer.secho(f"error: --format must be 'table' or 'json', got {output_format!r}", fg="red", err=True)
        raise typer.Exit(code=2)
    try:
        norm_mac = normalize_mac(mac)
    except ValueError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc

    cfg = _load_config(config)
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    apply_self_trust(allowlist, interface=cfg.scan.interface)

    with _open_store(cfg.resolved_db_path()) as store:
        dev = build_device(store, allowlist, norm_mac)
        if dev is None:
            typer.secho(f"error: no device with MAC {norm_mac} has been observed", fg="red", err=True)
            raise typer.Exit(code=2)
        if not dev.ip:
            typer.secho(
                f"error: {norm_mac} has no known IP address to inspect - it must be seen by a "
                "scan/monitor first", fg="red", err=True,
            )
            raise typer.Exit(code=2)

        if output_format != "json":
            typer.secho(f"Sending active inspection probes to {dev.ip} ({norm_mac})...", fg="yellow")

        result = active_inspect.inspect_device(norm_mac, dev.ip, use_nmap=nmap)
        store.record_inspection(result)

    if output_format == "json":
        typer.echo(result.model_dump_json(indent=2))
    else:
        typer.echo("")
        typer.echo(render_inspection_result(result, now=utcnow()))


def _stdin_is_interactive() -> bool:
    """Wrapped so tests can simulate a real terminal without fighting how
    the test runner's own stdin reports ``isatty()``."""

    return sys.stdin.isatty()


def _run_interactive_review(cfg: Config) -> None:
    if not _stdin_is_interactive():
        typer.secho(
            "error: `lanfence review` needs an interactive terminal. Use the "
            "noninteractive form instead, e.g.:\n"
            "  lanfence review <MAC> --trust --name \"...\"\n"
            "  lanfence review <MAC> --snooze 24h\n"
            "  lanfence review <MAC> --investigate --notes \"...\"\n"
            "  lanfence review <MAC> --clear",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)

    allowlist_path = cfg.resolved_allowlist_file()
    allowlist = Allowlist.load(allowlist_path)
    allowlist.path = allowlist_path

    signatures = SignatureSet.load(cfg.rogue_signatures_file)

    with _open_store(cfg.resolved_db_path()) as store:
        now = utcnow()
        # A separate copy (never saved) just for building the queue, so
        # self-trust never leaks into the file if the operator goes on to
        # trust some *other* device in this same session - `allowlist`
        # itself (the one .save() is called on below) stays exactly what
        # was on disk plus whatever the operator explicitly chooses here.
        display_allowlist = Allowlist(list(allowlist.entries), allowlist_path)
        apply_self_trust(display_allowlist, interface=cfg.scan.interface)

        # A stable snapshot taken once at the start - a decision made on one
        # device (trust/snooze/investigate) never reshuffles or reintroduces
        # others later in the same session. Ordered by review priority (see
        # `lanfence.dossier.review_priority`) - stronger security signals
        # and weaker identity evidence first, MAC as the deterministic
        # tie-break, never a numeric risk score.
        candidates = [d for d in build_inventory(store, display_allowlist) if is_review_needed(d, now=now)]
        dossiers = [
            build_device_dossier(store, display_allowlist, d.mac, signatures=signatures,
                                  vendor_file=cfg.vendor_file, now=now, device=d, inspection=None)
            for d in candidates
        ]
        queue = sorted(dossiers, key=lambda dos: (review_priority(dos)[0], dos.device.mac))

        if not queue:
            typer.secho("Nothing needs review.", fg="green")
            return

        typer.secho(f"{len(queue)} device(s) need review.\n", fg="cyan", bold=True)
        total = len(queue)
        for index, dossier in enumerate(queue, start=1):
            dev = dossier.device
            _rank, priority_label = review_priority(dossier)

            while True:
                typer.echo(render_dossier_compact(dossier, index=index, total=total, priority_label=priority_label))
                typer.echo("")
                typer.secho(
                    "Actions: [T]rust  [I]nvestigate  [S]nooze  [X] Inspect  [D] Full details  [N]ext  [Q]uit",
                    fg="cyan",
                )
                action = typer.prompt("  choice", default="n").strip().lower()

                if action in ("d", "details"):
                    events = store.events_for(dev.mac, since=now - timedelta(days=30))
                    typer.echo("")
                    render_device_detail(
                        dev, events, now - timedelta(days=30), now=now,
                        default_offline_after_seconds=cfg.scan.offline_grace_seconds,
                        addresses=dossier.addresses, names=dossier.names, services=dossier.services,
                        classification=dossier.classification,
                    )
                    typer.echo("")
                    continue
                if action in ("x", "inspect"):
                    typer.echo("")
                    if not dev.ip:
                        typer.secho(f"  {dev.mac} has no known IP address to inspect.", fg="yellow")
                    else:
                        typer.secho(
                            "  More information may be available by actively inspecting this device.\n"
                            f"  Active inspection sends probe traffic directly to {dev.ip}.",
                            fg="yellow",
                        )
                        if typer.confirm("  Run active inspection?", default=False):
                            result = active_inspect.inspect_device(dev.mac, dev.ip)
                            store.record_inspection(result)
                            typer.echo("")
                            typer.echo(render_inspection_result(result, now=now))
                    typer.echo("")
                    continue
                break

            if action in ("q", "quit"):
                typer.echo("stopping review.")
                return
            if action in ("t", "trust"):
                name = typer.prompt("  name", default=dev.mac)
                notes = typer.prompt("  notes", default="")
                entry = allowlist.add(dev.mac, name, notes)
                allowlist.save()
                store.clear_review(dev.mac)
                typer.secho(f"  trusted: {entry.name}", fg="green")

                # Presence is separate from trust - ask, but never let
                # exiting this sub-prompt undo the trust decision just made
                # above (already persisted) or abort the rest of the queue.
                current_policy = store.get_presence(dev.mac).policy
                try:
                    presence_choice = typer.prompt(
                        "  Should this device always be online, or is it normal for it "
                        "to come and go?\n    [i]ntermittent - normal to come and go\n"
                        "    [a]lways on - notify after a sustained absence\n"
                        "    [u]nspecified - retain existing behavior\n  presence",
                        default={"intermittent": "i", "always-on": "a"}.get(current_policy, "u"),
                    ).strip().lower()
                except (typer.Abort, EOFError):
                    presence_choice = None
                    typer.echo("  presence unchanged.")

                policy_map = {
                    "i": "intermittent", "intermittent": "intermittent",
                    "a": "always-on", "always-on": "always-on", "always on": "always-on",
                    "u": "unspecified", "unspecified": "unspecified",
                }
                new_policy = policy_map.get(presence_choice)
                if new_policy is not None and new_policy != current_policy:
                    store.set_presence_policy(dev.mac, new_policy, updated_at=utcnow())
                    typer.secho(f"  presence: {new_policy}", fg="green")

                # Inventory details are optional and separate from trust -
                # default no, and aborting this step never undoes the trust
                # (already persisted above) or the presence choice just made.
                try:
                    add_details = typer.confirm("  Add device details (owner/purpose/group/location)?", default=False)
                except (typer.Abort, EOFError):
                    add_details = False
                if add_details:
                    existing = store.get_device_metadata(dev.mac)
                    field_prompts = (
                        ("owner", "owner"), ("purpose", "purpose"),
                        ("group", "group"), ("location", "location"),
                    )
                    try:
                        raw_values = {}
                        for field, label in field_prompts:
                            current_value = getattr(existing, field)
                            shown = f" (current: {current_value})" if current_value else ""
                            raw_values[field] = typer.prompt(
                                f"  {label}{shown} - blank to leave unchanged, '-' to clear",
                                default="", show_default=False,
                            )
                    except (typer.Abort, EOFError):
                        typer.echo("  device details unchanged.")
                        raw_values = None
                    if raw_values is not None:
                        try:
                            updates: dict[str, Optional[str]] = {}
                            for field, _label in field_prompts:
                                raw = raw_values[field].strip()
                                current_value = getattr(existing, field)
                                if not raw:
                                    continue
                                if raw == "-":
                                    if current_value is not None:
                                        updates[field] = None
                                    continue
                                validated = validate_metadata_value(field, raw)
                                if validated != current_value:
                                    updates[field] = validated
                            if updates:
                                store.update_device_metadata(dev.mac, updated_at=utcnow(), **updates)
                                typer.secho(f"  device details updated: {', '.join(updates)}", fg="green")
                        except ValueError as exc:
                            typer.secho(f"  error: {exc} - device details unchanged.", fg="red")
            elif action in ("s", "snooze"):
                duration_str = typer.prompt("  snooze for", default="24h")
                seconds = _duration_seconds(duration_str)
                if seconds is None:
                    typer.secho(f"  could not parse {duration_str!r}, snoozing for 24h instead", fg="yellow")
                    seconds = 24 * 3600
                action_now = utcnow()
                until = action_now + timedelta(seconds=seconds)
                store.set_snoozed(dev.mac, until=until, updated_at=action_now)
                typer.secho(f"  snoozed until {format_datetime(until)}", fg="green")
            elif action in ("i", "investigate"):
                notes = typer.prompt("  notes", default="")
                store.set_investigating(dev.mac, notes=notes, updated_at=utcnow())
                typer.secho("  flagged for investigation", fg="green")
            else:
                typer.echo("  skipped.")
            typer.echo("")


@app.command()
def review(
    mac: Optional[str] = typer.Argument(
        None, help="MAC to act on directly. Omit to interactively review the queue."
    ),
    trust: bool = typer.Option(False, "--trust", help="Trust this device (adds it to the allowlist)."),
    name: Optional[str] = typer.Option(
        None, "--name", help="Friendly name when trusting (default: the MAC itself)."
    ),
    notes: Optional[str] = typer.Option(None, "--notes", help="Notes for --trust or --investigate."),
    snooze: Optional[str] = typer.Option(
        None, "--snooze", help="Snooze external alerts for this MAC, e.g. 24h."
    ),
    investigate: bool = typer.Option(False, "--investigate", help="Flag this device for investigation."),
    clear: bool = typer.Option(
        False, "--clear",
        help="Clear review flags/snooze for this MAC. Does not untrust it - see `allow --remove`.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Review devices needing attention: trust, snooze, flag, or clear.

    With no MAC, interactively walks the review queue (devices that are
    untrusted, not currently snoozed, and not already flagged for
    investigation) in a stable order, offering trust/snooze/investigate/skip/
    quit for each. With a MAC, exactly one of --trust, --snooze,
    --investigate, or --clear performs that action without prompting:

        lanfence review <MAC> --trust --name "Kitchen speaker" --notes "..."
        lanfence review <MAC> --snooze 24h
        lanfence review <MAC> --investigate --notes "..."
        lanfence review <MAC> --clear

    Trusting always uses the same allowlist `lanfence allow` writes to.
    Snoozing only suppresses external alert dispatch - findings, events, and
    CLI/JSON output are unaffected, and it never automatically trusts a
    device. `--clear` removes a snooze/investigation flag but leaves the
    allowlist untouched either way.
    """

    cfg = _load_config(config)
    actions_given = sum([trust, snooze is not None, investigate, clear])

    if mac is None:
        if actions_given:
            typer.secho(
                "error: --trust/--snooze/--investigate/--clear require a MAC argument",
                fg="red", err=True,
            )
            raise typer.Exit(code=2)
        _run_interactive_review(cfg)
        return

    try:
        norm_mac = normalize_mac(mac)
    except ValueError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc

    if actions_given != 1:
        typer.secho(
            "error: provide exactly one of --trust, --snooze, --investigate, --clear",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)
    if name is not None and not trust:
        typer.secho("error: --name only applies to --trust", fg="red", err=True)
        raise typer.Exit(code=2)
    if notes is not None and not (trust or investigate):
        typer.secho("error: --notes only applies to --trust or --investigate", fg="red", err=True)
        raise typer.Exit(code=2)

    now = utcnow()
    with _open_store(cfg.resolved_db_path()) as store:
        if trust:
            path = cfg.resolved_allowlist_file()
            al = Allowlist.load(path)
            al.path = path
            entry = al.add(norm_mac, name or norm_mac, notes or "")
            al.save()
            store.clear_review(norm_mac)
            typer.secho(f"trusted: {entry.name}  ({entry.mac})", fg="green")
        elif snooze is not None:
            duration = _parse_snooze_duration(snooze)
            until = now + duration
            store.set_snoozed(norm_mac, until=until, updated_at=now)
            typer.secho(f"snoozed {norm_mac} until {format_datetime(until)}", fg="green")
        elif investigate:
            store.set_investigating(norm_mac, notes=notes, updated_at=now)
            typer.secho(f"flagged {norm_mac} for investigation", fg="green")
        else:  # clear
            store.clear_review(norm_mac)
            typer.secho(f"cleared review state for {norm_mac}", fg="green")


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
    """Check that this host can run LAN Fence (permissions, scapy, nmap, interface)."""

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

    if active_inspect.nmap_available():
        typer.secho("  ok       nmap is installed (used automatically by `lanfence inspect`)", fg="green")
    else:
        typer.echo(
            "  optional nmap is not installed - `lanfence inspect` still works via its "
            "built-in scan; installing nmap improves service identification - "
            "on Debian/Ubuntu/Raspberry Pi OS: sudo apt-get install nmap"
        )

    iface = cfg.scan.interface or scanner.default_interface()
    typer.echo(f"  interface:   {iface or '(could not auto-detect)'}")
    net = cfg.scan.subnet or scanner.local_subnet(iface)
    typer.echo(f"  subnet:      {net or '(could not auto-detect)'}")
    ipv6_ok = scanner.has_ipv6(iface)
    typer.echo(f"  ipv6:        {'available' if ipv6_ok else 'not available on this interface'}")

    typer.secho("\nStorage", fg="cyan", bold=True)
    db_path = cfg.resolved_db_path()
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        DeviceStore(db_path).close()
        typer.secho(f"  ok       database writable: {db_path}", fg="green")
        db_ok = True
    except (OSError, RuntimeError) as exc:
        typer.secho(f"  FAIL     database not writable: {db_path} ({exc})", fg="red")
        hint = _ownership_fix_hint(exc, db_path.parent)
        if hint:
            typer.secho(f"           fix: {hint}", fg="yellow")
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


def _installed_version() -> Optional[str]:
    """The version on disk right now, read fresh from package metadata.

    Used after running an upgrade command to confirm it actually changed
    anything - `pipx upgrade` / `pip install --upgrade` both exit ``0`` when
    they find nothing newer to install, which is not the same as success.
    """

    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("lanfence")
    except (ImportError, PackageNotFoundError):
        return None


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

    # A `0` exit code alone doesn't mean the version actually changed - both
    # `pipx upgrade` and `pip install --upgrade` exit 0 when they find nothing
    # newer than what's installed (e.g. PyPI's package index, used to resolve
    # the actual download, can lag a minute or two behind the JSON API this
    # command checked against above, right after a release). Re-check what's
    # actually on disk before claiming success.
    now_installed = _installed_version()
    if now_installed and _version_key(now_installed) > _version_key(__version__):
        typer.secho(f"\nupgraded to {now_installed}.", fg="green")
        return
    typer.secho(
        f"\nthe upgrade command ran successfully, but the installed version is "
        f"still {now_installed or __version__} - not {latest}. PyPI's package "
        "index can lag a minute or two behind the check above right after a "
        "release; wait a bit and run `lanfence upgrade` again.",
        fg="yellow",
    )
    raise typer.Exit(code=10)


#: `lanfence update` is an exact alias for `lanfence upgrade` - hidden from
#: --help (upgrade is the documented name) but still works exactly the
#: same, for anyone who reaches for "update" instead.
app.command(name="update", hidden=True)(upgrade)


@app.command(name="web")
def web_cmd(config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file.")) -> None:
    """Run the local web portal for browsing and labeling devices.

    Configure it first via `lanfence setup`'s Web portal section (enable it
    and set a password) - this command only starts the already-configured
    server and has no flags of its own. Binds to this host's own detected
    LAN address only (never 0.0.0.0 or a public interface), and refuses to
    start if the portal isn't enabled or no password has been set yet.
    Runs in the foreground until interrupted (Ctrl+C); see README for
    running it continuously via the packaged systemd unit instead.
    """

    cfg = _load_config(config)
    if not cfg.web.enabled:
        typer.secho(
            "error: the web portal is disabled - enable it via `lanfence setup`.", fg="red", err=True
        )
        raise typer.Exit(code=2)
    if cfg.web.password_hash is None:
        typer.secho(
            "error: no web portal password is set - set one via `lanfence setup`.", fg="red", err=True
        )
        raise typer.Exit(code=2)
    try:
        host = web.resolve_bind_host()
    except web.WebError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=1) from exc
    typer.secho(f"LAN Fence web portal: https://{host}:{cfg.web.port}/", fg="green")
    web.run_server(cfg, host=host)


_IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"


@app.command(name="vendor-refresh")
def vendor_refresh(
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Where to save the refreshed table (default: config vendor_file, "
        "or ~/.config/lanfence/oui_vendors.txt).",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    url: str = typer.Option(_IEEE_OUI_CSV_URL, "--url", help="CSV source to fetch."),
    timeout: float = typer.Option(30.0, "--timeout", help="Download timeout, in seconds."),
) -> None:
    """Download the current IEEE OUI (MA-L) registry as an extra vendor table.

    LAN Fence ships a large built-in vendor table and makes no network calls
    on its own; this is the one deliberate, operator-triggered exception -
    the same pattern as `lanfence upgrade` checking PyPI. It fetches IEEE's
    public registry directly (a few MB) so a device assigned an OUI after
    this copy of LAN Fence was built is still recognised, without waiting for
    a new release. The result is saved as an *extra* table, never overwriting
    the packaged one - point `vendor_file:` in your config at it (printed at
    the end) to have `scan`/`monitor` merge it on top of the built-in table.
    """

    cfg = _load_config(config)
    dest = expand_operator_path(Path(output or cfg.vendor_file or "~/.config/lanfence/oui_vendors.txt"))

    typer.echo(f"fetching {url} ...")
    request = urllib.request.Request(url, headers={"User-Agent": f"lanfence/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - https literal
            raw = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        typer.secho(f"error: could not download vendor registry: {summarize_error(exc)}", fg="red", err=True)
        raise typer.Exit(code=1) from exc

    table = parse_ieee_oui_csv(raw.decode("utf-8", errors="replace"))
    if not table:
        typer.secho(
            "error: downloaded file did not parse as an IEEE OUI (MA-L) registry.",
            fg="red", err=True,
        )
        raise typer.Exit(code=1)

    header = (
        f"# Fetched via `lanfence vendor-refresh` from {url}\n"
        f"# on {datetime.now(timezone.utc).isoformat()}\n"
    )
    try:
        atomic_write(dest, header + format_vendor_table(table), mode=0o644)
    except OSError as exc:
        typer.secho(f"error: could not write {dest}: {exc}", fg="red", err=True)
        raise typer.Exit(code=1) from exc

    typer.secho(f"saved {len(table)} vendor entries to {dest}", fg="green")
    if cfg.vendor_file is None or expand_operator_path(Path(cfg.vendor_file)) != dest:
        typer.echo(f"add this to your config to use it:\n  vendor_file: {dest}")


# --- lanfence setup ----------------------------------------------------


def _channels_load_or_exit(config: Optional[Path]):
    path = resolve_channels_config_path(config)
    try:
        return path, load_channels_config_file(path)
    except ConfigFileError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc
    except OSError as exc:
        typer.secho(f"error: cannot read {path}; check permissions and the --config path.", fg="red", err=True)
        raise typer.Exit(code=2) from exc


def _channels_save_or_exit(path: Path, loaded, updated_raw: dict) -> None:
    if path.is_symlink():
        typer.echo(f"note: {path} is a symlink - the link itself will be replaced, its target left alone.")
    # Checked *before* saving - `save_channels_config_file` always writes
    # the replacement at 0o600 (see `lanfence.fsutil.atomic_write`'s
    # default), so any pre-existing looser permissions are only visible
    # right up until the save itself fixes them.
    insecure_mode = check_insecure_permissions(path)
    try:
        save_channels_config_file(loaded, updated_raw)
    except ConcurrentModificationError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc
    except ConfigFileError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(code=2) from exc

    typer.secho(f"saved {path}", fg="green")
    if insecure_mode is not None:
        typer.secho(
            f"note: {path} was readable beyond its owner (mode {oct(insecure_mode)}) before this save - "
            "restricted to owner-only (0o600), since it may hold secrets.",
            fg="yellow",
        )


def _prompt_secret_field(f, current_value: Optional[str]):
    if current_value:
        typer.echo(f"  {f.label}: already configured (hidden)")
        raw = typer.prompt(
            f"  {f.label} - blank to keep it, or type 'clear' to remove it",
            default="", show_default=False, hide_input=True,
        )
        if not raw:
            return KEEP
        if raw.strip().lower() == "clear":
            return CLEAR
        return raw
    suffix = "" if f.required else " (optional - blank to leave unset)"
    raw = typer.prompt(f"  {f.label}{suffix}", default="", show_default=False, hide_input=True)
    return raw or None


def _prompt_channel_fields(channel: str, current_cfg) -> dict:
    values: dict = {}
    for f in CHANNEL_FIELDS[channel]:
        current_value = getattr(current_cfg, f.name, None)
        if f.help_text:
            typer.echo(f"  {f.help_text}")
        if f.kind == "secret":
            values[f.name] = _prompt_secret_field(f, current_value)
        elif f.kind == "bool":
            values[f.name] = typer.confirm(f"  {f.label}", default=bool(current_value))
        elif f.kind == "choice":
            default = current_value or f.default
            values[f.name] = typer.prompt(f"  {f.label} ({'/'.join(f.choices)})", default=default)
        elif f.kind == "list_str":
            default_display = ", ".join(current_value or [])
            raw = typer.prompt(f"  {f.label}", default=default_display, show_default=bool(default_display))
            values[f.name] = [p.strip() for p in raw.split(",") if p.strip()]
        elif f.kind in ("int", "float"):
            default = current_value if current_value is not None else f.default
            raw = typer.prompt(f"  {f.label}", default=str(default) if default is not None else "")
            try:
                values[f.name] = int(raw) if f.kind == "int" else float(raw)
            except ValueError:
                values[f.name] = raw  # left as-is - validate_channel_values reports it clearly
        else:  # text
            default = current_value or f.default or ""
            raw = typer.prompt(f"  {f.label}", default=default, show_default=bool(default))
            values[f.name] = raw or None

    return values


def _wizard_webhook_scheme_note(channel: str, values: dict) -> None:
    url_field = "url" if channel in ("webhook", "ntfy") else "webhook_url"
    url = values.get(url_field)
    if isinstance(url, str) and url.startswith("http://"):
        typer.secho(
            "  note: this URL uses plain HTTP - the message will be sent unencrypted over the network.",
            fg="yellow",
        )


def _run_channel_wizard(channel: str, path: Path, loaded) -> None:
    typer.secho(f"\n{channel}", fg="cyan", bold=True)
    while True:
        current_cfg = getattr(loaded.cfg.alerts, channel)
        values = _prompt_channel_fields(channel, current_cfg)
        _wizard_webhook_scheme_note(channel, values)
        values["enabled"] = typer.confirm("  Enable this channel now?", default=current_cfg.enabled)

        errors = validate_channel_values(channel, values)
        if errors:
            typer.secho("\nThe following need fixing:", fg="red")
            for e in errors:
                typer.secho(f"  - {e}", fg="red")
            if not typer.confirm("\nTry entering these values again?", default=True):
                typer.echo("cancelled - no changes saved.")
                return
            continue

        # Sanitized preview against what *would* be saved - never the raw
        # secret values just entered.
        preview_raw = apply_channel_values(loaded.raw, channel, values)
        preview_cfg = Config.model_validate(preview_raw)
        typer.echo("\nProposed configuration:")
        for status in list_channel_statuses(preview_cfg):
            if status.channel == channel:
                typer.echo(
                    f"  {status.channel}: enabled={status.enabled} configured={status.configured} "
                    f"destination={status.summary}"
                )

        typer.echo("Saving rewrites YAML formatting/comments and restricts the file to owner-only permissions (0600).")
        if not typer.confirm("\nSave this configuration?", default=True):
            typer.echo("cancelled - no changes saved.")
            return

        digest_choice = None
        if supports_digest(channel):
            digest_choice = typer.confirm(
                "Use this channel for daily digests too?", default=channel in loaded.cfg.digest.channels
            )

        updated_raw = preview_raw
        if digest_choice is not None:
            updated_raw = apply_digest_selection(updated_raw, channel, selected=digest_choice)

        _channels_save_or_exit(path, loaded, updated_raw)

        # Re-load so a follow-up test message (or configuring another
        # channel) sees exactly what's now on disk, and so a second save
        # this session correctly detects further concurrent edits.
        loaded.raw = updated_raw
        loaded.raw_bytes = path.read_bytes()
        loaded.cfg = Config.model_validate(updated_raw)
        loaded.existed = True

        if values["enabled"]:
            send_test = typer.confirm("\nSend a test message now?", default=False)
            if send_test:
                if channel == "twilio":
                    typer.secho("  note: sending a test SMS may incur provider charges.", fg="yellow")
                ok, message = send_channel_test_message(channel, loaded.cfg)
                if ok:
                    typer.secho(f"  test message: {message}", fg="green")
                else:
                    typer.secho(f"  test message failed: {message}", fg="red")
        return


@app.command(name="setup")
def setup_cmd(
    channel: Optional[str] = typer.Argument(
        None, help="Channel to configure directly instead of the unified menu, e.g. slack."
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
) -> None:
    """Set up communications and application settings interactively.

    With no argument, opens the unified setup menu (Communications,
    Scanning, Offline detection, DHCP servers, Service discovery, Daily
    digest, Storage, Alert delivery) with a shared unsaved draft;
    `lanfence setup slack` goes straight to that channel's wizard. Needs an
    interactive terminal - for scripted/noninteractive use, edit the
    config file directly instead of piping answers into this command.
    """

    if not _stdin_is_interactive():
        typer.secho(
            "error: `lanfence setup` needs an interactive terminal. For scripted use, "
            "edit the config file directly instead.",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)
    if channel is not None and channel not in CHANNEL_NAMES:
        typer.secho(
            f"error: unknown channel {channel!r} - choose one of: {', '.join(CHANNEL_NAMES)}",
            fg="red", err=True,
        )
        raise typer.Exit(code=2)

    path, loaded = _channels_load_or_exit(config)
    path = path.absolute()
    loaded.path = path

    try:
        if channel is None:
            from lanfence.setup_ui import run_setup
            run_setup(path, loaded)
            return
        while True:
            if channel is None:
                render_channels_table(list_channel_statuses(loaded.cfg))
                typer.echo("")
                choice = typer.prompt(f"Which channel would you like to configure? ({', '.join(CHANNEL_NAMES)})")
                choice = choice.strip().lower()
                if choice not in CHANNEL_NAMES:
                    typer.secho(f"unknown channel {choice!r}", fg="red")
                    continue
            else:
                choice = channel
                channel = None  # only auto-select once, when given as an argument

            _run_channel_wizard(choice, path, loaded)

            if not typer.confirm("\nConfigure another channel?", default=False):
                break
    except (typer.Abort, EOFError):
        typer.echo("\ncancelled - no further changes saved.")



def main() -> None:  # pragma: no cover - entry point shim
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
