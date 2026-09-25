# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""``lanfence web`` - a small local portal for browsing the device
inventory and editing a device's trusted name/inventory metadata from a
browser, for anyone who'd rather click than type CLI flags.

Deliberately built on the standard library only (``http.server``, no new
dependency) - this is a small, single-purpose surface (list devices, edit
one), not a general web application. Design decisions, settled with the
project owner before writing this:

* **Configured entirely through ``lanfence setup``'s Web portal section** -
  there is no separate `lanfence web enable`/`set-password` command. This
  module only starts/stops the server and does the actual serving;
  `lanfence/setup_ui.py` owns the config-editing UI.
* **Single shared login, no per-user accounts** - a household tool, one
  password. The hash/salt live in ``Config.web`` (see ``lanfence/config.py``).
* **Bound to this host's own LAN-facing address only, never 0.0.0.0** - see
  :func:`resolve_bind_host`. Refuses to start otherwise, since anything
  that can reach 0.0.0.0 (including the internet, if this host is
  otherwise exposed) could reach a password-brute-forceable login on a
  security-monitoring tool.
* **Always HTTPS, via a self-signed certificate generated on first run -
  never plain HTTP.** LAN-only is not the same as trustworthy: LAN Fence's
  entire premise is that other devices on the LAN aren't necessarily
  trustworthy, so the login password must never go out in cleartext to
  them. There is deliberately no setting to turn this off - an optional
  insecure mode just recreates the problem for whoever doesn't flip it.
  The certificate is self-signed (not CA-issued), so every browser will
  show a one-time "connection is not private" warning to click through -
  the same experience as any router/NAS admin panel on your LAN. Requires
  the ``openssl`` CLI (not a new Python dependency - present on
  essentially every Linux/macOS install already) to generate the
  certificate; see :func:`ensure_self_signed_cert`.
* **The portal URL in a digest is never a fixed/configured address, and
  only ever shown when the portal is actually running right now** -
  :func:`build_portal_url` checks :func:`is_server_running` and
  recomputes the LAN address fresh each time a digest is generated (see
  ``lanfence/digest.py``); a stale/broken link would be worse than
  honestly saying the portal isn't running.
"""

from __future__ import annotations

import hashlib
import html
import http.cookies
import ipaddress
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from lanfence import branding
from lanfence.allowlist import Allowlist
from lanfence.baseline import (
    accept_pending,
    assess_device,
    maturity,
    reassess_device,
    reset_baseline,
    review_change,
    set_excluded_signals,
)
from lanfence.changes import day_heading, describe, format_time, service_label, significance_at_least
from lanfence.config import Config, expand_operator_path
from lanfence.db import DeviceStore
from lanfence.device_metadata import METADATA_LIMITS, validate_metadata_value
from lanfence.dossier import DeviceDossier, build_device_dossier
from lanfence.engine import apply_self_trust, build_inventory, is_review_needed
from lanfence.fingerprint import SignatureSet
from lanfence.identity import IdentityRuleSet
from lanfence.logging_config import get_logger
from lanfence.models import (
    ASSET_TYPES,
    CHANGE_TYPES,
    DEVICE_CATEGORIES,
    EXCLUDABLE_SIGNALS,
    SIGNIFICANCES,
    ChangeEvent,
    Device,
    RiskAssessment,
    format_datetime,
    utcnow,
)
from lanfence.policy import Policy, effective_policies
from lanfence.netutil import normalize_mac

log = get_logger("web")


class WebError(Exception):
    """A `lanfence web` setup/runtime problem with a clear, user-facing message."""


#: Shown in a digest (see ``lanfence/digest.py``'s ``format_digest_text``
#: and ``lanfence/report.py``'s ``render_digest``) whenever
#: :func:`build_portal_url` returns ``None`` - always one or the other, so
#: a digest also serves as a reminder the feature exists even if you've
#: never touched it.
PORTAL_NOT_RUNNING_NOTE = "Web portal is not running - enable it with `lanfence setup`."


# --- password hashing ---------------------------------------------------
#
# hashlib.scrypt (stdlib, no new dependency) rather than a raw hash - slow
# and memory-hard by design, so an attacker who obtains config.yaml can't
# cheaply brute-force the password offline. Parameters follow scrypt's own
# interactive-login recommendation (RFC 7914 SS2).

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16


def hash_password(password: str) -> tuple[str, str]:
    """Salt and hash ``password``; returns ``(password_hash, password_salt)``
    as hex strings, ready for ``Config.web.password_hash``/``password_salt``."""

    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN
    )
    return digest.hex(), salt.hex()


def verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    """Constant-time check of ``password`` against a stored hash/salt pair."""

    try:
        salt = bytes.fromhex(password_salt)
    except ValueError:
        return False
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN
    )
    return secrets.compare_digest(digest.hex(), password_hash)


# --- LAN address detection & bind policy --------------------------------


def detect_lan_ip() -> str | None:
    """Best-effort local LAN IPv4 address: the source address the OS would
    use to reach the public internet, found with a UDP "connect" that never
    actually transmits a packet (UDP is connectionless; this only asks the
    OS to pick a route and a local address for it). No traffic is sent, no
    root/raw-socket access is needed, and no dependency on scapy - unlike
    ``scanner.local_subnet()``, this must also work when the ``[scan]``
    extra isn't installed. Returns ``None`` if it can't be determined (no
    route at all, offline, sandboxed network namespace, ...).
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def resolve_bind_host() -> str:
    """The address `lanfence web` binds to: this host's own detected LAN
    address, verified private (RFC 1918/RFC 4193-equivalent for IPv4 -
    ``ipaddress``'s ``is_private``) - never ``0.0.0.0`` or a public address,
    so the portal stays unreachable from outside the LAN even on a host
    that also has a public interface. Raises :class:`WebError` with a
    clear, actionable message if no such address can be confirmed.
    """

    ip = detect_lan_ip()
    if ip is None:
        raise WebError(
            "could not determine this host's LAN IP address (no network route found) - "
            "check network connectivity and try again"
        )
    if not ipaddress.ip_address(ip).is_private:
        raise WebError(
            f"detected address {ip} is not a private LAN address - refusing to bind somewhere "
            "that could be reachable beyond your LAN"
        )
    return ip


def _addresses_on_interface_holding(ip: str) -> list[str]:
    """Every address (IPv4 and IPv6) on whichever interface holds ``ip``,
    read from iproute2's ``ip -j addr`` (Linux). Empty if that isn't
    available or ``ip`` isn't found on any interface."""

    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=2, check=False,
        )
        interfaces = json.loads(result.stdout) if result.returncode == 0 else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    for interface in interfaces if isinstance(interfaces, list) else []:
        addresses = [
            info.get("local") for info in interface.get("addr_info", [])
            if isinstance(info, dict) and isinstance(info.get("local"), str)
        ]
        if ip in addresses:
            return addresses
    return []


def resolve_bind_hosts() -> list[str]:
    """Every address `lanfence web` binds to: this host's detected LAN
    address (see :func:`resolve_bind_host`, always first) plus every other
    private address on the same interface - e.g. several addresses on
    eth0. The same bind policy applies to each: public addresses are
    skipped, as are IPv6 link-local ones (they need a scope ID and don't
    work in most browsers' URLs). Falls back to just the detected address
    where the interface's addresses can't be listed."""

    primary = resolve_bind_host()
    hosts = [primary]
    for address in _addresses_on_interface_holding(primary):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.is_private and not parsed.is_link_local and not parsed.is_loopback and address not in hosts:
            hosts.append(address)
    return hosts


def portal_url(host: str, port: int) -> str:
    return f"https://[{host}]:{port}/" if ":" in host else f"https://{host}:{port}/"


def build_portal_url(cfg: Config) -> str | None:
    """URL to link to the web portal from a digest, or ``None`` if it isn't
    actually reachable right now.

    Deliberately keyed off :func:`is_server_running`, not
    ``cfg.web.enabled`` - a config saying "enabled" with no process behind
    it would be a broken link, and a broken link is worse than an honest
    "not running" note (see ``lanfence/digest.py``). Also deliberately not
    read from a configured/cached address: the host's LAN address can
    change under DHCP, so this is recomputed fresh each time a digest is
    generated - "reachable here as of this digest", not a promise that it
    always will be.
    """

    if not is_server_running():
        return None
    ip = detect_lan_ip()
    if ip is None or not ipaddress.ip_address(ip).is_private:
        return None
    return f"https://{ip}:{cfg.web.port}/"


# --- TLS: mandatory self-signed certificate -----------------------------
#
# No plain-HTTP mode exists - see the module docstring for why. The
# certificate is generated once (via the `openssl` CLI, not a new Python
# dependency) and cached, rather than regenerated on every start; a
# sidecar file records which host it was issued for, so a DHCP-changed LAN
# address triggers a fresh certificate+SAN instead of silently serving one
# that no longer matches (which browsers would reject even harder than a
# plain self-signed warning).

_CERT_FILE = Path("~/.local/share/lanfence/web-cert.pem")
_KEY_FILE = Path("~/.local/share/lanfence/web-key.pem")
_CERT_HOST_FILE = Path("~/.local/share/lanfence/web-cert.host")


def _resolved_cert_file() -> Path:
    return expand_operator_path(_CERT_FILE)


def _resolved_key_file() -> Path:
    return expand_operator_path(_KEY_FILE)


def _resolved_cert_host_file() -> Path:
    return expand_operator_path(_CERT_HOST_FILE)


def ensure_self_signed_cert(host: str | list[str]) -> tuple[Path, Path]:
    """A self-signed cert+key covering ``host`` (one address, or every
    address the portal binds to), generating one with ``openssl`` if none
    exists yet (or the existing one was issued for different addresses -
    see above). Returns ``(cert_path, key_path)``.

    Raises :class:`WebError` if the ``openssl`` CLI isn't available or
    generation fails - there is no fallback to plain HTTP.
    """

    hosts = [host] if isinstance(host, str) else list(host)
    host_key = ",".join(hosts)
    cert_path = _resolved_cert_file()
    key_path = _resolved_key_file()
    host_path = _resolved_cert_host_file()

    if cert_path.is_file() and key_path.is_file():
        try:
            cached_host = host_path.read_text(encoding="utf-8").strip()
        except OSError:
            cached_host = None
        if cached_host == host_key:
            return cert_path, key_path

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "825", "-nodes",
                "-subj", f"/CN={hosts[0]}",
                "-addext", "subjectAltName=" + ",".join(f"IP:{h}" for h in hosts),
            ],
            capture_output=True, timeout=30, check=False,
        )
    except FileNotFoundError as exc:
        raise WebError(
            "the `openssl` command was not found - it's required to generate the web portal's "
            "self-signed TLS certificate (no plain-HTTP mode is offered); install it and try again"
        ) from exc
    except subprocess.SubprocessError as exc:
        raise WebError(f"could not generate a TLS certificate: {exc}") from exc
    if result.returncode != 0 or not cert_path.is_file() or not key_path.is_file():
        raise WebError(
            "could not generate a TLS certificate (openssl exited with an error) - "
            "check that `openssl` is a working installation and try again"
        )
    key_path.chmod(0o600)
    host_path.write_text(host_key, encoding="utf-8")
    return cert_path, key_path


# --- process management (pidfile + optional systemd unit) --------------
#
# Two ways the server can be running: a background process `lanfence
# setup` spawned for immediate convenience (tracked by the pidfile below),
# or the packaged systemd unit (packaging/lanfence-web.service) for
# anything long-lived. Stopping has to know which, since sending a raw
# kill signal to a systemd-managed process just gets it restarted per the
# unit's own restart policy.

#: Sudo-aware, same state directory convention as db_path/allowlist_file's
#: own defaults (see Config) - resolved against the *operator's* home even
#: under sudo, not root's.
_PID_FILE = Path("~/.local/share/lanfence/web.pid")
_LOG_FILE = Path("~/.local/share/lanfence/web.log")
_SYSTEMD_UNIT = "lanfence-web"


def _resolved_pid_file() -> Path:
    return expand_operator_path(_PID_FILE)


def _resolved_log_file() -> Path:
    return expand_operator_path(_LOG_FILE)


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just owned by someone else (e.g. root via sudo)
    return True


def running_pid() -> int | None:
    """The PID of a `lanfence web` process started via the pidfile
    convention (i.e. not the systemd unit, which manages its own process
    tracking) - ``None`` if the pidfile is absent, unreadable, or stale
    (in which case it's cleaned up)."""

    path = _resolved_pid_file()
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if _process_alive(pid):
        return pid
    path.unlink(missing_ok=True)
    return None


def _write_pid_file() -> None:
    path = _resolved_pid_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()), encoding="utf-8")


def _remove_pid_file() -> None:
    _resolved_pid_file().unlink(missing_ok=True)


def _systemd_unit_active(name: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", name], timeout=2, check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_server_running() -> bool:
    """Whether a `lanfence web` process is currently running, however it
    was started (systemd unit or pidfile-tracked background process)."""

    return _systemd_unit_active(_SYSTEMD_UNIT) or running_pid() is not None


def stop_server() -> bool:
    """Stop the web portal however it's currently running. Returns whether
    anything was actually stopped - a no-op (nothing running) is not an
    error, so callers (e.g. `lanfence setup` when you disable the portal)
    can call this unconditionally."""

    if _systemd_unit_active(_SYSTEMD_UNIT):
        subprocess.run(["systemctl", "stop", _SYSTEMD_UNIT], timeout=10, check=False)
        return True

    pid = running_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _remove_pid_file()
        return False
    for _ in range(50):  # ~5s grace before escalating
        if not _process_alive(pid):
            break
        time.sleep(0.1)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    _remove_pid_file()
    return True


def restart_server(config_path: Path) -> str | None:
    """Restart the web portal if it's running, so it picks up saved config
    changes - it reads its configuration only once, at startup. Returns a
    short description of what happened, or ``None`` if it wasn't running.
    Raises :class:`WebError` if it was stopped but couldn't be started
    again (e.g. no LAN address could be confirmed)."""

    if _systemd_unit_active(_SYSTEMD_UNIT):
        result = subprocess.run(["systemctl", "restart", _SYSTEMD_UNIT], timeout=15, check=False)
        if result.returncode != 0:
            raise WebError(f"`systemctl restart {_SYSTEMD_UNIT}` failed - run it yourself with sudo")
        return f"restarted the {_SYSTEMD_UNIT} service"
    if running_pid() is None:
        return None
    stop_server()
    return "restarted: " + ", ".join(start_background(config_path))


# --- local firewall (best-effort) ----------------------------------------
#
# Binding only to the LAN address (see resolve_bind_host) keeps the portal
# unreachable from outside the LAN, but says nothing about whether *this
# host's own* firewall lets LAN traffic reach the port at all - a fairly
# common reason "it works from this machine but not from my phone on the
# same network" (ERR_ADDRESS_UNREACHABLE-style failures from another
# device, even though the process is up and `ping` to the host works).
# ufw and firewalld are the two this checks for; anything else (nftables/
# iptables managed directly, an upstream router ACL) isn't visible here.

def detect_active_firewall() -> str | None:
    """Which local firewall manager is currently active - ``"ufw"``,
    ``"firewalld"``, or ``None`` if neither is active (which does not
    guarantee nothing is blocking the port - see module note above)."""

    try:
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0 and "Status: active" in result.stdout:
            return "ufw"
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        result = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0 and result.stdout.strip() == "running":
            return "firewalld"
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _firewall_allow_command(firewall: str, *, host: str, port: int) -> list[str]:
    if firewall == "ufw":
        # Scoped to the bound LAN address, not a blanket "allow this port
        # on every interface" - consistent with never widening exposure
        # beyond the LAN address this actually binds to.
        return ["ufw", "allow", "to", host, "port", str(port), "proto", "tcp", "comment", "lanfence web portal"]
    if firewall == "firewalld":
        # firewalld's plain --add-port isn't destination-scoped (unlike
        # the ufw rule above); reasonable in practice here since the
        # service itself only ever binds the LAN address, never 0.0.0.0.
        return ["firewall-cmd", "--permanent", f"--add-port={port}/tcp"]
    raise ValueError(f"unsupported firewall: {firewall}")


def allow_port_through_firewall(firewall: str, *, host: str, port: int) -> tuple[bool, str]:
    """Attempt to open ``port``/tcp (for ``host``, where the firewall
    supports scoping to it) through ``firewall``. Returns ``(success,
    message)`` - on failure (most commonly: not running as root, since
    `lanfence setup` itself normally isn't), the message includes the
    exact command to run manually with sudo, rather than silently leaving
    you stuck on the same unreachable-from-the-LAN error.
    """

    command = _firewall_allow_command(firewall, host=host, port=port)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not run `{' '.join(command)}`: {exc}"
    if result.returncode != 0:
        return False, (
            "could not update the firewall automatically (this usually needs root) - run this yourself:\n"
            f"  sudo {' '.join(command)}"
        )
    if firewall == "firewalld":
        subprocess.run(["firewall-cmd", "--reload"], capture_output=True, text=True, timeout=10, check=False)
    return True, f"firewall rule added ({firewall}): port {port}/tcp allowed for {host}"


def start_background(config_path: Path) -> list[str]:
    """Spawn `lanfence web` as a detached background process for immediate
    use right after `lanfence setup` enables it - convenience only. Not a
    substitute for the packaged systemd unit
    (``packaging/lanfence-web.service``) if you want the portal to survive
    a reboot or restart automatically after a crash; see README.

    Returns every URL it should be reachable at. Raises :class:`WebError` if
    the portal isn't actually ready to start (not enabled, no password) or
    no private LAN address can be confirmed.
    """

    cfg = Config.load(config_path)
    if not cfg.web.enabled:
        raise WebError("the web portal is not enabled")
    if cfg.web.password_hash is None:
        raise WebError("no web portal password is set")
    hosts = resolve_bind_hosts()

    log_path = _resolved_log_file()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "ab") as log_file:
        subprocess.Popen(
            [sys.executable, "-m", "lanfence.cli", "web", "--config", str(config_path)],
            stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    return [portal_url(host, cfg.web.port) for host in hosts]


# --- sessions ------------------------------------------------------------

_SESSION_COOKIE = "lanfence_session"
_SESSION_LIFETIME = timedelta(hours=12)
#: Failed-login lockout: a device on your own LAN is exactly the population
#: this whole tool exists to distrust, so the login form is rate-limited
#: the same as any internet-facing one would be.
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_SECONDS = 60.0


class _SessionStore:
    """In-memory only - a restart requires logging in again, which is a
    reasonable trade for never persisting session tokens to disk."""

    def __init__(self) -> None:
        self._sessions: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def create(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = datetime.now(timezone.utc) + _SESSION_LIFETIME
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            expiry = self._sessions.get(token)
            if expiry is None:
                return False
            if expiry < datetime.now(timezone.utc):
                del self._sessions[token]
                return False
            return True

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)


class _LoginThrottle:
    """Per-source-IP failed-login lockout, in memory only."""

    def __init__(self) -> None:
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def locked_out(self, source: str) -> bool:
        with self._lock:
            attempts = self._failures.get(source, [])
            cutoff = time.monotonic() - _LOCKOUT_SECONDS
            attempts = [t for t in attempts if t >= cutoff]
            self._failures[source] = attempts
            return len(attempts) >= _MAX_FAILED_ATTEMPTS

    def record_failure(self, source: str) -> None:
        with self._lock:
            self._failures.setdefault(source, []).append(time.monotonic())

    def clear(self, source: str) -> None:
        with self._lock:
            self._failures.pop(source, None)


# --- HTML rendering -------------------------------------------------------
#
# Look and feel mirrors the LAN Fence website (lanfence.com): same dark
# palette, same inline logo mark, same copyright/license/repo footer.
# Kept fully self-contained (inline <style>, inline <svg>) - no separate
# static-asset route, since the whole portal is a handful of small pages.

_STYLE = """
:root {
  --bg: #0b1120; --bg-alt: #0f172a; --panel: #131c31; --border: #23304d;
  --text: #e6ecf7; --muted: #9aa8c4; --accent: #2dd4bf; --accent-2: #38bdf8;
  --radius: 12px;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text); font-family: var(--font);
  font-size: 16px; line-height: 1.6; -webkit-font-smoothing: antialiased;
}
a { color: var(--accent-2); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1000px; margin: 0 auto; padding: 0 1.25rem; }
header.site {
  border-bottom: 1px solid var(--border); background: rgba(11,17,32,0.9);
  padding: 0.9rem 0;
}
.brand { display: flex; align-items: center; gap: 0.6rem; font-weight: 700; font-size: 1.1rem; }
.header-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
main { padding: 2rem 0 3rem; }
h1 { font-size: 1.5rem; margin: 0 0 1.2rem; }
h2 { font-size: 1.15rem; margin: 0 0 0.7rem; }
.panel {
  background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 1.3rem 1.4rem; margin-bottom: 1.5rem;
}
.muted { color: var(--muted); }
.table-scroll { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius); }
table { width: 100%; border-collapse: collapse; font-size: 0.93rem; }
th, td { text-align: left; padding: 0.7rem 0.9rem; border-bottom: 1px solid var(--border); }
thead th {
  background: var(--bg-alt); font-size: 0.78rem; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--muted);
}
thead th a { color: inherit; text-decoration: none; white-space: nowrap; }
thead th a:hover { color: var(--text); text-decoration: underline; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: rgba(148,163,184,0.06); }
code { font-family: var(--mono); font-size: 0.85em; background: rgba(148,163,184,0.14); padding: 0.1em 0.4em; border-radius: 5px; }
.badge { display: inline-block; padding: 0.15em 0.55em; border-radius: 999px; font-size: 0.78em; font-weight: 600; }
.badge--online { background: rgba(74,222,128,0.15); color: #4ade80; }
.badge--offline { background: rgba(148,163,184,0.15); color: var(--muted); }
.badge--trusted { background: rgba(45,212,191,0.15); color: var(--accent); }
.badge--untrusted { background: rgba(248,113,113,0.15); color: #f87171; }
form.stack { display: flex; flex-direction: column; gap: 0.9rem; max-width: 420px; }
label { font-size: 0.88rem; color: var(--muted); display: block; margin-bottom: 0.3rem; }
input[type=text], input[type=password] {
  width: 100%; padding: 0.55rem 0.7rem; border-radius: 8px; border: 1px solid var(--border);
  background: var(--bg-alt); color: var(--text); font: inherit;
}
input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
.btn {
  display: inline-block; font-weight: 600; font-size: 0.95rem; padding: 0.6rem 1.2rem;
  border-radius: 8px; border: 1px solid transparent; cursor: pointer; background: var(--accent);
  color: #04231f;
}
.btn:hover { background: #4fe3d2; }
.btn--ghost { background: transparent; border-color: var(--border); color: var(--text); }
.btn--ghost:hover { border-color: var(--accent); background: transparent; }
.btn--danger { background: transparent; border-color: #7c3d3d; color: #fca5a5; }
.btn--danger:hover { background: rgba(248,113,113,0.12); }
.flash { padding: 0.7rem 1rem; border-radius: var(--radius); margin-bottom: 1.2rem; }
.flash--ok { background: rgba(45,212,191,0.12); border: 1px solid #1f6f63; color: #9df0e4; }
.flash--error { background: rgba(248,113,113,0.12); border: 1px solid #7c3d3d; color: #fca5a5; }
.login-wrap { max-width: 360px; margin: 4rem auto 0; }
footer.site {
  border-top: 1px solid var(--border); padding: 1.5rem 0; margin-top: 2rem;
  color: var(--muted); font-size: 0.85rem;
}
footer.site a { color: var(--muted); }
.site-nav { display: flex; align-items: center; gap: 1.1rem; }
.site-nav a { color: var(--text); font-weight: 600; }
.sig { display: inline-block; padding: 0.1em 0.5em; border-radius: 999px; font-size: 0.75em; font-weight: 700;
  letter-spacing: 0.03em; }
.sig--info { background: rgba(148,163,184,0.15); color: var(--muted); }
.sig--low, .sig--moderate { background: rgba(56,189,248,0.15); color: var(--accent-2); }
.sig--medium { background: rgba(251,191,36,0.15); color: #fbbf24; }
.sig--high { background: rgba(248,113,113,0.18); color: #f87171; }
.sig--critical { background: #b91c1c; color: #fff; }
.change-row { display: grid; grid-template-columns: 4rem 1fr auto; gap: 0.3rem 1rem; padding: 0.7rem 0;
  border-bottom: 1px solid var(--border); }
.change-row:last-child { border-bottom: none; }
.change-when { color: var(--muted); font-variant-numeric: tabular-nums; }
.change-state { color: var(--muted); font-size: 0.85em; }
.muted-row { opacity: 0.6; }
.button-row { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; }
details > summary { cursor: pointer; color: var(--accent-2); }
footer.site a:hover { color: var(--text); }
"""


def _page(*, title: str, body: str, authed: bool) -> bytes:
    nav = (
        '<nav class="site-nav"><a href="/">Devices</a><a href="/changes">What Changed?</a>'
        '<form method="post" action="/logout" style="margin:0">'
        '<button class="btn btn--ghost" type="submit">Log out</button></form></nav>'
        if authed else ""
    )
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · LAN Fence</title>
<style>{_STYLE}</style>
</head>
<body>
<header class="site">
  <div class="wrap header-row">
    <div class="brand">{branding.logo_svg(28)}<span>LAN Fence</span></div>
    {nav}
  </div>
</header>
<main class="wrap">
{body}
</main>
<footer class="site">
  <div class="wrap">
    <p>{branding.FOOTER_HTML}</p>
  </div>
</footer>
</body>
</html>
"""
    return html_doc.encode("utf-8")


def _status_badge(device: Device) -> str:
    cls = "badge--online" if device.status == "online" else "badge--offline"
    return f'<span class="badge {cls}">{device.status}</span>'


def _trust_badge(device: Device) -> str:
    if device.allowlisted:
        return '<span class="badge badge--trusted">trusted</span>'
    return '<span class="badge badge--untrusted">untrusted</span>'


def _ip_display(device: Device) -> str:
    """Both addresses for a dual-stack device, or whichever one it
    actually has - see ``lanfence.report``'s identical helper and
    ``Device.ipv4``/``ipv6``'s own docstring for why ``device.ip`` (a
    single "preferred overall" address) is only a fallback."""

    parts = [ip for ip in (device.ipv4, device.ipv6) if ip]
    if parts:
        return " / ".join(parts)
    return device.ip or "-"


def _ip_sort_key(ip: str | None) -> tuple[int, object]:
    """Numeric ordering for dotted-quad addresses (so .9 sorts before .10,
    unlike a plain string sort) - devices with no IP sort last either way."""

    if not ip:
        return (1, "")
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def _dossier_owner(dossier: DeviceDossier) -> str:
    metadata = dossier.device.metadata
    return (metadata.owner if metadata else None) or ""


def _dossier_asset_type(dossier: DeviceDossier) -> str:
    metadata = dossier.device.metadata
    return (metadata.asset_type if metadata else None) or ""


#: Column key -> (header label, sort key function). Order here is the
#: table's column order. Every sort key is on the same text actually shown
#: in that column (e.g. "trusted"/"untrusted", not the raw boolean), so
#: sorting always matches what you see. Operates on a
#: :class:`~lanfence.dossier.DeviceDossier`, not a bare
#: :class:`~lanfence.models.Device`, so the identity/category/confidence
#: columns below have something to show and sort on.
_DEVICE_LIST_COLUMNS: dict[str, tuple[str, object]] = {
    "name": ("Name", lambda dos: dos.label.casefold()),
    "mac": ("MAC", lambda dos: dos.device.mac),
    "category": ("Category", lambda dos: dos.effective_category.casefold()),
    "owner": ("Owner", lambda dos: _dossier_owner(dos).casefold()),
    "asset_type": ("Asset type", lambda dos: _dossier_asset_type(dos).casefold()),
    "ip": ("IP", lambda dos: _ip_sort_key(dos.device.ip)),
    "vendor": ("Vendor", lambda dos: (dos.device.vendor or "").casefold()),
    "status": ("Status", lambda dos: dos.device.status),
    "trust": ("Trust", lambda dos: "trusted" if dos.device.allowlisted else "untrusted"),
    "confidence": ("Confidence", lambda dos: dos.identity.confidence),
    "last_seen": ("Last seen", lambda dos: dos.device.last_seen),
}
_DEFAULT_SORT = "mac"


def _render_device_list(
    dossiers: list[DeviceDossier], *, sort: str = _DEFAULT_SORT, direction: str = "asc",
    has_any_devices: bool = True, extra_query: str = "",
) -> str:
    if sort not in _DEVICE_LIST_COLUMNS:
        sort = _DEFAULT_SORT
    if direction not in ("asc", "desc"):
        direction = "asc"
    key_fn = _DEVICE_LIST_COLUMNS[sort][1]
    ordered = sorted(dossiers, key=key_fn, reverse=(direction == "desc"))

    column_count = len(_DEVICE_LIST_COLUMNS)
    if not dossiers:
        empty_message = (
            "No devices in the database yet - run `lanfence scan` first."
            if not has_any_devices else "No devices match the current filters."
        )
        rows = f'<tr><td colspan="{column_count}" class="muted">{empty_message}</td></tr>'
    else:
        rows = ""
        for dossier in ordered:
            device = dossier.device
            label = html.escape(dossier.label)
            identity = dossier.identity
            confidence = f"{identity.confidence}%" if identity.is_known else "-"
            rows += (
                "<tr>"
                f'<td><a href="/device/{html.escape(device.mac)}">{label}</a></td>'
                f"<td><code>{html.escape(device.mac)}</code></td>"
                f"<td>{html.escape(dossier.effective_category)}</td>"
                f"<td>{html.escape(_dossier_owner(dossier) or 'Not set')}</td>"
                f"<td>{html.escape(_dossier_asset_type(dossier) or 'Not set')}</td>"
                f"<td>{html.escape(_ip_display(device))}</td>"
                f"<td>{html.escape(device.vendor or '[unknown]')}</td>"
                f"<td>{_status_badge(device)}</td>"
                f"<td>{_trust_badge(device)}</td>"
                f"<td>{confidence}</td>"
                f"<td>{html.escape(device.last_seen.strftime('%Y-%m-%d %H:%M'))}</td>"
                "</tr>"
            )

    headers = ""
    for key, (label, _fn) in _DEVICE_LIST_COLUMNS.items():
        is_active = key == sort
        next_dir = "desc" if is_active and direction == "asc" else "asc"
        indicator = (" &#9650;" if direction == "asc" else " &#9660;") if is_active else ""
        headers += (
            f'<th><a href="/?sort={key}&amp;dir={next_dir}{extra_query}">{html.escape(label)}{indicator}</a></th>'
        )

    body = f"""
<div class="table-scroll panel" style="padding:0">
<table>
<thead><tr>{headers}</tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
"""
    return body


#: Query parameter name -> default value, for the inventory filters below -
#: shared between parsing the incoming request and building "preserve the
#: current filters" links (sort headers, overview counts).
_FILTER_PARAMS: tuple[str, ...] = (
    "trust", "status", "category", "asset_type", "owner", "unknown", "uncertain", "no_owner", "review", "q",
)


def _parse_filters(query: dict[str, list[str]]) -> dict[str, str]:
    return {name: query.get(name, [""])[0] for name in _FILTER_PARAMS}


def _filters_query_string(filters: dict[str, str]) -> str:
    """The current filters as a ``&amp;name=value`` suffix (HTML-escaped,
    empty values omitted) - appended to sort/pagination links so applying a
    filter is never silently lost by clicking a column header."""

    parts = [f"{name}={quote(value)}" for name, value in filters.items() if value]
    return "".join(f"&amp;{part}" for part in parts)


def _filter_dossiers(dossiers: list[DeviceDossier], filters: dict[str, str], *, now: datetime) -> list[DeviceDossier]:
    """Apply the inventory's filter/search controls (see
    :func:`_render_filter_form`) - every filter is independent and
    combines with AND, matching what the controls visually suggest."""

    owner_needle = filters["owner"].strip().casefold()
    q_needle = filters["q"].strip().casefold()
    out = []
    for dossier in dossiers:
        device = dossier.device
        if filters["trust"] == "trusted" and not device.allowlisted:
            continue
        if filters["trust"] == "untrusted" and device.allowlisted:
            continue
        if filters["status"] and device.status != filters["status"]:
            continue
        if filters["category"] and dossier.effective_category != filters["category"]:
            continue
        if filters["asset_type"] and _dossier_asset_type(dossier) != filters["asset_type"]:
            continue
        if owner_needle and owner_needle not in _dossier_owner(dossier).casefold():
            continue
        if filters["unknown"] == "1" and dossier.identity.is_known:
            continue
        if filters["uncertain"] == "1" and not dossier.identity.is_uncertain:
            continue
        if filters["no_owner"] == "1" and _dossier_owner(dossier):
            continue
        if filters["review"] == "1" and not is_review_needed(device, now=now):
            continue
        if q_needle:
            haystack = " ".join(
                [dossier.label, device.mac, device.ip or "", _dossier_owner(dossier), device.vendor or ""]
            ).casefold()
            if q_needle not in haystack:
                continue
        out.append(dossier)
    return out


def _render_filter_form(filters: dict[str, str], *, sort: str, direction: str) -> str:
    def _option(value: str, current: str) -> str:
        selected = " selected" if value == current else ""
        return f'<option value="{html.escape(value)}"{selected}>{html.escape(value or "Any")}</option>'

    trust_options = "".join(_option(v, filters["trust"]) for v in ("", "trusted", "untrusted"))
    status_options = "".join(_option(v, filters["status"]) for v in ("", "online", "offline"))
    category_options = "".join(_option(v, filters["category"]) for v in ("",) + DEVICE_CATEGORIES)
    asset_type_options = "".join(_option(v, filters["asset_type"]) for v in ("",) + ASSET_TYPES)
    unknown_checked = " checked" if filters["unknown"] == "1" else ""
    review_checked = " checked" if filters["review"] == "1" else ""
    uncertain_checked = " checked" if filters["uncertain"] == "1" else ""
    no_owner_checked = " checked" if filters["no_owner"] == "1" else ""

    return f"""
<form class="stack" method="get" action="/" style="flex-direction:row;flex-wrap:wrap;gap:0.75rem;align-items:end">
<input type="hidden" name="sort" value="{html.escape(sort)}">
<input type="hidden" name="dir" value="{html.escape(direction)}">
<div>
<label for="q">Search</label>
<input type="text" id="q" name="q" value="{html.escape(filters['q'])}" placeholder="name, MAC, IP, owner, vendor...">
</div>
<div>
<label for="trust">Trust</label>
<select id="trust" name="trust">{trust_options}</select>
</div>
<div>
<label for="status">Status</label>
<select id="status" name="status">{status_options}</select>
</div>
<div>
<label for="category">Category</label>
<select id="category" name="category">{category_options}</select>
</div>
<div>
<label for="asset_type">Asset type</label>
<select id="asset_type" name="asset_type">{asset_type_options}</select>
</div>
<div>
<label for="owner">Owner</label>
<input type="text" id="owner" name="owner" value="{html.escape(filters['owner'])}">
</div>
<div>
<label><input type="checkbox" name="unknown" value="1"{unknown_checked}> Unknown identity</label>
</div>
<div>
<label><input type="checkbox" name="review" value="1"{review_checked}> Needs review</label>
</div>
<div>
<label><input type="checkbox" name="uncertain" value="1"{uncertain_checked}> Uncertain identity</label>
</div>
<div>
<label><input type="checkbox" name="no_owner" value="1"{no_owner_checked}> No owner</label>
</div>
<button class="btn" type="submit">Filter</button>
<a class="btn" href="/">Clear</a>
</form>
"""


def _render_network_overview(dossiers: list[DeviceDossier], *, now: datetime) -> str:
    """The "Know Your Network" orientation panel on the index page - plain
    counts and attention items, deliberately not a security/risk score
    (see the feature's own scope control). Counts are clickable links that
    apply the matching inventory filter, not a separate view."""

    total = len(dossiers)
    by_asset_type: dict[str, int] = {}
    for dossier in dossiers:
        key = _dossier_asset_type(dossier) or "Unknown"
        by_asset_type[key] = by_asset_type.get(key, 0) + 1

    count_parts = [f"{total} devices"]
    for asset_type in (*ASSET_TYPES, "Unknown"):
        count = by_asset_type.get(asset_type, 0)
        if count and asset_type != "Unknown":
            count_parts.append(f'<a href="/?asset_type={quote(asset_type)}">{count} {html.escape(asset_type)}</a>')
    unset_count = by_asset_type.get("Unknown", 0)
    if unset_count:
        count_parts.append(f"{unset_count} with no asset type set")

    needs_review = sum(1 for d in dossiers if is_review_needed(d.device, now=now))
    unknown_identity = sum(1 for d in dossiers if not d.identity.is_known)
    uncertain_identity = sum(1 for d in dossiers if d.identity.is_uncertain)
    no_owner = sum(1 for d in dossiers if not _dossier_owner(d))

    attention_parts = []
    if needs_review:
        attention_parts.append(f'<a href="/?review=1">{needs_review} device(s) need review</a>')
    if unknown_identity:
        attention_parts.append(f'<a href="/?unknown=1">{unknown_identity} device(s) have unknown identities</a>')
    if uncertain_identity:
        attention_parts.append(f'<a href="/?uncertain=1">{uncertain_identity} device(s) have uncertain identities</a>')
    if no_owner:
        attention_parts.append(f'<a href="/?no_owner=1">{no_owner} device(s) have no owner</a>')

    attention_html = (
        f"<p>{' &middot; '.join(attention_parts)}</p>" if attention_parts else '<p class="muted">Nothing needs attention right now.</p>'
    )

    return f"""
<h2>Know Your Network</h2>
<p>{' &middot; '.join(count_parts)}</p>
{attention_html}
"""


# --- What Changed? --------------------------------------------------------

_SINCE_CHOICES: dict[str, timedelta | None] = {
    "24h": timedelta(days=1), "7d": timedelta(days=7), "30d": timedelta(days=30), "all": None,
}
_CHANGE_FILTER_PARAMS = ("since", "mac", "severity", "upto", "review", "trust", "category")
_REVIEW_FILTERS = {
    "": "Any", "attention": "Needs attention", "unreviewed": "Unreviewed", "investigating": "Investigating",
    "snoozed": "Snoozed", "reviewed": "Reviewed", "accepted": "Accepted",
}
#: Change types that mean a device *behaved* differently from its baseline -
#: the "changed behaviour" count on the dashboard.
_BEHAVIOUR_CHANGES = (
    "service_new", "service_removed", "mdns_service_new", "mdns_service_removed", "ssdp_service_new",
    "ssdp_service_removed", "identity_changed", "hostname_changed", "ipv6_prefix_new",
)
_SERVICE_CHANGES = (
    "service_new", "service_removed", "mdns_service_new", "mdns_service_removed", "ssdp_service_new",
    "ssdp_service_removed",
)
_MAX_LISTED_CHANGES = 500


def _sig_badge(level: str) -> str:
    return f'<span class="sig sig--{html.escape(level)}">{html.escape(level.upper())}</span>'


def _parse_change_filters(query: dict[str, list[str]]) -> dict[str, object]:
    filters: dict[str, object] = {name: query.get(name, [""])[0] for name in _CHANGE_FILTER_PARAMS}
    if filters["since"] not in _SINCE_CHOICES:
        filters["since"] = "7d"
    filters["types"] = [t for t in query.get("type", []) if t in CHANGE_TYPES]
    return filters


def _change_query_string(filters: dict[str, object]) -> str:
    parts = [f"{name}={quote(str(filters[name]))}" for name in _CHANGE_FILTER_PARAMS if filters.get(name)]
    parts += [f"type={quote(t)}" for t in filters.get("types", [])]
    return "&amp;".join(parts)


@dataclass(frozen=True)
class _DeviceSummary:
    label: str
    trusted: bool
    category: str


def _device_summaries(store: DeviceStore, allowlist: Allowlist) -> dict[str, _DeviceSummary]:
    """Label, trust and category for every device - cheap: category comes
    from each baseline's last-known identity (or the operator's override),
    not a fresh identity inference per device."""

    baselines = store.all_baselines()
    out = {}
    for device in build_inventory(store, allowlist):
        override = device.metadata.category_override if device.metadata else None
        baseline = baselines.get(device.mac)
        category = override or (baseline.identity_category if baseline else None) or "Unknown"
        out[device.mac] = _DeviceSummary(
            label=device.allowlist_name or device.hostname or device.mac, trusted=device.allowlisted,
            category=category,
        )
    return out


def _filter_changes(
    events: list[ChangeEvent], filters: dict[str, object], devices: dict[str, _DeviceSummary], *, now: datetime,
) -> list[ChangeEvent]:
    out = []
    for event in events:
        device = devices.get(event.mac) if event.mac else None
        if filters["severity"] and not significance_at_least(event.significance, str(filters["severity"])):
            continue
        if filters["upto"] and significance_at_least(event.significance, str(filters["upto"])) and (
            event.significance != filters["upto"]
        ):
            continue
        review = filters["review"]
        if review == "attention" and not event.needs_attention(now=now):
            continue
        if review and review != "attention" and event.review_state != review:
            continue
        if filters["trust"] in ("trusted", "untrusted"):
            if device is None or device.trusted != (filters["trust"] == "trusted"):
                continue
        if filters["category"] and (device is None or device.category != filters["category"]):
            continue
        out.append(event)
    return out


def _change_subject_label(event: ChangeEvent, devices: dict[str, _DeviceSummary]) -> str:
    if event.mac:
        device = devices.get(event.mac)
        return device.label if device else event.mac
    return event.subject_id or "Network"


def _render_changes_page(
    events: list[ChangeEvent], filters: dict[str, object], devices: dict[str, _DeviceSummary], *, now: datetime,
) -> str:
    def _option(value: str, current: object, label: str | None = None) -> str:
        selected = " selected" if value == current else ""
        return f'<option value="{html.escape(value)}"{selected}>{html.escape(label or value or "Any")}</option>'

    since_options = "".join(_option(v, filters["since"], {"24h": "Last 24 hours", "7d": "Last 7 days",
                                                          "30d": "Last 30 days", "all": "Everything kept"}[v])
                            for v in _SINCE_CHOICES)
    device_options = _option("", filters["mac"]) + "".join(
        _option(mac, filters["mac"], summary.label) for mac, summary in sorted(devices.items(), key=lambda kv: kv[1].label)
    )
    current_type = filters["types"][0] if len(filters["types"]) == 1 else ""
    type_options = _option("", current_type) + "".join(_option(t, current_type, t.replace("_", " ")) for t in CHANGE_TYPES)
    severity_options = _option("", filters["severity"]) + "".join(
        _option(s, filters["severity"], f"{s.upper()} and above") for s in SIGNIFICANCES
    )
    review_options = "".join(_option(k, filters["review"], v) for k, v in _REVIEW_FILTERS.items())
    trust_options = "".join(_option(v, filters["trust"], v or "Any") for v in ("", "trusted", "untrusted"))
    category_options = "".join(_option(v, filters["category"], v or "Any") for v in ("", *DEVICE_CATEGORIES))

    if not events:
        listing = '<p class="muted">Nothing changed that matches - LAN Fence stays quiet when nothing meaningful happens.</p>'
    else:
        listing = ""
        heading = None
        for event in events[:_MAX_LISTED_CHANGES]:
            day = day_heading(event.occurred_at, now=now)
            if day != heading:
                listing += ("</div>" if heading is not None else "") + f'<h2 style="margin-top:1rem">{html.escape(day)}</h2><div>'
                heading = day
            text = describe(event)
            state = [] if event.review_state == "unreviewed" else [event.review_state]
            if event.alerted_at:
                state.append("alert sent")
            if event.suppressed:
                state.append("excluded from alerting")
            muted = " muted-row" if event.suppressed or event.review_state in ("reviewed", "accepted") else ""
            listing += (
                f'<div class="change-row{muted}">'
                f'<div class="change-when">{html.escape(format_time(event.occurred_at))}</div>'
                f'<div><a href="/changes/{event.id}"><strong>{html.escape(_change_subject_label(event, devices))}</strong></a>'
                f'<br>{html.escape(text.title)}'
                + (f'<br><span class="change-state">{html.escape(", ".join(state))}</span>' if state else "")
                + f'</div><div>{_sig_badge(event.significance)}</div></div>'
            )
        listing += "</div>"
        if len(events) > _MAX_LISTED_CHANGES:
            listing += f'<p class="muted">Showing the latest {_MAX_LISTED_CHANGES} of {len(events)} - narrow the filters to see more.</p>'

    return f"""
<h1>What Changed?</h1>
<div class="panel">
<form class="stack" method="get" action="/changes" style="flex-direction:row;flex-wrap:wrap;gap:0.75rem;align-items:end;max-width:none">
<div><label for="since">When</label><select id="since" name="since">{since_options}</select></div>
<div><label for="mac">Device</label><select id="mac" name="mac">{device_options}</select></div>
<div><label for="type">Change</label><select id="type" name="type">{type_options}</select></div>
<div><label for="severity">Severity</label><select id="severity" name="severity">{severity_options}</select></div>
<div><label for="review">Review</label><select id="review" name="review">{review_options}</select></div>
<div><label for="trust">Trust</label><select id="trust" name="trust">{trust_options}</select></div>
<div><label for="category">Category</label><select id="category" name="category">{category_options}</select></div>
<button class="btn" type="submit">Filter</button>
<a class="btn btn--ghost" href="/changes">Clear</a>
</form>
</div>
<div class="panel">
{listing}
</div>
"""


def _risk_panel_html(assessment: RiskAssessment | None, *, title: str = "Risk") -> str:
    if assessment is None:
        return f"<h2>{html.escape(title)}</h2><p class=\"muted\">Not assessed yet - it's worked out on each scan or monitor sweep.</p>"
    rows = "".join(
        f"<li><strong>{c.points:+d}</strong>&nbsp; {html.escape(c.label)}</li>" for c in assessment.contributions
    ) or '<li class="muted">Nothing raises or lowers this device\'s risk.</li>'
    return f"""
<h2>{html.escape(title)}</h2>
<p><strong>{assessment.score} / 100</strong> {_sig_badge(assessment.level)}</p>
<details><summary>Why this risk?</summary><ul>{rows}</ul></details>
<p><strong>Recommended action:</strong> {html.escape(assessment.recommendation)}</p>
<p class="muted">A prioritisation aid, not a verdict - and separate from how sure LAN Fence is about what the device is.</p>
"""


def _render_change_detail(
    event: ChangeEvent,
    *,
    subject: str,
    risk: RiskAssessment | None,
    policy: Policy | None,
    now: datetime,
    message: str | None = None,
    error: str | None = None,
) -> str:
    text = describe(event)
    day = day_heading(event.occurred_at, now=now)
    when = f"{'today' if day == 'Today' else 'yesterday' if day == 'Yesterday' else day} at {format_time(event.occurred_at)}"
    details = "".join(f"<p>{html.escape(line)}</p>" for line in text.details)
    if event.change_type == "risk_changed":
        risk_block = ""
        contributions = event.current.get("contributions") or []
        if contributions:
            rows = "".join(f"<li><strong>{int(c['points']):+d}</strong>&nbsp; {html.escape(str(c['label']))}</li>"
                           for c in contributions)
            risk_block = f"<details open><summary>Why?</summary><ul>{rows}</ul></details>"
    else:
        risk_block = _risk_panel_html(risk, title="This device's risk now") if event.mac else ""
    if policy is not None and event.alerted_at:
        policy_line = (f"Alert sent {html.escape(format_datetime(event.alerted_at))} by policy "
                       f"<strong>{html.escape(policy.id)}</strong> ({html.escape(policy.description)}).")
    elif policy is not None:
        how = {"digest": "included in the digest", "none": "recorded only"}.get(policy.action, "no alert was needed")
        policy_line = f"Matched policy <strong>{html.escape(policy.id)}</strong> - {how}."
    elif event.policy_id:
        policy_line = f"Matched policy <strong>{html.escape(event.policy_id)}</strong> (no longer configured)."
    else:
        policy_line = "No alert policy matched - recorded for review only."
    technical_rows = "".join(
        f"<tr><td>{html.escape(key)}</td><td>{html.escape(str(event.previous.get(key, '-')))}</td>"
        f"<td>{html.escape(str(event.current.get(key, '-')))}</td></tr>"
        for key in sorted(set(event.previous) | set(event.current)) if key != "contributions"
    )
    evidence = "".join(f"<li>{html.escape(item)}</li>" for item in event.evidence)
    review = event.review_state + (
        f" until {format_datetime(event.snoozed_until)}" if event.review_state == "snoozed" and event.snoozed_until
        else ""
    )
    device_link = f' &middot; <a href="/device/{html.escape(event.mac)}">Device details</a>' if event.mac else ""
    note = html.escape(event.review_note or "")
    return f"""
<p><a href="/changes">&larr; What Changed?</a>{device_link}</p>
<h1>{html.escape(subject)}</h1>
{_flash(message)}
{_flash(error, error=True)}
<div class="panel">
<p class="muted">Something changed {html.escape(when)}.</p>
<h2>{html.escape(text.title)} {_sig_badge(event.significance)}</h2>
{details}
{'<p class="muted">This signal is excluded from alerting for this device; kept as history.</p>' if event.suppressed else ''}
<p>{policy_line}</p>
<details><summary>Technical detail</summary>
<table><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead><tbody>{technical_rows}</tbody></table>
<p class="muted">Observed by: {html.escape(event.source)}</p>
{f'<ul>{evidence}</ul>' if evidence else ''}
</details>
</div>
{f'<div class="panel">{risk_block}</div>' if risk_block else ''}
<div class="panel">
<h2>What now?</h2>
<p>Review: <strong>{html.escape(review)}</strong></p>
<form method="post" action="/changes/{event.id}" class="stack" style="max-width:none">
<div class="button-row">
<button class="btn" name="action" value="investigating" type="submit">Investigate</button>
<button class="btn" name="action" value="accepted" type="submit">Accept as expected</button>
<button class="btn btn--ghost" name="action" value="snooze_1d" type="submit">Snooze a day</button>
<button class="btn btn--ghost" name="action" value="snooze_7d" type="submit">Snooze a week</button>
<button class="btn btn--ghost" name="action" value="reviewed" type="submit">Mark reviewed</button>
{'<button class="btn btn--ghost" name="action" value="unreviewed" type="submit">Reopen</button>' if event.review_state != 'unreviewed' else ''}
</div>
<div>
<label for="note">Note</label>
<input type="text" id="note" name="note" value="{note}" maxlength="2000">
</div>
<div><button class="btn btn--ghost" name="action" value="note" type="submit">Save note</button></div>
</form>
<p class="muted">Accepting adds this to the device's expected baseline; the change itself stays in history.</p>
</div>
"""


def _flash(message: str | None, *, error: bool = False) -> str:
    if not message:
        return ""
    cls = "flash--error" if error else "flash--ok"
    return f'<div class="flash {cls}">{html.escape(message)}</div>'


def _render_login(*, error: str | None = None) -> str:
    return f"""
<div class="login-wrap panel">
<h1>Sign in</h1>
{_flash(error, error=True)}
<form class="stack" method="post" action="/login">
<div>
<label for="password">Password</label>
<input type="password" id="password" name="password" autofocus required>
</div>
<button class="btn" type="submit">Sign in</button>
</form>
</div>
"""


def _metadata_field_html(field: str, label: str, value: str | None) -> str:
    limit = METADATA_LIMITS[field]
    return f"""
<div>
<label for="{field}">{label} <span class="muted">(max {limit} chars)</span></label>
<input type="text" id="{field}" name="{field}" value="{html.escape(value or '')}" maxlength="{limit}">
</div>
"""


def _metadata_select_html(field: str, label: str, value: str | None, choices: tuple[str, ...]) -> str:
    """A fixed-choice metadata field (``asset_type``/``category_override`` -
    see :data:`lanfence.device_metadata.METADATA_CHOICES`) as a ``<select>``
    rather than free text, so the browser can only submit one of the
    allowed values. An empty first option clears the field."""

    options = ['<option value="">Not set</option>']
    for choice in choices:
        selected = " selected" if choice == value else ""
        options.append(f'<option value="{html.escape(choice)}"{selected}>{html.escape(choice)}</option>')
    return f"""
<div>
<label for="{field}">{label}</label>
<select id="{field}" name="{field}">{"".join(options)}</select>
</div>
"""


def _identity_evidence_html(dossier: DeviceDossier) -> str:
    """The "Why this identity?" disclosure - every rule that contributed to
    the current guess, positive or negative (see :mod:`lanfence.identity`).
    A plain ``<details>`` element rather than JavaScript - it works with no
    client-side script, matching this portal's stdlib-only design."""

    if not dossier.identity.evidence:
        return '<p class="muted">No supporting evidence.</p>'
    items = "".join(
        f"<li>{'+' if item.weight >= 0 else ''}{item.weight}&nbsp; {html.escape(item.label)}</li>"
        for item in dossier.identity.evidence
    )
    return f"""
<details>
<summary>Why this identity?</summary>
<ul>{items}</ul>
</details>
"""


def _identity_section_html(dossier: DeviceDossier) -> str:
    identity = dossier.identity
    metadata = dossier.device.metadata
    override = metadata.category_override if metadata else None
    hostname_line = f"<p>Hostname: {html.escape(dossier.device.hostname)}</p>" if dossier.device.hostname else ""
    # A category the operator set always wins for display, but is labelled
    # as theirs - the detected category stays visible beside it.
    if override:
        category_line = (
            f"<p>Category: <strong>{html.escape(override)}</strong> (assigned by you) &middot; "
            f"detected: {html.escape(identity.category)}</p>"
        )
    else:
        category_line = f"<p>Category: {html.escape(identity.category)} (detected)</p>"
    if not identity.is_known:
        return f"""
<h2>Identity (Know Your Network)</h2>
<p>Probable identity: <strong>{html.escape(identity.probable_identity)}</strong> (no supporting evidence)</p>
{category_line}
{hostname_line}
"""
    manufacturer_line = f"<p>Manufacturer: {html.escape(identity.manufacturer)}</p>" if identity.manufacturer else ""
    platform_line = f"<p>Platform: {html.escape(identity.platform)}</p>" if identity.platform else ""
    return f"""
<h2>Identity (Know Your Network)</h2>
<p>Probable identity: <strong>{html.escape(identity.probable_identity)}</strong></p>
{category_line}
<p>Identity confidence: {identity.confidence}%</p>
{manufacturer_line}
{platform_line}
{hostname_line}
{_identity_evidence_html(dossier)}
<p class="muted">A labelled inference from evidence LAN Fence has observed - not a verified fact.</p>
"""


def _network_section_html(dossier: DeviceDossier, *, offline_grace_seconds: float | None) -> str:
    """Everything LAN Fence has observed about where and when this device
    appears on the network - all retained evidence, nothing inferred."""

    # Imported here: lanfence.report imports this module at load time.
    from lanfence.report import _ADDRESS_SOURCE_LABELS, _NAME_SOURCE_LABELS, presence_label, review_status_label

    device = dossier.device
    trust = review_status_label(device, now=utcnow())
    address_items = "".join(
        f"<li><code>{html.escape(a.ip)}</code> <span class=\"muted\">({html.escape(_ADDRESS_SOURCE_LABELS.get(a.source, a.source))}"
        f"{', ' + html.escape(a.interface) if a.interface else ''}; "
        f"last seen {html.escape(format_datetime(a.last_seen))})</span></li>"
        for a in dossier.addresses
    ) or '<li class="muted">None retained</li>'
    name_items = "".join(
        f"<li>{html.escape(n.name)} <span class=\"muted\">({html.escape(_NAME_SOURCE_LABELS.get(n.source, n.source))}; "
        f"last seen {html.escape(format_datetime(n.last_seen))})</span></li>"
        for n in dossier.names
    ) or '<li class="muted">None observed</li>'
    services = dossier.observed_services_summary
    service_items = "".join(f"<li>{html.escape(s)}</li>" for s in services) or '<li class="muted">None advertised</li>'
    return f"""
<h2>Network</h2>
<p>MAC: <code>{html.escape(device.mac)}</code> &middot; Vendor: {html.escape(device.vendor or '[unknown]')}</p>
<p>Status: {_status_badge(device)} &middot; {html.escape(presence_label(device, default_offline_after_seconds=offline_grace_seconds))}
&middot; Trust: {html.escape(trust)}</p>
<p>First seen: {html.escape(format_datetime(device.first_seen))} &middot;
Last seen: {html.escape(format_datetime(device.last_seen))}</p>
<p>Addresses (IPv4/IPv6):</p>
<ul>{address_items}</ul>
<p>Hostnames:</p>
<ul>{name_items}</ul>
<p>Advertised services (the device's own claims):</p>
<ul>{service_items}</ul>
"""


def _security_section_html(dossier: DeviceDossier) -> str:
    """Security signals only - kept apart from identity confidence, which
    says how sure LAN Fence is of what a device is, not whether it's safe."""

    device = dossier.device
    matches = "".join(
        f"<li><strong>{html.escape(m.severity)}</strong>: {html.escape(m.title)}</li>"
        for m in dossier.fingerprint_matches
    ) or '<li class="muted">No rogue-device signatures matched</li>'
    investigation = ""
    if device.review_state == "investigating":
        notes = f": {html.escape(device.review_notes)}" if device.review_notes else ""
        investigation = f"<p>Flagged for investigation{notes}</p>"
    return f"""
<h2>Security</h2>
{investigation}
<ul>{matches}</ul>
<p class="muted">Identity confidence and security risk are separate: a well-identified device can
still be a risk, and an unidentified one can be perfectly safe.</p>
"""


@dataclass(frozen=True)
class _ChangeContext:
    """Know When It Changes data for one device's page."""

    risk: RiskAssessment | None
    baseline: object | None
    maturity: str
    items: list
    recent: list[ChangeEvent]


def _changes_section_html(mac: str, ctx: _ChangeContext, *, now: datetime) -> str:
    rows = "".join(
        f'<div class="change-row"><div class="change-when">{html.escape(format_time(e.occurred_at))}</div>'
        f'<div><a href="/changes/{e.id}">{html.escape(describe(e).title)}</a>'
        f'<br><span class="change-state">{html.escape(day_heading(e.occurred_at, now=now))}'
        f'{"" if e.review_state == "unreviewed" else " &middot; " + html.escape(e.review_state)}</span></div>'
        f"<div>{_sig_badge(e.significance)}</div></div>"
        for e in ctx.recent
    ) or '<p class="muted">No changes recorded for this device.</p>'
    return f"""
<h2>Changes</h2>
{rows}
<p><a href="/changes?mac={quote(mac)}&amp;since=all">All changes for this device &rarr;</a></p>
"""


def _services_section_html(ctx: _ChangeContext) -> str:
    services = [i for i in ctx.items if i.signal in ("port", "mdns", "ssdp")]
    if not services:
        return ('<h2>Services</h2><p class="muted">None observed yet. Advertised services are learned passively; '
                "open ports only appear after an explicit <code>lanfence inspect</code>.</p>")
    event_by_item = {(e.signal, e.subject): e for e in reversed(ctx.recent) if e.signal}

    def _state(item) -> str:
        if not item.present:
            return "No longer seen"
        if not item.in_baseline:
            event = event_by_item.get((item.signal, item.value))
            link = f' - <a href="/changes/{event.id}">review</a>' if event else ""
            return f"<strong>New</strong> - pending review{link}"
        return "Accepted by you" if item.origin == "accepted" else "Expected"

    order = {False: 0, True: 1}
    rows = "".join(
        f"<tr><td>{html.escape(service_label(i.signal, i.value))}</td><td>{_state(i)}</td></tr>"
        for i in sorted(services, key=lambda i: (order[i.in_baseline and i.present], service_label(i.signal, i.value)))
    )
    return f"""
<h2>Services</h2>
<table><thead><tr><th>Service</th><th>State</th></tr></thead><tbody>{rows}</tbody></table>
"""


def _baseline_section_html(mac: str, ctx: _ChangeContext) -> str:
    baseline = ctx.baseline
    if baseline is None:
        return '<h2>Baseline</h2><p class="muted">Not started yet - it begins on the next scan or monitor sweep.</p>'
    explain = {
        "learning": "Still learning what's normal. Ordinary new services are added quietly; remote-administration "
                    "services always wait for your approval.",
        "established": "Established - anything new is flagged for you to accept or investigate. Time alone never "
                       "makes a change trusted.",
        "stale": "Stale - this device hasn't been seen for a long time. Its baseline is kept for when it returns.",
    }.get(ctx.maturity, "")
    established = (f"<br>Established {html.escape(format_datetime(baseline.established_at))}"
                   if baseline.established_at else "")
    pending = sum(1 for i in ctx.items if not i.in_baseline and i.present)
    checkboxes = "".join(
        f'<label style="display:inline-block;margin-right:1rem"><input type="checkbox" name="exclude_{s}" value="1"'
        f'{" checked" if s in baseline.excluded_signals else ""}> {html.escape(s)}</label>'
        for s in EXCLUDABLE_SIGNALS
    )
    accept_button = (
        f'<button class="btn" name="action" value="accept_pending" type="submit">Accept all {pending} pending</button>'
        if pending else ""
    )
    return f"""
<h2>Baseline</h2>
<p><strong>{html.escape(ctx.maturity.capitalize())}</strong> - learning since
{html.escape(format_datetime(baseline.started_at))}{established}</p>
<p class="muted">{html.escape(explain)}</p>
<details><summary>Manage baseline</summary>
<form method="post" action="/device/{html.escape(mac)}" class="stack" style="max-width:none">
<div class="button-row">{accept_button}
<button class="btn btn--danger" name="action" value="baseline_reset" type="submit"
  onclick="return confirm('Forget what is normal for this device and learn it again? Its change history is kept.');">Reset and relearn</button>
</div>
</form>
<form method="post" action="/device/{html.escape(mac)}" class="stack" style="max-width:none;margin-top:1rem">
<input type="hidden" name="action" value="baseline_exclude">
<div><label>Don't alert on changes to (still kept as history):</label>{checkboxes}</div>
<div><button class="btn btn--ghost" type="submit">Save</button></div>
</form>
</details>
"""


def _render_device_detail(
    dossier: DeviceDossier, *, message: str | None = None, error: str | None = None,
    offline_grace_seconds: float | None = None, changes: _ChangeContext | None = None,
    now: datetime | None = None,
) -> str:
    device = dossier.device
    metadata = device.metadata
    trust_section = ""
    if device.allowlisted:
        trust_section = f"""
<h2>Name</h2>
<form class="stack" method="post" action="/device/{html.escape(device.mac)}">
<input type="hidden" name="action" value="rename">
<div>
<label for="name">Trusted name</label>
<input type="text" id="name" name="name" value="{html.escape(device.allowlist_name or '')}" maxlength="128" required>
</div>
<button class="btn" type="submit">Save name</button>
</form>
<form method="post" action="/device/{html.escape(device.mac)}" style="margin-top:0.9rem"
      onsubmit="return confirm('Remove this device from the allowlist? Its findings will be treated as untrusted again.');">
<input type="hidden" name="action" value="untrust">
<button class="btn btn--danger" type="submit">Untrust this device</button>
</form>
"""
    else:
        trust_section = f"""
<h2>Trust this device</h2>
<p class="muted">Not on the allowlist yet - its findings are still treated as untrusted.
Trusting it here is the same action as <code>lanfence allow</code>.</p>
<form class="stack" method="post" action="/device/{html.escape(device.mac)}">
<input type="hidden" name="action" value="trust">
<div>
<label for="name">Name</label>
<input type="text" id="name" name="name" value="{html.escape(device.hostname or '')}" maxlength="128" required>
</div>
<button class="btn" type="submit">Trust &amp; name this device</button>
</form>
"""

    def _value(field: str) -> str | None:
        return getattr(metadata, field) if metadata else None

    metadata_fields = "".join(
        _metadata_field_html(field, label, _value(field))
        for field, label in (
            ("owner", "Owner"), ("location", "Location"), ("purpose", "Purpose"), ("notes", "Notes"),
        )
    )
    metadata_fields += _metadata_select_html("asset_type", "Asset type", _value("asset_type"), ASSET_TYPES)
    metadata_fields += _metadata_select_html(
        "category_override", "Category (override)", _value("category_override"), DEVICE_CATEGORIES
    )

    change_sections = ""
    if changes is not None:
        now = now or utcnow()
        change_sections = "".join(
            f'<div class="panel">{section}</div>' for section in (
                _risk_panel_html(changes.risk),
                _changes_section_html(device.mac, changes, now=now),
                _services_section_html(changes),
                _baseline_section_html(device.mac, changes),
            )
        )

    body = f"""
<p><a href="/">&larr; All devices</a></p>
<h1>{html.escape(dossier.label)}</h1>
{_flash(message)}
{_flash(error, error=True)}
<div class="panel">
<p>
<code>{html.escape(device.mac)}</code> &middot;
{html.escape(_ip_display(device))} &middot;
{html.escape(device.vendor or '[unknown]')} &middot;
{_status_badge(device)} {_trust_badge(device)}
</p>
</div>
<div class="panel">
{_identity_section_html(dossier)}
</div>
{change_sections}
<div class="panel">
{trust_section}
</div>
<div class="panel">
<h2>Ownership</h2>
<form class="stack" method="post" action="/device/{html.escape(device.mac)}">
<input type="hidden" name="action" value="metadata">
{metadata_fields}
<button class="btn" type="submit">Save details</button>
</form>
</div>
<div class="panel">
{_network_section_html(dossier, offline_grace_seconds=offline_grace_seconds)}
</div>
<div class="panel">
{_security_section_html(dossier)}
</div>
"""
    return body


# --- HTTP handler ----------------------------------------------------------


@dataclass
class _WebContext:
    cfg: Config
    sessions: _SessionStore
    throttle: _LoginThrottle


def _make_handler(context: _WebContext) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "LANFence/1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
            log.info("%s - %s", self.address_string(), format % args)

        # --- plumbing --------------------------------------------------

        def _cookie_token(self) -> str | None:
            raw = self.headers.get("Cookie")
            if not raw:
                return None
            jar: http.cookies.SimpleCookie = http.cookies.SimpleCookie()
            jar.load(raw)
            morsel = jar.get(_SESSION_COOKIE)
            return morsel.value if morsel else None

        def _authed(self) -> bool:
            return context.sessions.valid(self._cookie_token())

        def _read_form(self) -> dict[str, str]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length else b""
            # Blank fields are kept so a deliberately emptied input ("clear
            # this") stays distinguishable from a field the form never sent.
            parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
            return {key: values[0] for key, values in parsed.items() if values}

        def _send(self, status: HTTPStatus, body: bytes, *, headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _redirect(self, location: str, *, set_cookie: str | None = None, clear_cookie: bool = False) -> None:
            headers = {"Location": location}
            if set_cookie is not None:
                headers["Set-Cookie"] = (
                    f"{_SESSION_COOKIE}={set_cookie}; Path=/; HttpOnly; SameSite=Strict"
                )
            elif clear_cookie:
                headers["Set-Cookie"] = f"{_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            self.send_response(HTTPStatus.SEE_OTHER)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _require_auth(self) -> bool:
            if self._authed():
                return True
            self._redirect("/login")
            return False

        # --- routes ------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 - stdlib method name
            path = urlsplit(self.path).path
            if path == "/login":
                if self._authed():
                    self._redirect("/")
                    return
                self._send(HTTPStatus.OK, _page(title="Sign in", body=_render_login(), authed=False))
                return
            if not self._require_auth():
                return
            if path == "/":
                self._handle_index()
                return
            if path.startswith("/device/"):
                self._handle_device_get(path[len("/device/"):])
                return
            if path == "/changes":
                self._handle_changes()
                return
            if path.startswith("/changes/"):
                self._handle_change_get(path[len("/changes/"):])
                return
            self._send(HTTPStatus.NOT_FOUND, _page(title="Not found", body="<h1>Not found</h1>", authed=True))

        def do_POST(self) -> None:  # noqa: N802 - stdlib method name
            path = urlsplit(self.path).path
            if path == "/login":
                self._handle_login()
                return
            if path == "/logout":
                context.sessions.revoke(self._cookie_token())
                self._redirect("/login", clear_cookie=True)
                return
            if not self._require_auth():
                return
            if path.startswith("/device/"):
                self._handle_device_post(path[len("/device/"):])
                return
            if path.startswith("/changes/"):
                self._handle_change_post(path[len("/changes/"):])
                return
            self._send(HTTPStatus.NOT_FOUND, _page(title="Not found", body="<h1>Not found</h1>", authed=True))

        # --- handlers ------------------------------------------------------

        def _not_found(self) -> None:
            self._send(HTTPStatus.NOT_FOUND, _page(title="Not found", body="<h1>Not found</h1>", authed=True))

        def _load_allowlist(self) -> Allowlist:
            allowlist = Allowlist.load(context.cfg.resolved_allowlist_file())
            apply_self_trust(allowlist, interface=context.cfg.scan.interfaces or context.cfg.scan.interface)
            return allowlist

        def _handle_changes(self) -> None:
            filters = _parse_change_filters(parse_qs(urlsplit(self.path).query))
            now = utcnow()
            window = _SINCE_CHOICES[str(filters["since"])]
            mac = None
            if filters["mac"]:
                try:
                    mac = normalize_mac(str(filters["mac"]))
                except ValueError:
                    filters["mac"] = ""
            with DeviceStore(context.cfg.resolved_db_path()) as store:
                devices = _device_summaries(store, self._load_allowlist())
                events = store.change_events(
                    since=now - window if window else None, mac=mac, change_types=filters["types"] or None,
                )
            events = _filter_changes(events, filters, devices, now=now)
            self._send(
                HTTPStatus.OK,
                _page(title="What Changed?", body=_render_changes_page(events, filters, devices, now=now), authed=True),
            )

        def _render_change(self, event_id: int, *, message: str | None = None, error: str | None = None) -> None:
            now = utcnow()
            cfg = context.cfg
            with DeviceStore(cfg.resolved_db_path()) as store:
                event = store.get_change_event(event_id)
                if event is None:
                    self._not_found()
                    return
                allowlist = self._load_allowlist()
                devices = _device_summaries(store, allowlist)
                risk = assess_device(
                    store, allowlist, cfg, event.mac, signatures=SignatureSet.load(cfg.rogue_signatures_file),
                    identity_rules=IdentityRuleSet.load(cfg.identity_rules_file), now=now,
                ) if event.mac else None
            policy = next((p for p in effective_policies(cfg.policies) if p.id == event.policy_id), None)
            body = _render_change_detail(
                event, subject=_change_subject_label(event, devices), risk=risk, policy=policy, now=now,
                message=message, error=error,
            )
            self._send(HTTPStatus.OK, _page(title="What Changed?", body=body, authed=True))

        def _handle_change_get(self, raw_id: str) -> None:
            if not raw_id.isdigit():
                self._not_found()
                return
            self._render_change(int(raw_id))

        def _handle_change_post(self, raw_id: str) -> None:
            if not raw_id.isdigit():
                self._not_found()
                return
            event_id = int(raw_id)
            form = self._read_form()
            action = form.get("action", "")
            note = form.get("note")
            actions = {
                "investigating": ("investigating", None), "accepted": ("accepted", None),
                "reviewed": ("reviewed", None), "unreviewed": ("unreviewed", None), "note": ("note", None),
                "snooze_1d": ("snoozed", timedelta(days=1)), "snooze_7d": ("snoozed", timedelta(days=7)),
            }
            if action not in actions:
                self._render_change(event_id, error="Unknown action.")
                return
            review_action, snooze_for = actions[action]
            cfg = context.cfg
            now = utcnow()
            with DeviceStore(cfg.resolved_db_path()) as store:
                updated = review_change(
                    store, event_id, review_action, now=now, note=note.strip() if note is not None else None,
                    snooze_for=snooze_for,
                )
                if updated is None:
                    self._not_found()
                    return
                if updated.mac:
                    reassess_device(
                        store, self._load_allowlist(), cfg, updated.mac,
                        signatures=SignatureSet.load(cfg.rogue_signatures_file),
                        identity_rules=IdentityRuleSet.load(cfg.identity_rules_file), now=now,
                    )
            messages = {
                "investigating": "Marked for investigation.", "accepted": "Accepted as expected - the baseline is updated.",
                "reviewed": "Marked reviewed.", "unreviewed": "Reopened.", "note": "Note saved.",
                "snooze_1d": "Snoozed for a day.", "snooze_7d": "Snoozed for a week.",
            }
            self._render_change(event_id, message=messages[action])

        def _handle_index(self) -> None:
            query = parse_qs(urlsplit(self.path).query)
            sort = query.get("sort", [_DEFAULT_SORT])[0]
            direction = query.get("dir", ["asc"])[0]
            filters = _parse_filters(query)
            now = utcnow()
            signatures = SignatureSet.load(context.cfg.rogue_signatures_file)
            identity_rules = IdentityRuleSet.load(context.cfg.identity_rules_file)
            with DeviceStore(context.cfg.resolved_db_path()) as store:
                allowlist = Allowlist.load(context.cfg.resolved_allowlist_file())
                apply_self_trust(allowlist, interface=context.cfg.scan.interfaces or context.cfg.scan.interface)
                inventory = build_inventory(store, allowlist)
                dossiers = [
                    build_device_dossier(
                        store, allowlist, d.mac, signatures=signatures, identity_rules=identity_rules,
                        vendor_file=context.cfg.vendor_file, now=now, device=d,
                    )
                    for d in inventory
                ]
            filtered = _filter_dossiers(dossiers, filters, now=now)
            extra_query = _filters_query_string(filters)
            body = f"""
<h1>Devices</h1>
<div class="panel">
{_render_network_overview(dossiers, now=now)}
</div>
<div class="panel">
{_render_filter_form(filters, sort=sort, direction=direction)}
</div>
{_render_device_list(filtered, sort=sort, direction=direction, has_any_devices=bool(dossiers), extra_query=extra_query)}
"""
            self._send(HTTPStatus.OK, _page(title="Devices", body=body, authed=True))

        def _load_dossier(self, store: DeviceStore, allowlist: Allowlist, mac: str) -> DeviceDossier | None:
            return build_device_dossier(
                store, allowlist, mac,
                signatures=SignatureSet.load(context.cfg.rogue_signatures_file),
                identity_rules=IdentityRuleSet.load(context.cfg.identity_rules_file),
                vendor_file=context.cfg.vendor_file,
            )

        def _send_device_page(self, mac: str, *, message: str | None = None, error: str | None = None) -> None:
            cfg = context.cfg
            now = utcnow()
            with DeviceStore(cfg.resolved_db_path()) as store:
                allowlist = self._load_allowlist()
                dossier = self._load_dossier(store, allowlist, mac)
                if dossier is None:
                    self._not_found()
                    return
                baseline = store.get_baseline(mac)
                changes = _ChangeContext(
                    risk=assess_device(
                        store, allowlist, cfg, mac, signatures=SignatureSet.load(cfg.rogue_signatures_file),
                        identity_rules=IdentityRuleSet.load(cfg.identity_rules_file), now=now,
                    ),
                    baseline=baseline,
                    maturity=maturity(baseline, last_seen=dossier.device.last_seen, now=now,
                                      stale_days=cfg.changes.stale_days),
                    items=store.baseline_items(mac),
                    recent=store.change_events(mac=mac, limit=8),
                )
            self._send(
                HTTPStatus.OK,
                _page(
                    title=dossier.device.allowlist_name or mac,
                    body=_render_device_detail(
                        dossier, message=message, error=error, offline_grace_seconds=cfg.scan.offline_grace_seconds,
                        changes=changes, now=now,
                    ),
                    authed=True,
                ),
            )

        def _handle_device_get(self, raw_mac: str) -> None:
            try:
                mac = normalize_mac(raw_mac)
            except ValueError:
                self._not_found()
                return
            self._send_device_page(mac)

        def _handle_device_post(self, raw_mac: str) -> None:
            try:
                mac = normalize_mac(raw_mac)
            except ValueError:
                self._send(HTTPStatus.NOT_FOUND, _page(title="Not found", body="<h1>Not found</h1>", authed=True))
                return
            form = self._read_form()
            action = form.get("action", "")

            allowlist = Allowlist.load(context.cfg.resolved_allowlist_file())
            message: str | None = None
            error: str | None = None

            if action in ("trust", "rename"):
                name = form.get("name", "").strip()
                if not name:
                    error = "Name must not be empty."
                else:
                    existing = allowlist.match(mac)
                    allowlist.add(mac, name, existing.notes if existing else "")
                    allowlist.save()
                    message = "Device trusted." if action == "trust" else "Name updated."
            elif action == "untrust":
                entry = allowlist.remove(mac)
                if entry is None:
                    error = "This device is not on the allowlist."
                else:
                    allowlist.save()
                    message = "Device untrusted - its findings are treated as untrusted again."
            elif action == "metadata":
                updates: dict[str, str | None] = {}
                try:
                    for field in (
                        "owner", "location", "asset_type", "category_override", "purpose", "notes",
                    ):
                        if field not in form:
                            continue  # e.g. a page loaded before this field existed - leave it alone
                        raw_value = form[field].strip()
                        updates[field] = validate_metadata_value(field, raw_value) if raw_value else None
                    with DeviceStore(context.cfg.resolved_db_path()) as store:
                        if store.get_device(mac) is None:
                            error = "No such device."
                        else:
                            store.update_device_metadata(mac, updated_at=utcnow(), **updates)
                            message = "Details saved."
                except ValueError as exc:
                    error = str(exc)
            elif action in ("baseline_reset", "accept_pending", "baseline_exclude"):
                now = utcnow()
                with DeviceStore(context.cfg.resolved_db_path()) as store:
                    if store.get_device(mac) is None:
                        error = "No such device."
                    elif action == "baseline_reset":
                        reset_baseline(store, mac, now=now)
                        message = "Baseline reset - it will be learned again from the next sweep."
                    elif action == "accept_pending":
                        count = accept_pending(store, mac, now=now)
                        message = f"Accepted {count} pending item(s) into the baseline."
                    else:
                        chosen = [s for s in EXCLUDABLE_SIGNALS if form.get(f"exclude_{s}")]
                        if set_excluded_signals(store, mac, chosen, now=now) is None:
                            error = "No baseline yet - it starts on the next scan or monitor sweep."
                        else:
                            message = "Saved."
                    if error is None and action != "baseline_exclude":
                        cfg = context.cfg
                        reassess_device(
                            store, self._load_allowlist(), cfg, mac,
                            signatures=SignatureSet.load(cfg.rogue_signatures_file),
                            identity_rules=IdentityRuleSet.load(cfg.identity_rules_file), now=now,
                        )
            else:
                error = "Unknown action."

            self._send_device_page(mac, message=message, error=error)

        def _handle_login(self) -> None:
            source = self.client_address[0]
            if context.throttle.locked_out(source):
                self._send(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    _page(
                        title="Sign in",
                        body=_render_login(error="Too many failed attempts - try again in a minute."),
                        authed=False,
                    ),
                )
                return
            form = self._read_form()
            password = form.get("password", "")
            password_hash, password_salt = context.cfg.web.password_hash, context.cfg.web.password_salt
            if password_hash and password_salt and verify_password(password, password_hash, password_salt):
                context.throttle.clear(source)
                token = context.sessions.create()
                self._redirect("/", set_cookie=token)
                return
            context.throttle.record_failure(source)
            self._send(
                HTTPStatus.UNAUTHORIZED,
                _page(title="Sign in", body=_render_login(error="Incorrect password."), authed=False),
            )

    return Handler


class _ThreadingHTTPServerV6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def run_server(cfg: Config, *, host: str | list[str], port: int | None = None, tls: bool = True) -> None:
    """Run the web portal in the foreground until interrupted (SIGINT/SIGTERM).

    ``host`` (one address, or several - one listening socket each, sharing
    sessions) is taken as given - callers needing the LAN-only bind policy
    enforced should call :func:`resolve_bind_hosts` themselves first (kept
    separate so this function stays testable against ``127.0.0.1``).
    Writes/removes the pidfile (:data:`_PID_FILE`) around the run so
    :func:`stop_server`/:func:`is_server_running` can find it.

    ``tls`` defaults to (and in real use is always) ``True`` - see the
    module docstring for why there is no supported insecure mode.
    Disabling it is for this module's own test suite only, to exercise the
    HTTP handler logic without a real TLS handshake in the loop; every
    actual entry point (`lanfence web`) calls this with the default.
    """

    hosts = [host] if isinstance(host, str) else list(host)
    bind_port = port if port is not None else cfg.web.port
    context = _WebContext(cfg=cfg, sessions=_SessionStore(), throttle=_LoginThrottle())
    handler = _make_handler(context)
    servers = []
    for index, address in enumerate(hosts):
        server_class = _ThreadingHTTPServerV6 if ":" in address else ThreadingHTTPServer
        try:
            servers.append(server_class((address, bind_port), handler))
        except OSError as exc:
            if index == 0:
                raise  # the primary LAN address is required
            log.warning("could not also bind the web portal to %s: %s", address, exc)
            hosts = [h for h in hosts if h != address]
    if tls:
        cert_path, key_path = ensure_self_signed_cert(hosts)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        for httpd in servers:
            httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
    _write_pid_file()
    for httpd in servers:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

    stop_event = threading.Event()

    def _handle_signal(_signum: int, _frame: object) -> None:
        stop_event.set()

    previous_term = signal.signal(signal.SIGTERM, _handle_signal)
    previous_int = signal.signal(signal.SIGINT, _handle_signal)
    try:
        stop_event.wait()
    finally:
        for httpd in servers:
            httpd.shutdown()
            httpd.server_close()
        _remove_pid_file()
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
