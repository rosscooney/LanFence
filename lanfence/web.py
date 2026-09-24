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
from lanfence.config import Config, expand_operator_path
from lanfence.db import DeviceStore
from lanfence.device_metadata import METADATA_LIMITS, validate_metadata_value
from lanfence.dossier import DeviceDossier, build_device_dossier
from lanfence.engine import apply_self_trust, build_inventory, is_review_needed
from lanfence.fingerprint import SignatureSet
from lanfence.identity import IdentityRuleSet
from lanfence.logging_config import get_logger
from lanfence.models import ASSET_TYPES, DEVICE_CATEGORIES, Device, utcnow
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


def ensure_self_signed_cert(host: str) -> tuple[Path, Path]:
    """A self-signed cert+key for ``host``, generating one with ``openssl``
    if none exists yet (or the existing one was issued for a different
    address - see above). Returns ``(cert_path, key_path)``.

    Raises :class:`WebError` if the ``openssl`` CLI isn't available or
    generation fails - there is no fallback to plain HTTP.
    """

    cert_path = _resolved_cert_file()
    key_path = _resolved_key_file()
    host_path = _resolved_cert_host_file()

    if cert_path.is_file() and key_path.is_file():
        try:
            cached_host = host_path.read_text(encoding="utf-8").strip()
        except OSError:
            cached_host = None
        if cached_host == host:
            return cert_path, key_path

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "825", "-nodes",
                "-subj", f"/CN={host}",
                "-addext", f"subjectAltName=IP:{host}",
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
    host_path.write_text(host, encoding="utf-8")
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


def start_background(config_path: Path) -> str:
    """Spawn `lanfence web` as a detached background process for immediate
    use right after `lanfence setup` enables it - convenience only. Not a
    substitute for the packaged systemd unit
    (``packaging/lanfence-web.service``) if you want the portal to survive
    a reboot or restart automatically after a crash; see README.

    Returns the URL it should be reachable at. Raises :class:`WebError` if
    the portal isn't actually ready to start (not enabled, no password) or
    no private LAN address can be confirmed.
    """

    cfg = Config.load(config_path)
    if not cfg.web.enabled:
        raise WebError("the web portal is not enabled")
    if cfg.web.password_hash is None:
        raise WebError("no web portal password is set")
    host = resolve_bind_host()

    log_path = _resolved_log_file()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "ab") as log_file:
        subprocess.Popen(
            [sys.executable, "-m", "lanfence.cli", "web", "--config", str(config_path)],
            stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    return f"https://{host}:{cfg.web.port}/"


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
footer.site a:hover { color: var(--text); }
"""


def _page(*, title: str, body: str, authed: bool) -> bytes:
    nav = (
        '<form method="post" action="/logout" style="margin:0">'
        '<button class="btn btn--ghost" type="submit">Log out</button></form>'
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
    "trust", "status", "category", "asset_type", "owner", "unknown", "review", "q",
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
    uncertain_identity = sum(1 for d in dossiers if d.identity.is_known and d.identity.confidence < 50)
    no_owner = sum(1 for d in dossiers if not _dossier_owner(d))

    attention_parts = []
    if needs_review:
        attention_parts.append(f'<a href="/?review=1">{needs_review} device(s) need review</a>')
    if unknown_identity:
        attention_parts.append(f'<a href="/?unknown=1">{unknown_identity} device(s) have unknown identities</a>')
    if uncertain_identity:
        attention_parts.append(f"{uncertain_identity} device(s) have uncertain identities")
    if no_owner:
        attention_parts.append(f"{no_owner} device(s) have no owner")

    attention_html = (
        f"<p>{' &middot; '.join(attention_parts)}</p>" if attention_parts else '<p class="muted">Nothing needs attention right now.</p>'
    )

    return f"""
<h2>Know Your Network</h2>
<p>{' &middot; '.join(count_parts)}</p>
{attention_html}
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
    if not identity.is_known:
        return f"""
<h2>Identity (Know Your Network)</h2>
<p>Probable identity: <strong>{html.escape(identity.probable_identity)}</strong> (no supporting evidence)</p>
"""
    manufacturer_line = f"<p>Manufacturer: {html.escape(identity.manufacturer)}</p>" if identity.manufacturer else ""
    platform_line = f"<p>Platform: {html.escape(identity.platform)}</p>" if identity.platform else ""
    return f"""
<h2>Identity (Know Your Network)</h2>
<p>Probable identity: <strong>{html.escape(identity.probable_identity)}</strong></p>
<p>Category: {html.escape(identity.category)}</p>
<p>Confidence: {identity.confidence}%</p>
{manufacturer_line}
{platform_line}
{_identity_evidence_html(dossier)}
<p class="muted">A labelled inference from evidence LAN Fence has observed - not a verified fact.</p>
"""


def _render_device_detail(dossier: DeviceDossier, *, message: str | None = None, error: str | None = None) -> str:
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
            ("friendly_name", "Friendly name"), ("owner", "Owner"), ("location", "Location"),
            ("purpose", "Purpose"), ("notes", "Notes"),
        )
    )
    metadata_fields += _metadata_select_html("asset_type", "Asset type", _value("asset_type"), ASSET_TYPES)
    metadata_fields += _metadata_select_html(
        "category_override", "Category (override)", _value("category_override"), DEVICE_CATEGORIES
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
<div class="panel">
{trust_section}
</div>
<div class="panel">
<h2>Inventory details</h2>
<form class="stack" method="post" action="/device/{html.escape(device.mac)}">
<input type="hidden" name="action" value="metadata">
{metadata_fields}
<button class="btn" type="submit">Save details</button>
</form>
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
            parsed = parse_qs(body.decode("utf-8", errors="replace"))
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
            self._send(HTTPStatus.NOT_FOUND, _page(title="Not found", body="<h1>Not found</h1>", authed=True))

        # --- handlers ------------------------------------------------------

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
                apply_self_trust(allowlist, interface=context.cfg.scan.interface)
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

        def _handle_device_get(self, raw_mac: str) -> None:
            try:
                mac = normalize_mac(raw_mac)
            except ValueError:
                self._send(HTTPStatus.NOT_FOUND, _page(title="Not found", body="<h1>Not found</h1>", authed=True))
                return
            with DeviceStore(context.cfg.resolved_db_path()) as store:
                allowlist = Allowlist.load(context.cfg.resolved_allowlist_file())
                apply_self_trust(allowlist, interface=context.cfg.scan.interface)
                dossier = self._load_dossier(store, allowlist, mac)
            if dossier is None:
                self._send(HTTPStatus.NOT_FOUND, _page(title="Not found", body="<h1>Not found</h1>", authed=True))
                return
            self._send(
                HTTPStatus.OK,
                _page(title=dossier.device.allowlist_name or mac, body=_render_device_detail(dossier), authed=True),
            )

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
                        "friendly_name", "owner", "location", "asset_type", "category_override",
                        "purpose", "notes",
                    ):
                        raw_value = form.get(field, "").strip()
                        updates[field] = validate_metadata_value(field, raw_value) if raw_value else None
                    with DeviceStore(context.cfg.resolved_db_path()) as store:
                        if store.get_device(mac) is None:
                            error = "No such device."
                        else:
                            store.update_device_metadata(mac, updated_at=utcnow(), **updates)
                            message = "Details saved."
                except ValueError as exc:
                    error = str(exc)
            else:
                error = "Unknown action."

            with DeviceStore(context.cfg.resolved_db_path()) as store:
                allowlist = Allowlist.load(context.cfg.resolved_allowlist_file())
                apply_self_trust(allowlist, interface=context.cfg.scan.interface)
                dossier = self._load_dossier(store, allowlist, mac)
            if dossier is None:
                self._send(HTTPStatus.NOT_FOUND, _page(title="Not found", body="<h1>Not found</h1>", authed=True))
                return
            self._send(
                HTTPStatus.OK,
                _page(
                    title=dossier.device.allowlist_name or mac,
                    body=_render_device_detail(dossier, message=message, error=error),
                    authed=True,
                ),
            )

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


def run_server(cfg: Config, *, host: str, port: int | None = None, tls: bool = True) -> None:
    """Run the web portal in the foreground until interrupted (SIGINT/SIGTERM).

    ``host`` is taken as given - callers needing the LAN-only bind policy
    enforced should call :func:`resolve_bind_host` themselves first (kept
    separate so this function stays testable against ``127.0.0.1``).
    Writes/removes the pidfile (:data:`_PID_FILE`) around the run so
    :func:`stop_server`/:func:`is_server_running` can find it.

    ``tls`` defaults to (and in real use is always) ``True`` - see the
    module docstring for why there is no supported insecure mode.
    Disabling it is for this module's own test suite only, to exercise the
    HTTP handler logic without a real TLS handshake in the loop; every
    actual entry point (`lanfence web`) calls this with the default.
    """

    context = _WebContext(cfg=cfg, sessions=_SessionStore(), throttle=_LoginThrottle())
    httpd = ThreadingHTTPServer((host, port if port is not None else cfg.web.port), _make_handler(context))
    if tls:
        cert_path, key_path = ensure_self_signed_cert(host)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
    _write_pid_file()
    serve_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    serve_thread.start()

    stop_event = threading.Event()

    def _handle_signal(_signum: int, _frame: object) -> None:
        stop_event.set()

    previous_term = signal.signal(signal.SIGTERM, _handle_signal)
    previous_int = signal.signal(signal.SIGINT, _handle_signal)
    try:
        stop_event.wait()
    finally:
        httpd.shutdown()
        httpd.server_close()
        _remove_pid_file()
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
