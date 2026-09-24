# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import http.client
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest

from lanfence import web
from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.dossier import DeviceDossier
from lanfence.models import Device


# --- password hashing ----------------------------------------------------


def test_hash_and_verify_password_roundtrip():
    password_hash, password_salt = web.hash_password("correct horse battery staple")
    assert web.verify_password("correct horse battery staple", password_hash, password_salt)


def test_verify_password_rejects_wrong_password():
    password_hash, password_salt = web.hash_password("correct horse battery staple")
    assert not web.verify_password("wrong password", password_hash, password_salt)


def test_hash_password_uses_a_fresh_salt_each_time():
    hash_a, salt_a = web.hash_password("same password")
    hash_b, salt_b = web.hash_password("same password")
    assert salt_a != salt_b
    assert hash_a != hash_b


def test_verify_password_rejects_malformed_salt():
    assert not web.verify_password("x", "0" * 64, "not-hex")


# --- LAN address detection & bind policy ----------------------------------


def test_resolve_bind_host_accepts_private_address():
    with patch("lanfence.web.detect_lan_ip", return_value="192.168.1.50"):
        assert web.resolve_bind_host() == "192.168.1.50"



_IP_JSON = """[
  {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
  {"ifname": "eth0", "addr_info": [
    {"family": "inet", "local": "192.168.1.50"},
    {"family": "inet", "local": "192.168.20.5"},
    {"family": "inet", "local": "81.2.69.160"},
    {"family": "inet6", "local": "fd12:3456::50"},
    {"family": "inet6", "local": "fe80::1234"}
  ]},
  {"ifname": "wlan0", "addr_info": [{"family": "inet", "local": "10.9.9.9"}]}
]"""


def test_addresses_on_interface_holding_reads_ip_json():
    import subprocess

    done = subprocess.CompletedProcess(args=[], returncode=0, stdout=_IP_JSON)
    with patch("lanfence.web.subprocess.run", return_value=done):
        assert web._addresses_on_interface_holding("192.168.1.50") == [
            "192.168.1.50", "192.168.20.5", "81.2.69.160", "fd12:3456::50", "fe80::1234",
        ]


def test_addresses_on_interface_holding_is_empty_without_ip_command():
    with patch("lanfence.web.subprocess.run", side_effect=FileNotFoundError()):
        assert web._addresses_on_interface_holding("192.168.1.50") == []


def test_resolve_bind_hosts_includes_every_private_address_on_the_interface():
    import subprocess

    done = subprocess.CompletedProcess(args=[], returncode=0, stdout=_IP_JSON)
    with patch.object(web, "detect_lan_ip", return_value="192.168.1.50"), \
         patch("lanfence.web.subprocess.run", return_value=done):
        hosts = web.resolve_bind_hosts()
    # public (81.2.69.160) and link-local (fe80::) are skipped; other interfaces aren't included
    assert hosts == ["192.168.1.50", "192.168.20.5", "fd12:3456::50"]


def test_resolve_bind_hosts_falls_back_to_the_detected_address():
    with patch.object(web, "detect_lan_ip", return_value="192.168.1.50"), \
         patch("lanfence.web.subprocess.run", side_effect=FileNotFoundError()):
        assert web.resolve_bind_hosts() == ["192.168.1.50"]


def test_portal_url_brackets_ipv6():
    assert web.portal_url("192.168.1.5", 8080) == "https://192.168.1.5:8080/"
    assert web.portal_url("fd12::5", 8080) == "https://[fd12::5]:8080/"

def test_resolve_bind_host_rejects_public_address():
    with patch("lanfence.web.detect_lan_ip", return_value="8.8.8.8"):
        with pytest.raises(web.WebError, match="not a private LAN address"):
            web.resolve_bind_host()


def test_resolve_bind_host_rejects_undetectable_address():
    with patch("lanfence.web.detect_lan_ip", return_value=None):
        with pytest.raises(web.WebError, match="could not determine"):
            web.resolve_bind_host()


def test_build_portal_url_none_when_not_running():
    cfg = Config()
    with patch("lanfence.web.is_server_running", return_value=False):
        assert web.build_portal_url(cfg) is None


def test_build_portal_url_none_when_enabled_but_not_actually_running():
    # cfg.web.enabled alone is not enough - a stale "enabled: true" with no
    # running process would be a broken link (see PORTAL_NOT_RUNNING_NOTE).
    cfg = Config()
    cfg.web.enabled = True
    with patch("lanfence.web.is_server_running", return_value=False), \
         patch("lanfence.web.detect_lan_ip", return_value="10.0.0.9"):
        assert web.build_portal_url(cfg) is None


def test_build_portal_url_built_from_detected_ip_and_configured_port_when_running():
    cfg = Config()
    cfg.web.port = 9090
    with patch("lanfence.web.is_server_running", return_value=True), \
         patch("lanfence.web.detect_lan_ip", return_value="10.0.0.9"):
        assert web.build_portal_url(cfg) == "https://10.0.0.9:9090/"


def test_build_portal_url_none_when_ip_undetectable():
    cfg = Config()
    with patch("lanfence.web.is_server_running", return_value=True), \
         patch("lanfence.web.detect_lan_ip", return_value=None):
        assert web.build_portal_url(cfg) is None


def test_build_portal_url_none_when_detected_address_is_public():
    # Never link to a public address even if one is somehow returned -
    # the digest link should only ever point somewhere LAN-reachable.
    cfg = Config()
    with patch("lanfence.web.is_server_running", return_value=True), \
         patch("lanfence.web.detect_lan_ip", return_value="8.8.8.8"):
        assert web.build_portal_url(cfg) is None


# --- pidfile / process lifecycle ------------------------------------------


def test_running_pid_none_when_no_pidfile(tmp_path: Path):
    with patch("lanfence.web._resolved_pid_file", return_value=tmp_path / "web.pid"):
        assert web.running_pid() is None


def test_write_and_read_own_pid(tmp_path: Path):
    pid_file = tmp_path / "web.pid"
    with patch("lanfence.web._resolved_pid_file", return_value=pid_file):
        web._write_pid_file()
        assert web.running_pid() == __import__("os").getpid()
        web._remove_pid_file()
        assert not pid_file.exists()


def test_running_pid_cleans_up_stale_pidfile(tmp_path: Path):
    pid_file = tmp_path / "web.pid"
    pid_file.write_text("999999999")  # exceedingly unlikely to be a live PID
    with patch("lanfence.web._resolved_pid_file", return_value=pid_file):
        assert web.running_pid() is None
        assert not pid_file.exists()


def test_is_server_running_false_when_nothing_running(tmp_path: Path):
    with patch("lanfence.web._resolved_pid_file", return_value=tmp_path / "web.pid"), \
         patch("lanfence.web._systemd_unit_active", return_value=False):
        assert web.is_server_running() is False


def test_stop_server_noop_when_nothing_running(tmp_path: Path):
    with patch("lanfence.web._resolved_pid_file", return_value=tmp_path / "web.pid"), \
         patch("lanfence.web._systemd_unit_active", return_value=False):
        assert web.stop_server() is False


def test_stop_server_prefers_systemd_over_pidfile(tmp_path: Path):
    pid_file = tmp_path / "web.pid"
    pid_file.write_text("1")  # would never actually be signalled if systemd path is taken
    with patch("lanfence.web._resolved_pid_file", return_value=pid_file), \
         patch("lanfence.web._systemd_unit_active", return_value=True), \
         patch("lanfence.web.subprocess.run") as run_mock, \
         patch("lanfence.web.os.kill") as kill_mock:
        assert web.stop_server() is True
        run_mock.assert_called_once()
        kill_mock.assert_not_called()


def test_stop_server_signals_pidfile_process_when_no_systemd_unit(tmp_path: Path):
    pid_file = tmp_path / "web.pid"
    pid_file.write_text("4242")
    with patch("lanfence.web._resolved_pid_file", return_value=pid_file), \
         patch("lanfence.web._systemd_unit_active", return_value=False), \
         patch("lanfence.web._process_alive", side_effect=[True, False]), \
         patch("lanfence.web.os.kill") as kill_mock:
        assert web.stop_server() is True
        kill_mock.assert_called_once()
        assert not pid_file.exists()


# --- local firewall detection/handling ------------------------------------


def _completed(returncode=0, stdout=""):
    import subprocess

    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_detect_active_firewall_finds_active_ufw():
    with patch("lanfence.web.subprocess.run", return_value=_completed(0, "Status: active\n")):
        assert web.detect_active_firewall() == "ufw"


def test_detect_active_firewall_ignores_inactive_ufw_then_checks_firewalld():
    def fake_run(command, **kwargs):
        if command[0] == "ufw":
            return _completed(0, "Status: inactive\n")
        return _completed(0, "running\n")

    with patch("lanfence.web.subprocess.run", side_effect=fake_run):
        assert web.detect_active_firewall() == "firewalld"


def test_detect_active_firewall_none_when_neither_present():
    with patch("lanfence.web.subprocess.run", side_effect=FileNotFoundError()):
        assert web.detect_active_firewall() is None


def test_detect_active_firewall_none_when_both_inactive():
    def fake_run(command, **kwargs):
        if command[0] == "ufw":
            return _completed(0, "Status: inactive\n")
        return _completed(0, "not running\n")

    with patch("lanfence.web.subprocess.run", side_effect=fake_run):
        assert web.detect_active_firewall() is None


def test_allow_port_through_firewall_ufw_success():
    with patch("lanfence.web.subprocess.run", return_value=_completed(0)) as run_mock:
        ok, message = web.allow_port_through_firewall("ufw", host="192.168.1.5", port=8080)
    assert ok is True
    assert "192.168.1.5" in message
    args = run_mock.call_args.args[0]
    assert args[:3] == ["ufw", "allow", "to"]
    assert "192.168.1.5" in args
    assert "8080" in args


def test_allow_port_through_firewall_firewalld_success_reloads():
    with patch("lanfence.web.subprocess.run", return_value=_completed(0)) as run_mock:
        ok, message = web.allow_port_through_firewall("firewalld", host="192.168.1.5", port=8080)
    assert ok is True
    assert run_mock.call_count == 2  # --add-port, then --reload
    reload_call = run_mock.call_args_list[1].args[0]
    assert reload_call == ["firewall-cmd", "--reload"]


def test_allow_port_through_firewall_reports_manual_command_on_failure():
    with patch("lanfence.web.subprocess.run", return_value=_completed(1)):
        ok, message = web.allow_port_through_firewall("ufw", host="192.168.1.5", port=8080)
    assert ok is False
    assert "sudo ufw allow to 192.168.1.5" in message


def test_allow_port_through_firewall_handles_missing_binary():
    with patch("lanfence.web.subprocess.run", side_effect=FileNotFoundError("no ufw")):
        ok, message = web.allow_port_through_firewall("ufw", host="192.168.1.5", port=8080)
    assert ok is False
    assert "could not run" in message


def test_start_background_refuses_when_not_enabled(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("web:\n  enabled: false\n")
    with pytest.raises(web.WebError, match="not enabled"):
        web.start_background(config_path)


def test_start_background_refuses_when_no_password(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("web:\n  enabled: true\n")
    with pytest.raises(web.WebError, match="no web portal password"):
        web.start_background(config_path)


def test_start_background_spawns_detached_process_and_returns_url(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    password_hash, password_salt = web.hash_password("s3cret")
    config_path.write_text(
        f"web:\n  enabled: true\n  port: 9191\n  password_hash: {password_hash!r}\n  password_salt: {password_salt!r}\n"
    )
    with patch("lanfence.web.resolve_bind_hosts", return_value=["192.168.1.5", "10.0.0.5"]), \
         patch("lanfence.web._resolved_log_file", return_value=tmp_path / "web.log"), \
         patch("lanfence.web.subprocess.Popen") as popen_mock:
        urls = web.start_background(config_path)
    assert urls == ["https://192.168.1.5:9191/", "https://10.0.0.5:9191/"]
    popen_mock.assert_called_once()
    args = popen_mock.call_args.args[0]
    assert args[-3:] == ["web", "--config", str(config_path)]
    assert popen_mock.call_args.kwargs["start_new_session"] is True


# --- TLS: self-signed certificate -----------------------------------------


def test_ensure_self_signed_cert_generates_cert_and_key(tmp_path: Path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    host_path = tmp_path / "cert.host"
    with patch("lanfence.web._resolved_cert_file", return_value=cert_path), \
         patch("lanfence.web._resolved_key_file", return_value=key_path), \
         patch("lanfence.web._resolved_cert_host_file", return_value=host_path):
        returned_cert, returned_key = web.ensure_self_signed_cert("192.168.1.50")
    assert returned_cert == cert_path
    assert returned_key == key_path
    assert cert_path.is_file()
    assert key_path.is_file()
    assert host_path.read_text(encoding="utf-8") == "192.168.1.50"
    assert oct(key_path.stat().st_mode)[-3:] == "600"
    # A real, parseable self-signed cert with the right subject alt name.
    import subprocess

    text = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-text"], capture_output=True, text=True, check=True
    ).stdout
    assert "192.168.1.50" in text


def test_ensure_self_signed_cert_reuses_existing_cert_for_same_host(tmp_path: Path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    host_path = tmp_path / "cert.host"
    with patch("lanfence.web._resolved_cert_file", return_value=cert_path), \
         patch("lanfence.web._resolved_key_file", return_value=key_path), \
         patch("lanfence.web._resolved_cert_host_file", return_value=host_path):
        web.ensure_self_signed_cert("192.168.1.50")
        first_cert_bytes = cert_path.read_bytes()
        web.ensure_self_signed_cert("192.168.1.50")
        assert cert_path.read_bytes() == first_cert_bytes


def test_ensure_self_signed_cert_regenerates_for_a_different_host(tmp_path: Path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    host_path = tmp_path / "cert.host"
    with patch("lanfence.web._resolved_cert_file", return_value=cert_path), \
         patch("lanfence.web._resolved_key_file", return_value=key_path), \
         patch("lanfence.web._resolved_cert_host_file", return_value=host_path):
        web.ensure_self_signed_cert("192.168.1.50")
        first_cert_bytes = cert_path.read_bytes()
        web.ensure_self_signed_cert("192.168.1.99")
        assert cert_path.read_bytes() != first_cert_bytes
    assert host_path.read_text(encoding="utf-8") == "192.168.1.99"



def test_ensure_self_signed_cert_covers_every_bound_address(tmp_path: Path):
    import subprocess

    cert_path = tmp_path / "cert.pem"
    with patch("lanfence.web._resolved_cert_file", return_value=cert_path), \
         patch("lanfence.web._resolved_key_file", return_value=tmp_path / "key.pem"), \
         patch("lanfence.web._resolved_cert_host_file", return_value=tmp_path / "cert.host"):
        web.ensure_self_signed_cert(["192.168.1.50", "192.168.20.5"])
        first = cert_path.read_bytes()
        web.ensure_self_signed_cert(["192.168.1.50", "192.168.20.5"])
        assert cert_path.read_bytes() == first  # reused for the same addresses
    text = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-text"], capture_output=True, text=True, check=True
    ).stdout
    assert "192.168.1.50" in text and "192.168.20.5" in text

def test_ensure_self_signed_cert_raises_web_error_when_openssl_missing(tmp_path: Path):
    with patch("lanfence.web._resolved_cert_file", return_value=tmp_path / "cert.pem"), \
         patch("lanfence.web._resolved_key_file", return_value=tmp_path / "key.pem"), \
         patch("lanfence.web._resolved_cert_host_file", return_value=tmp_path / "cert.host"), \
         patch("lanfence.web.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(web.WebError, match="openssl"):
            web.ensure_self_signed_cert("192.168.1.50")


def test_ensure_self_signed_cert_raises_web_error_on_openssl_failure(tmp_path: Path):
    import subprocess

    failed = subprocess.CompletedProcess(args=[], returncode=1)
    with patch("lanfence.web._resolved_cert_file", return_value=tmp_path / "cert.pem"), \
         patch("lanfence.web._resolved_key_file", return_value=tmp_path / "key.pem"), \
         patch("lanfence.web._resolved_cert_host_file", return_value=tmp_path / "cert.host"), \
         patch("lanfence.web.subprocess.run", return_value=failed):
        with pytest.raises(web.WebError, match="could not generate"):
            web.ensure_self_signed_cert("192.168.1.50")


def test_run_server_wraps_socket_in_tls_by_default(tmp_path: Path):
    """Unit-level: run_server()'s tls=True default path (real entry points
    never pass tls=False) generates a cert and wraps the listening socket -
    verified via mocks, not a live process/signal loop (see the real
    handshake test below for that)."""

    cfg = Config()
    fake_httpd = type(
        "FakeHTTPD", (), {"socket": "plain-socket", "serve_forever": lambda self: None, "shutdown": lambda self: None,
                          "server_close": lambda self: None},
    )()
    with patch("lanfence.web.ThreadingHTTPServer", return_value=fake_httpd), \
         patch("lanfence.web.ensure_self_signed_cert", return_value=(tmp_path / "c.pem", tmp_path / "k.pem")) as ensure_mock, \
         patch("lanfence.web.ssl.SSLContext") as ssl_context_cls, \
         patch("lanfence.web._write_pid_file"), patch("lanfence.web._remove_pid_file"), \
         patch("lanfence.web.threading.Thread") as thread_cls, \
         patch("lanfence.web.signal.signal"):
        ssl_context = ssl_context_cls.return_value
        ssl_context.wrap_socket.return_value = "tls-wrapped-socket"
        thread_cls.return_value.start.side_effect = lambda: None
        # stop_event.wait() would block forever for a real Event - swap in
        # one that returns immediately so this test doesn't hang.
        with patch("lanfence.web.threading.Event") as event_cls:
            event_cls.return_value.wait.return_value = None
            web.run_server(cfg, host="127.0.0.1", port=9443)
    ensure_mock.assert_called_once_with(["127.0.0.1"])
    ssl_context.load_cert_chain.assert_called_once()
    assert fake_httpd.socket == "tls-wrapped-socket"



def _run_server_with_mocks(hosts, *, v4=None, v6=None):
    from unittest.mock import MagicMock

    v4 = v4 or MagicMock()
    v6 = v6 or MagicMock()
    with patch("lanfence.web.ThreadingHTTPServer", v4), \
         patch("lanfence.web._ThreadingHTTPServerV6", v6), \
         patch("lanfence.web._write_pid_file"), patch("lanfence.web._remove_pid_file"), \
         patch("lanfence.web.threading.Thread"), patch("lanfence.web.signal.signal"), \
         patch("lanfence.web.threading.Event") as event_cls:
        event_cls.return_value.wait.return_value = None
        web.run_server(Config(), host=hosts, port=9443, tls=False)
    return v4, v6


def test_run_server_listens_on_every_address():
    v4, v6 = _run_server_with_mocks(["192.168.1.50", "192.168.20.5", "fd12::50"])
    assert [c.args[0] for c in v4.call_args_list] == [("192.168.1.50", 9443), ("192.168.20.5", 9443)]
    assert [c.args[0] for c in v6.call_args_list] == [("fd12::50", 9443)]


def test_run_server_skips_an_extra_address_it_cannot_bind():
    from unittest.mock import MagicMock

    bound = MagicMock()
    v4 = MagicMock(side_effect=[bound, OSError("Cannot assign requested address")])
    _run_server_with_mocks(["192.168.1.50", "192.168.20.5"], v4=v4)
    bound.shutdown.assert_called_once()  # the primary still served, and was shut down cleanly


def test_run_server_fails_if_the_primary_address_cannot_be_bound():
    from unittest.mock import MagicMock

    with pytest.raises(OSError):
        _run_server_with_mocks(["192.168.1.50"], v4=MagicMock(side_effect=OSError("in use")))


def test_restart_server_restarts_a_background_portal(tmp_path: Path):
    with patch.object(web, "_systemd_unit_active", return_value=False), \
         patch.object(web, "running_pid", return_value=1234), \
         patch.object(web, "stop_server") as stop_mock, \
         patch.object(web, "start_background", return_value=["https://192.168.1.5:8080/"]) as start_mock:
        outcome = web.restart_server(tmp_path / "config.yaml")
    stop_mock.assert_called_once()
    start_mock.assert_called_once_with(tmp_path / "config.yaml")
    assert "https://192.168.1.5:8080/" in outcome


def test_restart_server_uses_systemd_when_the_unit_is_active(tmp_path: Path):
    import subprocess

    with patch.object(web, "_systemd_unit_active", return_value=True), \
         patch("lanfence.web.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run_mock:
        outcome = web.restart_server(tmp_path / "config.yaml")
    assert run_mock.call_args.args[0] == ["systemctl", "restart", "lanfence-web"]
    assert "lanfence-web" in outcome


def test_restart_server_does_nothing_when_not_running(tmp_path: Path):
    with patch.object(web, "_systemd_unit_active", return_value=False), \
         patch.object(web, "running_pid", return_value=None), \
         patch.object(web, "start_background") as start_mock:
        assert web.restart_server(tmp_path / "config.yaml") is None
    start_mock.assert_not_called()

def test_tls_wrapped_server_accepts_real_https_requests(tmp_path: Path):
    """End-to-end: a ThreadingHTTPServer whose socket is wrapped in TLS
    exactly as run_server() does, using a real cert from
    ensure_self_signed_cert(), actually serves HTTPS - an HTTPS client
    (trust deliberately disabled, matching a real browser's manual
    click-through past the self-signed warning) can talk to it."""

    import ssl as ssl_module
    import threading as threading_module

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    host_path = tmp_path / "cert.host"
    with patch("lanfence.web._resolved_cert_file", return_value=cert_path), \
         patch("lanfence.web._resolved_key_file", return_value=key_path), \
         patch("lanfence.web._resolved_cert_host_file", return_value=host_path):
        cert, key = web.ensure_self_signed_cert("127.0.0.1")

    context = web._WebContext(cfg=Config(), sessions=web._SessionStore(), throttle=web._LoginThrottle())
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web._make_handler(context))
    port = httpd.server_address[1]
    server_ssl_context = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
    server_ssl_context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    httpd.socket = server_ssl_context.wrap_socket(httpd.socket, server_side=True)

    thread = threading_module.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        client_context = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl_module.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=client_context, timeout=5)
        try:
            conn.request("GET", "/login")
            resp = conn.getresponse()
            assert resp.status == 200
            resp.read()
        finally:
            conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


# --- HTTP server (integration) ---------------------------------------------


@pytest.fixture
def running_portal(tmp_path: Path):
    """A real ThreadingHTTPServer on 127.0.0.1 with an ephemeral port -
    resolve_bind_host()'s private-address policy is a separate, narrower
    concern (see the bind-policy tests above) and deliberately not
    exercised here, so the handler itself stays testable on localhost."""

    db_path = tmp_path / "db.sqlite"
    allowlist_path = tmp_path / "allowlist.yaml"
    with DeviceStore(db_path) as store:
        store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="testhost", vendor="TestVendor",
            seen_at=datetime.now(timezone.utc),
        )

    password_hash, password_salt = web.hash_password("s3cret-pw")
    cfg = Config(db_path=str(db_path), allowlist_file=str(allowlist_path))
    cfg.web.enabled = True
    cfg.web.password_hash = password_hash
    cfg.web.password_salt = password_salt

    context = web._WebContext(cfg=cfg, sessions=web._SessionStore(), throttle=web._LoginThrottle())
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web._make_handler(context))
    port = httpd.server_address[1]
    import threading

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", cfg
    finally:
        httpd.shutdown()
        httpd.server_close()


def _opener():
    cookie_jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))


def test_unauthenticated_request_redirects_to_login(running_portal):
    base_url, _ = running_portal
    resp = _opener().open(f"{base_url}/")
    assert resp.geturl() == f"{base_url}/login"


def test_wrong_password_rejected_with_401(running_portal):
    base_url, _ = running_portal
    data = urllib.parse.urlencode({"password": "wrong"}).encode()
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _opener().open(f"{base_url}/login", data=data)
    assert exc_info.value.code == 401


def test_correct_password_logs_in_and_lists_devices(running_portal):
    base_url, _ = running_portal
    opener = _opener()
    data = urllib.parse.urlencode({"password": "s3cret-pw"}).encode()
    resp = opener.open(f"{base_url}/login", data=data)
    assert resp.geturl() == f"{base_url}/"
    body = resp.read().decode()
    assert "aa:bb:cc:dd:ee:ff" in body


def test_login_throttled_after_repeated_failures(running_portal):
    base_url, _ = running_portal
    opener = _opener()
    data = urllib.parse.urlencode({"password": "wrong"}).encode()
    for _ in range(web._MAX_FAILED_ATTEMPTS):
        with pytest.raises(urllib.error.HTTPError):
            opener.open(f"{base_url}/login", data=data)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        opener.open(f"{base_url}/login", data=data)
    assert exc_info.value.code == 429


def test_metadata_edit_persists_and_is_html_escaped(running_portal):
    base_url, cfg = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    hostile = "<script>alert(1)</script>"
    data = urllib.parse.urlencode(
        {"action": "metadata", "owner": hostile, "location": ""}
    ).encode()
    resp = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data)
    body = resp.read().decode()
    assert "Details saved" in body
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body

    with DeviceStore(cfg.resolved_db_path()) as store:
        metadata = store.get_device_metadata("aa:bb:cc:dd:ee:ff")
    assert metadata.owner == hostile  # stored as-is; only display is escaped


def test_trust_action_adds_device_to_allowlist(running_portal):
    base_url, cfg = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    data = urllib.parse.urlencode({"action": "trust", "name": "Ross Laptop"}).encode()
    resp = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data)
    body = resp.read().decode()
    assert "Device trusted" in body
    assert "badge--trusted" in body

    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    entry = allowlist.match("aa:bb:cc:dd:ee:ff")
    assert entry is not None
    assert entry.name == "Ross Laptop"


def test_rename_action_preserves_existing_notes(running_portal):
    base_url, cfg = running_portal
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    allowlist.add("aa:bb:cc:dd:ee:ff", "Old Name", notes="do not remove")
    allowlist.save()

    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())
    data = urllib.parse.urlencode({"action": "rename", "name": "New Name"}).encode()
    opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data)

    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    entry = allowlist.match("aa:bb:cc:dd:ee:ff")
    assert entry.name == "New Name"
    assert entry.notes == "do not remove"


def test_untrust_action_removes_device_from_allowlist(running_portal):
    base_url, cfg = running_portal
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    allowlist.add("aa:bb:cc:dd:ee:ff", "Ross Laptop")
    allowlist.save()

    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())
    data = urllib.parse.urlencode({"action": "untrust"}).encode()
    resp = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data)
    body = resp.read().decode()
    assert "Device untrusted" in body
    assert "badge--untrusted" in body

    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    assert allowlist.match("aa:bb:cc:dd:ee:ff") is None


def test_untrust_action_on_already_untrusted_device_reports_error(running_portal):
    base_url, _ = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())
    data = urllib.parse.urlencode({"action": "untrust"}).encode()
    resp = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data)
    body = resp.read().decode()
    assert "not on the allowlist" in body


def test_untrust_button_only_shown_when_trusted(running_portal):
    base_url, cfg = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff").read().decode()
    assert "Untrust this device" not in body

    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    allowlist.add("aa:bb:cc:dd:ee:ff", "Ross Laptop")
    allowlist.save()
    body = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff").read().decode()
    assert "Untrust this device" in body


def test_device_list_and_detail_show_both_ipv4_and_ipv6(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.record_address_evidence(
            mac="aa:bb:cc:dd:ee:ff", ip="fe80::abcd", interface="eth0",
            source="ipv6_nd", kind="observed", seen_at=datetime.now(timezone.utc),
        )
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/").read().decode()
    assert "10.0.0.5 / fe80::abcd" in body

    body = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff").read().decode()
    assert "10.0.0.5 / fe80::abcd" in body


def test_metadata_rejects_overlong_value(running_portal):
    base_url, _ = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    data = urllib.parse.urlencode(
        {"action": "metadata", "owner": "x" * 200, "location": ""}
    ).encode()
    resp = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data)
    body = resp.read().decode()
    assert "must be at most" in body


# --- Know Your Network: asset metadata, identity, inventory filtering ------


def test_metadata_edit_sets_asset_fields(running_portal):
    base_url, cfg = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    data = urllib.parse.urlencode(
        {
            "action": "metadata", "owner": "", "location": "", "friendly_name": "Boardroom TV",
            "asset_type": "Company", "category_override": "Media Device", "purpose": "Boardroom display",
            "notes": "Mounted on wall",
        }
    ).encode()
    resp = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data)
    body = resp.read().decode()
    assert "Details saved" in body

    with DeviceStore(cfg.resolved_db_path()) as store:
        metadata = store.get_device_metadata("aa:bb:cc:dd:ee:ff")
    assert metadata.friendly_name == "Boardroom TV"
    assert metadata.asset_type == "Company"
    assert metadata.category_override == "Media Device"
    assert metadata.purpose == "Boardroom display"
    assert metadata.notes == "Mounted on wall"



def test_metadata_edit_leaves_fields_the_form_did_not_send_untouched(running_portal):
    """A page loaded before a field existed (or any partial form) must not
    silently clear the fields it doesn't include."""

    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", updated_at=datetime.now(timezone.utc),
            friendly_name="Boardroom TV", asset_type="Company",
        )
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    data = urllib.parse.urlencode({"action": "metadata", "owner": "Alice", "location": ""}).encode()
    opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data).read()

    with DeviceStore(cfg.resolved_db_path()) as store:
        metadata = store.get_device_metadata("aa:bb:cc:dd:ee:ff")
    assert metadata.owner == "Alice"
    assert metadata.friendly_name == "Boardroom TV"
    assert metadata.asset_type == "Company"


def test_metadata_edit_clears_a_field_submitted_empty(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", updated_at=datetime.now(timezone.utc), friendly_name="Boardroom TV",
        )
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    data = urllib.parse.urlencode({"action": "metadata", "friendly_name": ""}).encode()
    opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data).read()

    with DeviceStore(cfg.resolved_db_path()) as store:
        assert store.get_device_metadata("aa:bb:cc:dd:ee:ff").friendly_name is None

def test_metadata_rejects_invalid_asset_type(running_portal):
    base_url, _ = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    data = urllib.parse.urlencode({"action": "metadata", "asset_type": "Not A Real Type"}).encode()
    resp = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff", data=data)
    body = resp.read().decode()
    assert "must be one of" in body


def test_device_page_shows_identity_section(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="Ross-iPhone", vendor="Apple, Inc.",
            seen_at=datetime.now(timezone.utc),
        )
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff").read().decode()
    assert "Identity (Know Your Network)" in body
    assert "Apple iPhone" in body
    assert "Why this identity?" in body
    assert "Hostname suggests an iPhone" in body



def test_device_page_shows_network_and_security_sections(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.record_address_evidence(
            mac="aa:bb:cc:dd:ee:ff", ip="fe80::abcd", interface="eth0",
            source="ipv6_nd", kind="observed", seen_at=datetime.now(timezone.utc),
        )
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff").read().decode()
    assert "<h2>Network</h2>" in body
    assert "fe80::abcd" in body
    assert "First seen:" in body
    assert "Presence: unspecified" in body
    assert "<h2>Security</h2>" in body
    assert "Identity confidence and security risk are separate" in body
    assert "<h2>Ownership</h2>" in body


def test_device_page_labels_a_user_assigned_category_apart_from_the_detected_one(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", updated_at=datetime.now(timezone.utc), category_override="Printer",
        )
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff").read().decode()
    assert "<strong>Printer</strong> (assigned by you)" in body
    assert "detected: Unknown" in body


def test_device_page_security_section_shows_investigation_notes(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.set_investigating("aa:bb:cc:dd:ee:ff", notes="<b>odd</b> traffic", updated_at=datetime.now(timezone.utc))
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/device/aa:bb:cc:dd:ee:ff").read().decode()
    assert "Flagged for investigation: &lt;b&gt;odd&lt;/b&gt; traffic" in body

def test_index_shows_network_overview_panel(running_portal):
    base_url, _ = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/").read().decode()
    assert "Know Your Network" in body
    assert "1 devices" in body


def test_index_asset_type_filter_narrows_list(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor=None, seen_at=datetime.now(timezone.utc))
        store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", updated_at=datetime.now(timezone.utc), asset_type="Company",
        )
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/?asset_type=Company").read().decode()
    assert "aa:bb:cc:dd:ee:ff" in body
    assert "11:22:33:44:55:66" not in body


def test_index_search_matches_owner(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor=None, seen_at=datetime.now(timezone.utc))
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=datetime.now(timezone.utc), owner="Alice")
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/?q=Alice").read().decode()
    assert "aa:bb:cc:dd:ee:ff" in body
    assert "11:22:33:44:55:66" not in body


def test_index_review_filter(running_portal):
    # aa:bb:cc:dd:ee:ff (seeded by running_portal) stays in its default,
    # never-reviewed "pending" state - is_review_needed() is true for it.
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor=None, seen_at=datetime.now(timezone.utc))
    allowlist = Allowlist.load(cfg.resolved_allowlist_file())
    allowlist.path = cfg.resolved_allowlist_file()
    allowlist.add("11:22:33:44:55:66", "Trusted Thing")
    allowlist.save()

    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())

    body = opener.open(f"{base_url}/?review=1").read().decode()
    assert "aa:bb:cc:dd:ee:ff" in body
    assert "11:22:33:44:55:66" not in body


# --- inventory filtering (pure function) ------------------------------------


def test_filter_dossiers_by_trust_and_category():
    from lanfence.dossier import DeviceDossier
    from lanfence.identity import DeviceIdentity

    now = datetime.now(timezone.utc)
    trusted = DeviceDossier(
        device=_device("aa:aa:aa:aa:aa:aa", trusted=True), identity=DeviceIdentity(category="Printer", confidence=50),
    )
    untrusted = DeviceDossier(
        device=_device("bb:bb:bb:bb:bb:bb", trusted=False), identity=DeviceIdentity(category="Camera", confidence=50),
    )
    result = web._filter_dossiers([trusted, untrusted], web._parse_filters({"trust": ["trusted"]}), now=now)
    assert result == [trusted]

    result = web._filter_dossiers([trusted, untrusted], web._parse_filters({"category": ["Camera"]}), now=now)
    assert result == [untrusted]


def test_filter_dossiers_unknown_identity():
    from lanfence.dossier import DeviceDossier
    from lanfence.identity import DeviceIdentity

    now = datetime.now(timezone.utc)
    known = DeviceDossier(device=_device("aa:aa:aa:aa:aa:aa"), identity=DeviceIdentity(category="Printer", confidence=50))
    unknown = DeviceDossier(device=_device("bb:bb:bb:bb:bb:bb"), identity=DeviceIdentity())
    result = web._filter_dossiers([known, unknown], web._parse_filters({"unknown": ["1"]}), now=now)
    assert result == [unknown]



def test_filter_dossiers_uncertain_identity_and_no_owner():
    from lanfence.dossier import DeviceDossier
    from lanfence.identity import DeviceIdentity
    from lanfence.models import DeviceMetadata

    now = datetime.now(timezone.utc)
    confident = DeviceDossier(device=_device("aa:aa:aa:aa:aa:aa"), identity=DeviceIdentity(confidence=80))
    uncertain = DeviceDossier(device=_device("bb:bb:bb:bb:bb:bb"), identity=DeviceIdentity(confidence=20))
    unknown = DeviceDossier(device=_device("cc:cc:cc:cc:cc:cc"), identity=DeviceIdentity())
    owned_device = _device("dd:dd:dd:dd:dd:dd")
    owned_device.metadata = DeviceMetadata(mac="dd:dd:dd:dd:dd:dd", owner="Alice")
    owned = DeviceDossier(device=owned_device, identity=DeviceIdentity(confidence=80))
    everything = [confident, uncertain, unknown, owned]

    assert web._filter_dossiers(everything, web._parse_filters({"uncertain": ["1"]}), now=now) == [uncertain]
    assert owned not in web._filter_dossiers(everything, web._parse_filters({"no_owner": ["1"]}), now=now)


def test_network_overview_attention_counts_link_to_their_filters():
    from lanfence.dossier import DeviceDossier
    from lanfence.identity import DeviceIdentity

    dossiers = [DeviceDossier(device=_device("aa:aa:aa:aa:aa:aa"), identity=DeviceIdentity(confidence=20))]
    body = web._render_network_overview(dossiers, now=datetime.now(timezone.utc))
    assert 'href="/?uncertain=1"' in body
    assert 'href="/?no_owner=1"' in body

# --- device list sorting --------------------------------------------------


def _device(mac, *, name=None, hostname=None, ip=None, vendor=None, status="online", trusted=False):
    now = datetime.now(timezone.utc)
    return Device(
        mac=mac, ip=ip, hostname=hostname, vendor=vendor, status=status, first_seen=now, last_seen=now,
        allowlisted=trusted, allowlist_name=name,
    )


def _dossier(mac, **device_kwargs) -> DeviceDossier:
    return DeviceDossier(device=_device(mac, **device_kwargs))


def test_ip_sort_key_orders_numerically_not_lexicographically():
    assert web._ip_sort_key("10.0.0.2") < web._ip_sort_key("10.0.0.10")


def test_ip_sort_key_sorts_missing_ip_last():
    assert web._ip_sort_key("10.0.0.2") < web._ip_sort_key(None)


def test_render_device_list_defaults_to_mac_ascending():
    dossiers = [_dossier("bb:bb:bb:bb:bb:bb"), _dossier("aa:aa:aa:aa:aa:aa")]
    body = web._render_device_list(dossiers)
    assert body.index("aa:aa:aa:aa:aa:aa") < body.index("bb:bb:bb:bb:bb:bb")


def test_render_device_list_sorts_by_name_case_insensitively():
    dossiers = [_dossier("aa:aa:aa:aa:aa:aa", name="zeta"), _dossier("bb:bb:bb:bb:bb:bb", name="Alpha")]
    body = web._render_device_list(dossiers, sort="name", direction="asc")
    assert body.index("Alpha") < body.index("zeta")


def test_render_device_list_direction_desc_reverses_order():
    dossiers = [_dossier("aa:aa:aa:aa:aa:aa", name="alpha"), _dossier("bb:bb:bb:bb:bb:bb", name="zeta")]
    body = web._render_device_list(dossiers, sort="name", direction="desc")
    assert body.index("zeta") < body.index("alpha")


def test_render_device_list_sorts_by_ip_numerically():
    dossiers = [_dossier("aa:aa:aa:aa:aa:aa", ip="10.0.0.10"), _dossier("bb:bb:bb:bb:bb:bb", ip="10.0.0.2")]
    body = web._render_device_list(dossiers, sort="ip", direction="asc")
    assert body.index("10.0.0.2") < body.index("10.0.0.10")


def test_render_device_list_sorts_by_trust():
    dossiers = [_dossier("aa:aa:aa:aa:aa:aa", trusted=True), _dossier("bb:bb:bb:bb:bb:bb", trusted=False)]
    body = web._render_device_list(dossiers, sort="trust", direction="asc")
    assert body.index("badge--trusted") < body.index("badge--untrusted")


def test_render_device_list_unknown_sort_falls_back_to_default():
    dossiers = [_dossier("bb:bb:bb:bb:bb:bb"), _dossier("aa:aa:aa:aa:aa:aa")]
    body = web._render_device_list(dossiers, sort="not-a-real-column", direction="asc")
    assert body.index("aa:aa:aa:aa:aa:aa") < body.index("bb:bb:bb:bb:bb:bb")


def test_render_device_list_invalid_direction_falls_back_to_asc():
    dossiers = [_dossier("bb:bb:bb:bb:bb:bb"), _dossier("aa:aa:aa:aa:aa:aa")]
    body = web._render_device_list(dossiers, sort="mac", direction="sideways")
    assert body.index("aa:aa:aa:aa:aa:aa") < body.index("bb:bb:bb:bb:bb:bb")


def test_render_device_list_headers_link_to_toggled_direction():
    body = web._render_device_list([], sort="name", direction="asc")
    assert "sort=name&amp;dir=desc" in body
    assert "sort=mac&amp;dir=asc" in body


def test_index_route_honors_sort_query_params(running_portal):
    base_url, cfg = running_portal
    with DeviceStore(cfg.resolved_db_path()) as store:
        store.observe(mac="00:00:00:00:00:01", ip="10.0.0.1", hostname="aardvark", vendor=None, seen_at=datetime.now(timezone.utc))
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())
    body = opener.open(f"{base_url}/?sort=name&dir=asc").read().decode()
    assert body.index("aardvark") < body.index("testhost")
    body = opener.open(f"{base_url}/?sort=name&dir=desc").read().decode()
    assert body.index("testhost") < body.index("aardvark")


def test_unknown_device_returns_404(running_portal):
    base_url, _ = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        opener.open(f"{base_url}/device/11:22:33:44:55:66")
    assert exc_info.value.code == 404


def test_logout_clears_session(running_portal):
    base_url, _ = running_portal
    opener = _opener()
    opener.open(f"{base_url}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())
    opener.open(f"{base_url}/logout", data=b"")
    resp = opener.open(f"{base_url}/")
    assert resp.geturl() == f"{base_url}/login"


def test_session_cookie_is_httponly_and_samesite_strict(running_portal):
    base_url, _ = running_portal
    conn = http.client.HTTPConnection(base_url.replace("http://", ""))
    try:
        body = urllib.parse.urlencode({"password": "s3cret-pw"})
        conn.request(
            "POST", "/login", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        resp = conn.getresponse()
        set_cookie = resp.getheader("Set-Cookie")
        resp.read()
    finally:
        conn.close()
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
