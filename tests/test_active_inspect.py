from __future__ import annotations

import socket
import subprocess
import threading
from unittest.mock import patch

import pytest

from lanfence.active_inspect import (
    DEFAULT_PORTS,
    _validate_ip,
    infer_platform,
    inspect_device,
    nmap_available,
    nmap_scan,
    socket_scan,
)
from lanfence.models import InspectedPort


def _free_tcp_server(handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def _serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            handler(conn)
        finally:
            conn.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return srv, port


# --- _validate_ip ------------------------------------------------------------


def test_validate_ip_accepts_ipv4_and_ipv6():
    _validate_ip("192.168.1.10")
    _validate_ip("::1")


def test_validate_ip_rejects_hostname():
    with pytest.raises(ValueError):
        _validate_ip("example.com")


def test_validate_ip_rejects_garbage():
    with pytest.raises(ValueError):
        _validate_ip("not an address; rm -rf /")


# --- socket_scan ---------------------------------------------------------


def test_socket_scan_finds_open_port_and_reports_closed_port_as_absent():
    srv, port = _free_tcp_server(lambda conn: None)
    try:
        results = socket_scan("127.0.0.1", ports=[port, port + 1], timeout=0.3)
    finally:
        srv.close()
    assert [r.port for r in results] == [port]


def test_socket_scan_reads_passive_banner_for_greet_first_ports():
    def handler(conn):
        conn.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")

    srv, port = _free_tcp_server(handler)
    try:
        with patch("lanfence.active_inspect._BANNER_GREETS_FIRST", {port}):
            results = socket_scan("127.0.0.1", ports=[port], timeout=0.5)
    finally:
        srv.close()
    assert len(results) == 1
    assert "OpenSSH" in (results[0].banner or "")


def test_socket_scan_reads_http_server_header():
    def handler(conn):
        conn.recv(4096)
        conn.sendall(b"HTTP/1.0 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n")

    srv, port = _free_tcp_server(handler)
    try:
        with patch("lanfence.active_inspect._HTTP_BANNER_PORTS", {port}):
            results = socket_scan("127.0.0.1", ports=[port], timeout=0.5)
    finally:
        srv.close()
    assert results[0].banner == "nginx/1.18.0"


def test_socket_scan_rejects_invalid_ip():
    with pytest.raises(ValueError):
        socket_scan("not-an-ip", ports=[80])


def test_socket_scan_default_ports_used_when_omitted():
    # No server anywhere - every default port should come back closed/absent,
    # not raise, and DEFAULT_PORTS itself should be untouched.
    results = socket_scan("127.0.0.1", timeout=0.05)
    assert isinstance(results, list)
    assert len(DEFAULT_PORTS) == 20


# --- nmap_scan -------------------------------------------------------------


def test_nmap_scan_returns_none_when_nmap_is_not_installed():
    with patch("lanfence.active_inspect.nmap_available", return_value=False):
        assert nmap_scan("127.0.0.1", ports=[80]) is None


def test_nmap_scan_returns_none_on_timeout():
    with patch("lanfence.active_inspect.nmap_available", return_value=True), \
         patch("lanfence.active_inspect.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=30)):
        assert nmap_scan("127.0.0.1", ports=[80]) is None


def test_nmap_scan_returns_none_on_missing_binary_oserror():
    with patch("lanfence.active_inspect.nmap_available", return_value=True), \
         patch("lanfence.active_inspect.subprocess.run", side_effect=FileNotFoundError()):
        assert nmap_scan("127.0.0.1", ports=[80]) is None


def test_nmap_scan_never_uses_a_shell():
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        class _Completed:
            returncode = 0
            stdout = ""

        return _Completed()

    with patch("lanfence.active_inspect.nmap_available", return_value=True), \
         patch("lanfence.active_inspect.subprocess.run", side_effect=fake_run):
        nmap_scan("127.0.0.1", ports=[22, 80])

    assert isinstance(captured["command"], list)
    assert "shell" not in captured["kwargs"] or captured["kwargs"]["shell"] is False
    assert captured["command"][0] == "nmap"
    assert "127.0.0.1" == captured["command"][-1]


def test_nmap_scan_rejects_invalid_ip_before_running_anything():
    with patch("lanfence.active_inspect.subprocess.run") as run_mock:
        with pytest.raises(ValueError):
            nmap_scan("not-an-ip; echo pwned", ports=[80])
    run_mock.assert_not_called()


def test_nmap_scan_parses_grepable_output():
    output = (
        "Host: 192.168.1.10 ()\tStatus: Up\n"
        "Host: 192.168.1.10 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.2p1 Ubuntu//, "
        "80/open/tcp//http//nginx 1.18.0//, 443/closed/tcp//https///\t"
        "Ignored State: closed (997)\n"
    )

    class _Completed:
        returncode = 0
        stdout = output

    with patch("lanfence.active_inspect.nmap_available", return_value=True), \
         patch("lanfence.active_inspect.subprocess.run", return_value=_Completed()):
        results = nmap_scan("192.168.1.10", ports=[22, 80, 443])

    assert [r.port for r in results] == [22, 80]
    assert results[0].service == "ssh"
    assert "OpenSSH" in (results[0].banner or "")
    assert results[1].service == "http"


# --- infer_platform ----------------------------------------------------------


def test_infer_platform_no_ports_open():
    guess, confidence, reasons = infer_platform([])
    assert guess is None and confidence is None and reasons == []


def test_infer_platform_windows_rdp_and_smb():
    ports = [InspectedPort(port=p) for p in (135, 445, 3389)]
    guess, confidence, _reasons = infer_platform(ports)
    assert "Windows" in guess
    assert confidence == "medium"


def test_infer_platform_smb_only_is_lower_confidence():
    ports = [InspectedPort(port=445)]
    guess, confidence, _reasons = infer_platform(ports)
    assert confidence == "low"


def test_infer_platform_printer_ports():
    ports = [InspectedPort(port=9100)]
    guess, confidence, _reasons = infer_platform(ports)
    assert guess == "Network printer"
    assert confidence == "medium"


def test_infer_platform_apple_mobile_sync():
    ports = [InspectedPort(port=62078)]
    guess, confidence, _reasons = infer_platform(ports)
    assert "Apple mobile device" in guess
    assert confidence == "medium"


def test_infer_platform_ssh_only_is_low_confidence_linux_guess():
    ports = [InspectedPort(port=22)]
    guess, confidence, _reasons = infer_platform(ports)
    assert "Linux" in guess or "Unix" in guess
    assert confidence == "low"


def test_infer_platform_never_claims_high_confidence():
    # Across every branch, infer_platform must never claim more than
    # "medium" - it is a pattern match over open ports, not OS fingerprinting.
    all_ports = [InspectedPort(port=p) for p in (135, 139, 445, 3389, 22, 548, 9100, 631, 554, 62078)]
    _guess, confidence, _reasons = infer_platform(all_ports)
    assert confidence in (None, "medium", "low")


# --- inspect_device (orchestration) ------------------------------------------


def test_inspect_device_prefers_nmap_when_available():
    fake_ports = [InspectedPort(port=22, service="ssh")]
    with patch("lanfence.active_inspect.nmap_scan", return_value=fake_ports) as nmap_mock, \
         patch("lanfence.active_inspect.socket_scan") as socket_mock:
        result = inspect_device("aa:bb:cc:dd:ee:ff", "10.0.0.5", use_nmap=True)
    nmap_mock.assert_called_once()
    socket_mock.assert_not_called()
    assert result.method == "nmap"
    assert result.open_ports == fake_ports


def test_inspect_device_falls_back_to_socket_scan_when_nmap_unavailable():
    fake_ports = [InspectedPort(port=80, service="http")]
    with patch("lanfence.active_inspect.nmap_scan", return_value=None) as nmap_mock, \
         patch("lanfence.active_inspect.socket_scan", return_value=fake_ports) as socket_mock:
        result = inspect_device("aa:bb:cc:dd:ee:ff", "10.0.0.5", use_nmap=True)
    nmap_mock.assert_called_once()
    socket_mock.assert_called_once()
    assert result.method == "socket"
    assert result.open_ports == fake_ports


def test_inspect_device_use_nmap_false_never_calls_nmap():
    with patch("lanfence.active_inspect.nmap_scan") as nmap_mock, \
         patch("lanfence.active_inspect.socket_scan", return_value=[]) as socket_mock:
        inspect_device("aa:bb:cc:dd:ee:ff", "10.0.0.5", use_nmap=False)
    nmap_mock.assert_not_called()
    socket_mock.assert_called_once()


def test_inspect_device_rejects_invalid_ip():
    with pytest.raises(ValueError):
        inspect_device("aa:bb:cc:dd:ee:ff", "not-an-ip", use_nmap=False)


def test_inspect_device_normalizes_mac():
    with patch("lanfence.active_inspect.socket_scan", return_value=[]):
        result = inspect_device("AA:BB:CC:DD:EE:FF", "10.0.0.5", use_nmap=False)
    assert result.mac == "aa:bb:cc:dd:ee:ff"


def test_inspect_device_populates_platform_guess_from_open_ports():
    with patch("lanfence.active_inspect.socket_scan", return_value=[InspectedPort(port=9100, service="jetdirect")]):
        result = inspect_device("aa:bb:cc:dd:ee:ff", "10.0.0.5", use_nmap=False)
    assert result.platform_guess == "Network printer"
    assert result.platform_confidence == "medium"
    assert result.is_known_platform is True


def test_nmap_available_reflects_shutil_which():
    with patch("lanfence.active_inspect.shutil.which", return_value=None):
        assert nmap_available() is False
    with patch("lanfence.active_inspect.shutil.which", return_value="/usr/bin/nmap"):
        assert nmap_available() is True
