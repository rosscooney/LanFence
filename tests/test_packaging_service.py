from __future__ import annotations

import configparser
from pathlib import Path

SERVICE_PATH = Path(__file__).resolve().parents[1] / "packaging" / "lanfence.service"


def _load() -> configparser.RawConfigParser:
    """Parse the unit file as basic INI - a rough syntax sanity check only.

    This is *not* a systemd-aware validator: it doesn't know systemd's
    directive names, value grammar, or semantics, and doesn't support a
    directive repeated across multiple lines the way real systemd unit
    files can. It exists to catch an accidentally-broken section/key=value
    shape and to let the tests below make targeted assertions about which
    directives this specific file sets - not to replace `systemd-analyze
    verify`, which was not available in this environment (no Linux/systemd
    runtime - see the unit file's own comments).
    """

    parser = configparser.RawConfigParser()
    parser.optionxform = str  # systemd directives are case-sensitive
    read = parser.read(SERVICE_PATH)
    assert read, f"could not read {SERVICE_PATH}"
    return parser


def test_service_file_exists():
    assert SERVICE_PATH.is_file()


def test_service_file_parses_as_well_formed_ini_with_expected_sections():
    parser = _load()
    assert parser.sections() == ["Unit", "Service", "Install"]


def test_service_does_not_run_as_root():
    parser = _load()
    assert parser.get("Service", "User") == "lanfence"
    assert parser.get("Service", "Group") == "lanfence"


def test_service_grants_only_cap_net_raw_never_a_broader_set():
    parser = _load()
    assert parser.get("Service", "AmbientCapabilities").strip() == "CAP_NET_RAW"
    assert parser.get("Service", "CapabilityBoundingSet").strip() == "CAP_NET_RAW"


def test_service_sets_no_new_privileges():
    parser = _load()
    assert parser.get("Service", "NoNewPrivileges").lower() == "true"


def test_service_sets_restrictive_umask():
    parser = _load()
    assert parser.get("Service", "UMask") == "0077"


def test_service_uses_state_directory_not_a_hardcoded_writable_path():
    parser = _load()
    assert parser.get("Service", "StateDirectory") == "lanfence"
    assert parser.get("Service", "StateDirectoryMode") == "0700"


def test_service_protects_the_filesystem():
    parser = _load()
    assert parser.get("Service", "ProtectSystem") == "strict"
    assert parser.get("Service", "ProtectHome").lower() == "true"


def test_service_restricts_address_families_to_what_scanning_and_alerts_need():
    parser = _load()
    families = set(parser.get("Service", "RestrictAddressFamilies").split())
    assert families == {"AF_UNIX", "AF_INET", "AF_INET6", "AF_PACKET", "AF_NETLINK"}


def test_service_does_not_instruct_setcap_on_the_interpreter():
    """The hardening approach must be systemd capability grants, not a
    setcap invocation anywhere in this file's own setup instructions -
    `setcap` may still be *mentioned* to explain why it's avoided."""

    text = SERVICE_PATH.read_text()
    assert "setcap cap_net_raw" not in text.lower()


def test_service_documents_account_creation_and_migration():
    text = SERVICE_PATH.read_text()
    assert "useradd" in text
    assert "migrat" in text.lower()
    assert "systemd-analyze verify" in text


def test_service_still_declares_capability_requirement_needed_for_scanning():
    """A quick cross-check against lanfence's own documented requirement
    (see lanfence/scanner.py and README.md's Install section) - this test
    would fail if that requirement ever changed without this file being
    updated to match."""

    scanner_source = (Path(__file__).resolve().parents[1] / "lanfence" / "scanner.py").read_text()
    assert "CAP_NET_RAW" in scanner_source

    parser = _load()
    assert "CAP_NET_RAW" in parser.get("Service", "AmbientCapabilities")
