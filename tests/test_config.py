from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from lanfence.config import Config


def test_defaults():
    cfg = Config()
    assert cfg.scan.scan_interval_seconds == 60.0
    assert cfg.scan.passive is True
    assert cfg.scan.ipv6 is True
    assert cfg.scan.dhcp_snooping is True
    assert cfg.scan.offline_grace_seconds == 180.0
    assert cfg.scan.offline_after_missed_scans == 3
    assert cfg.alerts.min_severity == "medium"
    assert cfg.digest.channels == []
    assert cfg.digest.send_when_empty is False
    assert cfg.digest.max_devices_per_section == 20


def test_digest_channels_rejects_unsupported_name(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"digest": {"channels": ["sms"]}}), encoding="utf-8")
    with pytest.raises(Exception):
        Config.load(path)


def test_digest_channels_rejects_syslog():
    with pytest.raises(Exception):
        Config(digest={"channels": ["syslog"]})


def test_digest_channels_accepts_supported_names():
    cfg = Config(digest={"channels": ["email", "webhook", "slack", "discord", "teams", "ntfy"]})
    assert cfg.digest.channels == ["email", "webhook", "slack", "discord", "teams", "ntfy"]


def test_digest_max_devices_per_section_rejects_zero():
    with pytest.raises(Exception):
        Config(digest={"max_devices_per_section": 0})


def test_digest_send_when_empty_default_false():
    assert Config().digest.send_when_empty is False


def test_offline_grace_seconds_rejects_negative(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"scan": {"offline_grace_seconds": -1}}), encoding="utf-8")
    with pytest.raises(Exception):
        Config.load(path)


def test_offline_grace_seconds_rejects_non_finite(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"scan": {"offline_grace_seconds": float("inf")}}), encoding="utf-8")
    with pytest.raises(Exception):
        Config.load(path)


def test_offline_grace_seconds_zero_is_allowed():
    cfg = Config(scan={"offline_grace_seconds": 0})
    assert cfg.scan.offline_grace_seconds == 0


def test_offline_after_missed_scans_rejects_zero(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"scan": {"offline_after_missed_scans": 0}}), encoding="utf-8")
    with pytest.raises(Exception):
        Config.load(path)


def test_offline_after_missed_scans_rejects_negative(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"scan": {"offline_after_missed_scans": -1}}), encoding="utf-8")
    with pytest.raises(Exception):
        Config.load(path)


def test_offline_after_missed_scans_one_is_allowed():
    cfg = Config(scan={"offline_after_missed_scans": 1})
    assert cfg.scan.offline_after_missed_scans == 1


def test_load_none_returns_defaults():
    cfg = Config.load(None)
    assert cfg == Config()


def test_load_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        Config.load(tmp_path / "nope.yaml")


def test_load_overrides_nested_fields(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({"scan": {"scan_interval_seconds": 30, "passive": False}}),
        encoding="utf-8",
    )
    cfg = Config.load(path)
    assert cfg.scan.scan_interval_seconds == 30
    assert cfg.scan.passive is False
    # untouched fields keep their defaults
    assert cfg.scan.resolve_hostnames is True


def test_unknown_top_level_key_rejected(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"not_a_real_field": 1}), encoding="utf-8")
    with pytest.raises(Exception):
        Config.load(path)


def test_bad_severity_rejected(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"alerts": {"min_severity": "critical"}}), encoding="utf-8")
    with pytest.raises(Exception):
        Config.load(path)


def test_resolved_paths_expand_user():
    cfg = Config(db_path=Path("~/x.db"), allowlist_file=Path("~/allow.yaml"))
    assert "~" not in str(cfg.resolved_db_path())
    assert "~" not in str(cfg.resolved_allowlist_file())


# --- resolving `~` correctly under `sudo` -----------------------------------
#
# `sudo lanfence scan`/`monitor` runs as root, and stock sudoers resets
# $HOME to root's home - a bare Path.expanduser() would then silently point
# db_path/allowlist_file at /root while a plain, unprivileged `lanfence
# devices`/`review`/`allow` resolves the same `~` to the real operator's
# home, so the two commands would read and write two different databases
# with no error at all (see the GitHub issue this was reported from).


def test_resolved_db_path_uses_sudo_user_home_when_run_as_root_via_sudo(monkeypatch):
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        "pwd.getpwnam", lambda name: type("_pw", (), {"pw_dir": "/home/alice"})()
    )
    cfg = Config(db_path=Path("~/.local/share/lanfence/lanfence.db"))
    assert str(cfg.resolved_db_path()) == "/home/alice/.local/share/lanfence/lanfence.db"


def test_resolved_allowlist_file_uses_sudo_user_home_when_run_as_root_via_sudo(monkeypatch):
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        "pwd.getpwnam", lambda name: type("_pw", (), {"pw_dir": "/home/alice"})()
    )
    cfg = Config(allowlist_file=Path("~/.config/lanfence/allowlist.yaml"))
    assert str(cfg.resolved_allowlist_file()) == "/home/alice/.config/lanfence/allowlist.yaml"


def test_resolved_db_path_bare_tilde_uses_sudo_user_home(monkeypatch):
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        "pwd.getpwnam", lambda name: type("_pw", (), {"pw_dir": "/home/alice"})()
    )
    cfg = Config(db_path=Path("~"))
    assert str(cfg.resolved_db_path()) == "/home/alice"


def test_resolved_db_path_not_root_ignores_sudo_user(monkeypatch):
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 1000)
    monkeypatch.setenv("SUDO_USER", "alice")
    cfg = Config(db_path=Path("~/x.db"))
    # Not actually root - SUDO_USER (however it got set) must be ignored,
    # and the normal expanduser() behavior (the real caller's own $HOME) used.
    assert str(cfg.resolved_db_path()) == str(Path("~/x.db").expanduser())


def test_resolved_db_path_root_without_sudo_user_uses_normal_expanduser(monkeypatch):
    # A genuine root login or system service - no SUDO_USER at all - is left
    # alone; /root legitimately is the operator's home there.
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_USER", raising=False)
    cfg = Config(db_path=Path("~/x.db"))
    assert str(cfg.resolved_db_path()) == str(Path("~/x.db").expanduser())


def test_resolved_db_path_sudo_user_is_root_uses_normal_expanduser(monkeypatch):
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "root")
    cfg = Config(db_path=Path("~/x.db"))
    assert str(cfg.resolved_db_path()) == str(Path("~/x.db").expanduser())


def test_resolved_db_path_unknown_sudo_user_falls_back_to_normal_expanduser(monkeypatch):
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "nosuchuser")

    def _raise(name):
        raise KeyError(name)

    monkeypatch.setattr("pwd.getpwnam", _raise)
    cfg = Config(db_path=Path("~/x.db"))
    assert str(cfg.resolved_db_path()) == str(Path("~/x.db").expanduser())


def test_resolved_paths_absolute_path_unaffected_by_sudo_substitution(monkeypatch):
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        "pwd.getpwnam", lambda name: type("_pw", (), {"pw_dir": "/home/alice"})()
    )
    cfg = Config(db_path=Path("/var/lib/lanfence/lanfence.db"))
    assert str(cfg.resolved_db_path()) == "/var/lib/lanfence/lanfence.db"


def test_empty_file_returns_defaults(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("", encoding="utf-8")
    cfg = Config.load(path)
    assert cfg == Config()


def test_non_mapping_file_rejected(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ValueError):
        Config.load(path)


# --- dhcp_servers ------------------------------------------------------


def test_dhcp_servers_defaults():
    cfg = Config()
    assert cfg.dhcp_servers.enabled is False
    assert cfg.dhcp_servers.approved == []
    assert cfg.dhcp_servers.alert_cooldown_seconds == 3600.0


def test_dhcp_servers_accepts_valid_approval():
    cfg = Config(dhcp_servers={
        "enabled": True,
        "approved": [{"interface": "eth0", "server_ip": "192.168.1.1", "name": "Router"}],
    })
    assert cfg.dhcp_servers.approved[0].interface == "eth0"
    assert cfg.dhcp_servers.approved[0].server_ip == "192.168.1.1"
    assert cfg.dhcp_servers.approved[0].name == "Router"


def test_dhcp_servers_supports_vlan_subinterface_name():
    cfg = Config(dhcp_servers={"approved": [{"interface": "eth0.20", "server_ip": "10.20.0.1"}]})
    assert cfg.dhcp_servers.approved[0].interface == "eth0.20"


def test_dhcp_servers_rejects_empty_interface():
    with pytest.raises(Exception):
        Config(dhcp_servers={"approved": [{"interface": "", "server_ip": "192.168.1.1"}]})


def test_dhcp_servers_rejects_invalid_ip():
    with pytest.raises(Exception):
        Config(dhcp_servers={"approved": [{"interface": "eth0", "server_ip": "not-an-ip"}]})


def test_dhcp_servers_rejects_ipv6_server_ip():
    with pytest.raises(Exception):
        Config(dhcp_servers={"approved": [{"interface": "eth0", "server_ip": "::1"}]})


def test_dhcp_servers_rejects_duplicate_entries():
    with pytest.raises(Exception):
        Config(dhcp_servers={"approved": [
            {"interface": "eth0", "server_ip": "192.168.1.1"},
            {"interface": "eth0", "server_ip": "192.168.1.1"},
        ]})


def test_dhcp_servers_allows_same_ip_on_different_interfaces():
    cfg = Config(dhcp_servers={"approved": [
        {"interface": "eth0", "server_ip": "192.168.1.1"},
        {"interface": "eth1", "server_ip": "192.168.1.1"},
    ]})
    assert len(cfg.dhcp_servers.approved) == 2


def test_dhcp_servers_allows_multiple_servers_per_interface():
    cfg = Config(dhcp_servers={"approved": [
        {"interface": "eth0", "server_ip": "192.168.1.1"},
        {"interface": "eth0", "server_ip": "192.168.1.2"},
    ]})
    assert len(cfg.dhcp_servers.approved) == 2


def test_dhcp_servers_rejects_negative_cooldown():
    with pytest.raises(Exception):
        Config(dhcp_servers={"alert_cooldown_seconds": -1})


def test_dhcp_servers_rejects_non_finite_cooldown():
    with pytest.raises(Exception):
        Config(dhcp_servers={"alert_cooldown_seconds": float("inf")})


def test_dhcp_servers_cooldown_zero_is_allowed():
    cfg = Config(dhcp_servers={"alert_cooldown_seconds": 0})
    assert cfg.dhcp_servers.alert_cooldown_seconds == 0


def test_discovery_defaults_are_opt_in():
    cfg = Config()
    assert cfg.discovery.mdns is False
    assert cfg.discovery.ssdp is False


def test_discovery_can_be_enabled():
    cfg = Config(discovery={"mdns": True, "ssdp": True})
    assert cfg.discovery.mdns is True
    assert cfg.discovery.ssdp is True


def test_discovery_rejects_unknown_field():
    with pytest.raises(Exception):
        Config(discovery={"unknown_field": True})


def test_email_alert_config_ca_file_defaults_to_none():
    cfg = Config()
    assert cfg.alerts.email.ca_file is None


def test_email_alert_config_ca_file_round_trips_from_yaml(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({"alerts": {"email": {"ca_file": "/etc/ssl/private-ca.pem"}}}), encoding="utf-8"
    )
    cfg = Config.load(path)
    assert cfg.alerts.email.ca_file == "/etc/ssl/private-ca.pem"


# --- global alert rate limit -------------------------------------------


def test_alert_config_global_rate_limit_defaults():
    cfg = Config()
    assert cfg.alerts.global_rate_limit_max == 20
    assert cfg.alerts.global_rate_limit_window_seconds == 60.0


def test_alert_config_global_rate_limit_rejects_negative_max():
    with pytest.raises(Exception):
        Config(alerts={"global_rate_limit_max": -1})


def test_alert_config_global_rate_limit_rejects_negative_window():
    with pytest.raises(Exception):
        Config(alerts={"global_rate_limit_window_seconds": -1})


def test_alert_config_global_rate_limit_zero_is_allowed():
    cfg = Config(alerts={"global_rate_limit_max": 0})
    assert cfg.alerts.global_rate_limit_max == 0


# --- Twilio SMS segment budget -------------------------------------------


def test_twilio_config_max_segments_per_day_default():
    cfg = Config()
    assert cfg.alerts.twilio.max_segments_per_day == 200


def test_twilio_config_max_segments_per_day_rejects_negative():
    with pytest.raises(Exception):
        Config(alerts={"twilio": {"max_segments_per_day": -1}})


def test_twilio_config_max_segments_per_day_zero_is_allowed():
    cfg = Config(alerts={"twilio": {"max_segments_per_day": 0}})
    assert cfg.alerts.twilio.max_segments_per_day == 0


# --- retention caps ------------------------------------------------------


def test_retention_config_defaults():
    cfg = Config()
    assert cfg.retention.max_evidence_rows_per_mac == 100
    assert cfg.retention.max_dhcp_server_findings == 5000
    assert cfg.retention.max_discovery_rows_per_table == 5000


def test_retention_config_rejects_zero_or_negative():
    with pytest.raises(Exception):
        Config(retention={"max_evidence_rows_per_mac": 0})
    with pytest.raises(Exception):
        Config(retention={"max_dhcp_server_findings": -5})
    with pytest.raises(Exception):
        Config(retention={"max_discovery_rows_per_table": 0})


def test_retention_config_round_trips_from_yaml(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({"retention": {"max_evidence_rows_per_mac": 25}}), encoding="utf-8"
    )
    cfg = Config.load(path)
    assert cfg.retention.max_evidence_rows_per_mac == 25


# --- passive queue maxsize -------------------------------------------------


def test_scan_config_passive_queue_maxsize_default():
    cfg = Config()
    assert cfg.scan.passive_queue_maxsize == 2000


def test_scan_config_passive_queue_maxsize_rejects_non_positive():
    with pytest.raises(Exception):
        Config(scan={"passive_queue_maxsize": 0})
