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
