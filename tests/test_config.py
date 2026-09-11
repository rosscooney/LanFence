from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from lanfence.config import Config


def test_defaults():
    cfg = Config()
    assert cfg.scan.scan_interval_seconds == 60.0
    assert cfg.scan.passive is True
    assert cfg.alerts.min_severity == "medium"


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
