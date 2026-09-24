from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from lanfence.db import DeviceStore
from lanfence.models import DeviceMetadata


def _now():
    return datetime.now(timezone.utc)


# --- defaults / migration -----------------------------------------------


def test_get_device_metadata_defaults_to_unset(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        meta = store.get_device_metadata("aa:bb:cc:dd:ee:ff")

    assert meta.mac == "aa:bb:cc:dd:ee:ff"
    assert meta.owner is None
    assert meta.location is None
    assert meta.friendly_name is None
    assert meta.asset_type is None
    assert meta.purpose is None
    assert meta.notes is None
    assert meta.category_override is None
    assert meta.updated_at is None


def test_device_metadata_table_migration_adds_asset_columns(tmp_path: Path):
    """A database created before Know Your Network's asset fields (only
    owner/location on device_metadata) gets the new columns idempotently,
    without losing an existing owner/location value."""

    db_path = tmp_path / "db.sqlite"
    t0 = _now()
    with DeviceStore(db_path) as store:
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice")
        # Simulate a pre-feature database by rebuilding device_metadata
        # without the new columns, preserving the pre-existing row.
        store._conn.executescript(
            """
            CREATE TABLE device_metadata_old (
                mac TEXT PRIMARY KEY, owner TEXT, location TEXT, updated_at TEXT NOT NULL
            );
            INSERT INTO device_metadata_old SELECT mac, owner, location, updated_at FROM device_metadata;
            DROP TABLE device_metadata;
            ALTER TABLE device_metadata_old RENAME TO device_metadata;
            """
        )
        store._conn.commit()

    with DeviceStore(db_path) as store:  # re-opening should add the missing columns
        meta = store.get_device_metadata("aa:bb:cc:dd:ee:ff")
        assert meta.owner == "Alice"  # pre-existing value preserved
        assert meta.friendly_name is None
        assert meta.asset_type is None

        # And the new columns are genuinely writable now, not just readable.
        updated = store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", updated_at=_now(), friendly_name="Boardroom TV", asset_type="Company",
        )
        assert updated.friendly_name == "Boardroom TV"
        assert updated.asset_type == "Company"
        assert updated.owner == "Alice"  # untouched by the asset-field update


def test_device_metadata_for_macs_empty_list_returns_empty_dict(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert store.device_metadata_for_macs([]) == {}


def test_device_metadata_for_macs_bulk_fetch(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice")
        store.update_device_metadata("11:22:33:44:55:66", updated_at=t0, owner="Bob")
        by_mac = store.device_metadata_for_macs(["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "77:88:99:aa:bb:cc"])

    assert by_mac["aa:bb:cc:dd:ee:ff"].owner == "Alice"
    assert by_mac["11:22:33:44:55:66"].owner == "Bob"
    assert "77:88:99:aa:bb:cc" not in by_mac  # never observed, never queried for individually


# --- set / clear / tri-state update --------------------------------------


def test_update_device_metadata_sets_one_field(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        result = store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice")

    assert result.owner == "Alice"
    assert result.location is None
    assert result.updated_at == t0


def test_update_device_metadata_sets_several_fields_at_once(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        result = store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice", location="Office",
        )

    assert (result.owner, result.location) == ("Alice", "Office")


def test_update_device_metadata_omitted_field_left_unchanged(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice")
        t1 = t0 + timedelta(minutes=5)
        result = store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t1, location="Office")

    assert result.owner == "Alice"  # untouched by the second call
    assert result.location == "Office"
    assert result.updated_at == t1


def test_update_device_metadata_clears_a_field_with_explicit_none(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice")
        t1 = t0 + timedelta(minutes=5)
        result = store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t1, owner=None)

    assert result.owner is None


def test_update_device_metadata_no_op_does_not_advance_updated_at(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice")
        t1 = t0 + timedelta(minutes=5)
        # Setting the exact same value again is a no-op - updated_at should
        # not move, since nothing actually changed.
        result = store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t1, owner="Alice")

    assert result.updated_at == t0


def test_update_device_metadata_persists_across_reopen(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    with DeviceStore(db_path) as store:
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=_now(), owner="Alice")

    with DeviceStore(db_path) as store:
        meta = store.get_device_metadata("aa:bb:cc:dd:ee:ff")

    assert meta.owner == "Alice"


# --- Know Your Network asset/ownership fields -------------------------------


def test_update_device_metadata_sets_all_asset_fields_at_once(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        result = store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", updated_at=_now(), owner="Operations", friendly_name="Boardroom TV",
            asset_type="Company", purpose="Boardroom display", notes="Wall-mounted, HDMI 2",
            category_override="Media Device",
        )

    assert result.owner == "Operations"
    assert result.friendly_name == "Boardroom TV"
    assert result.asset_type == "Company"
    assert result.purpose == "Boardroom display"
    assert result.notes == "Wall-mounted, HDMI 2"
    assert result.category_override == "Media Device"


def test_update_device_metadata_asset_fields_independent_of_owner_location(tmp_path: Path):
    """Setting an asset field must not disturb owner/location, and vice
    versa - each field is its own independent tri-state slot."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice", location="Office")
        result = store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", updated_at=t0 + timedelta(minutes=5), friendly_name="Alice's Laptop",
        )

    assert result.owner == "Alice"
    assert result.location == "Office"
    assert result.friendly_name == "Alice's Laptop"


def test_update_device_metadata_clears_category_override_with_explicit_none(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, category_override="Printer")
        t1 = t0 + timedelta(minutes=5)
        result = store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t1, category_override=None)

    assert result.category_override is None


# --- model validation -----------------------------------------------------


def test_device_metadata_normalizes_mac_case():
    meta = DeviceMetadata(mac="AA:BB:CC:DD:EE:FF")
    assert meta.mac == "aa:bb:cc:dd:ee:ff"


def test_device_metadata_rejects_invalid_mac():
    with pytest.raises(ValueError):
        DeviceMetadata(mac="not-a-mac")


def test_device_metadata_sanitizes_control_characters():
    meta = DeviceMetadata(mac="aa:bb:cc:dd:ee:ff", owner="Ali\x00ce")
    assert "\x00" not in (meta.owner or "")


# --- reset_all interaction -------------------------------------------------


def test_reset_all_clears_device_metadata(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=_now(), owner="Alice")
        store.reset_all()
        meta = store.get_device_metadata("aa:bb:cc:dd:ee:ff")

    assert meta.owner is None


def test_reset_all_via_cli_keep_allowlist_still_clears_metadata(tmp_path: Path):
    """`lanfence reset --keep-allowlist` still clears metadata - that flag's
    documented scope is the allowlist file only, not device inventory data."""

    import yaml
    from typer.testing import CliRunner

    from lanfence.cli import app

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {"db_path": str(tmp_path / "lanfence.db"), "allowlist_file": str(tmp_path / "allowlist.yaml")}
        ),
        encoding="utf-8",
    )
    cfg = yaml.safe_load(config_path.read_text())
    with DeviceStore(cfg["db_path"]) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=_now(), owner="Alice")

    runner = CliRunner()
    result = runner.invoke(app, ["reset", "--yes", "--keep-allowlist", "--config", str(config_path)])
    assert result.exit_code == 0

    with DeviceStore(cfg["db_path"]) as store:
        meta = store.get_device_metadata("aa:bb:cc:dd:ee:ff")

    assert meta.owner is None


# --- build_inventory integration ------------------------------------------


def test_build_inventory_joins_metadata_without_per_device_queries(tmp_path: Path):
    from lanfence.allowlist import Allowlist
    from lanfence.engine import build_inventory

    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor=None, seen_at=now)
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=now, owner="Alice")

        allowlist = Allowlist([], tmp_path / "allowlist.yaml")
        inventory = build_inventory(store, allowlist)

    by_mac = {d.mac: d for d in inventory}
    assert by_mac["aa:bb:cc:dd:ee:ff"].metadata.owner == "Alice"
    assert by_mac["11:22:33:44:55:66"].metadata.owner is None


def test_metadata_edit_creates_no_lifecycle_event(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        before = len(store.events_for("aa:bb:cc:dd:ee:ff"))
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=now, owner="Alice")
        after = len(store.events_for("aa:bb:cc:dd:ee:ff"))

    assert before == after
