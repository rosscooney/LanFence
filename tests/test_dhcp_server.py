from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.dhcp_server import (
    dhcp_server_detection_active,
    dhcp_server_inventory,
    process_dhcp_server_sighting,
)
from lanfence.scanner import DhcpServerSighting


def _now():
    return datetime.now(timezone.utc)


def _sighting(**overrides):
    base = dict(
        interface="eth0", server_id="192.168.1.66", message_type="offer", observed_at=_now(),
        source_ip="192.168.1.66", source_mac="bb:bb:bb:bb:bb:bb", relay_ip=None,
        transaction_id=1, client_mac_evidence="aa:bb:cc:dd:ee:ff", offered_ip="192.168.1.50",
        router=None, dns=None,
    )
    base.update(overrides)
    return DhcpServerSighting(**base)


def _approved_cfg(**overrides) -> Config:
    base = dict(dhcp_servers={
        "enabled": True,
        "approved": [{"interface": "eth0", "server_ip": "192.168.1.1", "name": "Router"}],
    })
    base.update(overrides)
    return Config(**base)


# --- process_dhcp_server_sighting: approval, findings, cooldown ------------


def test_unapproved_server_produces_finding_with_no_mac(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        finding = process_dhcp_server_sighting(_sighting(), store, _approved_cfg())

    assert finding is not None
    assert finding.mac is None
    assert finding.kind == "network_service"
    assert finding.severity == "medium"
    assert finding.subject_id == "eth0/192.168.1.66"
    assert "Unexpected DHCP server" in finding.title


def test_approved_server_produces_no_finding_but_updates_inventory(tmp_path: Path):
    cfg = _approved_cfg()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        finding = process_dhcp_server_sighting(
            _sighting(server_id="192.168.1.1", source_mac="aa:aa:aa:aa:aa:aa"), store, cfg
        )
        inventory = dhcp_server_inventory(store, cfg)

    assert finding is None
    assert len(inventory) == 1
    assert inventory[0].approved is True
    assert inventory[0].name == "Router"


def test_detection_disabled_produces_no_finding_but_still_updates_inventory(tmp_path: Path):
    cfg = Config(dhcp_servers={"enabled": False})
    with DeviceStore(tmp_path / "db.sqlite") as store:
        finding = process_dhcp_server_sighting(_sighting(), store, cfg)
        inventory = dhcp_server_inventory(store, cfg)

    assert finding is None
    assert len(inventory) == 1  # observed regardless of enabled - see dhcp-servers CLI


def test_repeated_unapproved_sighting_within_cooldown_fires_once(tmp_path: Path):
    cfg = _approved_cfg(dhcp_servers={
        "enabled": True, "approved": [], "alert_cooldown_seconds": 3600,
    })
    t0 = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        first = process_dhcp_server_sighting(_sighting(observed_at=t0), store, cfg)
        second = process_dhcp_server_sighting(
            _sighting(observed_at=t0 + timedelta(seconds=1)), store, cfg
        )
        third_after_cooldown = process_dhcp_server_sighting(
            _sighting(observed_at=t0 + timedelta(hours=2)), store, cfg
        )

    assert first is not None
    assert second is None  # within cooldown
    assert third_after_cooldown is not None  # cooldown elapsed


def test_cooldown_is_independent_per_server_identifier(tmp_path: Path):
    cfg = _approved_cfg(dhcp_servers={"enabled": True, "approved": []})
    t0 = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        a = process_dhcp_server_sighting(_sighting(server_id="10.0.0.5", observed_at=t0), store, cfg)
        b = process_dhcp_server_sighting(_sighting(server_id="10.0.0.6", observed_at=t0), store, cfg)

    assert a is not None
    assert b is not None  # a different server - independent cooldown


def test_cooldown_is_independent_per_interface(tmp_path: Path):
    cfg = _approved_cfg(dhcp_servers={"enabled": True, "approved": []})
    t0 = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        a = process_dhcp_server_sighting(
            _sighting(interface="eth0", server_id="10.0.0.5", observed_at=t0), store, cfg
        )
        b = process_dhcp_server_sighting(
            _sighting(interface="eth1", server_id="10.0.0.5", observed_at=t0), store, cfg
        )

    assert a is not None
    assert b is not None  # same server_id, different interface - independent


def test_zero_cooldown_fires_every_time(tmp_path: Path):
    cfg = _approved_cfg(dhcp_servers={"enabled": True, "approved": [], "alert_cooldown_seconds": 0})
    t0 = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        a = process_dhcp_server_sighting(_sighting(observed_at=t0), store, cfg)
        b = process_dhcp_server_sighting(_sighting(observed_at=t0), store, cfg)

    assert a is not None
    assert b is not None


# --- inventory: coalescing, first/last seen, persistence -------------------


def test_inventory_coalesces_repeated_observations(tmp_path: Path):
    cfg = _approved_cfg(dhcp_servers={"enabled": False})
    t0 = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        process_dhcp_server_sighting(_sighting(observed_at=t0), store, cfg)
        process_dhcp_server_sighting(_sighting(observed_at=t0 + timedelta(minutes=1)), store, cfg)
        process_dhcp_server_sighting(_sighting(observed_at=t0 + timedelta(minutes=2)), store, cfg)
        inventory = dhcp_server_inventory(store, cfg)

    assert len(inventory) == 1
    record = inventory[0]
    assert record.observation_count == 3
    assert record.first_seen == t0
    assert record.last_seen == t0 + timedelta(minutes=2)


def test_inventory_persists_across_reopening_the_database(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    cfg = _approved_cfg(dhcp_servers={"enabled": False})
    t0 = _now()

    with DeviceStore(db_path) as store:
        process_dhcp_server_sighting(_sighting(observed_at=t0), store, cfg)

    with DeviceStore(db_path) as store:  # simulates a restart
        inventory = dhcp_server_inventory(store, cfg)

    assert len(inventory) == 1
    assert inventory[0].observation_count == 1


def test_inventory_migrates_idempotently_on_an_existing_database(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    with DeviceStore(db_path) as store:
        store._conn.execute("DROP TABLE dhcp_servers")
        store._conn.execute("DROP TABLE dhcp_server_findings")
        store._conn.commit()

    cfg = _approved_cfg(dhcp_servers={"enabled": False})
    with DeviceStore(db_path) as store:  # re-opening should recreate both tables
        process_dhcp_server_sighting(_sighting(), store, cfg)
        assert len(dhcp_server_inventory(store, cfg)) == 1


def test_approving_a_server_later_does_not_rewrite_historical_evidence(tmp_path: Path):
    """Historical findings persisted while a server was unapproved must
    keep saying so, even after config later approves it."""

    db_path = tmp_path / "db.sqlite"
    unapproved_cfg = _approved_cfg(dhcp_servers={"enabled": True, "approved": []})
    with DeviceStore(db_path) as store:
        process_dhcp_server_sighting(_sighting(), store, unapproved_cfg)
        rows = store._conn.execute(
            "SELECT approved_at_observation FROM dhcp_server_findings"
        ).fetchall()

    assert len(rows) == 1
    assert rows[0]["approved_at_observation"] == 0

    # Now approve it - the persisted finding evidence is untouched, only
    # *current* inventory approval status (computed fresh) changes.
    approved_cfg = _approved_cfg(dhcp_servers={
        "enabled": True, "approved": [{"interface": "eth0", "server_ip": "192.168.1.66"}],
    })
    with DeviceStore(db_path) as store:
        inventory = dhcp_server_inventory(store, approved_cfg)
        rows_after = store._conn.execute(
            "SELECT approved_at_observation FROM dhcp_server_findings"
        ).fetchall()

    assert inventory[0].approved is True
    assert rows_after[0]["approved_at_observation"] == 0  # unchanged


def test_dhcp_server_detection_active_requires_passive_and_dhcp_snooping(tmp_path: Path):
    cfg = Config(dhcp_servers={"enabled": True})
    assert dhcp_server_detection_active(cfg) is True

    cfg.scan.passive = False
    assert dhcp_server_detection_active(cfg) is False

    cfg.scan.passive = True
    cfg.scan.dhcp_snooping = False
    assert dhcp_server_detection_active(cfg) is False


def test_dhcp_server_detection_inactive_when_dhcp_servers_disabled():
    cfg = Config(dhcp_servers={"enabled": False})
    assert dhcp_server_detection_active(cfg) is False


# --- trust/presence-policy independence -------------------------------------


def test_unexpected_server_finding_fires_regardless_of_device_trust_or_presence(tmp_path: Path):
    """A trusted, intermittent-presence device acting as an unapproved DHCP
    server still generates this finding - role approval is independent of
    device trust, and presence policy has no bearing on a network-service
    finding (it isn't about a device at all)."""

    cfg = _approved_cfg(dhcp_servers={"enabled": True, "approved": []})
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="bb:bb:bb:bb:bb:bb", ip="192.168.1.66", hostname=None, vendor=None, seen_at=now)
        store.set_presence_policy("bb:bb:bb:bb:bb:bb", "intermittent", updated_at=now)
        from lanfence.allowlist import Allowlist
        allowlist = Allowlist.load(None)
        allowlist.add("bb:bb:bb:bb:bb:bb", "Trusted Thing")

        finding = process_dhcp_server_sighting(
            _sighting(source_mac="bb:bb:bb:bb:bb:bb"), store, cfg
        )

    assert finding is not None
    assert finding.severity == "medium"


def test_no_placeholder_mac_ever_used(tmp_path: Path):
    """Never a fabricated/placeholder MAC, never the client's, never the
    relay's."""

    cfg = _approved_cfg(dhcp_servers={"enabled": True, "approved": []})
    with DeviceStore(tmp_path / "db.sqlite") as store:
        finding = process_dhcp_server_sighting(
            _sighting(client_mac_evidence="aa:bb:cc:dd:ee:ff", source_mac="99:99:99:99:99:99"),
            store, cfg,
        )

    assert finding.mac is None
    assert "aa:bb:cc:dd:ee:ff" not in (finding.mac or "")
    assert "99:99:99:99:99:99" not in (finding.mac or "")
