from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from lanfence.cli import app
from lanfence.db import DeviceStore
from lanfence.models import BaselineItem, ChangeEvent, DeviceBaseline

runner = CliRunner()
NAS = "00:11:32:aa:bb:01"
PHONE = "3c:22:fb:aa:bb:02"


def _now():
    return datetime.now(timezone.utc)


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({
        "db_path": str(tmp_path / "lanfence.db"), "allowlist_file": str(tmp_path / "allowlist.yaml"),
    }))
    return path


def _store(config_path: Path) -> DeviceStore:
    return DeviceStore(yaml.safe_load(config_path.read_text())["db_path"])


@pytest.fixture
def seeded(config_path: Path):
    """A NAS with an established baseline that just gained SSH, and a phone
    whose address changed yesterday."""

    now = _now()
    with _store(config_path) as store:
        store.observe(mac=NAS, ip="192.168.1.10", hostname="diskstation", vendor="Synology Incorporated",
                      seen_at=now - timedelta(days=30))
        store.observe(mac=NAS, ip="192.168.1.10", hostname="diskstation", vendor="Synology Incorporated", seen_at=now)
        store.observe(mac=PHONE, ip="192.168.1.45", hostname="janes-iphone", vendor="Apple, Inc.", seen_at=now)
        store.save_baseline(DeviceBaseline(
            mac=NAS, started_at=now - timedelta(days=30), established_at=now - timedelta(days=23),
            ipv4="192.168.1.10", hostname="diskstation",
        ), now=now)
        for value, in_baseline, first_seen in (
            ("tcp/443", True, now - timedelta(days=30)), ("tcp/22", False, now - timedelta(hours=2)),
        ):
            store.save_baseline_item(BaselineItem(
                mac=NAS, signal="port", value=value, in_baseline=in_baseline,
                origin="initial" if in_baseline else "observed", first_seen=first_seen, last_seen=now,
            ))
        ssh = store.record_change_event(ChangeEvent(
            mac=NAS, change_type="service_new", occurred_at=now - timedelta(hours=2), signal="port", subject="tcp/22",
            source="inspection", significance="high", policy_id="new-remote-admin-service", alerted_at=now,
            current={"baseline": ["HTTPS / TCP 443"], "established": True, "monitored_days": 30},
        ))
        ip = store.record_change_event(ChangeEvent(
            mac=PHONE, change_type="ip_changed", occurred_at=now - timedelta(days=1), signal="ip",
            subject="192.168.1.45", source="arp", significance="info",
            previous={"ipv4": "192.168.1.20"}, current={"ipv4": "192.168.1.45", "different_network": False},
        ))
    return {"ssh": ssh.id, "ip": ip.id}


def _invoke(config_path, *args):
    return runner.invoke(app, [*args, "--config", str(config_path)])


# --- lanfence changes ---------------------------------------------------------------


def test_changes_lists_newest_first_grouped_by_day(config_path, seeded):
    result = _invoke(config_path, "changes")
    assert result.exit_code == 0, result.output
    assert "Today" in result.output and "Yesterday" in result.output
    assert result.output.index("New service detected: SSH / TCP 22") < result.output.index("IP address changed")
    assert "HIGH" in result.output


def test_changes_filters(config_path, seeded):
    high = _invoke(config_path, "changes", "--severity", "high")
    assert "SSH" in high.output and "IP address changed" not in high.output
    by_type = _invoke(config_path, "changes", "--type", "ip_changed")
    assert "IP address changed" in by_type.output and "SSH" not in by_type.output
    by_device = _invoke(config_path, "changes", "--mac", PHONE)
    assert "IP address changed" in by_device.output and "SSH" not in by_device.output
    recent = _invoke(config_path, "changes", "--since", "12h")
    assert "SSH" in recent.output and "IP address changed" not in recent.output


def test_changes_json_is_structured(config_path, seeded):
    result = _invoke(config_path, "changes", "--format", "json")
    events = json.loads(result.output)
    ssh = next(e for e in events if e["change_type"] == "service_new")
    assert ssh["title"] == "New service detected: SSH / TCP 22"
    assert ssh["device"] == "diskstation"
    assert ssh["current"]["baseline"] == ["HTTPS / TCP 443"]
    assert ssh["policy_id"] == "new-remote-admin-service"


def test_change_detail_explains_it(config_path, seeded):
    result = _invoke(config_path, "changes", str(seeded["ssh"]))
    assert result.exit_code == 0, result.output
    assert "New service detected: SSH / TCP 22" in result.output
    assert "Previous baseline: HTTPS / TCP 443" in result.output
    assert "Policy:       new-remote-admin-service" in result.output
    assert "alert sent" in result.output


def test_accepting_a_change_from_the_cli_updates_the_baseline(config_path, seeded):
    result = _invoke(config_path, "changes", str(seeded["ssh"]), "--accept", "--note", "Enabled for backups")
    assert result.exit_code == 0, result.output
    assert f"change #{seeded['ssh']}: accepted" in result.output
    with _store(config_path) as store:
        ssh = next(i for i in store.baseline_items(NAS) if i.value == "tcp/22")
        assert (ssh.in_baseline, ssh.origin) == (True, "accepted")
        assert store.get_change_event(seeded["ssh"]).review_note == "Enabled for backups"


def test_snoozing_and_unreviewed_filter(config_path, seeded):
    _invoke(config_path, "changes", str(seeded["ssh"]), "--snooze", "24h")
    listed = _invoke(config_path, "changes", "--unreviewed")
    assert "SSH" not in listed.output


@pytest.mark.parametrize("args", [
    ["changes", "--reviewed"],  # action without a change number
    ["changes", "1", "--reviewed", "--accept"],  # two actions
    ["changes", "--type", "port_delta"],
    ["changes", "--severity", "urgent"],
    ["changes", "999"],
])
def test_changes_rejects_bad_input(config_path, seeded, args):
    assert _invoke(config_path, *args).exit_code == 2


# --- lanfence baseline ------------------------------------------------------------------


def test_baseline_shows_expected_and_pending(config_path, seeded):
    result = _invoke(config_path, "baseline", NAS)
    assert result.exit_code == 0, result.output
    assert "Status:        established" in result.output
    expected = result.output.index("Expected:")
    pending = result.output.index("Pending review:")
    assert expected < result.output.index("HTTPS / TCP 443") < pending < result.output.index("SSH / TCP 22")


def test_baseline_compare_json(config_path, seeded):
    result = _invoke(config_path, "baseline", NAS, "--compare", "baseline", "--format", "json")
    rows = {r["label"]: r["status"] for r in json.loads(result.output)["comparison"]["rows"]}
    assert rows == {"SSH / TCP 22": "new", "HTTPS / TCP 443": "unchanged"}
    week = _invoke(config_path, "baseline", NAS, "--compare", "7d")
    assert "NEW" in week.output


def test_baseline_exclude_include_and_accept_pending(config_path, seeded):
    _invoke(config_path, "baseline", NAS, "--exclude", "ip", "--exclude", "hostname")
    with _store(config_path) as store:
        assert store.get_baseline(NAS).excluded_signals == ["hostname", "ip"]
    _invoke(config_path, "baseline", NAS, "--include", "ip")
    result = _invoke(config_path, "baseline", NAS, "--accept-pending")
    assert "accepted 1 pending item(s)" in result.output
    with _store(config_path) as store:
        assert store.get_baseline(NAS).excluded_signals == ["hostname"]
        assert all(i.in_baseline for i in store.baseline_items(NAS))


def test_baseline_reset_needs_confirmation(config_path, seeded):
    refused = _invoke(config_path, "baseline", NAS, "--reset")
    assert refused.exit_code == 2
    result = _invoke(config_path, "baseline", NAS, "--reset", "--yes")
    assert "baseline reset" in result.output
    with _store(config_path) as store:
        assert store.get_baseline(NAS) is None
        assert store.get_change_event(seeded["ssh"]) is not None  # history kept


def test_baseline_rejects_unknown_signals_and_devices(config_path, seeded):
    assert _invoke(config_path, "baseline", NAS, "--exclude", "everything").exit_code == 2
    assert _invoke(config_path, "baseline", "aa:bb:cc:dd:ee:ff").exit_code == 2


# --- lanfence risk / policy / device -----------------------------------------------------


def test_risk_for_one_device_explains_itself(config_path, seeded):
    result = _invoke(config_path, "risk", NAS)
    assert result.exit_code == 0, result.output
    assert "Risk score:" in result.output and "Why:" in result.output and "Recommended:" in result.output
    payload = json.loads(_invoke(config_path, "risk", NAS, "--format", "json").output)
    assert 0 <= payload["score"] <= 100
    assert {c["label"] for c in payload["contributions"]} >= {"Device is not trusted"}


def test_risk_ranks_every_assessed_device(config_path, seeded):
    from lanfence.models import RiskAssessment

    with _store(config_path) as store:
        store.save_risk(NAS, RiskAssessment(score=57, level="high"), now=_now())
        store.save_risk(PHONE, RiskAssessment(score=12, level="low"), now=_now())
    result = _invoke(config_path, "risk")
    assert result.output.index("diskstation") < result.output.index("janes-iphone")


def test_policy_lists_the_defaults_and_config_overrides(config_path):
    result = _invoke(config_path, "policy", "--list")
    assert "built-in defaults" in result.output and "new-remote-admin-service" in result.output
    cfg = yaml.safe_load(config_path.read_text())
    cfg["policies"] = [{"id": "only-ssh", "triggers": ["service_new"], "severity": "high",
                        "conditions": {"services": ["tcp/22"]}}]
    config_path.write_text(yaml.safe_dump(cfg))
    payload = json.loads(_invoke(config_path, "policy", "--format", "json").output)
    assert payload["source"] == "config"
    assert [p["id"] for p in payload["policies"]] == ["only-ssh"]


def test_device_shows_risk_and_baseline(config_path, seeded):
    table = _invoke(config_path, "device", NAS)
    assert "Risk score:" in table.output
    assert "Baseline:     established; 1 item(s) pending review" in table.output
    payload = json.loads(_invoke(config_path, "device", NAS, "--format", "json").output)
    assert payload["baseline"]["maturity"] == "established"
    assert payload["baseline"]["pending_review"] == 1
    assert payload["risk"]["level"] in ("low", "moderate", "high", "critical")
