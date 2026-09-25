from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from lanfence import baseline as baseline_mod
from lanfence.config import AlertConfig, Config
from lanfence.db import DeviceStore
from lanfence.engine import filter_rate_limited
from lanfence.fingerprint import SignatureSet
from lanfence.identity import IdentityRuleSet
from lanfence.models import AdvertisedService, ChangeEvent, Finding
from lanfence.policy import (
    DEFAULT_POLICIES,
    DeviceContext,
    Policy,
    PolicyConditions,
    change_alert,
    effective_policies,
    match,
    shape_builtin_finding,
)

NOW = datetime(2026, 9, 25, 3, 14, tzinfo=timezone.utc)
NAS = "00:11:32:aa:bb:01"
POLICIES = list(DEFAULT_POLICIES)
TRUSTED_NAS = DeviceContext(trusted=True, category="Storage / NAS", label="Office NAS")
UNKNOWN = DeviceContext(trusted=False, category="Unknown", label="00:11:22:33:44:55")


def _event(change_type, **kwargs):
    kwargs.setdefault("mac", NAS)
    return ChangeEvent(change_type=change_type, occurred_at=NOW, source="test", **kwargs)


def _matched(change_type, device, **kwargs):
    policy = match(POLICIES, _event(change_type, **kwargs), device)
    return policy.id if policy else None


# --- the built-in defaults (the spec's examples) --------------------------------


def test_new_unknown_device_is_high():
    assert _matched("new_device", UNKNOWN, significance="medium") == "new-unknown-device"


def test_new_infrastructure_device_is_critical():
    router = DeviceContext(trusted=False, category="Network Infrastructure")
    policy = match(POLICIES, _event("new_device"), router)
    assert (policy.id, policy.severity) == ("new-infrastructure-device", "critical")


def test_a_trusted_new_device_matches_no_policy():
    assert _matched("new_device", TRUSTED_NAS) is None


def test_new_ssh_is_high_even_on_a_trusted_server():
    """First match wins: the remote-admin policy sits above the trusted-server one."""

    policy = match(POLICIES, _event("service_new", signal="port", subject="tcp/22", significance="high"), TRUSTED_NAS)
    assert (policy.id, policy.severity) == ("new-remote-admin-service", "high")


def test_new_ordinary_service_on_a_trusted_server_is_medium():
    policy = match(POLICIES, _event("service_new", signal="port", subject="tcp/8443", significance="medium"),
                   TRUSTED_NAS)
    assert (policy.id, policy.severity) == ("new-service-on-trusted-server", "medium")


def test_unapproved_dhcp_server_is_critical():
    event = _event("dhcp_server_unexpected", mac=None, subject_id="eth0/192.168.1.66", significance="high")
    assert match(POLICIES, event, DeviceContext()).severity == "critical"


def test_unknown_device_present_is_high():
    assert _matched("unknown_device_present", UNKNOWN, significance="high") == "unknown-device-present"


def test_risk_rising_to_high_alerts_but_falling_does_not():
    rising = _event("risk_changed", current={"level": "high", "rising": True})
    falling = _event("risk_changed", current={"level": "high", "rising": False})
    moderate = _event("risk_changed", current={"level": "moderate", "rising": True})
    assert match(POLICIES, rising, TRUSTED_NAS).id == "risk-high"
    assert match(POLICIES, falling, TRUSTED_NAS) is None
    assert match(POLICIES, moderate, TRUSTED_NAS) is None


def test_informational_changes_go_to_the_digest_only():
    policy = match(POLICIES, _event("hostname_changed", significance="low"), UNKNOWN)
    assert (policy.id, policy.action) == ("informational-changes", "digest")
    assert match(POLICIES, _event("ip_changed", significance="info"), UNKNOWN) is None  # routine DHCP - nothing


# --- conditions and ordering -----------------------------------------------------


def test_each_condition_must_hold():
    policy = Policy(
        id="p", triggers=["service_new"], severity="high",
        conditions=PolicyConditions(trusted=True, categories=["Printer"], services=["tcp/23"], min_significance="low"),
    )
    printer = DeviceContext(trusted=True, category="Printer")
    event = _event("service_new", signal="port", subject="tcp/23", significance="high")
    assert match([policy], event, printer) is policy
    assert match([policy], event, DeviceContext(trusted=False, category="Printer")) is None
    assert match([policy], event, DeviceContext(trusted=True, category="Camera")) is None
    assert match([policy], event.model_copy(update={"subject": "tcp/80"}), printer) is None
    assert match([policy], event.model_copy(update={"significance": "info"}), printer) is None


def test_disabled_policies_are_skipped_and_first_match_wins():
    first = Policy(id="first", triggers=["hostname_changed"], severity="high", enabled=False)
    second = Policy(id="second", triggers=["hostname_changed"], severity="medium")
    third = Policy(id="third", triggers=["hostname_changed"], severity="info")
    assert match([first, second, third], _event("hostname_changed"), UNKNOWN).id == "second"


# --- configuration --------------------------------------------------------------


def test_policies_load_from_config_and_replace_the_defaults(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"policies": [{
        "id": "telnet-anywhere", "triggers": ["service_new"], "severity": "critical",
        "conditions": {"services": ["tcp/23"]}, "cooldown_seconds": 3600,
    }]}))
    cfg = Config.load(path)
    assert [p.id for p in effective_policies(cfg.policies)] == ["telnet-anywhere"]
    assert effective_policies(None) == list(DEFAULT_POLICIES)


@pytest.mark.parametrize("bad", [
    {"id": "x", "triggers": ["service_new"], "severity": "high", "run": "rm -rf /"},  # no free-form keys
    {"id": "x", "triggers": ["port_delta"], "severity": "high"},  # unknown change type
    {"id": "x", "triggers": [], "severity": "high"},
    {"id": "Bad Id!", "triggers": ["service_new"], "severity": "high"},
    {"id": "x", "triggers": ["service_new"], "severity": "extreme"},
    {"id": "x", "triggers": ["service_new"], "severity": "high", "conditions": {"shell": "true"}},
    {"id": "x", "triggers": ["service_new"], "severity": "high", "cooldown_seconds": -1},
])
def test_unsafe_or_malformed_policies_are_rejected(tmp_path: Path, bad):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"policies": [bad]}))
    with pytest.raises(Exception):
        Config.load(path)


def test_duplicate_policy_ids_are_rejected(tmp_path: Path):
    path = tmp_path / "config.yaml"
    entry = {"id": "same", "triggers": ["service_new"], "severity": "high"}
    path.write_text(yaml.safe_dump({"policies": [entry, entry]}))
    with pytest.raises(Exception):
        Config.load(path)


# --- shaping built-in findings (never a second alert) ------------------------------


def test_a_policy_raises_the_built_in_new_device_alert_instead_of_adding_one():
    finding = Finding(mac="00:11:22:33:44:55", title="Unknown device connected", severity="medium",
                      change_type="new_device")
    shaped, dispatch = shape_builtin_finding(finding, POLICIES, UNKNOWN)
    assert (shaped.severity, shaped.policy_id, dispatch) == ("high", "new-unknown-device", True)
    assert shaped.title == finding.title


def test_a_digest_only_policy_holds_back_a_built_in_alert():
    quiet = Policy(id="quiet-new-devices", triggers=["new_device"], severity="info", action="digest")
    finding = Finding(mac="00:11:22:33:44:55", title="Unknown device connected", severity="medium",
                      change_type="new_device")
    _shaped, dispatch = shape_builtin_finding(finding, [quiet], UNKNOWN)
    assert dispatch is False


def test_an_unmatched_built_in_finding_is_unchanged():
    finding = Finding(mac=NAS, title="Previously seen device reappeared", severity="info", change_type="reappeared")
    assert shape_builtin_finding(finding, POLICIES, TRUSTED_NAS) == (finding, True)


# --- change alerts and noise control --------------------------------------------------


def _ssh_alert(event_id=1, subject="tcp/22"):
    event = _event("service_new", id=event_id, signal="port", subject=subject, significance="high",
                   current={"baseline": ["HTTPS / TCP 443"], "established": True, "monitored_days": 127})
    policy = match(POLICIES, event, TRUSTED_NAS)
    return change_alert(event, policy, TRUSTED_NAS, evidence=[f"MAC: {NAS}"], recommendation="Investigate.")


def test_a_change_alert_says_what_changed_and_which_policy_sent_it():
    alert = _ssh_alert()
    assert alert.title == "Office NAS: New service detected: SSH / TCP 22"
    assert (alert.kind, alert.severity, alert.policy_id, alert.change_event_id) == (
        "change", "high", "new-remote-admin-service", 1,
    )
    assert "Policy: new-remote-admin-service" in alert.evidence[-1]
    assert "cooldown_key" not in alert.model_dump(mode="json")  # internal only


def test_the_same_change_alerts_once_then_stays_quiet(tmp_path: Path):
    cfg = AlertConfig()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert filter_rate_limited([_ssh_alert(1)], store, cfg, now=NOW)
        # SSH flaps: gone and back again within the cooldown - a new change, but no new alert
        assert filter_rate_limited([_ssh_alert(2)], store, cfg, now=NOW + timedelta(minutes=5)) == []
        # a different service on the same device is its own alert
        assert filter_rate_limited([_ssh_alert(3, subject="tcp/3389")], store, cfg, now=NOW + timedelta(minutes=6))


def test_a_policy_cooldown_overrides_the_global_one(tmp_path: Path):
    cfg = AlertConfig()
    alert = _ssh_alert().model_copy(update={"cooldown_seconds": 60})
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert filter_rate_limited([alert], store, cfg, now=NOW)
        assert filter_rate_limited([alert], store, cfg, now=NOW + timedelta(minutes=2))


# --- end to end: detection -> policy -> alert --------------------------------------


def _detect(store, allowlist, cfg, services, at):
    rows = [AdvertisedService(protocol="mdns", service_type=s, identity=s, mac=NAS, first_seen=at, last_seen=at)
            for s in services]
    with patch.object(DeviceStore, "advertised_services", lambda _self, **kw: rows):
        return baseline_mod.run_change_detection(
            store, allowlist, cfg, signatures=SignatureSet.load(), identity_rules=IdentityRuleSet.load(), now=at,
        )


def test_new_ssh_on_an_established_nas_produces_one_alert_with_its_policy_recorded(tmp_path: Path):
    from lanfence.allowlist import Allowlist

    cfg = Config()
    allowlist = Allowlist.load(None)
    allowlist.add(NAS, "Office NAS")
    t0 = NOW - timedelta(days=10)
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac=NAS, ip="192.168.1.10", hostname="diskstation", vendor="Synology Incorporated", seen_at=t0)
        _detect(store, allowlist, cfg, ["_http._tcp.local."], t0)
        store.observe(mac=NAS, ip="192.168.1.10", hostname="diskstation", vendor="Synology Incorporated", seen_at=NOW)
        _detect(store, allowlist, cfg, ["_http._tcp.local."], NOW)  # establishes the baseline
        events, alerts = _detect(store, allowlist, cfg, ["_http._tcp.local.", "_ssh._tcp.local."],
                                 NOW + timedelta(minutes=1))
        by_policy = {a.policy_id: a for a in alerts}
        assert set(by_policy) == {"new-remote-admin-service", "risk-high"}
        assert by_policy["new-remote-admin-service"].title == "Office NAS: New advertised service detected: SSH (mDNS _ssh._tcp)"
        ssh = next(e for e in events if e.change_type == "mdns_service_new")
        assert store.get_change_event(ssh.id).policy_id == "new-remote-admin-service"
        # nothing further while SSH stays put
        assert _detect(store, allowlist, cfg, ["_http._tcp.local.", "_ssh._tcp.local."], NOW + timedelta(hours=1)) == (
            [], [],
        )


def test_changes_the_built_in_pipeline_already_alerts_on_are_not_alerted_twice(tmp_path: Path):
    from lanfence.allowlist import Allowlist
    from lanfence.models import DeviceEvent

    cfg = Config()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac=NAS, ip="192.168.1.10", hostname=None, vendor=None, seen_at=NOW)
        _detect(store, Allowlist.load(None), cfg, [], NOW)
        store.record_event(DeviceEvent(mac=NAS, event_type="new_device", timestamp=NOW))
        events, alerts = _detect(store, Allowlist.load(None), cfg, [], NOW + timedelta(minutes=1))
        new_device = next(e for e in events if e.change_type == "new_device")
        assert store.get_change_event(new_device.id).policy_id == "new-unknown-device"  # recorded...
        assert not [a for a in alerts if a.change_type == "new_device"]  # ...but not alerted again


def test_marking_sent_change_alerts(tmp_path: Path):
    from lanfence.cli import _mark_change_alerts_sent

    with DeviceStore(tmp_path / "db.sqlite") as store:
        saved = store.record_change_event(_event("service_new", signal="port", subject="tcp/22"))
        alert = _ssh_alert(event_id=saved.id)
        _mark_change_alerts_sent(store, [alert], now=NOW)
        stored = store.get_change_event(saved.id)
        assert (stored.policy_id, stored.alerted_at) == ("new-remote-admin-service", NOW)
