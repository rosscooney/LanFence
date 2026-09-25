from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from lanfence import baseline as baseline_mod
from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.fingerprint import SignatureSet
from lanfence.identity import IdentityRuleSet
from lanfence.models import AdvertisedService, DeviceEvent, InspectedPort, InspectionResult

NAS = "00:11:32:aa:bb:01"  # Synology OUI
PHONE = "3c:22:fb:aa:bb:02"
T0 = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)


class Net:
    """A small synthetic network: one store, one allowlist, and the mDNS/
    SSDP services each device is currently advertising."""

    def __init__(self, tmp_path: Path):
        self.store = DeviceStore(tmp_path / "db.sqlite")
        self.allowlist = Allowlist.load(None)
        self.services: dict[str, list[tuple[str, str]]] = {}
        self.cfg = Config()

    def see(self, mac, at, *, ip="192.168.1.10", hostname=None, vendor=None):
        self.store.observe(mac=mac, ip=ip, hostname=hostname, vendor=vendor, seen_at=at, interface="eth0")

    def advertise(self, mac, *services):
        self.services[mac] = [(s, "mdns") if not s.startswith("urn:") else (s, "ssdp") for s in services]

    def _advertised(self, **_kwargs):
        out = []
        for mac, entries in self.services.items():
            for service_type, protocol in entries:
                out.append(AdvertisedService(
                    protocol=protocol, service_type=service_type, identity=f"{mac}-{service_type}",
                    mac=mac, first_seen=T0, last_seen=T0, status="current",
                ))
        return out

    def detect(self, at):
        with patch.object(DeviceStore, "advertised_services", lambda _self, **kw: self._advertised(**kw)):
            return baseline_mod.detect_changes(
                self.store, self.allowlist, self.cfg, signatures=SignatureSet.load(),
                identity_rules=IdentityRuleSet.load(), now=at,
            )

    def inspect(self, mac, at, *ports):
        self.store.record_inspection(InspectionResult(
            mac=mac, ip="192.168.1.10", method="socket", observed_at=at,
            open_ports=[InspectedPort(port=p) for p in ports],
        ))


@contextmanager
def network(tmp_path):
    net = Net(tmp_path)
    try:
        yield net
    finally:
        net.store.close()


#: Changes that follow from time passing or other changes rather than from
#: the observation a test is about - each has its own dedicated tests below.
_CONSEQUENTIAL = ("risk_changed", "unknown_device_present")


def _changes(events):
    return [e for e in events if e.change_type not in _CONSEQUENTIAL]


def _types(events):
    return [e.change_type for e in _changes(events)]


def _established_nas(net, *services, trusted=True):
    """A Synology NAS seen for 8 days - its baseline is established."""

    if trusted:
        net.allowlist.add(NAS, "Office NAS")
    net.see(NAS, T0, vendor="Synology Incorporated", hostname="diskstation")
    net.advertise(NAS, *services)
    net.detect(T0)
    later = T0 + timedelta(days=8)
    net.see(NAS, later, vendor="Synology Incorporated", hostname="diskstation")
    events = net.detect(later)
    assert "baseline_established" in _types(events)
    return later


# --- baseline creation and maturity -----------------------------------------


def test_first_evaluation_seeds_the_baseline_silently(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0, vendor="Synology Incorporated")
        net.advertise(NAS, "_ssh._tcp.local.", "_http._tcp.local.")
        assert _changes(net.detect(T0)) == []
        items = net.store.baseline_items(NAS)
        assert {(i.value, i.in_baseline, i.origin) for i in items} == {
            ("_ssh._tcp", True, "initial"), ("_http._tcp", True, "initial"),
        }
        assert baseline_mod.maturity(net.store.get_baseline(NAS), last_seen=T0, now=T0, stale_days=30) == "learning"


def test_baseline_is_established_only_after_the_learning_period(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.detect(T0)
        net.see(NAS, T0 + timedelta(days=3))
        assert "baseline_established" not in _types(net.detect(T0 + timedelta(days=3)))
        net.see(NAS, T0 + timedelta(days=8))
        events = net.detect(T0 + timedelta(days=8))
        assert _types(events) == ["baseline_established"]
        assert baseline_mod.maturity(
            net.store.get_baseline(NAS), last_seen=T0 + timedelta(days=8), now=T0 + timedelta(days=8), stale_days=30,
        ) == "established"


def test_a_device_seen_only_once_keeps_learning(tmp_path):
    """Time passing without the device being around isn't learning."""

    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.detect(T0)
        assert "baseline_established" not in _types(net.detect(T0 + timedelta(days=30)))


def test_a_long_unseen_device_has_a_stale_baseline(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.detect(T0)
        assert baseline_mod.maturity(
            net.store.get_baseline(NAS), last_seen=T0, now=T0 + timedelta(days=40), stale_days=30,
        ) == "stale"


def test_upgrade_never_replays_existing_history(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.store.record_event(DeviceEvent(mac=NAS, event_type="new_device", timestamp=T0))
        assert _changes(net.detect(T0)) == []  # the pre-existing event is history, not a new change
        net.store.record_event(DeviceEvent(mac=NAS, event_type="disconnected", timestamp=T0 + timedelta(hours=1)))
        assert _types(net.detect(T0 + timedelta(hours=2))) == ["disconnected"]
        assert _changes(net.detect(T0 + timedelta(hours=3))) == []  # each lifecycle event becomes exactly one change


# --- learning vs established -------------------------------------------------


def test_learning_absorbs_an_ordinary_new_service_quietly(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.")
        net.detect(T0)
        net.advertise(NAS, "_http._tcp.local.", "_airplay._tcp.local.")
        assert _changes(net.detect(T0 + timedelta(hours=2))) == []
        item = next(i for i in net.store.baseline_items(NAS) if i.value == "_airplay._tcp")
        assert (item.in_baseline, item.origin) == (True, "learned")


def test_learning_never_absorbs_a_remote_admin_service(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.")
        net.detect(T0)
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        (event,) = _changes(net.detect(T0 + timedelta(hours=2)))
        assert (event.change_type, event.subject, event.significance) == ("mdns_service_new", "_ssh._tcp", "high")
        item = next(i for i in net.store.baseline_items(NAS) if i.value == "_ssh._tcp")
        assert item.in_baseline is False


def test_established_baseline_flags_a_new_service_and_never_absorbs_it(tmp_path):
    with network(tmp_path) as net:
        later = _established_nas(net, "_http._tcp.local.")
        net.advertise(NAS, "_http._tcp.local.", "_airplay._tcp.local.")
        (event,) = [e for e in net.detect(later + timedelta(hours=1)) if e.change_type != "risk_changed"]
        assert event.change_type == "mdns_service_new"
        assert event.significance == "medium"  # a trusted NAS - server-like
        assert event.current["baseline"] == ["Web service (mDNS _http._tcp)"]
        assert event.current["established"] is True
        # months later, it's still pending - time never makes it trusted
        net.see(NAS, later + timedelta(days=90), vendor="Synology Incorporated")
        net.detect(later + timedelta(days=90))
        item = next(i for i in net.store.baseline_items(NAS) if i.value == "_airplay._tcp")
        assert item.in_baseline is False


def test_an_unchanged_service_is_never_reported_twice(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.")
        net.detect(T0)
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        assert len(_changes(net.detect(T0 + timedelta(hours=1)))) == 1
        for hours in range(2, 10):
            assert _changes(net.detect(T0 + timedelta(hours=hours))) == []


# --- removals ------------------------------------------------------------------


def test_a_service_is_only_removed_after_the_grace_period(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.", "_smb._tcp.local.")
        net.detect(T0)
        net.advertise(NAS, "_http._tcp.local.")
        assert _changes(net.detect(T0 + timedelta(hours=1))) == []
        (event,) = _changes(net.detect(T0 + timedelta(hours=7)))
        assert (event.change_type, event.subject, event.significance) == ("mdns_service_removed", "_smb._tcp", "low")
        assert _changes(net.detect(T0 + timedelta(hours=8))) == []


def test_nothing_is_removed_while_the_device_is_offline(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.")
        net.detect(T0)
        net.store.mark_offline(set(), as_of=T0 + timedelta(hours=1))
        net.advertise(NAS)
        assert [e for e in net.detect(T0 + timedelta(days=2)) if e.change_type.endswith("removed")] == []


def test_a_pending_service_that_leaves_and_returns_is_a_new_change(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.")
        net.detect(T0)
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        net.detect(T0 + timedelta(hours=1))
        net.advertise(NAS, "_http._tcp.local.")
        assert _types(net.detect(T0 + timedelta(hours=8))) == ["mdns_service_removed"]
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        (event,) = _changes(net.detect(T0 + timedelta(hours=9)))
        assert event.change_type == "mdns_service_new"
        assert event.current["returned"] is True


# --- open ports from explicit inspection ---------------------------------------


def test_ports_change_only_when_a_new_inspection_says_so(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.inspect(NAS, T0, 443, 445, 5000)
        net.detect(T0)
        assert _changes(net.detect(T0 + timedelta(hours=1))) == []  # same inspection - nothing new to judge
        net.inspect(NAS, T0 + timedelta(hours=2), 22, 443, 5000)
        events = {e.change_type: e for e in net.detect(T0 + timedelta(hours=2))}
        assert events["service_new"].subject == "tcp/22"
        assert events["service_new"].significance == "high"
        assert events["service_removed"].subject == "tcp/445"


# --- addresses, hostnames, identity, trust -------------------------------------


def test_dhcp_reassignment_on_the_same_network_is_informational(tmp_path):
    with network(tmp_path) as net:
        net.see(PHONE, T0, ip="192.168.1.20")
        net.detect(T0)
        net.see(PHONE, T0 + timedelta(hours=1), ip="192.168.1.45")
        (event,) = _changes(net.detect(T0 + timedelta(hours=1)))
        assert (event.change_type, event.significance) == ("ip_changed", "info")
        assert event.previous == {"ipv4": "192.168.1.20"}


def test_moving_to_a_different_network_is_more_significant(tmp_path):
    with network(tmp_path) as net:
        net.see(PHONE, T0, ip="192.168.1.20")
        net.detect(T0)
        net.see(PHONE, T0 + timedelta(hours=1), ip="10.20.0.5")
        (event,) = _changes(net.detect(T0 + timedelta(hours=1)))
        assert event.current["different_network"] is True
        assert event.significance in ("low", "medium")


def test_ipv6_privacy_addresses_within_one_prefix_are_quiet(tmp_path):
    with network(tmp_path) as net:
        later = _established_nas(net)
        for suffix in ("1", "abcd", "beef:1"):
            net.store.record_address_evidence(
                NAS, f"2001:db8:1:2::{suffix}", interface="eth0", source="ipv6_nd", kind="observed", seen_at=later,
            )
            net.detect(later)
        (event,) = [e for e in net.store.change_events(mac=NAS) if e.change_type == "ipv6_prefix_new"]
        assert (event.subject, event.significance) == ("2001:db8:1:2::/64", "info")


def test_hostname_change_is_recorded_with_before_and_after(tmp_path):
    with network(tmp_path) as net:
        net.see(PHONE, T0, hostname="janes-iphone")
        net.detect(T0)
        net.see(PHONE, T0 + timedelta(hours=1), hostname="android-7f3a")
        (event,) = _changes(net.detect(T0 + timedelta(hours=1)))
        assert event.change_type == "hostname_changed"
        assert (event.previous["hostname"], event.current["hostname"]) == ("janes-iphone", "android-7f3a")


def test_identity_learning_more_is_not_a_change_but_a_different_identity_is(tmp_path):
    with network(tmp_path) as net:
        net.see(PHONE, T0)  # no evidence yet - identity unknown
        net.detect(T0)
        net.see(PHONE, T0 + timedelta(hours=1), hostname="Ross-iPhone", vendor="Apple, Inc.")
        assert _changes(net.detect(T0 + timedelta(hours=1))) == []  # unknown -> Phone is just more evidence
        net.see(PHONE, T0 + timedelta(hours=2), hostname="brother-printer", vendor="Brother Industries")
        changed = [e for e in net.detect(T0 + timedelta(hours=2)) if e.change_type == "identity_changed"]
        assert len(changed) == 1
        assert changed[0].previous["category"] == "Phone"


def test_trusting_a_device_is_recorded(tmp_path):
    with network(tmp_path) as net:
        net.see(PHONE, T0)
        net.detect(T0)
        net.allowlist.add(PHONE, "Jane's iPhone")
        (event,) = [e for e in net.detect(T0 + timedelta(minutes=5)) if e.change_type == "trust_changed"]
        assert event.current == {"trusted": True, "name": "Jane's iPhone"}


def test_unknown_device_present_is_flagged_once_until_cleared(tmp_path):
    with network(tmp_path) as net:
        net.detect(T0 - timedelta(minutes=1))  # change detection starts before the phone arrives
        net.see(PHONE, T0)
        net.detect(T0)
        net.see(PHONE, T0 + timedelta(minutes=30))
        assert _changes(net.detect(T0 + timedelta(minutes=30))) == []
        net.see(PHONE, T0 + timedelta(minutes=61))
        flagged = [e for e in net.detect(T0 + timedelta(minutes=61)) if e.change_type == "unknown_device_present"]
        assert len(flagged) == 1 and flagged[0].significance == "high"
        net.see(PHONE, T0 + timedelta(hours=5))
        assert not [e for e in net.detect(T0 + timedelta(hours=5)) if e.change_type == "unknown_device_present"]


def test_devices_present_when_detection_began_are_never_flagged_as_unknown(tmp_path):
    # An upgrade or a fresh install shouldn't flag every untrusted device
    # already on the network - that's what `lanfence review` is for.
    with network(tmp_path) as net:
        net.see(PHONE, T0 - timedelta(days=30))
        net.see(PHONE, T0)
        net.detect(T0)
        net.see(PHONE, T0 + timedelta(hours=3))
        assert not [e for e in net.detect(T0 + timedelta(hours=3)) if e.change_type == "unknown_device_present"]


# --- lifecycle and network-level changes ---------------------------------------


def _prime_cursors(net):
    net.detect(T0)


def test_an_always_on_device_going_offline_is_significant(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        _prime_cursors(net)
        net.store.set_presence_policy(NAS, "always-on", updated_at=T0)
        net.store.record_event(DeviceEvent(mac=NAS, event_type="disconnected", timestamp=T0 + timedelta(hours=1)))
        (event,) = [e for e in net.detect(T0 + timedelta(hours=1)) if e.change_type == "disconnected"]
        assert event.significance == "medium"


def test_a_trusted_device_back_after_a_long_absence_is_significant(tmp_path):
    with network(tmp_path) as net:
        net.allowlist.add(NAS, "Office NAS")
        net.see(NAS, T0)
        _prime_cursors(net)
        net.store.record_event(DeviceEvent(mac=NAS, event_type="disconnected", timestamp=T0))
        net.store.record_event(DeviceEvent(mac=NAS, event_type="reappeared", timestamp=T0 + timedelta(days=20)))
        events = {e.change_type: e for e in net.detect(T0 + timedelta(days=20))}
        assert events["reappeared"].significance == "medium"
        assert events["reappeared"].current["absent_days"] == 20.0


def test_an_unapproved_dhcp_server_becomes_one_change(tmp_path):
    with network(tmp_path) as net:
        _prime_cursors(net)
        net.store.record_dhcp_server_finding(
            interface="eth0", server_id="192.168.1.66", observed_at=T0 + timedelta(minutes=1),
            approved_at_observation=False, message_type="offer", source_ip="192.168.1.66",
            source_mac=PHONE, relay_ip=None, router=None, dns=None,
        )
        (event,) = _changes(net.detect(T0 + timedelta(minutes=2)))
        assert (event.change_type, event.subject_id, event.significance) == (
            "dhcp_server_unexpected", "eth0/192.168.1.66", "high",
        )
        assert _changes(net.detect(T0 + timedelta(minutes=3))) == []


# --- operator actions ------------------------------------------------------------


def test_an_excluded_signal_is_kept_as_history_but_suppressed(tmp_path):
    with network(tmp_path) as net:
        net.see(PHONE, T0, ip="192.168.1.20")
        net.detect(T0)
        baseline_mod.set_excluded_signals(net.store, PHONE, ["ip"], now=T0)
        net.see(PHONE, T0 + timedelta(hours=1), ip="192.168.1.45")
        (event,) = _changes(net.detect(T0 + timedelta(hours=1)))
        assert event.suppressed is True
        assert event.needs_attention(now=T0 + timedelta(hours=1)) is False


def test_accepting_a_change_updates_the_baseline_and_keeps_history(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.")
        net.detect(T0)
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        (event,) = _changes(net.detect(T0 + timedelta(hours=1)))
        baseline_mod.review_change(net.store, event.id, "accepted", now=T0 + timedelta(hours=2), note="Enabled by IT")
        item = next(i for i in net.store.baseline_items(NAS) if i.value == "_ssh._tcp")
        assert (item.in_baseline, item.origin) == (True, "accepted")
        kept = net.store.get_change_event(event.id)
        assert (kept.review_state, kept.review_note) == ("accepted", "Enabled by IT")


def test_other_review_actions(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.")
        net.detect(T0)
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        (event,) = _changes(net.detect(T0 + timedelta(hours=1)))
        now = T0 + timedelta(hours=2)
        snoozed = baseline_mod.review_change(net.store, event.id, "snoozed", now=now, snooze_for=timedelta(days=1))
        assert snoozed.needs_attention(now=now) is False
        assert snoozed.needs_attention(now=now + timedelta(days=2)) is True
        investigating = baseline_mod.review_change(net.store, event.id, "investigating", now=now)
        assert investigating.needs_attention(now=now) is True
        reviewed = baseline_mod.review_change(net.store, event.id, "reviewed", now=now)
        assert reviewed.needs_attention(now=now) is False
        item = next(i for i in net.store.baseline_items(NAS) if i.value == "_ssh._tcp")
        assert item.in_baseline is False  # reviewed is not the same as accepted
        noted = baseline_mod.review_change(net.store, event.id, "note", now=now, note="Checking with IT")
        assert (noted.review_state, noted.review_note) == ("reviewed", "Checking with IT")


def test_accept_pending_accepts_every_pending_item(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.detect(T0)
        net.advertise(NAS, "_ssh._tcp.local.", "_rfb._tcp.local.")
        net.detect(T0 + timedelta(hours=1))
        assert baseline_mod.accept_pending(net.store, NAS, now=T0 + timedelta(hours=2)) == 2
        assert all(i.in_baseline for i in net.store.baseline_items(NAS))
        assert {e.review_state for e in net.store.change_events(mac=NAS) if e.signal == "mdns"} == {"accepted"}


def test_resetting_a_baseline_relearns_and_keeps_history(tmp_path):
    with network(tmp_path) as net:
        net.see(NAS, T0)
        net.advertise(NAS, "_http._tcp.local.")
        net.detect(T0)
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        net.detect(T0 + timedelta(hours=1))
        baseline_mod.reset_baseline(net.store, NAS, now=T0 + timedelta(hours=2))
        assert net.store.get_baseline(NAS) is None
        assert _changes(net.detect(T0 + timedelta(hours=3))) == []  # re-seeded silently from what's there now
        assert {i.origin for i in net.store.baseline_items(NAS)} == {"initial"}
        assert {"mdns_service_new", "baseline_reset"} <= set(_types(net.store.change_events(mac=NAS)))


# --- historical comparison ---------------------------------------------------------


def test_compare_with_a_past_date_and_with_the_baseline(tmp_path):
    with network(tmp_path) as net:
        later = _established_nas(net, "_http._tcp.local.", "_smb._tcp.local.")
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        net.detect(later + timedelta(hours=1))
        net.detect(later + timedelta(hours=8))  # _smb gone long enough to count as removed
        rows = {r.label: r.status for r in baseline_mod.compare(
            net.store, NAS, since=later - timedelta(days=1), now=later + timedelta(hours=8),
        )}
        assert rows["SSH (mDNS _ssh._tcp)"] == "new"
        assert rows["mDNS _smb._tcp"] == "removed"
        assert rows["Web service (mDNS _http._tcp)"] == "unchanged"
        vs_baseline = {r.label: (r.now, r.then) for r in baseline_mod.compare(
            net.store, NAS, since=None, now=later + timedelta(hours=8),
        )}
        assert vs_baseline["SSH (mDNS _ssh._tcp)"] == (True, False)


# --- risk --------------------------------------------------------------------------


def test_a_new_admin_service_on_an_established_trusted_nas_raises_risk(tmp_path):
    """The spec's own example: a trusted NAS gains SSH -> LOW to HIGH."""

    with network(tmp_path) as net:
        later = _established_nas(net, "_http._tcp.local.")
        assert net.store.get_risk(NAS).level == "low"
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        events = net.detect(later + timedelta(hours=1))
        (risk,) = [e for e in events if e.change_type == "risk_changed"]
        assert (risk.previous["level"], risk.current["level"]) == ("low", "high")
        assert risk.risk_after == net.store.get_risk(NAS).score
        labels = [c.label for c in net.store.get_risk(NAS).contributions]
        assert "New administrative service: SSH (mDNS _ssh._tcp)" in labels
        assert "Unexpected behaviour change against an established baseline" in labels


def test_accepting_the_change_brings_risk_back_down(tmp_path):
    with network(tmp_path) as net:
        later = _established_nas(net, "_http._tcp.local.")
        net.advertise(NAS, "_http._tcp.local.", "_ssh._tcp.local.")
        new = next(e for e in net.detect(later + timedelta(hours=1)) if e.change_type == "mdns_service_new")
        baseline_mod.review_change(net.store, new.id, "accepted", now=later + timedelta(hours=2))
        assessment = baseline_mod.reassess_device(
            net.store, net.allowlist, net.cfg, NAS, signatures=SignatureSet.load(),
            identity_rules=IdentityRuleSet.load(), now=later + timedelta(hours=2),
        )
        assert assessment.level == "low"
        assert net.store.change_events(mac=NAS, change_types=["risk_changed"])[0].current["level"] == "low"


# --- retention ------------------------------------------------------------------------


def test_change_history_is_bounded(tmp_path):
    from lanfence.models import ChangeEvent

    with DeviceStore(tmp_path / "db.sqlite", max_change_events=5) as store:
        for minute in range(8):
            store.record_change_event(ChangeEvent(
                mac=PHONE, change_type="ip_changed", occurred_at=T0 + timedelta(minutes=minute), source="arp",
            ))
        assert len(store.change_events()) == 5
    with DeviceStore(tmp_path / "db2.sqlite", change_event_retention=timedelta(days=30)) as store:
        store.record_change_event(ChangeEvent(mac=PHONE, change_type="ip_changed", occurred_at=T0, source="arp"))
        store.record_change_event(ChangeEvent(
            mac=PHONE, change_type="ip_changed", occurred_at=T0 + timedelta(days=40), source="arp",
        ))
        assert len(store.change_events()) == 1


def test_an_existing_database_gains_the_new_tables_and_keeps_its_data(tmp_path):
    import sqlite3

    path = tmp_path / "db.sqlite"
    with DeviceStore(path) as store:
        store.observe(mac=NAS, ip="192.168.1.10", hostname="nas", vendor=None, seen_at=T0)
        store.update_device_metadata(NAS, updated_at=T0, owner="Operations")
    conn = sqlite3.connect(path)
    for table in ("change_events", "device_baselines", "baseline_items", "device_risk", "change_cursors"):
        conn.execute(f"DROP TABLE {table}")  # as a pre-upgrade database
    conn.commit()
    conn.close()
    with DeviceStore(path) as store:
        assert store.get_device(NAS) is not None
        assert store.get_device_metadata(NAS).owner == "Operations"
        assert store.change_events() == []
        assert store.all_baselines() == {}
