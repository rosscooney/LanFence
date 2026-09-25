# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Know When It Changes: behaviour baselines and change detection.

Observe -> Baseline -> Compare -> Explain -> Assess. :func:`detect_changes`
runs once per active sweep (see `lanfence scan`/`monitor`), reads what LAN
Fence already observes passively (addresses, hostnames, identity,
mDNS/SSDP advertisements) plus open ports from an explicit `lanfence
inspect`, compares each device against what it has learned is normal, and
records a :class:`~lanfence.models.ChangeEvent` for each meaningful change.
It never sends traffic of its own.

**Baselines.** A device's baseline starts the first time it's evaluated
(for an existing installation, the first sweep after upgrading), seeded
silently from whatever is observed right then - so an upgrade never floods
"What Changed?" with things that were always there. It then *learns* for
``changes.learning_days``: ordinary new services are quietly added to the
baseline, but a remote-administration service (SSH, Telnet, RDP, VNC, ...)
is never absorbed without the operator's approval. Once learning ends the
baseline is *established*, and from then on anything new stays *pending* -
recorded, flagged, counted in the device's risk - until the operator
accepts it. Time alone never makes a change trusted. A device not seen for
``changes.stale_days`` has a *stale* baseline (shown as such; nothing is
thrown away).

**Quiet by design.** A change is recorded once, when state changes - never
again just because the new state persists. IPv6 is tracked by network
prefix, not individual (privacy) address. An mDNS/SSDP service is only
judged removed while its device is online and after it's been missing for
``changes.service_removal_hours``, since advertisements come and go. IP
changes within the same network are informational. Per-device signals can
be excluded from alerting entirely (see :func:`set_excluded_signals`).

Lifecycle events (``events``) and unapproved-DHCP-server findings are
re-expressed as changes via cursors, so each becomes exactly one change
and a fresh installation or upgrade starts from "now" rather than
replaying history.
"""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from lanfence.allowlist import Allowlist
from lanfence.changes import is_admin_service, normalize_mdns_type, port_value, service_label
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.dossier import DeviceDossier, build_device_dossier
from lanfence.engine import _device_evidence_lines, build_inventory, is_review_needed
from lanfence.fingerprint import SignatureSet
from lanfence.identity import IdentityRuleSet
from lanfence.logging_config import get_logger
from lanfence.models import RISK_LEVELS, BaselineItem, ChangeEvent, DeviceBaseline, Finding, RiskAssessment
from lanfence.policy import BUILTIN_ALERTED, DeviceContext, change_alert, effective_policies, match, shape_builtin_finding
from lanfence.risk import assess, gather_inputs

log = get_logger("baseline")

#: A present item's last-seen time is refreshed at most this often, so an
#: unchanged observation costs no write on most sweeps.
_LAST_SEEN_REFRESH = timedelta(hours=1)
#: How far back risk looks at a device's changes.
_RISK_EVENT_WINDOW = timedelta(days=30)
#: How long an unapproved DHCP reply from a device counts towards its risk.
_DHCP_RISK_WINDOW = timedelta(days=7)
#: How recently an IPv6 address must have been seen to count its prefix.
_IPV6_PREFIX_WINDOW = timedelta(days=7)
#: Categories where a new service on a trusted device matters more.
_SERVER_LIKE = frozenset({"Server", "Storage / NAS", "Network Infrastructure", "Printer", "Camera"})

_NEW_CHANGE = {"port": "service_new", "mdns": "mdns_service_new", "ssdp": "ssdp_service_new",
               "ipv6_prefix": "ipv6_prefix_new"}
_REMOVED_CHANGE = {"port": "service_removed", "mdns": "mdns_service_removed", "ssdp": "ssdp_service_removed"}
_SIGNAL_SOURCE = {"port": "inspection", "mdns": "mdns", "ssdp": "ssdp", "ipv6_prefix": "arp"}


def maturity(baseline: DeviceBaseline | None, *, last_seen: datetime | None, now: datetime, stale_days: float) -> str:
    """"learning", "established" or "stale" - or "none" before the first
    evaluation."""

    if baseline is None:
        return "none"
    if last_seen is not None and now - last_seen >= timedelta(days=stale_days):
        return "stale"
    return "learning" if baseline.established_at is None else "established"


# --- current observations ------------------------------------------------


def _observations(dossier: DeviceDossier, *, now: datetime) -> dict[str, set[str]]:
    services = [s for s in dossier.services if s.status == "current"]
    prefixes: set[str] = set()
    for address in dossier.addresses:
        if address.family != "ipv6" or now - address.last_seen > _IPV6_PREFIX_WINDOW:
            continue
        try:
            parsed = ipaddress.ip_address(address.ip)
        except ValueError:
            continue
        if parsed.is_link_local or parsed.is_loopback:
            continue
        prefixes.add(str(ipaddress.ip_network(f"{address.ip}/64", strict=False)))
    inspection = dossier.inspection
    return {
        "port": {port_value(p.port, p.protocol) for p in inspection.open_ports} if inspection else set(),
        "mdns": {normalize_mdns_type(s.service_type) for s in services if s.protocol == "mdns"},
        # Per-device "uuid:..." notification types are identities, not
        # capabilities - tracking them would only add noise.
        "ssdp": {s.service_type for s in services if s.protocol == "ssdp" and not s.service_type.startswith("uuid:")},
        "ipv6_prefix": prefixes,
    }


def _same_network(old: str, new: str) -> bool:
    try:
        return ipaddress.ip_network(f"{old}/24", strict=False) == ipaddress.ip_network(f"{new}/24", strict=False)
    except ValueError:
        return False


def _identity_label(manufacturer: str | None, category: str | None) -> str | None:
    if not manufacturer and not category:
        return None
    if manufacturer and category:
        return f"{manufacturer} ({category})"
    return manufacturer or category


# --- the detector ----------------------------------------------------------


@dataclass
class _Context:
    store: DeviceStore
    cfg: Config
    now: datetime
    recorded: list[ChangeEvent]
    #: When change detection first ran on this network - see
    #: :func:`_watching_since`.
    watching_since: datetime | None = None

    def record(self, event: ChangeEvent, *, excluded: set[str] | frozenset[str] = frozenset()) -> ChangeEvent:
        if event.signal is not None and event.signal in excluded:
            event = event.model_copy(update={"suppressed": True})
        saved = self.store.record_change_event(event)
        self.recorded.append(saved)
        return saved


def detect_changes(
    store: DeviceStore,
    allowlist: Allowlist,
    cfg: Config,
    *,
    signatures: SignatureSet,
    identity_rules: IdentityRuleSet,
    now: datetime,
) -> list[ChangeEvent]:
    """Compare every device with its baseline and record what changed.
    Returns only the changes recorded by this call."""

    if not cfg.changes.enabled:
        return []
    ctx = _Context(store=store, cfg=cfg, now=now, recorded=[], watching_since=_watching_since(store, now))
    _ingest_lifecycle(ctx, allowlist)
    _ingest_dhcp_servers(ctx)

    services_by_mac: dict[str, list] = defaultdict(list)
    for service in store.advertised_services(now=now):
        if service.mac is not None:
            services_by_mac[service.mac].append(service)
    inspections = store.all_inspections()
    baselines = store.all_baselines()
    items_by_mac: dict[str, list[BaselineItem]] = defaultdict(list)
    for item in store.baseline_items():
        items_by_mac[item.mac].append(item)
    risks = store.all_risk()
    dhcp_macs = store.dhcp_server_source_macs_since(now - _DHCP_RISK_WINDOW)
    recent_by_mac: dict[str, list[ChangeEvent]] = defaultdict(list)
    for event in store.change_events(since=now - _RISK_EVENT_WINDOW):
        if event.mac is not None:
            recent_by_mac[event.mac].append(event)
    for event in ctx.recorded:
        if event.mac is not None:
            recent_by_mac[event.mac].append(event)

    for device in build_inventory(store, allowlist):
        dossier = build_device_dossier(
            store, allowlist, device.mac, signatures=signatures, identity_rules=identity_rules,
            vendor_file=cfg.vendor_file, now=now, device=device,
            services=services_by_mac.get(device.mac, []), inspection=inspections.get(device.mac),
        )
        if dossier is None:
            continue
        before = len(ctx.recorded)
        items = items_by_mac.get(device.mac, [])
        baseline = _compare(ctx, dossier, baselines.get(device.mac), items)
        recent_by_mac[device.mac].extend(ctx.recorded[before:])
        _reassess_risk(
            ctx, dossier, baseline=baseline, items=store.baseline_items(device.mac) if len(ctx.recorded) > before
            else items, events=recent_by_mac[device.mac], previous=risks.get(device.mac),
            dhcp_server=device.mac in dhcp_macs,
        )
    return ctx.recorded


def _watching_since(store: DeviceStore, now: datetime) -> datetime:
    """When change detection first ran here (recorded on the first run).
    Devices already present then are the existing network: like the
    silently seeded baselines, they never count as unknown devices that
    turned up and lingered - `lanfence review` is where those get
    worked through."""

    started = store.get_cursor("watching_since")
    if started is None:
        started = math.ceil(now.timestamp())  # whole seconds; round up so nothing already seen is "after"
        store.set_cursor("watching_since", started)
    return datetime.fromtimestamp(started, tz=timezone.utc)


def _ingest_lifecycle(ctx: _Context, allowlist: Allowlist) -> None:
    store = ctx.store
    cursor = store.get_cursor("events")
    if cursor is None:
        store.set_cursor("events", store.max_event_id())  # start from now - never replay history
        return
    while True:
        rows = store.events_after_id(cursor)
        for row_id, event in rows:
            trusted = allowlist.match(event.mac) is not None
            current: dict = {"ip": event.ip, "hostname": event.hostname}
            significance = "info"
            if event.event_type == "new_device":
                significance = "info" if trusted else "medium"
            elif event.event_type == "reappeared":
                disconnect = store.last_event_before(event.mac, row_id, event_type="disconnected")
                if disconnect is not None:
                    absent_days = (event.timestamp - disconnect.timestamp).total_seconds() / 86400
                    current["absent_days"] = round(absent_days, 1)
                    if trusted and absent_days >= ctx.cfg.changes.long_absence_days:
                        significance = "medium"
            elif event.event_type == "disconnected":
                presence = store.get_presence(event.mac).policy
                current["presence"] = presence
                if presence == "always-on":
                    significance = "medium"
            ctx.record(ChangeEvent(
                mac=event.mac, change_type=event.event_type, occurred_at=event.timestamp, source="lifecycle",
                current=current, significance=significance,
            ))
            cursor = row_id
        store.set_cursor("events", cursor)
        if len(rows) < 1000:
            return


def _ingest_dhcp_servers(ctx: _Context) -> None:
    store = ctx.store
    cursor = store.get_cursor("dhcp_server_findings")
    if cursor is None:
        store.set_cursor("dhcp_server_findings", store.max_dhcp_server_finding_id())
        return
    while True:
        rows = store.dhcp_server_findings_after_id(cursor)
        for row in rows:
            ctx.record(ChangeEvent(
                subject_id=f"{row['interface']}/{row['server_id']}", change_type="dhcp_server_unexpected",
                occurred_at=datetime.fromisoformat(row["observed_at"]), source="dhcp", significance="high",
                current={
                    "interface": row["interface"], "server_id": row["server_id"], "source_ip": row["source_ip"],
                    "source_mac": row["source_mac"], "router": row["router"], "dns": row["dns"],
                },
            ))
            cursor = row["id"]
        store.set_cursor("dhcp_server_findings", cursor)
        if len(rows) < 1000:
            return


def _compare(
    ctx: _Context, dossier: DeviceDossier, baseline: DeviceBaseline | None, items: list[BaselineItem],
) -> DeviceBaseline:
    store, cfg, now = ctx.store, ctx.cfg.changes, ctx.now
    device, identity = dossier.device, dossier.identity
    mac = device.mac
    observed = _observations(dossier, now=now)
    inspection = dossier.inspection

    if baseline is None:
        baseline = DeviceBaseline(
            mac=mac, started_at=now, ipv4=device.ipv4, hostname=device.hostname,
            identity_category=identity.category if identity.is_known else None,
            identity_manufacturer=identity.manufacturer if identity.is_known else None,
            trusted=device.allowlisted, inspection_at=inspection.observed_at if inspection else None,
        )
        store.save_baseline(baseline, now=now)
        for signal, values in observed.items():
            for value in values:
                store.save_baseline_item(BaselineItem(
                    mac=mac, signal=signal, value=value, in_baseline=True, origin="initial",
                    first_seen=now, last_seen=now,
                ))
        return baseline

    original = baseline.model_copy(deep=True)
    excluded = set(baseline.excluded_signals)
    learning = baseline.established_at is None
    monitored_days = round((now - baseline.started_at).total_seconds() / 86400, 1)
    trusted = device.allowlisted
    server_like = dossier.effective_category in _SERVER_LIKE

    if learning:
        learned_for = now - baseline.started_at
        if learned_for >= timedelta(days=cfg.learning_days) and device.last_seen - baseline.started_at >= min(
            timedelta(days=1), timedelta(days=cfg.learning_days)
        ):
            baseline.established_at = now
            ctx.record(ChangeEvent(
                mac=mac, change_type="baseline_established", occurred_at=now, source="baseline",
                current={"learning_days": round(learned_for.total_seconds() / 86400, 1)},
            ))

    by_key = {(item.signal, item.value): item for item in items}
    ports_fresh = inspection is not None and (
        baseline.inspection_at is None or inspection.observed_at > baseline.inspection_at
    )
    for signal, values in observed.items():
        if signal == "port" and not ports_fresh:
            continue
        if signal in ("mdns", "ssdp") and device.status != "online":
            continue  # services expire while a device is away - nothing to judge
        baseline_labels = sorted(
            service_label(i.signal, i.value) for i in items if i.signal == signal and i.in_baseline and i.present
        )
        for value in sorted(values):
            item = by_key.get((signal, value))
            admin = is_admin_service(signal, value)
            if item is None:
                absorb = learning and not admin
                store.save_baseline_item(BaselineItem(
                    mac=mac, signal=signal, value=value, in_baseline=absorb,
                    origin="learned" if absorb else "observed", first_seen=now, last_seen=now,
                ))
                if not absorb:
                    ctx.record(_new_item_event(
                        mac, signal, value, now=now, admin=admin, learning=learning, trusted=trusted,
                        server_like=server_like, baseline_labels=baseline_labels, monitored_days=monitored_days,
                        returned=False,
                    ), excluded=excluded)
            elif not item.present:
                store.save_baseline_item(item.model_copy(update={"present": True, "removed_at": None, "last_seen": now}))
                if not item.in_baseline:
                    ctx.record(_new_item_event(
                        mac, signal, value, now=now, admin=admin, learning=learning, trusted=trusted,
                        server_like=server_like, baseline_labels=baseline_labels, monitored_days=monitored_days,
                        returned=True,
                    ), excluded=excluded)
            elif now - item.last_seen >= _LAST_SEEN_REFRESH:
                store.save_baseline_item(item.model_copy(update={"last_seen": now}))
        if signal == "ipv6_prefix":
            continue  # a prefix going quiet isn't a meaningful change
        for item in items:
            if item.signal != signal or not item.present or item.value in values:
                continue
            if signal != "port" and now - item.last_seen < timedelta(hours=cfg.service_removal_hours):
                continue
            store.save_baseline_item(item.model_copy(update={"present": False, "removed_at": now}))
            ctx.record(ChangeEvent(
                mac=mac, change_type=_REMOVED_CHANGE[signal], occurred_at=now, signal=signal, subject=item.value,
                source=_SIGNAL_SOURCE[signal], significance="low" if item.in_baseline else "info",
                previous={"present": True}, current={"present": False, "was_baseline": item.in_baseline},
            ), excluded=excluded)
    if ports_fresh:
        baseline.inspection_at = inspection.observed_at

    if device.ipv4 and baseline.ipv4 and device.ipv4 != baseline.ipv4:
        different = not _same_network(baseline.ipv4, device.ipv4)
        ctx.record(ChangeEvent(
            mac=mac, change_type="ip_changed", occurred_at=now, signal="ip", subject=device.ipv4, source="arp",
            significance=("medium" if not learning else "low") if different else "info",
            previous={"ipv4": baseline.ipv4}, current={"ipv4": device.ipv4, "different_network": different},
        ), excluded=excluded)
    if device.ipv4:
        baseline.ipv4 = device.ipv4

    if device.hostname and baseline.hostname and device.hostname.lower() != baseline.hostname.lower():
        ctx.record(ChangeEvent(
            mac=mac, change_type="hostname_changed", occurred_at=now, signal="hostname", subject=device.hostname,
            source="arp", significance="info" if learning else "low",
            previous={"hostname": baseline.hostname}, current={"hostname": device.hostname},
        ), excluded=excluded)
    if device.hostname:
        baseline.hostname = device.hostname

    if identity.is_known:
        category_changed = (
            baseline.identity_category not in (None, "Unknown") and identity.category != "Unknown"
            and identity.category != baseline.identity_category
        )
        maker_changed = bool(
            baseline.identity_manufacturer and identity.manufacturer
            and identity.manufacturer != baseline.identity_manufacturer
        )
        if category_changed or maker_changed:
            ctx.record(ChangeEvent(
                mac=mac, change_type="identity_changed", occurred_at=now, signal="identity",
                subject=identity.probable_identity, source="identity",
                significance="info" if learning else "medium",
                previous={
                    "identity": _identity_label(baseline.identity_manufacturer, baseline.identity_category),
                    "category": baseline.identity_category, "manufacturer": baseline.identity_manufacturer,
                },
                current={
                    "identity": _identity_label(identity.manufacturer, identity.category),
                    "category": identity.category, "manufacturer": identity.manufacturer,
                    "confidence": identity.confidence,
                },
            ), excluded=excluded)
        baseline.identity_category = identity.category
        baseline.identity_manufacturer = identity.manufacturer or baseline.identity_manufacturer

    if trusted != baseline.trusted:
        ctx.record(ChangeEvent(
            mac=mac, change_type="trust_changed", occurred_at=now, source="allowlist",
            previous={"trusted": baseline.trusted},
            current={"trusted": trusted, "name": device.allowlist_name},
        ))
        baseline.trusted = trusted

    unknown_minutes = (now - device.first_seen).total_seconds() / 60
    arrived_while_watching = ctx.watching_since is None or device.first_seen > ctx.watching_since
    unknown_present = (
        arrived_while_watching and not trusted and device.status == "online" and device.review_state == "pending"
        and is_review_needed(device, now=now) and unknown_minutes >= cfg.unknown_device_minutes
    )
    if unknown_present and baseline.unknown_present_event_id is None:
        saved = ctx.record(ChangeEvent(
            mac=mac, change_type="unknown_device_present", occurred_at=now, source="baseline", significance="high",
            current={"minutes": round(unknown_minutes)},
        ))
        baseline.unknown_present_event_id = saved.id
    elif baseline.unknown_present_event_id is not None and (trusted or not is_review_needed(device, now=now)):
        baseline.unknown_present_event_id = None  # cleared by trusting/reviewing - may fire again later

    if baseline != original:
        store.save_baseline(baseline, now=now)
    return baseline


def _new_item_event(
    mac: str, signal: str, value: str, *, now: datetime, admin: bool, learning: bool, trusted: bool,
    server_like: bool, baseline_labels: list[str], monitored_days: float, returned: bool,
) -> ChangeEvent:
    if signal == "ipv6_prefix":
        significance = "info"
    elif admin:
        significance = "high"
    elif not learning and trusted and server_like:
        significance = "medium"
    else:
        significance = "low"
    return ChangeEvent(
        mac=mac, change_type=_NEW_CHANGE[signal], occurred_at=now, signal=signal, subject=value,
        source=_SIGNAL_SOURCE[signal], significance=significance, previous={"present": False},
        current={
            "present": True, "admin": admin, "baseline": baseline_labels, "monitored_days": monitored_days,
            "established": not learning, "learning": learning, "returned": returned,
        },
    )


def _reassess_risk(
    ctx: _Context, dossier: DeviceDossier, *, baseline: DeviceBaseline, items: list[BaselineItem],
    events: list[ChangeEvent], previous: RiskAssessment | None, dhcp_server: bool,
    record_decrease: bool = False,
) -> RiskAssessment:
    """Score one device and store it. A rise in level is recorded as a
    change; a fall is only recorded when it's the direct result of an
    operator action (``record_decrease``) - risk easing as, say, "first
    seen today" ages out is not news."""

    now = ctx.now
    assessment = assess(gather_inputs(
        dossier, now=now, baseline=baseline, items=items, events=events, dhcp_server=dhcp_server,
        long_absence_days=ctx.cfg.changes.long_absence_days,
    ), now=now)
    mac = dossier.device.mac
    rising = previous is not None and RISK_LEVELS.index(assessment.level) > RISK_LEVELS.index(previous.level)
    if previous is not None and previous.level != assessment.level and (rising or record_decrease):
        significance = {"critical": "critical", "high": "high", "moderate": "medium"}.get(assessment.level, "info")
        ctx.record(ChangeEvent(
            mac=mac, change_type="risk_changed", occurred_at=now, source="risk",
            significance=significance if rising else "info",
            risk_before=previous.score, risk_after=assessment.score,
            previous={"score": previous.score, "level": previous.level},
            current={
                "score": assessment.score, "level": assessment.level, "rising": rising,
                "contributions": [c.model_dump() for c in assessment.contributions],
            },
        ))
    if previous is None or (previous.score, previous.level, previous.contributions) != (
        assessment.score, assessment.level, assessment.contributions
    ):
        ctx.store.save_risk(mac, assessment, now=now)
    return assessment


# --- operator actions ------------------------------------------------------


def assess_device(
    store: DeviceStore, allowlist: Allowlist, cfg: Config, mac: str, *,
    signatures: SignatureSet, identity_rules: IdentityRuleSet, now: datetime,
) -> RiskAssessment | None:
    """One device's risk right now, without storing or recording anything
    - for showing it (`lanfence risk`, the web device page)."""

    dossier = build_device_dossier(
        store, allowlist, mac, signatures=signatures, identity_rules=identity_rules,
        vendor_file=cfg.vendor_file, now=now,
    )
    if dossier is None:
        return None
    return assess(gather_inputs(
        dossier, now=now, baseline=store.get_baseline(mac), items=store.baseline_items(mac),
        events=store.change_events(since=now - _RISK_EVENT_WINDOW, mac=mac),
        dhcp_server=dossier.device.mac in store.dhcp_server_source_macs_since(now - _DHCP_RISK_WINDOW),
        long_absence_days=cfg.changes.long_absence_days,
    ), now=now)


def reassess_device(
    store: DeviceStore, allowlist: Allowlist, cfg: Config, mac: str, *,
    signatures: SignatureSet, identity_rules: IdentityRuleSet, now: datetime,
) -> RiskAssessment | None:
    """Recompute and store one device's risk straight away - after a
    review action, so the change is reflected without waiting for the
    next sweep. A level change is recorded like any other."""

    dossier = build_device_dossier(
        store, allowlist, mac, signatures=signatures, identity_rules=identity_rules,
        vendor_file=cfg.vendor_file, now=now,
    )
    if dossier is None:
        return None
    ctx = _Context(store=store, cfg=cfg, now=now, recorded=[])
    return _reassess_risk(
        ctx, dossier, baseline=store.get_baseline(mac), items=store.baseline_items(mac),
        events=store.change_events(since=now - _RISK_EVENT_WINDOW, mac=mac), previous=store.get_risk(mac),
        dhcp_server=dossier.device.mac in store.dhcp_server_source_macs_since(now - _DHCP_RISK_WINDOW),
        record_decrease=True,
    )


def review_change(
    store: DeviceStore, event_id: int, action: str, *, now: datetime, note: str | None = None,
    snooze_for: timedelta | None = None,
) -> ChangeEvent | None:
    """Apply one review action to a change: "reviewed", "investigating",
    "snoozed" (for ``snooze_for``), "accepted" (also folds the item into
    the baseline - the change itself stays in history), "unreviewed", or
    "note" (annotate only). Returns the updated change, or ``None`` if it
    doesn't exist."""

    event = store.get_change_event(event_id)
    if event is None:
        return None
    note_arg = note if note is not None else event.review_note
    if action == "note":
        return store.update_change_review(
            event_id, review_state=event.review_state, now=now, note=note_arg, snoozed_until=event.snoozed_until,
        )
    if action == "snoozed":
        return store.update_change_review(
            event_id, review_state="snoozed", now=now, note=note_arg,
            snoozed_until=now + (snooze_for or timedelta(days=1)),
        )
    if action == "accepted" and event.mac and event.signal in ("port", "mdns", "ssdp", "ipv6_prefix"):
        for item in store.baseline_items(event.mac):
            if item.signal == event.signal and item.value == event.subject and not item.in_baseline:
                store.save_baseline_item(item.model_copy(update={"in_baseline": True, "origin": "accepted"}))
    return store.update_change_review(event_id, review_state=action, now=now, note=note_arg)


def accept_pending(store: DeviceStore, mac: str, *, now: datetime) -> int:
    """Accept every pending item for ``mac`` into its baseline, marking
    their changes accepted. Returns how many items were accepted."""

    pending = [i for i in store.baseline_items(mac) if not i.in_baseline]
    keys = {(i.signal, i.value) for i in pending}
    for item in pending:
        store.save_baseline_item(item.model_copy(update={"in_baseline": True, "origin": "accepted"}))
    for event in store.change_events(mac=mac):
        if (event.signal, event.subject) in keys and event.review_state not in ("accepted",):
            store.update_change_review(event.id, review_state="accepted", now=now)
    return len(pending)


def reset_baseline(store: DeviceStore, mac: str, *, now: datetime) -> ChangeEvent:
    """Forget what's normal for ``mac`` and learn it again from scratch.
    Every past change is kept."""

    store.delete_baseline(mac)
    return store.record_change_event(ChangeEvent(
        mac=mac, change_type="baseline_reset", occurred_at=now, source="baseline",
    ))


def set_excluded_signals(store: DeviceStore, mac: str, signals: list[str], *, now: datetime) -> DeviceBaseline | None:
    baseline = store.get_baseline(mac)
    if baseline is None:
        return None
    baseline.excluded_signals = sorted(set(signals))
    store.save_baseline(baseline, now=now)
    return baseline


# --- historical comparison ---------------------------------------------------


@dataclass(frozen=True)
class ComparisonRow:
    """One line of "then vs now" for a device."""

    signal: str
    label: str
    now: bool
    then: bool
    in_baseline: bool
    origin: str

    @property
    def status(self) -> str:
        if self.now and not self.then:
            return "new"
        if self.then and not self.now:
            return "removed"
        return "unchanged" if self.now else "absent"


def compare(store: DeviceStore, mac: str, *, since: datetime | None, now: datetime) -> list[ComparisonRow]:
    """Each tracked item for ``mac``: present now vs present at ``since``
    - or, with ``since=None``, vs the expected baseline. Built from each
    item's first-seen/removed times, not stored snapshots."""

    rows = []
    for item in store.baseline_items(mac):
        if since is None:
            then = item.in_baseline
        else:
            then = item.first_seen <= since and (item.present or (item.removed_at is not None and item.removed_at > since))
        rows.append(ComparisonRow(
            signal=item.signal, label=service_label(item.signal, item.value), now=item.present, then=then,
            in_baseline=item.in_baseline, origin=item.origin,
        ))
    return sorted(rows, key=lambda r: (r.signal, r.label))


# --- policies: which changes become alerts -----------------------------------


def _device_context(dossier: DeviceDossier | None) -> DeviceContext:
    if dossier is None:
        return DeviceContext()
    return DeviceContext(
        trusted=dossier.device.allowlisted, category=dossier.effective_category, label=dossier.label,
    )


def run_change_detection(
    store: DeviceStore,
    allowlist: Allowlist,
    cfg: Config,
    *,
    signatures: SignatureSet,
    identity_rules: IdentityRuleSet,
    now: datetime,
) -> tuple[list[ChangeEvent], list[Finding]]:
    """Detect changes, record which policy (if any) each one matched, and
    return the recorded changes plus the alerts to send for them. Alerts
    for change types LAN Fence already alerts on in its own right (see
    :data:`lanfence.policy.BUILTIN_ALERTED`) are never duplicated here -
    :func:`shape_findings` handles those."""

    events = detect_changes(store, allowlist, cfg, signatures=signatures, identity_rules=identity_rules, now=now)
    policies = effective_policies(cfg.policies)
    alerts: list[Finding] = []
    dossiers: dict[str, DeviceDossier | None] = {}
    for event in events:
        if event.suppressed:
            continue
        if event.mac is not None and event.mac not in dossiers:
            dossiers[event.mac] = build_device_dossier(
                store, allowlist, event.mac, signatures=signatures, identity_rules=identity_rules,
                vendor_file=cfg.vendor_file, now=now, inspection=None,
            )
        dossier = dossiers.get(event.mac) if event.mac else None
        policy = match(policies, event, _device_context(dossier))
        if policy is None:
            continue
        store.set_change_policy(event.id, policy.id, alerted_at=None)
        if policy.action != "alert" or event.change_type in BUILTIN_ALERTED:
            continue
        risk = store.get_risk(event.mac) if event.mac else None
        device = dossier.device if dossier else None
        evidence = _device_evidence_lines(
            mac=device.mac, ip=device.ip, hostname=device.hostname, vendor=device.vendor,
            allowlisted=device.allowlisted, allowlist_name=device.allowlist_name, metadata=device.metadata,
        ) if device else []
        recommendation = risk.recommendation if risk is not None and risk.level in ("high", "critical") else (
            "Review this change in LAN Fence's What Changed? view, and accept it if it's expected."
        )
        alerts.append(change_alert(
            event, policy, _device_context(dossier), evidence=evidence, recommendation=recommendation,
        ))
    return events, alerts


def shape_findings(
    findings: list[Finding],
    store: DeviceStore,
    allowlist: Allowlist,
    cfg: Config,
    *,
    signatures: SignatureSet,
    identity_rules: IdentityRuleSet,
    now: datetime,
) -> tuple[list[Finding], list[Finding]]:
    """Apply alert policies to LAN Fence's built-in findings (new or
    returning devices, always-on absence, unapproved DHCP servers).
    Returns ``(shaped, to_dispatch)``: every finding with any
    policy-adjusted severity, and the ones still to send now (a
    digest-only or "none" policy holds a finding back)."""

    policies = effective_policies(cfg.policies)
    shaped: list[Finding] = []
    to_dispatch: list[Finding] = []
    for finding in findings:
        dossier = build_device_dossier(
            store, allowlist, finding.mac, signatures=signatures, identity_rules=identity_rules,
            vendor_file=cfg.vendor_file, now=now, inspection=None,
        ) if finding.mac and finding.change_type else None
        result, dispatch = shape_builtin_finding(finding, policies, _device_context(dossier))
        shaped.append(result)
        if dispatch:
            to_dispatch.append(result)
    return shaped, to_dispatch
