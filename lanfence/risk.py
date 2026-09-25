# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Device security risk: a bounded, explainable 0-100 prioritisation aid.

Separate from identity confidence (:mod:`lanfence.identity` - how sure
LAN Fence is about *what* a device is): risk says how much a device
deserves a look *right now*. It is never a verdict - a high score means
"this deserves investigation", not "this is compromised".

Deterministic and centralised: every weight is in :data:`RISK_WEIGHTS` and
every level boundary in :data:`RISK_THRESHOLDS`, both documented in the
README. The score is the sum of each applicable factor's points, clamped
to 0-100, and every contribution is kept so "why?" always has an answer.

Context matters: a private (locally administered) MAC on an identified
phone or laptop is how modern devices protect their owner's privacy, not a
warning sign, so it barely counts; the same on an unidentified device
counts more.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from lanfence.changes import is_admin_service, service_label, significance_at_least
from lanfence.models import BaselineItem, ChangeEvent, DeviceBaseline, RiskAssessment, RiskContribution

#: Points per factor. Positive raises risk, negative lowers it.
RISK_WEIGHTS: dict[str, int] = {
    "untrusted": 25,
    "investigating": 10,
    "first_seen_recently": 10,
    "private_mac": 10,
    "private_mac_expected": 2,
    "rogue_signature_high": 35,
    "rogue_signature_medium": 20,
    "identity_unknown": 10,
    "identity_uncertain": 5,
    "known_manufacturer": -5,
    "new_admin_service": 25,
    "new_service": 8,
    "unexpected_change": 20,
    "identity_changed": 15,
    "untrusted_infrastructure": 15,
    "dhcp_server": 30,
    "always_on_absent": 5,
    "long_absence_return": 5,
    "many_changes": 10,
}

#: At most this many services count individually - a device suddenly
#: advertising ten services is one concern, not ten.
_MAX_COUNTED_SERVICES = 2

#: Lowest score for each level, highest first.
RISK_THRESHOLDS: tuple[tuple[int, str], ...] = ((75, "critical"), (40, "high"), (20, "moderate"), (0, "low"))

#: Categories where a private MAC is normal privacy behaviour.
_PRIVATE_MAC_EXPECTED_CATEGORIES = frozenset({"Phone", "Tablet", "Computer"})


def level_for(score: int) -> str:
    for minimum, level in RISK_THRESHOLDS:
        if score >= minimum:
            return level
    return "low"


@dataclass
class RiskInputs:
    """Everything the score considers for one device - gathered by
    :func:`gather_inputs` from data LAN Fence already has."""

    trusted: bool = False
    investigating: bool = False
    first_seen: datetime | None = None
    online: bool = True
    always_on: bool = False
    private_mac: bool = False
    identity_category: str = "Unknown"
    identity_confidence: int = 0
    identity_manufacturer: str | None = None
    identity_uncertain: bool = False
    signature_severities: set[str] = field(default_factory=set)
    new_admin_services: list[str] = field(default_factory=list)
    new_services: list[str] = field(default_factory=list)
    unexpected_change: bool = False
    identity_changed: bool = False
    dhcp_server: bool = False
    long_absence_return: bool = False
    recent_changes: int = 0


def assess(inputs: RiskInputs, *, now: datetime) -> RiskAssessment:
    """Score one device - the single place risk is computed."""

    contributions: list[RiskContribution] = []

    def add(factor: str, label: str, points: int | None = None) -> None:
        contributions.append(
            RiskContribution(factor=factor, label=label, points=RISK_WEIGHTS[factor] if points is None else points)
        )

    if not inputs.trusted:
        add("untrusted", "Device is not trusted")
    if inputs.investigating:
        add("investigating", "Flagged for investigation")
    if inputs.first_seen is not None and now - inputs.first_seen < timedelta(days=1):
        add("first_seen_recently", "Device first seen in the last 24 hours")
    if inputs.private_mac:
        if inputs.identity_category in _PRIVATE_MAC_EXPECTED_CATEGORIES:
            add("private_mac_expected", f"Private MAC address (normal for a {inputs.identity_category.lower()})")
        else:
            add("private_mac", "Locally administered (private) MAC address")
    if "critical" in inputs.signature_severities or "high" in inputs.signature_severities:
        add("rogue_signature_high", "Matches a rogue-device signature (high)")
    elif "medium" in inputs.signature_severities:
        add("rogue_signature_medium", "Matches a rogue-device signature (medium)")
    if inputs.identity_confidence == 0:
        add("identity_unknown", "Device identity unknown")
    else:
        # Independent: the maker can be known while the exact device isn't.
        if inputs.identity_uncertain:
            add("identity_uncertain", "Device identity uncertain")
        if inputs.identity_manufacturer:
            add("known_manufacturer", f"Known manufacturer ({inputs.identity_manufacturer})")
    for label in inputs.new_admin_services[:_MAX_COUNTED_SERVICES]:
        add("new_admin_service", f"New administrative service: {label}")
    for label in inputs.new_services[:_MAX_COUNTED_SERVICES]:
        add("new_service", f"New service not in baseline: {label}")
    if inputs.unexpected_change:
        add("unexpected_change", "Unexpected behaviour change against an established baseline")
    if inputs.identity_changed:
        add("identity_changed", "Identity changed recently")
    if not inputs.trusted and inputs.identity_category == "Network Infrastructure":
        add("untrusted_infrastructure", "Untrusted network infrastructure device")
    if inputs.dhcp_server:
        add("dhcp_server", "Answered as an unapproved DHCP server")
    if inputs.always_on and not inputs.online:
        add("always_on_absent", "Always-on device is offline")
    if inputs.long_absence_return:
        add("long_absence_return", "Returned after an unusually long absence")
    if inputs.recent_changes >= 3:
        add("many_changes", f"{inputs.recent_changes} unreviewed changes in the last 24 hours")

    score = max(0, min(100, sum(c.points for c in contributions)))
    level = level_for(score)
    contributions.sort(key=lambda c: -abs(c.points))
    return RiskAssessment(
        score=score, level=level, contributions=contributions,
        recommendation=_recommendation(inputs, level), assessed_at=now,
    )


def _recommendation(inputs: RiskInputs, level: str) -> str:
    if inputs.dhcp_server:
        return (
            "This deserves investigation: find out why this device answered DHCP requests. If it's an "
            "expected DHCP server, add it to dhcp_servers.approved."
        )
    if level in ("high", "critical"):
        if inputs.new_admin_services:
            return (
                f"This deserves investigation. Check whether {inputs.new_admin_services[0]} was enabled "
                "deliberately - if it was, accept the change as expected."
            )
        if not inputs.trusted:
            return (
                "This deserves investigation. Identify the device: if it belongs on your network, trust it; "
                "if not, remove it."
            )
        return "This deserves investigation. Review its recent changes."
    if level == "moderate":
        if not inputs.trusted:
            return "Review this device when convenient, and trust it if it's yours."
        return "Review its recent changes when convenient."
    return "No action needed."


def gather_inputs(
    dossier,
    *,
    now: datetime,
    baseline: DeviceBaseline | None,
    items: list[BaselineItem],
    events: list[ChangeEvent],
    dhcp_server: bool,
    long_absence_days: float,
) -> RiskInputs:
    """Build :class:`RiskInputs` for one device from its dossier (see
    :mod:`lanfence.dossier`) and its baseline state. ``events`` are this
    device's recent changes (the last 30 days is plenty); only ones still
    needing attention count."""

    device = dossier.device
    identity = dossier.identity
    attention = [e for e in events if e.needs_attention(now=now)]
    attention_subjects = {(e.signal, e.subject) for e in attention}

    new_admin: list[str] = []
    new_other: list[str] = []
    for item in items:
        if item.in_baseline or not item.present or item.signal == "ipv6_prefix":
            continue
        if (item.signal, item.value) not in attention_subjects:
            continue  # reviewed or snoozed - no longer counted
        target = new_admin if is_admin_service(item.signal, item.value) else new_other
        target.append(service_label(item.signal, item.value))

    established = baseline is not None and baseline.established_at is not None
    week_ago, day_ago = now - timedelta(days=7), now - timedelta(days=1)
    unexpected = established and any(
        e.occurred_at >= week_ago and e.change_type not in ("risk_changed", "new_device", "reappeared", "disconnected")
        and significance_at_least(e.significance, "medium")
        for e in attention
    )
    return RiskInputs(
        trusted=device.allowlisted,
        investigating=device.review_state == "investigating",
        first_seen=device.first_seen,
        online=device.status == "online",
        always_on=device.presence_policy == "always-on",
        private_mac=dossier.is_locally_administered_mac,
        identity_category=dossier.effective_category,
        identity_confidence=identity.confidence,
        identity_manufacturer=identity.manufacturer,
        identity_uncertain=identity.is_uncertain,
        signature_severities={m.severity for m in dossier.fingerprint_matches},
        new_admin_services=new_admin,
        new_services=new_other,
        unexpected_change=unexpected,
        identity_changed=any(e.change_type == "identity_changed" for e in attention),
        dhcp_server=dhcp_server,
        long_absence_return=any(
            e.change_type == "reappeared" and e.occurred_at >= day_ago
            and float(e.current.get("absent_days") or 0) >= long_absence_days
            for e in attention
        ),
        recent_changes=sum(
            1 for e in attention
            if e.occurred_at >= day_ago and e.change_type != "risk_changed"
            and significance_at_least(e.significance, "low")
        ),
    )
