# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""The device dossier: one consolidated view of everything LAN Fence
already retains about a single device, plus a conservative, labeled
"likely device" classification (see :mod:`lanfence.classify`) and a
structured, confidence-scored "Know Your Network" identity (see
:mod:`lanfence.identity`).

This is deliberately a *read* layer, not a new source of truth - every
field here comes from data :mod:`lanfence.db`/:mod:`lanfence.engine`
already persist and already expose individually (``lanfence device``'s
address/name/service evidence, current fingerprint matches, operator
metadata). The dossier's job is only to gather that once, in one place, so
`lanfence device`, the interactive `lanfence review` queue, and `lanfence
allow`'s pre-trust confirmation all show the *same* consolidated context
instead of three slightly different reimplementations of it - see
:func:`build_device_dossier`.

``review_priority`` (used to order the interactive review queue) is a
transparent, deterministic sort key built from existing signals already in
the dossier - never a numeric "risk score" claiming a precision this data
doesn't support.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from lanfence.allowlist import Allowlist
from lanfence.classify import DeviceClassification, classify_device
from lanfence.db import DeviceStore
from lanfence.engine import build_device, is_review_needed
from lanfence.fingerprint import SignatureSet, fingerprint_device
from lanfence.identity import DeviceIdentity, IdentityEvidence, IdentityRuleSet, infer_identity
from lanfence.models import AddressEvidence, AdvertisedService, Device, InspectionResult, NameEvidence, Severity
from lanfence.netutil import is_locally_administered
from lanfence.sanitize import clean_text


#: Sentinel distinguishing "not given" (fetch fresh) from an explicit
#: ``None`` ("skip the lookup") for :func:`build_device_dossier`'s
#: ``inspection`` parameter - see its docstring.
_UNSET = object()


class FingerprintMatchInfo(BaseModel):
    """A JSON-serializable mirror of :class:`lanfence.fingerprint.SignatureMatch`
    - kept as its own model here (rather than importing the dataclass
    directly) since :mod:`lanfence.fingerprint` doesn't otherwise need a
    pydantic dependency, and this dossier is the one place a signature
    match needs to be embedded in a JSON payload."""

    category: str
    severity: Severity
    title: str
    description: str
    evidence: str


class DeviceDossier(BaseModel):
    """Everything LAN Fence currently knows about one device, gathered once.
    See the module docstring - nothing here is fabricated: every field
    traces back to evidence already retained elsewhere, and
    ``classification`` is always confidence-labeled and reasoned rather
    than presented as fact."""

    device: Device
    addresses: list[AddressEvidence] = Field(default_factory=list)
    names: list[NameEvidence] = Field(default_factory=list)
    services: list[AdvertisedService] = Field(default_factory=list)
    fingerprint_matches: list[FingerprintMatchInfo] = Field(default_factory=list)
    classification: DeviceClassification = Field(default_factory=DeviceClassification)
    #: The "Know Your Network" structured identity guess (see
    #: :mod:`lanfence.identity`) - additive alongside ``classification``
    #: above, not a replacement for it; see the module docstring.
    identity: DeviceIdentity = Field(default_factory=DeviceIdentity)
    is_locally_administered_mac: bool = False
    #: The most recent `lanfence inspect` result for this device, if it has
    #: ever been actively inspected - see :mod:`lanfence.active_inspect`.
    #: ``None`` (the common case) means never inspected, not "inspected and
    #: found nothing" (an empty ``open_ports`` list on a real result means
    #: that).
    inspection: Optional[InspectionResult] = None

    @property
    def label(self) -> str:
        """The best available short human label for this device - the
        allowlist (trusted) name first, then an operator-set friendly name
        (see :attr:`~lanfence.models.DeviceMetadata.friendly_name`), then
        the observed hostname, finally the bare MAC. Never a fabricated
        name."""

        if self.device.allowlist_name:
            return self.device.allowlist_name
        metadata = self.device.metadata
        if metadata and metadata.friendly_name:
            return metadata.friendly_name
        if self.device.hostname:
            return self.device.hostname
        return self.device.mac

    @property
    def effective_category(self) -> str:
        """The category to show/filter/sort on: the operator's own
        override when set (see
        :attr:`~lanfence.models.DeviceMetadata.category_override`),
        otherwise the inferred identity's category. Never discards the
        underlying inference - :attr:`identity` still holds it either way."""

        metadata = self.device.metadata
        if metadata and metadata.category_override:
            return metadata.category_override
        return self.identity.category

    @property
    def observed_services_summary(self) -> list[str]:
        """A short, deduplicated list of friendly service labels (falling
        back to the raw service type for anything without one) from
        *currently* advertised services only - see
        :meth:`lanfence.db.DeviceStore.advertised_services`."""

        seen: list[str] = []
        for service in self.services:
            if service.status != "current":
                continue
            label = service.service_label or service.service_type
            if label and label not in seen:
                seen.append(label)
        return seen


def build_device_dossier(
    store: DeviceStore,
    allowlist: Allowlist,
    mac: str,
    *,
    signatures: SignatureSet,
    identity_rules: IdentityRuleSet,
    vendor_file: Path | str | None = None,
    now: datetime | None = None,
    device: Optional[Device] = None,
    addresses: Optional[list[AddressEvidence]] = None,
    names: Optional[list[NameEvidence]] = None,
    services: Optional[list[AdvertisedService]] = None,
    inspection: Optional[InspectionResult] | object = _UNSET,
) -> Optional[DeviceDossier]:
    """Gather one device's full dossier. ``None`` if this MAC has never
    been observed. Every optional keyword lets a caller that already
    fetched a piece (e.g. `lanfence device`, which needs the same evidence
    for its own JSON payload) pass it straight through instead of a second
    database round trip; omitted pieces are fetched fresh here.

    ``identity_rules`` (see :class:`~lanfence.identity.IdentityRuleSet`)
    drives the ``identity`` field the same way ``signatures`` drives
    ``fingerprint_matches`` - required, not defaulted, so a caller always
    makes an explicit choice about which rule set (packaged plus any
    operator extra file) to score against.

    ``inspection`` is tri-state, unlike the other overrides: omit it (the
    default) to look up any persisted `lanfence inspect` result fresh;
    pass ``None`` explicitly to skip that lookup entirely (e.g. the review
    queue building many dossiers at once, where inspection results are
    rare and not needed for priority ordering); pass an actual
    :class:`~lanfence.models.InspectionResult` to reuse one already fetched.
    """

    now = now or datetime.now(timezone.utc)
    if device is None:
        device = build_device(store, allowlist, mac)
        if device is None:
            return None
    mac = device.mac

    if addresses is None:
        addresses = store.address_evidence_for(mac)
    if names is None:
        names = store.name_evidence_for(mac)
    if services is None:
        services = store.advertised_services(mac=mac, now=now)
    if inspection is _UNSET:
        inspection = store.inspection_for(mac)

    _vendor, matches = fingerprint_device(mac, device.hostname, signatures=signatures, vendor_file=vendor_file)
    fingerprint_matches = [
        FingerprintMatchInfo(
            category=m.category, severity=m.severity,
            title=clean_text(m.title, max_len=256), description=clean_text(m.description, max_len=1000),
            evidence=clean_text(m.evidence, max_len=500),
        )
        for m in matches
    ]

    current_services = [s for s in services if s.status == "current"]
    classification = classify_device(
        vendor=device.vendor,
        hostname=device.hostname,
        fingerprint_categories=[m.category for m in matches],
        service_labels=[s.service_label for s in current_services if s.service_label],
        service_types=[s.service_type for s in current_services],
    )

    identity = infer_identity(
        IdentityEvidence(
            vendor=device.vendor,
            hostname=device.hostname,
            locally_administered=is_locally_administered(mac),
            fingerprint_categories=frozenset(m.category for m in matches),
            service_types=tuple(s.service_type for s in current_services),
            service_labels=tuple(s.service_label for s in current_services if s.service_label),
            txt_values=tuple(v for s in current_services for v in s.attributes.values()),
            ssdp_servers=tuple(s.server for s in current_services if s.server),
            open_ports=frozenset(p.port for p in inspection.open_ports) if inspection else frozenset(),
        ),
        identity_rules,
    )

    return DeviceDossier(
        device=device,
        addresses=addresses,
        names=names,
        services=services,
        fingerprint_matches=fingerprint_matches,
        classification=classification,
        identity=identity,
        is_locally_administered_mac=is_locally_administered(mac),
        inspection=inspection,
    )


# --- review priority ---------------------------------------------------

#: The three human-facing priority labels - a transparent tier, never a
#: numeric "risk score" claiming more precision than this evidence
#: supports. Sort rank 0 is highest priority (shown first in `lanfence
#: review`); higher numbers sort later.
_PRIORITY_LABELS: dict[int, str] = {
    0: "Priority",
    1: "Priority",
    2: "Needs identification",
    3: "Needs identification",
    4: "Likely familiar",
    5: "Likely familiar",
}


def review_priority(dossier: DeviceDossier) -> tuple[int, str]:
    """A deterministic ``(sort_rank, label)`` pair for ordering the
    interactive review queue - devices with stronger security signals or
    weaker identity evidence sort first. Built entirely from signals
    already computed elsewhere (fingerprint matches, the locally-
    administered-MAC bit, the classification's own confidence) - never a
    weighted numeric score, so "why is this first" always has a plain-
    language answer (see each rank's comment below).
    """

    severities = {m.severity for m in dossier.fingerprint_matches}
    if "high" in severities or "medium" in severities:
        # An existing rogue-device signature match at meaningful severity -
        # the strongest available signal.
        rank = 0
    elif dossier.is_locally_administered_mac:
        # No vendor to go on at all - the weakest possible identity evidence.
        rank = 1
    elif not dossier.classification.is_known:
        # Nothing (vendor, hostname, advertised service) reasonably
        # supports even a low-confidence guess.
        rank = 2
    elif dossier.classification.confidence == "low":
        rank = 3
    elif not dossier.device.hostname and not dossier.observed_services_summary:
        # A named vendor but no corroborating hostname/service identity -
        # weak identity evidence, even if the classification itself is
        # confident (e.g. a vendor-only guess).
        rank = 4
    else:
        # A known manufacturer plus a hostname or advertised service to
        # back it up - the easiest devices to recognize on sight.
        rank = 5
    return rank, _PRIORITY_LABELS[rank]


# --- first-run triage summary --------------------------------------------


class TriageSummary(BaseModel):
    """Orientation counts for the *whole* inventory, shown once after a
    scan - not a replacement for the compact scan table, and not a "risk
    score": each device lands in exactly one of four plain-language
    buckets, built from the same :func:`review_priority` rank already used
    to order the review queue (see :func:`build_triage_summary`), plus a
    count of how many devices already have a review decision recorded
    (:func:`lanfence.engine.is_review_needed`)."""

    total: int = 0
    straightforward: int = 0
    needs_identification: int = 0
    private_mac: int = 0
    security_flagged: int = 0
    reviewed: int = 0

    @property
    def pending(self) -> int:
        return self.total - self.reviewed


def build_triage_summary(dossiers: list[DeviceDossier], *, now: datetime | None = None) -> TriageSummary:
    """Bucket every discovered device's dossier into one of four
    orientation categories, reusing :func:`review_priority`'s rank rather
    than inventing a second classification: rank 0 (an existing
    medium/high-severity fingerprint match) is "higher-priority security
    characteristics"; rank 1 (a locally administered/randomized MAC - no
    real vendor identity at all) is "private/randomised MAC addresses";
    ranks 2-3 (unidentified, or only a low-confidence guess) are "need
    identification"; ranks 4-5 (a known manufacturer, ideally corroborated
    by a hostname or service) "appear straightforward".
    """

    now = now or datetime.now(timezone.utc)
    summary = TriageSummary()
    for dossier in dossiers:
        summary.total += 1
        rank, _label = review_priority(dossier)
        if rank == 0:
            summary.security_flagged += 1
        elif rank == 1:
            summary.private_mac += 1
        elif rank in (2, 3):
            summary.needs_identification += 1
        else:
            summary.straightforward += 1
        if not is_review_needed(dossier.device, now=now):
            summary.reviewed += 1
    return summary
