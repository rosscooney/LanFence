# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Structured (Pydantic) models shared across LAN Fence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from lanfence.netutil import normalize_mac
from lanfence.sanitize import clean_text

Severity = Literal["info", "medium", "high", "critical"]
SEVERITIES: tuple[str, ...] = ("info", "medium", "high", "critical")

EventType = Literal["new_device", "reappeared", "disconnected"]

#: Persisted review states are mutually exclusive; "pending" is the default
#: for any device with no review row at all, or whose snooze has expired.
ReviewStateName = Literal["pending", "snoozed", "investigating"]

#: Per-device presence expectation (separate from trust). "unspecified" is
#: the default and preserves pre-existing behavior; "intermittent" devices
#: (laptops, phones) routinely leave/rejoin and their routine lifecycle
#: announcements are suppressed; "always-on" devices are expected to stay
#: connected, and a sustained absence produces its own availability finding.
PresencePolicyName = Literal["unspecified", "intermittent", "always-on"]

#: What a finding is *about*, so intermittent-presence suppression and
#: availability-alert cooldown bucketing can act on an explicit signal
#: rather than pattern-matching human-readable titles. "security" (the
#: default) covers new-device/rogue-signature findings; "lifecycle" is a
#: routine connect/reappear announcement with no independent security
#: signal; "availability" is an always-on absence/recovery finding;
#: "network_service" is about a network role (e.g. a DHCP server) rather
#: than any one device - see :attr:`Finding.mac` being optional.
FindingKind = Literal["security", "lifecycle", "availability", "network_service", "change"]

#: The device-category taxonomy used by the identity engine
#: (:mod:`lanfence.identity`) and an operator's own category override (see
#: :attr:`DeviceMetadata.category_override`). Deliberately a closed,
#: coarse-grained list rather than open free text - "extend later" means
#: adding another entry here, not inventing a new shape of data. "Unknown"
#: is a real category, not an error state: plenty of genuinely-unidentified
#: devices belong on a network without LAN Fence pretending otherwise.
DeviceCategory = Literal[
    "Computer",
    "Phone",
    "Tablet",
    "Server",
    "Network Infrastructure",
    "Printer",
    "Camera",
    "Smart Home / IoT",
    "Media Device",
    "Storage / NAS",
    "Virtual Machine",
    "Development Board / SBC",
    "Unknown",
]
DEVICE_CATEGORIES: tuple[str, ...] = (
    "Computer", "Phone", "Tablet", "Server", "Network Infrastructure", "Printer", "Camera",
    "Smart Home / IoT", "Media Device", "Storage / NAS", "Virtual Machine", "Development Board / SBC", "Unknown",
)

#: Who a device belongs to and why it's on the network, set by the
#: operator (see :attr:`DeviceMetadata.asset_type`) - entirely separate
#: from the identity engine's *inferred* category above. A phone (category)
#: can be Company-owned, Personal/BYOD, or a Guest's; the two questions are
#: independent.
AssetType = Literal["Company", "Personal / BYOD", "Infrastructure", "IoT", "Guest", "Unknown"]
ASSET_TYPES: tuple[str, ...] = ("Company", "Personal / BYOD", "Infrastructure", "IoT", "Guest", "Unknown")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime) -> str:
    """A human-readable rendering of a timestamp, used by every CLI/report/
    email display - "2026-09-21 14:05:53 BST" instead of
    ``datetime.isoformat()``'s "2026-09-21T13:05:53+00:00" (a literal "T"
    separator and a numeric "+00:00" offset instead of a named zone).

    Converted to this machine's local timezone, same as `lanfence
    monitor`'s live dashboard (see ``lanfence.monitor_ui.local_now``) - the
    zone abbreviation is included precisely because "local" is otherwise
    ambiguous to a reader elsewhere (e.g. a digest email opened on a
    different machine/timezone than the one that generated it).

    Always second precision (sub-second precision has no display value
    here) - a naive ``dt`` is assumed to already be UTC, matching every
    timestamp this codebase stores (see ``lanfence.db._parse_dt``), before
    converting to local time.
    """

    aware = dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    return aware.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


#: How a piece of address/name evidence was obtained. Carried through
#: explicitly from the observation pipeline rather than inferred later -
#: see :class:`lanfence.scanner.ArpSighting.source` and
#: :func:`lanfence.engine.process_sighting`.
AddressSource = Literal["arp", "ipv6_nd", "icmp", "dhcp_ack", "legacy_snapshot"]
NameSource = Literal["dhcp_option_12", "reverse_dns", "legacy_snapshot"]

#: "observed" - LAN Fence itself saw this address in use (ARP/ND, or a name
#: it resolved/received directly). "lease_reported" - a DHCP server's ACK
#: *claims* this client was assigned this address; real evidence, but never
#: alone proof the client is actually using or reachable at it.
AddressAssociationKind = Literal["observed", "lease_reported"]


class DeviceMetadata(BaseModel):
    """Operator-provided inventory context for one device - who's
    responsible for it, where it is, and what kind of asset it is.
    Entirely separate from observed hostname/vendor, trust, review state,
    and presence policy: nothing here is verified, detected, or
    authenticated - ``owner`` is a responsibility label, not an
    authenticated identity, and ``location`` is whatever the operator
    typed in, not a detected physical position. ``updated_at`` is
    ``None`` for a MAC with no metadata set yet (every field unset).

    ``category_override`` and ``asset_type`` are the user-assigned half of
    "Know Your Network": a category the operator has explicitly chosen for
    this device, which always takes precedence over the identity engine's
    own inferred category (see :mod:`lanfence.identity`) when displaying or
    filtering by category - but the underlying inferred identity is never
    discarded or silently altered just because one device was corrected.
    """

    mac: str
    owner: str | None = None
    location: str | None = None
    #: What kind of asset this is (Company/Personal/Infrastructure/IoT/
    #: Guest) - see :data:`AssetType`. Independent of category: a phone can
    #: be Company-owned or a guest's.
    asset_type: AssetType | None = None
    purpose: str | None = None
    notes: str | None = None
    #: The operator's own correction of the identity engine's inferred
    #: category (see :data:`DeviceCategory`) - ``None`` means "trust the
    #: inferred category". Never fed back into the fingerprint rules
    #: themselves; it only overrides the *display* for this one device.
    category_override: DeviceCategory | None = None
    updated_at: datetime | None = None

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("owner", "location", "purpose")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else None

    @field_validator("notes")
    @classmethod
    def _clean_notes(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=2000) if value is not None else None


class Device(BaseModel):
    """The current known state of one device, keyed by MAC address.

    ``ip``/``hostname`` are **preferred values** computed from retained
    evidence (see :class:`AddressEvidence`/:class:`NameEvidence` and
    :func:`lanfence.db.DeviceStore.preferred_address`/``preferred_name``),
    not simply "whatever was observed most recently" - directly-observed
    address evidence outranks a DHCP-reported lease or imported legacy data
    regardless of recency, and a DHCP-reported name outranks reverse-DNS.
    They are a convenience, not a claim that other retained evidence is
    invalid - see ``lanfence device <mac>`` for the full evidence list.
    """

    mac: str
    ip: str | None = None
    #: This device's current preferred address in each family separately
    #: (see :meth:`lanfence.db.DeviceStore.preferred_addresses_by_family_for_macs`),
    #: so a dual-stack device can show both instead of just whichever
    #: family ``ip`` above happens to prefer overall. ``None`` unless a
    #: device inventory query has populated it - same join-at-read pattern
    #: as ``review_state``/``metadata``.
    ipv4: str | None = None
    ipv6: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    status: Literal["online", "offline"] = "online"
    first_seen: datetime
    last_seen: datetime
    allowlisted: bool = False
    allowlist_name: str | None = None
    fingerprints: list[str] = Field(default_factory=list)
    #: Review/snooze state (see :class:`ReviewState`) - "pending" and unset
    #: unless a device inventory query has populated these from the database.
    #: Not itself stored on the ``devices`` table; joined in at read time.
    review_state: ReviewStateName = "pending"
    review_notes: str | None = None
    snoozed_until: datetime | None = None
    #: Presence expectation (see :data:`PresencePolicyName`) - "unspecified"
    #: and unset unless a device inventory query has populated this from the
    #: database. Separate from trust: not itself stored on ``devices`` or in
    #: the allowlist; joined in at read time from ``device_presence``.
    presence_policy: PresencePolicyName = "unspecified"
    #: Per-device override of how long an "always-on" device may be absent
    #: before an availability finding fires. ``None`` means "use the
    #: configured global ``scan.offline_grace_seconds``" - callers needing
    #: the *effective* value combine this with that config themselves (see
    #: ``lanfence device``/``devices`` rendering). Meaningless when
    #: ``presence_policy`` isn't ``"always-on"``.
    offline_after_seconds: float | None = None
    #: Operator-provided inventory context (see :class:`DeviceMetadata`) -
    #: ``None`` unless a device inventory query (``lanfence devices``/
    #: ``device``) has populated it from the database - same join-at-read
    #: pattern as ``review_state``/``presence_policy``. Independent of
    #: trust/review/presence.
    metadata: DeviceMetadata | None = None

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("ip", "ipv4", "ipv6", "hostname", "vendor", "allowlist_name", "review_notes")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else None

    @field_validator("fingerprints")
    @classmethod
    def _clean_list(cls, value: list[str]) -> list[str]:
        return [clean_text(v, max_len=128) for v in value]


class ReviewState(BaseModel):
    """The persisted review/trust-review state for one MAC (``lanfence review``).

    Trust itself lives in the YAML allowlist, not here - this only tracks the
    mutually-exclusive ``snoozed``/``investigating`` states (``pending`` is
    the default and is never itself persisted as a row). ``updated_at`` is
    ``None`` for a MAC with no review row yet (never reviewed).
    """

    mac: str
    state: ReviewStateName = "pending"
    notes: str | None = None
    snoozed_until: datetime | None = None
    updated_at: datetime | None = None

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("notes")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=1000) if value is not None else None


class PresenceState(BaseModel):
    """The persisted presence policy for one MAC (separate from trust - see
    :data:`PresencePolicyName`). ``updated_at`` is ``None`` for a MAC with no
    presence row yet (``unspecified``, the default).

    ``availability_alerted`` tracks whether an availability (absence) finding
    has already fired for the device's *current* offline episode, so a
    recovery finding fires exactly once per episode and a restart never
    duplicates either - see ``lanfence/engine.py``'s always-on handling.
    """

    mac: str
    policy: PresencePolicyName = "unspecified"
    offline_after_seconds: float | None = None
    availability_alerted: bool = False
    updated_at: datetime | None = None

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)


class DeviceEvent(BaseModel):
    """A lifecycle transition for one device (connect / disconnect / reappear)."""

    mac: str
    event_type: EventType
    timestamp: datetime
    ip: str | None = None
    hostname: str | None = None

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("ip", "hostname")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else None


class AddressEvidence(BaseModel):
    """One retained (mac, ip, interface, source) address observation - not
    a lease interval. ``first_seen``/``last_seen`` summarize when this
    *specific* evidence row was first and most recently observed; they do
    not claim the address was continuously assigned throughout that span,
    and an old, stale-looking entry does not mean the address was released
    - only that nothing has re-confirmed it recently. See
    :meth:`lanfence.db.DeviceStore.address_evidence_for`.
    """

    mac: str
    ip: str
    family: Literal["ipv4", "ipv6"]
    #: The interface this was observed/reported on. ``""`` (never ``None`` -
    #: deliberately, so this participates correctly in uniqueness/dedup
    #: rather than SQL's NULL-never-equals-NULL behavior silently defeating
    #: it) means "not recorded" (e.g. very old legacy data).
    interface: str = ""
    source: AddressSource
    kind: AddressAssociationKind
    first_seen: datetime
    last_seen: datetime

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("interface")
    @classmethod
    def _clean_interface(cls, value: str) -> str:
        return clean_text(value, max_len=64) or ""


class NameEvidence(BaseModel):
    """One retained (mac, name_key, source, ip, interface) name observation.

    ``name`` is the sanitized display text (original case preserved);
    ``name_key`` is the normalized comparison key (lowercase, trailing DNS
    root dot stripped) used only for equivalence checks - "printer" and
    "printer.local" are deliberately *not* treated as the same name just
    because one is a prefix of the other. ``ip`` is the address this name
    is evidence *for* (the queried address, for reverse DNS) - ``""`` when
    not applicable. See :meth:`lanfence.db.DeviceStore.name_evidence_for`.
    """

    mac: str
    name: str
    name_key: str
    source: NameSource
    ip: str = ""
    interface: str = ""
    first_seen: datetime
    last_seen: datetime

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        return clean_text(value, max_len=256)

    @field_validator("interface")
    @classmethod
    def _clean_interface(cls, value: str) -> str:
        return clean_text(value, max_len=64) or ""


class Finding(BaseModel):
    """A plain-language finding, usually about one device - but not always:
    ``mac`` is ``None`` for a finding about a network *role* rather than a
    device (e.g. an unexpected DHCP server - see ``kind="network_service"``
    and ``lanfence/dhcp_server.py``). Never fabricate a MAC (a placeholder,
    a client's, or a relay's) to satisfy this field - leave it ``None`` and
    use ``subject_id`` instead."""

    mac: str | None = None
    title: str
    severity: Severity
    rationale: str = ""
    recommendation: str = ""
    evidence: list[str] = Field(default_factory=list)
    #: What this finding is about (see :data:`FindingKind`). Additive field;
    #: defaults to "security" so every finding predating this field - and
    #: every finding this codebase already builds without setting it
    #: explicitly - keeps its existing meaning.
    kind: FindingKind = "security"
    #: A stable identity for a finding not about one device (``mac is
    #: None``) - e.g. ``"eth0/192.168.1.9"`` for a DHCP server scoped by
    #: interface and server identifier. Used for cooldown keying and display
    #: instead of matching on ``title`` text. ``None`` for an ordinary
    #: device finding, where ``mac`` already is that identity.
    subject_id: str | None = None
    #: The kind of change this finding is about (see :data:`ChangeType`) -
    #: how alert policies recognise it (see :mod:`lanfence.policy`).
    change_type: str | None = None
    #: The alert policy that decided this finding's severity, if any.
    policy_id: str | None = None
    #: The recorded change this finding alerts on, if any.
    change_event_id: int | None = None
    #: A policy's own cooldown for this alert (``None``: the configured
    #: ``alerts.rate_limit_seconds``). Internal - not part of JSON output.
    cooldown_seconds: float | None = Field(default=None, exclude=True)
    #: Its own cooldown lane (see :func:`lanfence.engine.filter_rate_limited`),
    #: e.g. one per service per device for a change alert. Internal.
    cooldown_key: str | None = Field(default=None, exclude=True)

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str | None) -> str | None:
        return normalize_mac(value) if value is not None else None

    @field_validator("title", "rationale", "recommendation")
    @classmethod
    def _clean_text_fields(cls, value: str) -> str:
        return clean_text(value, max_len=1000)

    @field_validator("evidence")
    @classmethod
    def _clean_list_fields(cls, value: list[str]) -> list[str]:
        return [clean_text(v, max_len=1000) for v in value]

    @field_validator("subject_id")
    @classmethod
    def _clean_subject_id(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else None


class ScanResult(BaseModel):
    """The outcome of one scan sweep (a one-off ``scan`` or a tick of ``monitor``)."""

    started_at: datetime
    ended_at: datetime
    interface: str | None = None
    subnet: str | None = None
    #: Every interface this sweep covered. ``interface`` above holds the
    #: single one when exactly one was swept, and is ``None`` when more
    #: than one was (see :func:`lanfence.engine.run_active_sweep_multi`).
    interfaces: list[str] = Field(default_factory=list)
    #: The operator-set site name/location (see
    #: :class:`lanfence.config.SiteConfig`), so a script consuming JSON
    #: output from more than one LAN Fence instance can tell them apart -
    #: purely descriptive, ``None`` when unset.
    site_name: str | None = None
    site_location: str | None = None
    mode: Literal["active", "passive", "active+passive"] = "active"
    devices: list[Device] = Field(default_factory=list)
    events: list[DeviceEvent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @field_validator("errors")
    @classmethod
    def _clean_errors(cls, value: list[str]) -> list[str]:
        return [clean_text(v, max_len=500) for v in value]

    @property
    def highest_severity(self) -> Severity | None:
        for sev in reversed(SEVERITIES):
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    def to_json(self, *, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)


class DigestDeviceEntry(BaseModel):
    """One device's line in a digest section - a snapshot of *current*
    trust/review/presence state, regardless of which section (new,
    needs-review, investigating, missing-always-on) it appears in or why."""

    mac: str
    name: str | None = None
    ip: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    trusted: bool = False
    presence_policy: PresencePolicyName = "unspecified"
    review_state: ReviewStateName = "pending"
    review_notes: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    #: Current owner metadata, for context only - see ``DeviceMetadata``.
    #: Location is deliberately left out of digest rows to keep them
    #: terse; the full detail is one `lanfence device <MAC>` away.
    owner: str | None = None
    #: A terse, bounded summary of currently-advertised services (see
    #: :mod:`lanfence.discovery`) - populated only for ``new_devices``
    #: entries (see ``lanfence/digest.py``'s ``_bounded_section``); every
    #: other section leaves this ``None`` to keep routine rows terse.
    #: Advertised claims, never verified capabilities.
    services_summary: str | None = None

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("name", "ip", "hostname", "vendor", "review_notes", "owner", "services_summary")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else None


class DigestSection(BaseModel):
    """The full list of devices for one part of the digest - never
    truncated. ``omitted_count`` is always 0 and kept only so a JSON
    consumer written against an older digest doesn't break on a missing
    field; ``total_count`` equals ``len(items)``."""

    items: list[DigestDeviceEntry] = Field(default_factory=list)
    total_count: int = 0
    omitted_count: int = 0


class DigestActivity(BaseModel):
    """A compact, factual summary of lifecycle activity within the digest
    window - counts of *distinct devices*, not raw event counts, so a
    device that flapped several times within the window is counted once per
    activity type rather than inflating the total."""

    reappeared_device_count: int = 0
    disconnected_device_count: int = 0
    new_device_count: int = 0


class Digest(BaseModel):
    """A structured, side-effect-free summary of recent network activity -
    see :func:`lanfence.digest.build_digest`. Distinguishes activity that
    happened *within* ``window_start``..``window_end`` (``activity``,
    ``new_devices``) from *current* inventory/review state as of
    ``generated_at`` (``needs_review``, ``investigating``,
    ``missing_always_on``, ``counts.known_devices``/``online_devices``) -
    the latter intentionally includes devices first seen before the window.
    """

    schema_version: int = 1
    generated_at: datetime
    #: This host's own hostname (``socket.gethostname()``), so a digest is
    #: self-identifying if you run LAN Fence on more than one machine -
    #: separate from any *observed device's* hostname elsewhere in this
    #: model. ``None`` only if the caller never set it (e.g. an older
    #: caller, or the lookup itself failed). Set by the caller (`lanfence
    #: digest`), never computed inside :func:`lanfence.digest.build_digest`
    #: itself, for the same presentation-vs-database-read reason as
    #: ``portal_url``/``monitor_running`` below.
    generated_by_host: str | None = None
    #: The operator-set site name/location (see
    #: :class:`lanfence.config.SiteConfig`), so a digest is self-identifying
    #: when you run more than one LAN Fence instance - purely descriptive,
    #: ``None`` when unset. Set by the caller (`lanfence digest`), never
    #: computed inside :func:`lanfence.digest.build_digest` itself, for the
    #: same reason as ``generated_by_host`` above.
    site_name: str | None = None
    site_location: str | None = None
    window_start: datetime
    window_end: datetime

    known_devices: int = 0
    online_devices: int = 0

    new_devices: DigestSection = Field(default_factory=DigestSection)
    needs_review: DigestSection = Field(default_factory=DigestSection)
    investigating: DigestSection = Field(default_factory=DigestSection)
    missing_always_on: DigestSection = Field(default_factory=DigestSection)
    activity: DigestActivity = Field(default_factory=DigestActivity)

    #: Whether `lanfence monitor` is running right now, checked via its own
    #: pidfile (see ``lanfence/monitor_status.py``) - ``None`` if this was
    #: never checked. This is a live, present-tense check ("is the process
    #: up as of right now"), not a durable historical record of past
    #: uptime/alert-delivery success, which this version doesn't persist.
    #: Set by the caller (`lanfence digest`), never computed inside
    #: :func:`lanfence.digest.build_digest` itself, for the same
    #: presentation-vs-database-read reason as ``portal_url`` below.
    monitor_running: bool | None = None
    #: Capabilities this digest could not draw on because the underlying
    #: data isn't implemented/persisted in this version - e.g. historical
    #: security-finding storage, or monitor health tracking.
    omitted_capabilities: list[str] = Field(default_factory=list)
    #: Link to the web portal (see `lanfence/web.py`), if it's actually
    #: running right now - never just because it's *enabled* in config,
    #: since a stale/broken link would be worse than the "not running"
    #: note shown in its place (see ``lanfence/digest.py``'s
    #: ``format_digest_text``). Set by the caller (`lanfence digest`),
    #: never computed inside :func:`lanfence.digest.build_digest` itself,
    #: since it's a presentation/delivery detail, not database-derived
    #: digest data. Recomputed fresh each time (a DHCP-assigned address
    #: can change), so this is never a stored/configured value - see
    #: :func:`lanfence.web.build_portal_url`.
    portal_url: str | None = None

    @property
    def is_empty(self) -> bool:
        """No window activity, no outstanding review/investigation items,
        and no missing always-on devices. ``known_devices``/``online_devices``
        are informational only and never affect this - an unchanged
        inventory alone does not make a digest nonempty, and neither does
        the other direction: a big inventory with nothing new or
        outstanding is still an empty digest.
        """

        return (
            self.new_devices.total_count == 0
            and self.needs_review.total_count == 0
            and self.investigating.total_count == 0
            and self.missing_always_on.total_count == 0
            and self.activity.reappeared_device_count == 0
            and self.activity.disconnected_device_count == 0
        )


class DhcpServerRecord(BaseModel):
    """One observed DHCP server, coalesced by (interface, server identifier)
    - not a per-packet log. ``approved`` is computed at read time against
    current config, never stored, so approving a server later never rewrites
    the historical evidence already captured in ``last_*``/``first_seen``.

    Scoped by ``interface`` alone - already the OS-level name for a VLAN
    sub-interface (e.g. ``eth0.20``) where one is configured; this project
    does not parse raw 802.1Q tags, so no separate VLAN field is claimed.
    """

    interface: str
    server_id: str
    first_seen: datetime
    last_seen: datetime
    observation_count: int = 1
    last_message_type: str | None = None
    last_source_ip: str | None = None
    last_source_mac: str | None = None
    last_relay_ip: str | None = None
    last_router: str | None = None
    last_dns: str | None = None
    #: Computed at read time from current config - see the class docstring.
    approved: bool = False
    #: The operator's configured name for this server, if approved and named.
    name: str | None = None

    @field_validator(
        "last_message_type", "last_source_ip", "last_relay_ip", "last_router", "last_dns", "name"
    )
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else None

    @field_validator("last_source_mac")
    @classmethod
    def _normalize_source_mac(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return normalize_mac(value)
        except ValueError:
            # Untrusted wire evidence - keep the raw (sanitized) value
            # rather than dropping it or crashing, if it's ever malformed.
            return clean_text(value, max_len=64)


#: mDNS/DNS-SD (RFC 6762/6763) or SSDP/UPnP - the two passive discovery
#: mechanisms this project parses. See :mod:`lanfence.discovery`.
DiscoveryProtocol = Literal["mdns", "ssdp"]

#: "current": not expired/withdrawn - not a claim the service was ever
#: probed or verified reachable, only that its last-advertised lifetime
#: hasn't lapsed. "expired": its TTL/max-age lapsed with no refresh.
#: "withdrawn": the advertiser explicitly announced it's gone (mDNS
#: goodbye / SSDP ssdp:byebye) - a stronger, earlier signal than expiry.
AdvertisedServiceStatus = Literal["current", "expired", "withdrawn"]


class AdvertisedService(BaseModel):
    """One device-advertised service, correlated from mDNS/DNS-SD or SSDP/
    UPnP evidence (see :mod:`lanfence.discovery`) - a claim the advertising
    device makes about itself, never a verified capability, an
    authenticated identity, or proof the service is reachable.

    ``identity`` is the stable protocol-specific key evidence is correlated
    on: the full DNS-SD instance name (e.g.
    ``"Office Printer._ipp._tcp.local"``) for mDNS, or the ``USN`` for
    SSDP. ``mac``/``attribution_basis`` are computed at read time from
    current address evidence, never stored statically - see
    :meth:`lanfence.db.DeviceStore.advertised_services` for why a
    transmitting frame's own Ethernet/IP source is deliberately *not*
    trusted as attribution (mDNS proxies/reflectors and shared responders
    can advertise services for other hosts), and why an ambiguous or
    merely historical IP-to-MAC association leaves ``mac`` ``None`` rather
    than guessing. ``server``/``location`` (SSDP only) and ``attributes``
    (mDNS TXT only, bounded and allowlisted - see
    ``lanfence/discovery.py``) are all advertised claims, never verified;
    ``location`` in particular is never fetched, followed, or embedded as
    a resource - see the SSDP section of :mod:`lanfence.discovery`.
    """

    protocol: DiscoveryProtocol
    interface: str = ""
    family: Literal["ipv4", "ipv6"] | None = None
    service_type: str
    service_label: str | None = None
    instance_name: str | None = None
    identity: str
    target_host: str | None = None
    target_port: int | None = None
    addresses: list[str] = Field(default_factory=list)
    mac: str | None = None
    attribution_basis: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)
    server: str | None = None
    location: str | None = None
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None = None
    status: AdvertisedServiceStatus = "current"

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str | None) -> str | None:
        return normalize_mac(value) if value is not None else None

    @field_validator(
        "interface", "service_type", "service_label", "instance_name", "identity",
        "target_host", "attribution_basis", "server", "location",
    )
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=512) if value is not None else value

    @field_validator("addresses")
    @classmethod
    def _clean_addresses(cls, value: list[str]) -> list[str]:
        return [clean_text(v, max_len=64) for v in value]

    @field_validator("attributes")
    @classmethod
    def _clean_attributes(cls, value: dict[str, str]) -> dict[str, str]:
        return {clean_text(k, max_len=64): clean_text(v, max_len=256) for k, v in value.items()}


#: How one active-inspection result was obtained - "socket" is the always-
#: available bounded TCP connect-scan (see :mod:`lanfence.active_inspect`),
#: "nmap" the optional richer scan used only when the ``nmap`` binary is
#: present. Persisted so a stale result never silently looks more (or less)
#: thorough than it was.
InspectionMethod = Literal["socket", "nmap"]
InspectionConfidence = Literal["medium", "low"]


class InspectedPort(BaseModel):
    """One TCP port confirmed open on one device during active inspection
    (see :mod:`lanfence.active_inspect`) - ``service`` is an *inferred*
    label from the port number/banner, never a verified capability. Direct,
    targeted probe traffic to the device itself, unlike every other
    evidence model in this file, which is built entirely from passive
    observation or a response to a routine ARP/ND request.
    """

    port: int
    protocol: Literal["tcp"] = "tcp"
    service: str | None = None
    banner: str | None = None

    @field_validator("service", "banner")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else value


class InspectionResult(BaseModel):
    """The outcome of one ``lanfence inspect <mac>`` run against one device,
    persisted so it can be shown again (labeled with its age) without
    re-probing - see :meth:`lanfence.db.DeviceStore.record_inspection`/
    ``inspection_for``. Never produced by ``scan``/``monitor``/passive
    discovery/``review`` on their own - only an explicit, operator-initiated
    probe of one already-known device.

    ``platform_guess`` is a coarse, low-confidence inference from open-port
    patterns (see :mod:`lanfence.active_inspect`) - not OS fingerprinting,
    and never presented as definitive.
    """

    mac: str
    ip: str
    method: InspectionMethod
    observed_at: datetime
    open_ports: list[InspectedPort] = Field(default_factory=list)
    platform_guess: str | None = None
    platform_confidence: InspectionConfidence | None = None
    platform_reasons: list[str] = Field(default_factory=list)

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("ip", "platform_guess")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else value

    @field_validator("platform_reasons")
    @classmethod
    def _clean_reasons(cls, value: list[str]) -> list[str]:
        return [clean_text(v, max_len=256) for v in value]

    @property
    def is_known_platform(self) -> bool:
        return self.platform_confidence is not None


# --- Know When It Changes: baselines, change events, risk -------------------

#: What kind of change a :class:`ChangeEvent` records. The first three
#: mirror :data:`EventType` (a lifecycle event, re-expressed as a change);
#: the rest come from comparing a device against its baseline (see
#: :mod:`lanfence.baseline`), from DHCP-server monitoring, or from risk
#: re-assessment.
ChangeType = Literal[
    "new_device", "reappeared", "disconnected",
    "ip_changed", "ipv6_prefix_new", "hostname_changed", "identity_changed", "trust_changed",
    "service_new", "service_removed",
    "mdns_service_new", "mdns_service_removed",
    "ssdp_service_new", "ssdp_service_removed",
    "baseline_established", "baseline_reset",
    "unknown_device_present", "dhcp_server_unexpected", "risk_changed",
]
CHANGE_TYPES: tuple[str, ...] = (
    "new_device", "reappeared", "disconnected",
    "ip_changed", "ipv6_prefix_new", "hostname_changed", "identity_changed", "trust_changed",
    "service_new", "service_removed",
    "mdns_service_new", "mdns_service_removed",
    "ssdp_service_new", "ssdp_service_removed",
    "baseline_established", "baseline_reset",
    "unknown_device_present", "dhcp_server_unexpected", "risk_changed",
)

#: How much a change matters, lowest first - a prioritisation aid, never a
#: verdict. Distinct from :data:`Severity` (what an *alert* is sent at,
#: decided by a policy - see :mod:`lanfence.policy`).
Significance = Literal["info", "low", "medium", "high", "critical"]
SIGNIFICANCES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

#: Where a change stands in the operator's review. "accepted" means
#: "expected - fold it into the baseline" (history is kept either way).
ChangeReviewState = Literal["unreviewed", "reviewed", "investigating", "snoozed", "accepted"]
CHANGE_REVIEW_STATES: tuple[str, ...] = ("unreviewed", "reviewed", "investigating", "snoozed", "accepted")

#: Set-valued observations tracked as :class:`BaselineItem` rows. Scalar
#: observations (IPv4, hostname, identity, trust) live on
#: :class:`DeviceBaseline` itself.
BaselineSignal = Literal["port", "mdns", "ssdp", "ipv6_prefix"]
BASELINE_SIGNALS: tuple[str, ...] = ("port", "mdns", "ssdp", "ipv6_prefix")
#: Every signal an operator may exclude from alerting for one device -
#: the set-valued ones above plus the scalar ones.
EXCLUDABLE_SIGNALS: tuple[str, ...] = (*BASELINE_SIGNALS, "ip", "hostname", "identity")


class ChangeEvent(BaseModel):
    """One structured, reviewable change - see :mod:`lanfence.baseline`.
    ``previous``/``current`` hold the before/after state as data, never only
    prose; human wording is generated at display time (see
    :func:`lanfence.changes.describe`). ``mac`` is ``None`` for a
    network-level change (e.g. an unexpected DHCP server), identified by
    ``subject_id`` instead, exactly like :class:`Finding`."""

    id: int | None = None
    mac: str | None = None
    subject_id: str | None = None
    change_type: ChangeType
    occurred_at: datetime
    #: The baseline signal involved (see :data:`EXCLUDABLE_SIGNALS`), if any.
    signal: str | None = None
    #: The specific thing that changed within that signal, e.g. "tcp/22".
    subject: str | None = None
    previous: dict = Field(default_factory=dict)
    current: dict = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    #: What observed it: "lifecycle", "mdns", "ssdp", "inspection", "arp",
    #: "dhcp", "identity", "allowlist", "baseline", "risk".
    source: str
    significance: Significance = "info"
    risk_before: int | None = None
    risk_after: int | None = None
    #: The signal is excluded from alerting for this device: kept as
    #: history, never alerted or counted as needing attention.
    suppressed: bool = False
    review_state: ChangeReviewState = "unreviewed"
    review_note: str | None = None
    reviewed_at: datetime | None = None
    snoozed_until: datetime | None = None
    #: The policy that matched this change (see :mod:`lanfence.policy`), if
    #: any, and when an alert actually went out for it.
    policy_id: str | None = None
    alerted_at: datetime | None = None

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str | None) -> str | None:
        return normalize_mac(value) if value is not None else None

    @field_validator("subject_id", "signal", "subject", "source", "policy_id")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else None

    @field_validator("review_note")
    @classmethod
    def _clean_note(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=2000) if value is not None else None

    @field_validator("evidence")
    @classmethod
    def _clean_evidence(cls, value: list[str]) -> list[str]:
        return [clean_text(v, max_len=1000) for v in value]

    def needs_attention(self, *, now: datetime) -> bool:
        """Still waiting on the operator: not suppressed, not reviewed or
        accepted, and not inside an active snooze."""

        if self.suppressed or self.review_state in ("reviewed", "accepted"):
            return False
        if self.review_state == "snoozed" and self.snoozed_until is not None and self.snoozed_until > now:
            return False
        return True


class DeviceBaseline(BaseModel):
    """What LAN Fence has learned is normal for one device - see
    :mod:`lanfence.baseline`. Scalar observations are kept here; set-valued
    ones as :class:`BaselineItem` rows."""

    mac: str
    started_at: datetime
    established_at: datetime | None = None
    excluded_signals: list[str] = Field(default_factory=list)
    ipv4: str | None = None
    hostname: str | None = None
    identity_category: str | None = None
    identity_manufacturer: str | None = None
    trusted: bool = False
    inspection_at: datetime | None = None
    unknown_present_event_id: int | None = None


class BaselineItem(BaseModel):
    """One set-valued observation for a device (an open port, an mDNS or
    SSDP service type, an IPv6 /64 prefix). ``in_baseline`` is whether it's
    part of the expected baseline (learned during the learning period, or
    accepted by the operator) or still pending review."""

    mac: str
    signal: BaselineSignal
    value: str
    in_baseline: bool
    #: "initial" (present when the baseline began), "learned" (absorbed
    #: during learning), "accepted" (the operator accepted it) or
    #: "observed" (appeared later and awaits review).
    origin: Literal["initial", "learned", "accepted", "observed"]
    present: bool = True
    first_seen: datetime
    last_seen: datetime
    removed_at: datetime | None = None


RiskLevel = Literal["low", "moderate", "high", "critical"]
RISK_LEVELS: tuple[str, ...] = ("low", "moderate", "high", "critical")


class RiskContribution(BaseModel):
    """One factor's contribution to a device's risk score - see
    :mod:`lanfence.risk`."""

    factor: str
    label: str
    points: int


class RiskAssessment(BaseModel):
    """A device's security risk score: a bounded 0-100 prioritisation aid,
    separate from identity confidence and never a verdict - see
    :mod:`lanfence.risk`."""

    score: int = 0
    level: RiskLevel = "low"
    contributions: list[RiskContribution] = Field(default_factory=list)
    recommendation: str = ""
    assessed_at: datetime | None = None
