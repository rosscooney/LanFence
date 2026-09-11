# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Structured (Pydantic) models shared across LAN Fence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from lanfence.netutil import normalize_mac
from lanfence.sanitize import clean_text

Severity = Literal["info", "medium", "high"]
SEVERITIES: tuple[str, ...] = ("info", "medium", "high")

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
FindingKind = Literal["security", "lifecycle", "availability", "network_service"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Device(BaseModel):
    """The current known state of one device, keyed by MAC address."""

    mac: str
    ip: str | None = None
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

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("ip", "hostname", "vendor", "allowlist_name", "review_notes")
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
        for sev in ("high", "medium", "info"):
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

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("name", "ip", "hostname", "vendor", "review_notes")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=256) if value is not None else None


class DigestSection(BaseModel):
    """A bounded list of devices for one part of the digest - "and N more"
    instead of an unbounded dump. ``total_count`` is the true count before
    truncation, so a caller can tell "20 shown, 20 total" from "20 shown, 45
    total"."""

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

    ``monitoring_health`` is deliberately never inferred from the absence of
    evidence - this codebase has no durable, persisted record of monitor
    uptime or alert-delivery success/failure to draw on, so it always reads
    ``"Monitoring health unavailable"`` rather than guessing "healthy". A
    future version could persist real health evidence and report it here
    instead.
    """

    schema_version: int = 1
    generated_at: datetime
    window_start: datetime
    window_end: datetime

    known_devices: int = 0
    online_devices: int = 0

    new_devices: DigestSection = Field(default_factory=DigestSection)
    needs_review: DigestSection = Field(default_factory=DigestSection)
    investigating: DigestSection = Field(default_factory=DigestSection)
    missing_always_on: DigestSection = Field(default_factory=DigestSection)
    activity: DigestActivity = Field(default_factory=DigestActivity)

    monitoring_health: str = "Monitoring health unavailable"
    #: Capabilities this digest could not draw on because the underlying
    #: data isn't implemented/persisted in this version - e.g. historical
    #: security-finding storage, or monitor health tracking.
    omitted_capabilities: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """No window activity, no outstanding review/investigation items,
        and no missing always-on devices. ``known_devices``/``online_devices``
        are informational only and never affect this - an unchanged
        inventory alone does not make a digest nonempty, and neither does
        the other direction: a big inventory with nothing new or
        outstanding is still an empty digest. ``monitoring_health`` being
        unavailable is an absence of evidence, not a known problem, so it
        never makes a digest nonempty either.
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
