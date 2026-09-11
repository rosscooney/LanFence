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
#: signal; "availability" is an always-on absence/recovery finding.
FindingKind = Literal["security", "lifecycle", "availability"]


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
    """A plain-language finding about one device."""

    mac: str
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

    @field_validator("mac")
    @classmethod
    def _normalize_mac(cls, value: str) -> str:
        return normalize_mac(value)

    @field_validator("title", "rationale", "recommendation")
    @classmethod
    def _clean_text_fields(cls, value: str) -> str:
        return clean_text(value, max_len=1000)

    @field_validator("evidence")
    @classmethod
    def _clean_list_fields(cls, value: list[str]) -> list[str]:
        return [clean_text(v, max_len=1000) for v in value]


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
