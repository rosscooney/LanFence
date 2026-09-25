# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Alert policies: a deliberately small, declarative way to decide which
changes deserve an alert, and how urgently.

A policy says: *when* one of these kinds of change happens (``triggers``),
*and* these simple conditions hold (``conditions`` - trust, category,
significance, remote-admin service, specific services, risk level),
*then* alert at this ``severity`` (or send it to the digest only, or do
nothing) - optionally with its own cooldown. Policies are data in the
config file, validated strictly; there is no expression language and
nothing is ever executed. Evaluated in order, first match wins - like a
firewall rule list - so a specific policy placed above a general one
overrides it.

Alerts go through LAN Fence's existing notification stack (snooze,
per-subject cooldown, global cap, channels) - policies never send
anything themselves. For change types LAN Fence already alerts on in its
own right (a new or returning device, an always-on device going missing,
an unapproved DHCP server), a matching policy *shapes that existing
alert* - its severity, or turning it into digest-only - rather than
sending a second one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from lanfence.changes import describe, is_admin_service, significance_at_least
from lanfence.models import (
    ChangeEvent,
    ChangeType,
    DeviceCategory,
    Finding,
    RiskLevel,
    Severity,
    Significance,
)

#: Change types whose alert comes from LAN Fence's existing built-in
#: findings (see :func:`lanfence.engine.build_findings`,
#: ``evaluate_availability`` and ``lanfence.dhcp_server``); a policy
#: shapes those instead of alerting twice.
BUILTIN_ALERTED: frozenset[str] = frozenset({"new_device", "reappeared", "disconnected", "dhcp_server_unexpected"})

#: Placeholder time for the change a built-in finding stands for - only its
#: type, device and significance matter to policy matching.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

_SEVERITY_TO_SIGNIFICANCE = {"info": "info", "medium": "medium", "high": "high", "critical": "critical"}


class PolicyConditions(BaseModel):
    """Every condition given must hold; an omitted one always holds."""

    model_config = {"extra": "forbid"}

    #: Only trusted (``true``) or only untrusted (``false``) devices.
    trusted: bool | None = None
    #: The device's category (its category override if set, otherwise
    #: its inferred identity) is one of these.
    categories: list[DeviceCategory] = Field(default_factory=list)
    #: The change is at least this significant.
    min_significance: Significance | None = None
    #: The change is (``true``) or isn't (``false``) about a
    #: remote-administration service (SSH, Telnet, RDP, VNC, ...).
    admin_service: bool | None = None
    #: The change is about one of these services, e.g. "tcp/22" or
    #: "_ssh._tcp".
    services: list[str] = Field(default_factory=list)
    #: For a risk change: the device's new risk level is one of these.
    risk_levels: list[RiskLevel] = Field(default_factory=list)
    #: For a risk change: only when risk went up (``true``).
    rising: bool | None = None


class Policy(BaseModel):
    model_config = {"extra": "forbid"}

    id: str
    description: str = ""
    enabled: bool = True
    triggers: list[ChangeType]
    conditions: PolicyConditions = Field(default_factory=PolicyConditions)
    severity: Severity
    #: "alert" dispatches through the configured channels, "digest" only
    #: includes the change in the daily digest, "none" records it only.
    action: Literal["alert", "digest", "none"] = "alert"
    #: Minimum gap between alerts from this policy for the same change;
    #: unset uses alerts.rate_limit_seconds.
    cooldown_seconds: float | None = None

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value):
            raise ValueError("policy id must be lowercase letters, digits and hyphens (max 64)")
        return value

    @field_validator("triggers")
    @classmethod
    def _at_least_one(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("a policy needs at least one trigger")
        return value

    @field_validator("cooldown_seconds")
    @classmethod
    def _non_negative(cls, value: float | None) -> float | None:
        if value is not None and value < 0:
            raise ValueError("cooldown_seconds must not be negative")
        return value


#: The built-in policies, used unless the config file sets ``policies``.
DEFAULT_POLICIES: tuple[Policy, ...] = (
    Policy(
        id="new-infrastructure-device", description="New untrusted network infrastructure device",
        triggers=["new_device"], conditions=PolicyConditions(trusted=False, categories=["Network Infrastructure"]),
        severity="critical",
    ),
    Policy(
        id="new-unknown-device", description="New untrusted device joined",
        triggers=["new_device"], conditions=PolicyConditions(trusted=False), severity="high",
    ),
    Policy(
        id="unapproved-dhcp-server", description="Unapproved DHCP server answered",
        triggers=["dhcp_server_unexpected"], severity="critical",
    ),
    Policy(
        id="new-remote-admin-service", description="New remote-administration service (SSH, RDP, VNC, ...)",
        triggers=["service_new", "mdns_service_new"], conditions=PolicyConditions(admin_service=True),
        severity="high",
    ),
    Policy(
        id="new-service-on-trusted-server", description="New service on a trusted server, NAS or infrastructure",
        triggers=["service_new", "mdns_service_new", "ssdp_service_new"],
        conditions=PolicyConditions(
            trusted=True, categories=["Server", "Storage / NAS", "Network Infrastructure"],
        ),
        severity="medium",
    ),
    Policy(
        id="unknown-device-present", description="Untrusted, unreviewed device on the network for over an hour",
        triggers=["unknown_device_present"], severity="high",
    ),
    Policy(
        id="risk-high", description="A device's risk rose to high or critical",
        triggers=["risk_changed"], conditions=PolicyConditions(risk_levels=["high", "critical"], rising=True),
        severity="high",
    ),
    Policy(
        id="identity-changed", description="A device's identity changed",
        triggers=["identity_changed"], severity="medium",
    ),
    Policy(
        id="informational-changes", description="Everything else worth knowing - digest only",
        triggers=[
            "ip_changed", "ipv6_prefix_new", "hostname_changed", "trust_changed", "baseline_established",
            "service_new", "service_removed", "mdns_service_new", "mdns_service_removed",
            "ssdp_service_new", "ssdp_service_removed",
        ],
        conditions=PolicyConditions(min_significance="low"),
        severity="info", action="digest",
    ),
)


def validate_policies(policies: list[Policy]) -> list[Policy]:
    ids = [p.id for p in policies]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate policy id(s): {', '.join(duplicates)}")
    return policies


def effective_policies(configured: list[Policy] | None) -> list[Policy]:
    """The configured policies, or the built-in defaults if none are set."""

    return list(DEFAULT_POLICIES) if configured is None else list(configured)


@dataclass(frozen=True)
class DeviceContext:
    """What a policy may know about the device a change is about."""

    trusted: bool = False
    category: str = "Unknown"
    label: str | None = None


def matches(policy: Policy, event: ChangeEvent, device: DeviceContext) -> bool:
    if not policy.enabled or event.change_type not in policy.triggers:
        return False
    cond = policy.conditions
    if cond.trusted is not None and device.trusted != cond.trusted:
        return False
    if cond.categories and device.category not in cond.categories:
        return False
    if cond.min_significance is not None and not significance_at_least(event.significance, cond.min_significance):
        return False
    if cond.admin_service is not None and is_admin_service(event.signal, event.subject) != cond.admin_service:
        return False
    if cond.services and event.subject not in cond.services:
        return False
    if cond.risk_levels and event.current.get("level") not in cond.risk_levels:
        return False
    if cond.rising is not None and bool(event.current.get("rising")) != cond.rising:
        return False
    return True


def match(policies: list[Policy], event: ChangeEvent, device: DeviceContext) -> Policy | None:
    """The first enabled policy that matches, or ``None``."""

    return next((p for p in policies if matches(p, event, device)), None)


def shape_builtin_finding(
    finding: Finding, policies: list[Policy], device: DeviceContext,
) -> tuple[Finding, bool]:
    """Apply the first matching policy to one of LAN Fence's built-in
    findings (identified by ``finding.change_type``). Returns the finding
    (with the policy's severity and id, if one matched) and whether it
    should still be dispatched now."""

    if finding.change_type not in BUILTIN_ALERTED:
        return finding, True
    pseudo = ChangeEvent(
        mac=finding.mac, subject_id=finding.subject_id, change_type=finding.change_type,
        occurred_at=_EPOCH, source="finding", significance=_SEVERITY_TO_SIGNIFICANCE[finding.severity],
    )
    policy = match(policies, pseudo, device)
    if policy is None:
        return finding, True
    shaped = finding.model_copy(update={
        "severity": policy.severity, "policy_id": policy.id, "cooldown_seconds": policy.cooldown_seconds,
    })
    return shaped, policy.action == "alert"


def change_alert(
    event: ChangeEvent, policy: Policy, device: DeviceContext, *, evidence: list[str], recommendation: str,
) -> Finding:
    """The alert for one change, in the same :class:`Finding` shape every
    other alert uses, so it flows through the existing notification stack."""

    text = describe(event)
    subject = device.label or event.subject_id or event.mac or "network"
    return Finding(
        mac=event.mac, subject_id=event.subject_id, kind="change", change_type=event.change_type,
        title=f"{subject}: {text.title}", severity=policy.severity,
        rationale=" ".join(text.details), recommendation=recommendation,
        evidence=[*evidence, *event.evidence, f"Policy: {policy.id} ({policy.description or policy.severity})"],
        policy_id=policy.id, change_event_id=event.id, cooldown_seconds=policy.cooldown_seconds,
        # One lane per specific change - e.g. SSH on this device - so a
        # service that flaps doesn't re-alert within the cooldown, while a
        # different service on the same device still does.
        cooldown_key=f"change#{event.mac or event.subject_id}#{event.change_type}#{event.subject or ''}",
    )
