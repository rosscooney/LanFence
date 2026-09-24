# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Device identity engine: "Know Your Network", phase one.

LAN Fence already turns raw traffic into individual pieces of evidence - a
MAC vendor OUI, a self-reported DHCP hostname, an mDNS/DNS-SD or SSDP/UPnP
service advertisement, an existing rogue-device signature match (see
:mod:`lanfence.fingerprint`). This module combines that evidence into a
single, explainable guess at what a device actually *is* - its probable
manufacturer, category, product family, and platform - with a numeric,
deterministic confidence score and the individual evidence contributions
behind it, so the answer to "why does LAN Fence think this is an iPhone?"
is never "trust the model".

Every identity here is a labelled *inference*, never presented as a
verified fact - the same standing caveat as :mod:`lanfence.classify` (which
this module deliberately leaves untouched; see below) and every rogue
signature this codebase already ships: a MAC's vendor prefix, its hostname,
and everything it advertises over mDNS/SSDP are all trivially spoofable by
a device that wants to blend in.

Design notes, since this is a companion to (not a replacement for)
:mod:`lanfence.classify`:

- :mod:`lanfence.classify` produces a single free-text "likely device"
  label (e.g. "Sonos speaker") with a coarse high/medium/low confidence,
  and its output already drives the interactive review queue's ordering
  (:func:`lanfence.dossier.review_priority`) and the first-run triage
  summary - both established, tested behaviour this change does not touch.
- This module produces a *structured* identity (separate manufacturer/
  category/family/platform fields) with a numeric 0-100 confidence and a
  itemised evidence trail, driven entirely by a YAML rule set
  (:data:`lanfence.data.identity_rules`) rather than hard-coded Python
  conditionals - see :class:`IdentityRuleSet`. It is additive: a new
  ``identity`` field alongside the existing ``classification`` on
  :class:`lanfence.dossier.DeviceDossier`, computed fresh at read time from
  evidence already gathered, never persisted - the same "derive, don't
  cache" approach already used for classification and review priority, so
  there is no history table to keep consistent and no way for a stale
  assessment to linger after new evidence arrives.

Confidence is deterministic and centralised: every point value lives in the
YAML rule set, never scattered through application code, and
:func:`infer_identity` is the one place scores are combined. Conflicting
evidence (two rules asserting different values for the same field) reduces
confidence rather than being silently ignored - see its docstring for
exactly how.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dataclass_field
from importlib import resources
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from lanfence.logging_config import get_logger
from lanfence.models import DEVICE_CATEGORIES, DeviceCategory
from lanfence.sanitize import clean_text

log = get_logger("identity")

_PACKAGED_RULES = "identity_rules.yaml"

#: The fields a rule may assert a value for - see :class:`IdentityRule`.
_IDENTITY_FIELDS = ("manufacturer", "category", "family", "platform")


class IdentityEvidenceItem(BaseModel):
    """One rule's contribution to an identity assessment - always shown
    alongside the assessment itself (see ``lanfence device``'s "Why?"
    output), never left implicit. ``weight`` is negative for a rule whose
    asserted value *lost* to a different, higher-weighted value for the
    same field (see :func:`infer_identity`'s conflict handling) - shown as
    a penalty, not silently dropped."""

    label: str
    weight: int

    @field_validator("label")
    @classmethod
    def _clean(cls, value: str) -> str:
        return clean_text(value, max_len=256)


class DeviceIdentity(BaseModel):
    """A structured, confidence-scored guess at what a device is - see the
    module docstring. ``category`` always resolves to a real value
    (``"Unknown"`` when nothing supports more); ``manufacturer``/
    ``family``/``platform`` are ``None`` when no rule asserted them.
    ``confidence`` is bounded to 0-100 and is 0 exactly when no evidence
    matched at all."""

    category: DeviceCategory = "Unknown"
    manufacturer: str | None = None
    family: str | None = None
    platform: str | None = None
    confidence: int = 0
    evidence: list[IdentityEvidenceItem] = Field(default_factory=list)

    @field_validator("manufacturer", "family", "platform")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return clean_text(value, max_len=128) if value is not None else None

    @field_validator("confidence")
    @classmethod
    def _bounded(cls, value: int) -> int:
        return max(0, min(100, value))

    @property
    def is_known(self) -> bool:
        return self.confidence > 0

    @property
    def probable_identity(self) -> str:
        """The short human label the web/CLI headline shows, e.g. "Apple
        iPhone" - manufacturer plus family when both are known, falling
        back to whichever is available, and finally the bare category."""

        parts = [p for p in (self.manufacturer, self.family) if p]
        if parts:
            return " ".join(parts)
        return self.category


# --- rule set (YAML-driven, no hard-coded fingerprints in application code) -


@dataclass(frozen=True)
class _IdentityCondition:
    """One rule's ``when`` clause, fully evaluated against a device's
    evidence bag - see :meth:`matches`. Every key is optional; a rule
    matches only when *every* condition it specifies is satisfied (a bare
    rule with no conditions would match everything, so the loader rejects
    one - see :func:`_parse_rules`)."""

    vendor_contains: tuple[str, ...] = ()
    hostname_regex: re.Pattern | None = None
    locally_administered: bool | None = None
    fingerprint_category: tuple[str, ...] = ()
    service_type_contains: tuple[str, ...] = ()
    service_label: tuple[str, ...] = ()
    txt_contains: tuple[str, ...] = ()
    ssdp_server_contains: tuple[str, ...] = ()
    open_port_in: tuple[int, ...] = ()

    def matches(self, evidence: "IdentityEvidence") -> bool:
        if self.vendor_contains and not any(k in evidence.vendor_l for k in self.vendor_contains):
            return False
        if self.hostname_regex is not None and not self.hostname_regex.search(evidence.hostname_l):
            return False
        if self.locally_administered is not None and evidence.locally_administered != self.locally_administered:
            return False
        if self.fingerprint_category and not (set(self.fingerprint_category) & evidence.fingerprint_categories):
            return False
        if self.service_type_contains and not any(
            k in t for t in evidence.service_types_l for k in self.service_type_contains
        ):
            return False
        if self.service_label and not any(k in label for label in evidence.service_labels_l for k in self.service_label):
            return False
        if self.txt_contains and not any(k in v for v in evidence.txt_values_l for k in self.txt_contains):
            return False
        if self.ssdp_server_contains and not any(
            k in s for s in evidence.ssdp_servers_l for k in self.ssdp_server_contains
        ):
            return False
        if self.open_port_in and not (set(self.open_port_in) & evidence.open_ports):
            return False
        return True


@dataclass(frozen=True)
class IdentityRule:
    """One weighted, human-authored piece of evidence - see
    ``lanfence/data/identity_rules.yaml`` for the packaged starter set.
    ``asserts`` maps a subset of ``manufacturer``/``category``/``family``/
    ``platform`` to the value this rule votes for; a rule may assert as few
    as one field (most do)."""

    id: str
    weight: int
    when: _IdentityCondition
    asserts: dict[str, str]
    label: str


def _compile_condition(raw: dict) -> _IdentityCondition:
    def _tuple_of_str(key: str) -> tuple[str, ...]:
        value = raw.get(key)
        if value is None:
            return ()
        if isinstance(value, str):
            value = [value]
        return tuple(str(v).lower() for v in value)

    hostname_pattern = raw.get("hostname_regex")
    locally_administered = raw.get("locally_administered")
    open_ports_raw = raw.get("open_port_in")
    open_ports = tuple(int(p) for p in open_ports_raw) if open_ports_raw else ()

    return _IdentityCondition(
        vendor_contains=_tuple_of_str("vendor_contains"),
        hostname_regex=re.compile(str(hostname_pattern), re.IGNORECASE) if hostname_pattern else None,
        locally_administered=bool(locally_administered) if locally_administered is not None else None,
        fingerprint_category=_tuple_of_str("fingerprint_category"),
        service_type_contains=_tuple_of_str("service_type_contains"),
        service_label=_tuple_of_str("service_label"),
        txt_contains=_tuple_of_str("txt_contains"),
        ssdp_server_contains=_tuple_of_str("ssdp_server_contains"),
        open_port_in=open_ports,
    )


def _parse_rules(rows: list[dict]) -> list[IdentityRule]:
    out: list[IdentityRule] = []
    for row in rows or []:
        try:
            rule_id = str(row["id"])
            weight = int(row["weight"])
            if weight <= 0:
                raise ValueError(f"weight must be positive, got {weight}")
            when_raw = row.get("when") or {}
            if not when_raw:
                raise ValueError("a rule with no 'when' conditions would match every device")
            # A rule may assert nothing at all - a purely corroborating
            # signal (e.g. "advertises AirPlay") that adds weight to
            # whatever the other, field-asserting rules already establish,
            # without itself claiming a specific manufacturer/category/
            # family/platform. It can never conflict (see infer_identity),
            # since it makes no claim to disagree with.
            asserts = {k: str(row[k]) for k in _IDENTITY_FIELDS if row.get(k)}
            for field_name, value in asserts.items():
                if field_name == "category" and value not in DEVICE_CATEGORIES:
                    raise ValueError(f"category {value!r} is not in the known taxonomy")
            label = " ".join(str(row.get("label") or rule_id).split())
            out.append(IdentityRule(id=rule_id, weight=weight, when=_compile_condition(when_raw), asserts=asserts, label=label))
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("skipping malformed identity rule %r: %s", row, exc)
    return out


class IdentityRuleSet:
    """A loaded set of identity rules - packaged starter set plus an
    optional operator-supplied extra file, exactly mirroring
    :class:`lanfence.fingerprint.SignatureSet`'s own load pattern so the
    two stay consistent for anyone editing either."""

    def __init__(self, rules: list[IdentityRule]) -> None:
        self._rules = rules

    def __len__(self) -> int:
        return len(self._rules)

    @classmethod
    def _load_yaml_text(cls, text: str) -> "IdentityRuleSet":
        data = yaml.safe_load(text) or {}
        return cls(_parse_rules(data.get("rules")))

    @classmethod
    def load(cls, extra: Path | str | None = None) -> "IdentityRuleSet":
        text = resources.files("lanfence.data").joinpath(_PACKAGED_RULES).read_text(encoding="utf-8")
        base = cls._load_yaml_text(text)
        if extra is None:
            return base
        path = Path(extra)
        if not path.is_file():
            log.warning("identity rules file not found: %s", path)
            return base
        extra_set = cls._load_yaml_text(path.read_text(encoding="utf-8"))
        return cls(base._rules + extra_set._rules)

    def matched(self, evidence: "IdentityEvidence") -> list[IdentityRule]:
        return [rule for rule in self._rules if rule.when.matches(evidence)]


# --- evidence bag + scoring --------------------------------------------


@dataclass(frozen=True)
class IdentityEvidence:
    """Everything :func:`infer_identity` considers for one device, gathered
    entirely from evidence LAN Fence already retains (see
    :func:`lanfence.dossier.build_device_dossier` for how a real instance is
    built) - a pure data holder with no I/O of its own, so the engine can be
    exercised with plain synthetic values in tests.

    ``open_ports`` is only ever populated from a *previous, explicit*
    ``lanfence inspect`` result - this module never triggers a scan of its
    own to fill it in."""

    vendor: str | None = None
    hostname: str | None = None
    locally_administered: bool = False
    fingerprint_categories: frozenset[str] = dataclass_field(default_factory=frozenset)
    service_types: tuple[str, ...] = ()
    service_labels: tuple[str, ...] = ()
    txt_values: tuple[str, ...] = ()
    ssdp_servers: tuple[str, ...] = ()
    open_ports: frozenset[int] = dataclass_field(default_factory=frozenset)

    @property
    def vendor_l(self) -> str:
        return (self.vendor or "").lower()

    @property
    def hostname_l(self) -> str:
        return (self.hostname or "").lower()

    @property
    def service_types_l(self) -> tuple[str, ...]:
        return tuple(t.lower() for t in self.service_types)

    @property
    def service_labels_l(self) -> tuple[str, ...]:
        return tuple(t.lower() for t in self.service_labels)

    @property
    def txt_values_l(self) -> tuple[str, ...]:
        return tuple(t.lower() for t in self.txt_values)

    @property
    def ssdp_servers_l(self) -> tuple[str, ...]:
        return tuple(t.lower() for t in self.ssdp_servers)


def infer_identity(evidence: IdentityEvidence, rules: IdentityRuleSet) -> DeviceIdentity:
    """Combine every matching rule's weighted vote into one explainable
    identity - the single place LAN Fence's identity scoring happens.

    For each of ``manufacturer``/``category``/``family``/``platform``
    independently: every matched rule that asserts a value for that field
    contributes its ``weight`` towards that value, and the highest-scoring
    value wins (ties keep whichever rule was checked first, i.e. its
    position in the rule set - deterministic, not arbitrary).

    A matched rule then either *supports* the resulting identity (every
    field it asserts equals that field's winning value) or *conflicts*
    with it (at least one field it asserts lost to a different value). A
    supporting rule adds its full weight to the overall confidence;
    a conflicting rule subtracts its full weight - evidence that
    disagrees with the final answer makes LAN Fence less sure of it,
    never simply discarded. The result is clamped to 0-100.
    """

    matched = rules.matched(evidence)
    if not matched:
        return DeviceIdentity()

    field_totals: dict[str, dict[str, int]] = {field_name: {} for field_name in _IDENTITY_FIELDS}
    for rule in matched:
        for field_name, value in rule.asserts.items():
            field_totals[field_name][value] = field_totals[field_name].get(value, 0) + rule.weight

    winners: dict[str, str | None] = {}
    for field_name, totals in field_totals.items():
        if not totals:
            winners[field_name] = None
            continue
        best_weight = max(totals.values())
        # Deterministic tie-break: the value asserted by the
        # earliest-matching rule among those tied for the top weight.
        winners[field_name] = next(
            value for rule in matched for field, value in rule.asserts.items()
            if field == field_name and totals.get(value) == best_weight
        )

    confidence = 0
    evidence_items: list[IdentityEvidenceItem] = []
    for rule in matched:
        conflicts = any(winners[field_name] != value for field_name, value in rule.asserts.items())
        signed_weight = -rule.weight if conflicts else rule.weight
        confidence += signed_weight
        label = rule.label if not conflicts else f"{rule.label} (conflicts with the stronger evidence above)"
        evidence_items.append(IdentityEvidenceItem(label=label, weight=signed_weight))

    evidence_items.sort(key=lambda item: item.weight, reverse=True)

    return DeviceIdentity(
        category=winners["category"] or "Unknown",
        manufacturer=winners["manufacturer"],
        family=winners["family"],
        platform=winners["platform"],
        confidence=max(0, min(100, confidence)),
        evidence=evidence_items,
    )
