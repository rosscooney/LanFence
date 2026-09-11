# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Device fingerprinting: vendor lookup + built-in rogue-device signatures.

Every signal here is a heuristic. A MAC vendor prefix, a locally administered
bit, and a DHCP hostname are all attacker-controllable by anyone deliberately
trying to blend in - a match is a lead worth checking by hand, never proof on
its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml

from lanfence.logging_config import get_logger
from lanfence.models import Severity
from lanfence.netutil import is_locally_administered
from lanfence.vendor import lookup_vendor

log = get_logger("fingerprint")

_PACKAGED_SIGNATURES = "rogue_signatures.yaml"


@dataclass(frozen=True)
class SignatureMatch:
    category: str
    severity: Severity
    title: str
    description: str
    evidence: str


@dataclass(frozen=True)
class _Keyword:
    match: str
    category: str
    severity: str
    description: str


def _parse_keywords(rows: list[dict]) -> list[_Keyword]:
    out: list[_Keyword] = []
    for row in rows or []:
        try:
            severity = str(row.get("severity") or "info")
            if severity not in ("info", "medium", "high"):
                raise ValueError(f"signature {row.get('match')!r} has bad severity {severity!r}")
            out.append(
                _Keyword(
                    match=str(row["match"]).lower(),
                    category=str(row.get("category") or "unknown"),
                    severity=severity,
                    description=" ".join(str(row.get("description") or "").split()),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("skipping malformed signature entry %r: %s", row, exc)
    return out


class SignatureSet:
    def __init__(self, vendor_keywords: list[_Keyword], hostname_keywords: list[_Keyword]) -> None:
        self._vendor_keywords = vendor_keywords
        self._hostname_keywords = hostname_keywords

    def __len__(self) -> int:
        return len(self._vendor_keywords) + len(self._hostname_keywords)

    @classmethod
    def _load_yaml_text(cls, text: str) -> "SignatureSet":
        data = yaml.safe_load(text) or {}
        return cls(
            _parse_keywords(data.get("vendor_keywords")),
            _parse_keywords(data.get("hostname_keywords")),
        )

    @classmethod
    def load(cls, extra: Path | str | None = None) -> "SignatureSet":
        text = (
            resources.files("lanfence.data").joinpath(_PACKAGED_SIGNATURES).read_text(encoding="utf-8")
        )
        base = cls._load_yaml_text(text)
        if extra is None:
            return base
        path = Path(extra)
        if not path.is_file():
            log.warning("rogue signatures file not found: %s", path)
            return base
        extra_set = cls._load_yaml_text(path.read_text(encoding="utf-8"))
        return cls(
            base._vendor_keywords + extra_set._vendor_keywords,
            base._hostname_keywords + extra_set._hostname_keywords,
        )

    def match(self, *, vendor: str | None, hostname: str | None) -> list[SignatureMatch]:
        matches: list[SignatureMatch] = []
        if vendor:
            low = vendor.lower()
            for kw in self._vendor_keywords:
                if kw.match in low:
                    matches.append(
                        SignatureMatch(
                            category=kw.category,
                            severity=kw.severity,
                            title=f"Vendor matches known signature: {kw.category}",
                            description=kw.description,
                            evidence=f"vendor = {vendor!r} (matched {kw.match!r})",
                        )
                    )
        if hostname:
            low = hostname.lower()
            for kw in self._hostname_keywords:
                if kw.match in low:
                    matches.append(
                        SignatureMatch(
                            category=kw.category,
                            severity=kw.severity,
                            title=f"Hostname matches known signature: {kw.category}",
                            description=kw.description,
                            evidence=f"hostname = {hostname!r} (matched {kw.match!r})",
                        )
                    )
        return matches


def fingerprint_device(
    mac: str,
    hostname: str | None,
    *,
    signatures: SignatureSet,
    vendor_file: Path | str | None = None,
) -> tuple[str | None, list[SignatureMatch]]:
    """Return ``(vendor, signature_matches)`` for one device.

    A locally administered / randomized MAC is itself flagged as a low-grade
    signature match: it carries no vendor information and is common both for
    privacy-randomized phones/laptops and for spoofed or gadget hardware.
    """

    vendor = lookup_vendor(mac, extra_file=vendor_file)
    matches = signatures.match(vendor=vendor, hostname=hostname)
    if vendor is None and is_locally_administered(mac):
        matches.append(
            SignatureMatch(
                category="locally_administered_mac",
                severity="info",
                title="Locally administered (randomized/spoofed) MAC address",
                description=(
                    "The vendor bit pattern indicates a locally administered address "
                    "rather than one assigned by a hardware vendor. Common causes: "
                    "MAC-randomization privacy features on modern phones/laptops, "
                    "virtual machines/containers, or a device deliberately spoofing "
                    "its address."
                ),
                evidence=f"mac = {mac} (U/L bit set, no vendor OUI match)",
            )
        )
    return vendor, matches
