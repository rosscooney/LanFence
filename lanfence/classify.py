# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Conservative, evidence-based device-type classification.

A "likely device" guess (e.g. "Sonos speaker", "Network printer") is built
entirely from evidence LAN Fence already retains elsewhere - a MAC vendor
OUI, a self-reported hostname, an mDNS/SSDP service advertisement, or an
existing rogue-signature category match (see :mod:`lanfence.fingerprint`).
None of that evidence is authenticated: a MAC's vendor prefix, its hostname,
and everything it advertises over mDNS/SSDP are all trivially spoofable by
a device that wants to blend in - the same caveat this project's README and
rogue-signature findings already carry. A classification here is always a
labeled *inference*, never presented as a verified fact, and defaults to
"Unknown device" (no confidence) when the available evidence doesn't
reasonably support anything more specific - a guess is never invented just
to fill the field.

:func:`classify_device` is a pure function (no I/O, no database access) so
it can be tested with plain evidence tuples - see
:func:`lanfence.dossier.build_device_dossier` for how real evidence is
gathered and passed in.
"""

from __future__ import annotations

import re
from typing import Iterable, Literal, Optional

from pydantic import BaseModel, Field

from lanfence.sanitize import clean_text

Confidence = Literal["high", "medium", "low"]


class DeviceClassification(BaseModel):
    """A conservative guess at what kind of device this is, or the
    deliberate absence of one. ``confidence`` is ``None`` exactly when
    ``device_type`` is the ``"Unknown device"`` default - there is no such
    thing as a confident "unknown". ``reasons`` is the human-readable
    evidence trail behind the guess, always shown alongside it (see
    ``lanfence device``/``lanfence review``) rather than left implicit.
    """

    device_type: str = "Unknown device"
    confidence: Optional[Confidence] = None
    reasons: list[str] = Field(default_factory=list)

    @property
    def is_known(self) -> bool:
        return self.confidence is not None


# --- rule tables (small, conservative, and documented) ----------------------

#: Rogue-signature categories (see ``lanfence/data/rogue_signatures.yaml``)
#: that identify specific single-board-computer hardware strongly enough to
#: name it directly - the vendor OUI IS the hardware, not a guess about what
#: runs on it.
_SBC_CATEGORY_LABELS: dict[str, str] = {
    "raspberry_pi": "Raspberry Pi",
    "orange_pi": "Orange Pi (single-board computer)",
}

#: Chipset-level rogue-signature categories that only identify a *class* of
#: hardware (used in both legitimate IoT gear and some concerning devices) -
#: kept to "low" confidence and never claimed as a specific product.
_IOT_CHIPSET_CATEGORIES = {"esp32_esp8266", "allwinner_sbc_or_camera", "hisilicon_camera_soc", "usb_ethernet_gadget"}

_PRINTER_VENDOR_KEYWORDS = ("hewlett packard", "canon", "epson", "brother industries", "xerox", "kyocera", "lexmark")
_TV_MEDIA_VENDOR_KEYWORDS = (
    "samsung electronics", "lg electronics", "vizio", "roku", "sony corporation", "tcl", "amazon technologies",
)
_SONOS_VENDOR_KEYWORDS = ("sonos",)
_APPLE_VENDOR_KEYWORDS = ("apple, inc", "apple inc")

_WINDOWS_HOSTNAME_RE = re.compile(r"^(desktop|laptop)-[a-z0-9]+$", re.IGNORECASE)
_IPHONE_HOSTNAME_RE = re.compile(r"iphone", re.IGNORECASE)
_IPAD_HOSTNAME_RE = re.compile(r"ipad", re.IGNORECASE)
_MAC_HOSTNAME_RE = re.compile(r"macbook|imac|mac[\s-]?mini|mac[\s-]?studio", re.IGNORECASE)

_CONFIDENCE_ORDER: dict[Confidence, int] = {"high": 0, "medium": 1, "low": 2}


def classify_device(
    *,
    vendor: Optional[str],
    hostname: Optional[str],
    fingerprint_categories: Iterable[str] = (),
    service_labels: Iterable[str] = (),
    service_types: Iterable[str] = (),
) -> DeviceClassification:
    """Guess a device type from evidence already gathered elsewhere.

    ``fingerprint_categories`` are :attr:`lanfence.fingerprint.SignatureMatch.category`
    values already matched for this device; ``service_labels``/
    ``service_types`` come from its current :class:`~lanfence.models.AdvertisedService`
    evidence (``service_label`` is the small friendly-label allowlist from
    :mod:`lanfence.discovery`, ``service_type`` the raw DNS-SD/UPnP type
    string). When more than one rule matches, the highest-confidence result
    wins; a tie keeps whichever rule is checked first below (most specific
    signals are checked first).
    """

    vendor_l = (vendor or "").lower()
    hostname_l = (hostname or "").lower()
    categories = set(fingerprint_categories)
    labels_l = {clean_text(label, max_len=64).lower() for label in service_labels if label}
    types_l = {clean_text(t, max_len=256).lower() for t in service_types if t}

    candidates: list[DeviceClassification] = []

    for category, label in _SBC_CATEGORY_LABELS.items():
        if category in categories:
            candidates.append(
                DeviceClassification(
                    device_type=label, confidence="high",
                    reasons=[f"Vendor OUI identifies {label} hardware"],
                )
            )

    has_ipp = "printing" in labels_l or any("_ipp" in t for t in types_l)
    if has_ipp:
        reasons = ["Advertises IPP printing (mDNS _ipp._tcp/_ipps._tcp)"]
        if vendor:
            reasons.append(f"Vendor OUI: {vendor}")
        candidates.append(DeviceClassification(device_type="Network printer", confidence="high", reasons=reasons))
    elif any(k in vendor_l for k in _PRINTER_VENDOR_KEYWORDS):
        candidates.append(
            DeviceClassification(
                device_type="Network printer", confidence="medium",
                reasons=[f"Vendor OUI: {vendor} (a known printer manufacturer)"],
            )
        )

    has_airplay = (
        "airplay" in labels_l or "remote audio" in labels_l
        or any("_raop" in t or "_airplay" in t for t in types_l)
    )
    if any(k in vendor_l for k in _SONOS_VENDOR_KEYWORDS):
        reasons = [f"Vendor OUI: {vendor}"]
        if has_airplay:
            reasons.append("Advertises AirPlay/remote-audio services")
        candidates.append(DeviceClassification(device_type="Sonos speaker", confidence="high", reasons=reasons))

    if any(k in vendor_l for k in _APPLE_VENDOR_KEYWORDS):
        if _IPHONE_HOSTNAME_RE.search(hostname_l):
            candidates.append(
                DeviceClassification(
                    device_type="Apple iPhone", confidence="medium",
                    reasons=[f"Vendor OUI: {vendor}", f"Hostname suggests an iPhone: {hostname}"],
                )
            )
        elif _IPAD_HOSTNAME_RE.search(hostname_l):
            candidates.append(
                DeviceClassification(
                    device_type="Apple iPad", confidence="medium",
                    reasons=[f"Vendor OUI: {vendor}", f"Hostname suggests an iPad: {hostname}"],
                )
            )
        elif _MAC_HOSTNAME_RE.search(hostname_l):
            candidates.append(
                DeviceClassification(
                    device_type="Apple Mac", confidence="medium",
                    reasons=[f"Vendor OUI: {vendor}", f"Hostname suggests a Mac: {hostname}"],
                )
            )
        else:
            candidates.append(
                DeviceClassification(device_type="Apple device", confidence="low", reasons=[f"Vendor OUI: {vendor}"])
            )

    has_media_renderer = any("mediarenderer" in t for t in types_l)
    has_cast = any("cast" in label for label in labels_l)
    if any(k in vendor_l for k in _TV_MEDIA_VENDOR_KEYWORDS):
        candidates.append(
            DeviceClassification(
                device_type="Smart TV / media device", confidence="medium",
                reasons=[f"Vendor OUI: {vendor} (a known TV/media-device manufacturer)"],
            )
        )
    elif has_media_renderer or has_cast:
        candidates.append(
            DeviceClassification(
                device_type="Smart TV / media device", confidence="medium",
                reasons=["Advertises a UPnP MediaRenderer or cast service"],
            )
        )

    if any("internetgatewaydevice" in t for t in types_l):
        candidates.append(
            DeviceClassification(
                device_type="Router / gateway", confidence="high",
                reasons=["Advertises itself as a UPnP Internet Gateway Device"],
            )
        )

    if hostname and _WINDOWS_HOSTNAME_RE.match(hostname.strip()):
        candidates.append(
            DeviceClassification(
                device_type="Windows workstation", confidence="medium",
                reasons=[f"Hostname matches Windows's default computer-name pattern: {hostname}"],
            )
        )

    iot_hit = categories & _IOT_CHIPSET_CATEGORIES
    if iot_hit and not candidates:
        # A class-level signal only, and only offered when nothing more
        # specific matched - a printer built on an Allwinner SoC should be
        # reported as a printer, not demoted to a vague "IoT device".
        candidates.append(
            DeviceClassification(
                device_type="IoT / embedded device", confidence="low",
                reasons=[f"Vendor OUI matches a common IoT/embedded chipset ({c})" for c in sorted(iot_hit)],
            )
        )

    if not candidates:
        return DeviceClassification()

    return min(candidates, key=lambda c: _CONFIDENCE_ORDER[c.confidence])
