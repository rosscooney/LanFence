# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Passive advertised-service discovery: mDNS/DNS-SD (RFC 6762/6763) and
SSDP/UPnP (UPnP Device Architecture) - observation-only.

Strictly passive: this module only ever *parses* datagrams that
``scanner.passive_sniff`` has already captured. It never builds or sends an
mDNS query, an SSDP M-SEARCH request, an HTTP request, or any other
discovery traffic, and it never fetches an SSDP ``LOCATION`` URL or resolves
a hostname through a new lookup - see the functions below for exactly what
"parse only" means for each protocol.

A service **advertisement** is a claim the advertising device makes about
itself (`"I speak _ipp._tcp"`), not a verified capability, an authenticated
identity, or proof the service is reachable - see :class:`AdvertisedService`.

Two independent concerns, kept apart throughout this module:

1. **Parsing** (``parse_mdns_packet``/``parse_ssdp_packet``) - pure,
   allocation-only functions with no I/O, no scapy dependency, and no
   database access, so a raw captured payload can be fed through them and
   unit-tested with synthetic bytes alone. Bounded against a malformed or
   adversarial datagram: label/RR/header counts are capped, TXT/attribute
   text is length-bounded, and any structural error aborts parsing that one
   datagram (returning an empty/``None`` result) rather than raising -
   passive discovery of one malformed packet must never crash monitoring or
   flood logs.
2. **Correlation and persistence** (``process_mdns_record_sighting``/
   ``process_ssdp_sighting``) - folds one parsed sighting into
   :mod:`lanfence.db`'s bounded, TTL-aware discovery tables. mDNS in
   particular never carries all of a service's information in one packet -
   the PTR (service type -> instance), SRV (instance -> host:port), TXT
   (instance -> attributes), and A/AAAA (host -> address) records commonly
   arrive across separate packets, sometimes minutes apart - so this state
   lives in the database (coherent across restarts), not in memory, and a
   caller must not assume any one sighting carries the complete picture.

Attribution (which inventory device, if any, "owns" an advertisement) is
deliberately conservative and kept apart from *who transmitted* the frame -
see :func:`lanfence.db.DeviceStore.advertised_services`'s docstring for why
an mDNS proxy/reflector or a stale IP reassignment must never produce a
confident (but wrong) device association.
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime

from lanfence.db import DeviceStore
from lanfence.logging_config import get_logger
from lanfence.sanitize import clean_text

log = get_logger("discovery")

MDNS_PORT = 5353
SSDP_PORT = 1900

# --- bounding (see module docstring) ---------------------------------------

#: Resource records processed per mDNS message, across the answer/authority/
#: additional sections combined - a spoofed ANCOUNT/NSCOUNT/ARCOUNT claiming
#: more than this is simply truncated, not trusted.
_MAX_RRS_PER_MESSAGE = 64
#: DNS name compression pointers must only ever point strictly backwards in
#: the message (RFC 1035 s4.1.4), so a chain longer than this is malformed
#: (or a deliberate decompression-bomb attempt), not a real name.
_MAX_NAME_POINTER_DEPTH = 20
#: TXT records: retain at most this many allowlisted attributes...
_MAX_TXT_ATTRIBUTES = 8
#: ...each value bounded to this many characters...
_MAX_TXT_VALUE_LEN = 128
#: ...and the whole retained set bounded to this many bytes, so a device
#: cannot use a legitimately-shaped TXT record to smuggle an outsized blob
#: into the database one 128-byte value at a time.
_MAX_TXT_TOTAL_BYTES = 512
#: SSDP header values (SERVER, LOCATION, etc.) are bounded the same way as
#: any other device-supplied text - see ``lanfence/sanitize.py``.
_SSDP_HEADER_MAX_LEN = 512
#: A missing/unparseable/absurd SSDP CACHE-CONTROL max-age must never grant
#: an immortal advertisement (see ``_parse_ssdp_max_age``) nor a
#: vanishingly short one either - clamp to a protocol-appropriate range.
_SSDP_MIN_MAX_AGE = 60
_SSDP_MAX_MAX_AGE = 7 * 24 * 3600
#: Used only as a documented fallback when CACHE-CONTROL is missing or
#: unparseable - deliberately short, since it is not the advertiser's own
#: promise (see ``_parse_ssdp_max_age``).
_SSDP_FALLBACK_MAX_AGE = 900
#: SSDP datagrams are small UDP packets in practice; a claimed size far
#: beyond that is not a real SSDP message.
_MAX_SSDP_MESSAGE_BYTES = 8192
_MAX_SSDP_HEADER_LINES = 64

#: Small, documented allowlist of mDNS TXT-record keys retained verbatim
#: (case-insensitively matched, stored lowercase) - deliberately not "every
#: key seen," since TXT records can carry arbitrary and sometimes sensitive
#: device-chosen text (see the module and README's TXT-handling notes).
#: Values are advertised claims, never verified.
_TXT_ATTRIBUTE_ALLOWLIST = {
    "md", "model", "ty", "product", "note", "description", "usb_mfg", "usb_mdl", "fn",
}

#: Friendly labels for a small, documented set of well-known DNS-SD service
#: types (RFC 6763 lists no canonical registry LAN Fence should trust beyond
#: this - see IANA's service name registry for the full, much larger list).
#: An unrecognized type is retained with its raw name, never guessed at.
WELL_KNOWN_MDNS_LABELS: dict[str, str] = {
    "_ipp._tcp": "Printing",
    "_ipps._tcp": "Printing",
    "_airplay._tcp": "AirPlay",
    "_raop._tcp": "Remote audio",
    "_googlecast._tcp": "Cast",
    "_http._tcp": "Web service",
    "_https._tcp": "Web service",
}


class _ParseError(ValueError):
    """Internal: raised on any structurally malformed input, caught at the
    top of each ``parse_*`` function so one bad datagram never propagates."""


# --- mDNS / DNS-SD (RFC 6762, RFC 6763) -------------------------------------


@dataclass(frozen=True)
class MdnsRecordSighting:
    """One parsed mDNS resource record, tagged with capture metadata.

    Only ever built from a *response* message (``QR=1``) - see
    :func:`parse_mdns_packet`'s docstring for why questions and a query's
    own known-answer section never reach here. ``rtype`` is one of
    ``"PTR"``/``"SRV"``/``"TXT"``/``"A"``/``"AAAA"``; the type-specific
    payload is carried in the matching field below, the others left at
    their defaults.
    """

    rtype: str
    ttl: int
    cache_flush: bool
    interface: str
    source_ip: str | None
    source_mac: str | None
    family: str | None  # "ipv4" | "ipv6" | None (the *packet's* IP version)
    seen_at: datetime
    #: PTR: the service type this record enumerates, e.g. "_ipp._tcp.local".
    service_type: str = ""
    #: PTR: the target's first label (the instance name), decoded for
    #: display - never obtained by splitting a pre-joined dotted string
    #: (see the module docstring) since label boundaries are already known
    #: from the DNS wire format itself.
    instance_name: str = ""
    #: PTR/SRV: the full target name (e.g.
    #: "Office Printer._ipp._tcp.local") - the stable join key correlating
    #: a PTR to its SRV/TXT records, since PTR/SRV/TXT need not arrive
    #: together (see the module docstring).
    fq_instance: str = ""
    #: SRV: the instance's target hostname and port.
    target_host: str = ""
    target_port: int = 0
    #: TXT: bounded, allowlisted attributes only (see
    #: ``_TXT_ATTRIBUTE_ALLOWLIST``) - never the raw TXT blob.
    attributes: dict[str, str] = field(default_factory=dict)
    #: A/AAAA: the owner name (target hostname) and resolved address.
    address_owner: str = ""
    address: str = ""


def _read_u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise _ParseError("truncated")
    return struct.unpack_from(">H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise _ParseError("truncated")
    return struct.unpack_from(">I", data, offset)[0]


def _read_name(data: bytes, offset: int, *, _depth: int = 0) -> tuple[list[bytes], int]:
    """Parse a (possibly compressed) DNS name starting at ``offset``.

    Returns ``(labels, next_offset)`` where ``labels`` is the raw label
    bytes in order (deliberately *not* joined into a dotted string here -
    see the module docstring on why DNS-SD instance names must be handled
    at the label level, since an instance label can itself contain a
    literal dot) and ``next_offset`` is the position immediately after this
    name in ``data`` - i.e. right after a compression pointer if one was
    followed, not after the pointer's target.
    """

    if _depth > _MAX_NAME_POINTER_DEPTH:
        raise _ParseError("dns name compression too deep")
    labels: list[bytes] = []
    start = offset
    pos = offset
    end_offset: int | None = None
    while True:
        if pos >= len(data):
            raise _ParseError("truncated dns name")
        length = data[pos]
        if length == 0:
            pos += 1
            if end_offset is None:
                end_offset = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise _ParseError("truncated dns pointer")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if pointer >= start:
                # RFC 1035 s4.1.4: a pointer must point to a *prior*
                # location - forward/self pointers are only ever seen in a
                # malformed or adversarial (decompression loop) message.
                raise _ParseError("dns pointer does not point backwards")
            if end_offset is None:
                end_offset = pos + 2
            sub_labels, _ = _read_name(data, pointer, _depth=_depth + 1)
            labels.extend(sub_labels)
            break
        if length & 0xC0 != 0:
            raise _ParseError("reserved dns label length bits set")
        if pos + 1 + length > len(data):
            raise _ParseError("truncated dns label")
        labels.append(data[pos + 1 : pos + 1 + length])
        pos += 1 + length
    return labels, end_offset if end_offset is not None else pos


def _decode_label(label: bytes) -> str:
    return clean_text(label.decode("utf-8", errors="replace"), max_len=256)


def _labels_to_display(labels: list[bytes]) -> str:
    return ".".join(_decode_label(label) for label in labels)


def _skip_question(data: bytes, offset: int) -> int:
    _labels, offset = _read_name(data, offset)
    offset += 4  # QTYPE + QCLASS
    if offset > len(data):
        raise _ParseError("truncated question")
    return offset


def _parse_txt_rdata(rdata: bytes) -> dict[str, str]:
    """Bounded, allowlisted TXT attributes - see ``_TXT_ATTRIBUTE_ALLOWLIST``
    and the module's TXT-handling docstring. Never returns the raw blob or
    an unrecognized key, regardless of how many the record actually has."""

    attrs: dict[str, str] = {}
    total_bytes = 0
    pos = 0
    while pos < len(rdata) and len(attrs) < _MAX_TXT_ATTRIBUTES:
        length = rdata[pos]
        pos += 1
        if pos + length > len(rdata):
            break  # truncated trailing string - keep what parsed so far
        entry = rdata[pos : pos + length]
        pos += length
        if b"=" in entry:
            key_b, _, value_b = entry.partition(b"=")
        else:
            key_b, value_b = entry, b""
        key = key_b.decode("utf-8", errors="replace").strip().lower()
        if key not in _TXT_ATTRIBUTE_ALLOWLIST or key in attrs:
            continue
        value = clean_text(value_b.decode("utf-8", errors="replace"), max_len=_MAX_TXT_VALUE_LEN)
        if total_bytes + len(value) > _MAX_TXT_TOTAL_BYTES:
            continue
        attrs[key] = value
        total_bytes += len(value)
    return attrs


def parse_mdns_packet(
    payload: bytes,
    *,
    interface: str = "",
    source_ip: str | None = None,
    source_mac: str | None = None,
    family: str | None = None,
    seen_at: datetime,
) -> list[MdnsRecordSighting]:
    """Parse one captured mDNS UDP payload into zero or more
    :class:`MdnsRecordSighting`. Pure/allocation-only - no I/O, no scapy.

    Only ANSWER/AUTHORITY/ADDITIONAL records from a *response* message
    (header ``QR`` bit set) are ever returned - a *query* message (``QR``
    unset) is skipped entirely, even though RFC 6762 s7.1 known-answer
    suppression means a query's own answer section can carry resource
    records: those describe what the *querier* already knows, not a fresh
    advertisement, and must never be treated as one.

    Any structural parse failure (truncated header, a malformed/looping
    name, a record claiming to extend past the datagram) aborts parsing
    this one packet and returns ``[]`` - never raises to the caller, and
    never partially trusts a datagram that didn't parse cleanly throughout.
    """

    try:
        return _parse_mdns_packet(
            payload, interface=interface, source_ip=source_ip, source_mac=source_mac,
            family=family, seen_at=seen_at,
        )
    except _ParseError as exc:
        log.debug("dropping malformed mDNS packet on %s: %s", interface or "(unknown)", exc)
        return []
    except Exception as exc:  # noqa: BLE001 - untrusted network input must never crash monitoring
        log.debug("dropping mDNS packet that failed to parse on %s: %s", interface or "(unknown)", exc)
        return []


# DNS resource record type numbers this module understands.
_TYPE_A = 1
_TYPE_PTR = 12
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_KNOWN_TYPES = {_TYPE_A, _TYPE_PTR, _TYPE_TXT, _TYPE_AAAA, _TYPE_SRV}


def _parse_mdns_packet(
    payload: bytes, *, interface: str, source_ip: str | None, source_mac: str | None,
    family: str | None, seen_at: datetime,
) -> list[MdnsRecordSighting]:
    if len(payload) < 12:
        raise _ParseError("truncated dns header")
    _id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHHHH", payload, 0)
    is_response = bool(flags & 0x8000)
    if not is_response:
        # A query - including its own known-answer section, which is not a
        # fresh advertisement (see this function's docstring).
        return []

    offset = 12
    for _ in range(min(qdcount, _MAX_RRS_PER_MESSAGE)):
        offset = _skip_question(payload, offset)

    sightings: list[MdnsRecordSighting] = []
    processed = 0
    for section_count in (ancount, nscount, arcount):
        for _ in range(min(section_count, _MAX_RRS_PER_MESSAGE)):
            if processed >= _MAX_RRS_PER_MESSAGE:
                break
            processed += 1
            name_labels, offset = _read_name(payload, offset)
            rtype = _read_u16(payload, offset)
            rrclass_raw = _read_u16(payload, offset + 2)
            ttl = _read_u32(payload, offset + 4)
            rdlength = _read_u16(payload, offset + 8)
            rdata_offset = offset + 10
            if rdata_offset + rdlength > len(payload):
                raise _ParseError("record extends past end of message")
            rdata = payload[rdata_offset : rdata_offset + rdlength]
            offset = rdata_offset + rdlength
            cache_flush = bool(rrclass_raw & 0x8000)

            if rtype not in _KNOWN_TYPES:
                continue
            ttl = max(0, ttl)

            if rtype == _TYPE_PTR:
                target_labels, _ = _read_name(payload, rdata_offset)
                if not target_labels:
                    continue
                # A DNS-SD service-type *enumeration* PTR
                # ("_services._dns-sd._udp.local") lists service *types*,
                # not an instance of one - RFC 6763 s9. Recognized and
                # skipped rather than mistaken for a real instance.
                owner_display = _labels_to_display(name_labels)
                if owner_display.lower().startswith("_services._dns-sd._udp."):
                    continue
                sightings.append(
                    MdnsRecordSighting(
                        rtype="PTR", ttl=ttl, cache_flush=cache_flush, interface=interface,
                        source_ip=source_ip, source_mac=source_mac, family=family, seen_at=seen_at,
                        service_type=owner_display,
                        instance_name=_decode_label(target_labels[0]),
                        fq_instance=_labels_to_display(target_labels),
                    )
                )
            elif rtype == _TYPE_SRV:
                if len(rdata) < 6:
                    continue
                port = struct.unpack_from(">H", rdata, 4)[0]
                target_labels, _ = _read_name(payload, rdata_offset + 6)
                sightings.append(
                    MdnsRecordSighting(
                        rtype="SRV", ttl=ttl, cache_flush=cache_flush, interface=interface,
                        source_ip=source_ip, source_mac=source_mac, family=family, seen_at=seen_at,
                        fq_instance=_labels_to_display(name_labels),
                        target_host=_labels_to_display(target_labels),
                        target_port=port,
                    )
                )
            elif rtype == _TYPE_TXT:
                sightings.append(
                    MdnsRecordSighting(
                        rtype="TXT", ttl=ttl, cache_flush=cache_flush, interface=interface,
                        source_ip=source_ip, source_mac=source_mac, family=family, seen_at=seen_at,
                        fq_instance=_labels_to_display(name_labels),
                        attributes=_parse_txt_rdata(rdata),
                    )
                )
            elif rtype == _TYPE_A:
                if len(rdata) != 4:
                    continue
                sightings.append(
                    MdnsRecordSighting(
                        rtype="A", ttl=ttl, cache_flush=cache_flush, interface=interface,
                        source_ip=source_ip, source_mac=source_mac, family=family, seen_at=seen_at,
                        address_owner=_labels_to_display(name_labels),
                        address=str(ipaddress.IPv4Address(rdata)),
                    )
                )
            elif rtype == _TYPE_AAAA:
                if len(rdata) != 16:
                    continue
                sightings.append(
                    MdnsRecordSighting(
                        rtype="AAAA", ttl=ttl, cache_flush=cache_flush, interface=interface,
                        source_ip=source_ip, source_mac=source_mac, family=family, seen_at=seen_at,
                        address_owner=_labels_to_display(name_labels),
                        address=str(ipaddress.IPv6Address(rdata)),
                    )
                )
        if processed >= _MAX_RRS_PER_MESSAGE:
            break
    return sightings


def well_known_mdns_label(service_type: str) -> str | None:
    """Friendly label for a well-known DNS-SD service type, e.g.
    ``"_ipp._tcp.local"`` -> ``"Printing"``. ``None`` for anything not in
    the small, documented allowlist (see ``WELL_KNOWN_MDNS_LABELS``) - an
    unrecognized type is retained with its raw name, never guessed at."""

    normalized = service_type.lower()
    if normalized.endswith(".local") or normalized.endswith(".local."):
        normalized = normalized.rsplit(".local", 1)[0]
    return WELL_KNOWN_MDNS_LABELS.get(normalized)


# --- SSDP / UPnP -------------------------------------------------------------


@dataclass(frozen=True)
class SsdpSighting:
    """One parsed SSDP NOTIFY/response, tagged with capture metadata.

    ``message_type`` is one of ``"alive"``/``"update"``/``"byebye"``/
    ``"response"`` - an ``M-SEARCH`` request (or anything else unparseable)
    never produces one of these (see :func:`parse_ssdp_packet`).
    """

    message_type: str
    usn: str
    nt_or_st: str | None
    server: str | None
    location: str | None
    max_age: int | None
    boot_id: str | None
    config_id: str | None
    interface: str
    source_ip: str | None
    source_mac: str | None
    family: str | None
    seen_at: datetime


#: Identity-bearing headers where two differing values in the same message
#: make the message's own identity ambiguous - safer to drop the whole
#: message than guess which one is authoritative.
_SSDP_IDENTITY_HEADERS = {"usn", "nt", "st"}
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_BOOT_ID_HEADERS = ("bootid.upnp.org",)
_CONFIG_ID_HEADERS = ("configid.upnp.org",)


def _parse_ssdp_headers(lines: list[str]) -> dict[str, str] | None:
    """Case-insensitive header parsing. Returns ``None`` (reject the whole
    message) if any identity header (USN/NT/ST) appears twice with
    genuinely different values - an ambiguous identity is worse than none.
    """

    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        value = clean_text(value.strip(), max_len=_SSDP_HEADER_MAX_LEN)
        if not key:
            continue
        if key in headers:
            if key in _SSDP_IDENTITY_HEADERS and headers[key] != value:
                return None
            continue  # duplicate non-identity header or identical repeat - keep the first
        headers[key] = value
    return headers


def _parse_ssdp_max_age(cache_control: str | None) -> int:
    """Bounded, protocol-appropriate max-age in seconds. Missing or
    unparseable input never grants an immortal advertisement - it falls
    back to a short, explicitly-documented default instead (see
    ``_SSDP_FALLBACK_MAX_AGE``), and any value that does parse is clamped
    to ``[_SSDP_MIN_MAX_AGE, _SSDP_MAX_MAX_AGE]``."""

    if cache_control:
        match = _MAX_AGE_RE.search(cache_control)
        if match:
            try:
                value = int(match.group(1))
            except ValueError:
                value = _SSDP_FALLBACK_MAX_AGE
            return max(_SSDP_MIN_MAX_AGE, min(_SSDP_MAX_MAX_AGE, value))
    return _SSDP_FALLBACK_MAX_AGE


def parse_ssdp_packet(
    payload: bytes,
    *,
    interface: str = "",
    source_ip: str | None = None,
    source_mac: str | None = None,
    family: str | None = None,
    seen_at: datetime,
) -> SsdpSighting | None:
    """Parse one captured SSDP UDP payload into an :class:`SsdpSighting`,
    or ``None`` if it is not a recognized advertisement.

    An ``M-SEARCH`` request (a *query*, never an advertisement) always
    returns ``None``, as does anything that fails to parse, is missing a
    usable ``USN``, or carries ambiguous duplicate identity headers - see
    :func:`_parse_ssdp_headers`. Defensive against CRLF/LF-only line
    endings and a truncated/oversized datagram; never raises.
    """

    try:
        return _parse_ssdp_packet(
            payload, interface=interface, source_ip=source_ip, source_mac=source_mac,
            family=family, seen_at=seen_at,
        )
    except Exception as exc:  # noqa: BLE001 - untrusted network input must never crash monitoring
        log.debug("dropping malformed SSDP packet on %s: %s", interface or "(unknown)", exc)
        return None


def _parse_ssdp_packet(
    payload: bytes, *, interface: str, source_ip: str | None, source_mac: str | None,
    family: str | None, seen_at: datetime,
) -> SsdpSighting | None:
    if not payload or len(payload) > _MAX_SSDP_MESSAGE_BYTES:
        return None
    text = payload.decode("utf-8", errors="replace")
    lines = text.replace("\r\n", "\n").split("\n")[:_MAX_SSDP_HEADER_LINES]
    if not lines:
        return None
    start_line = lines[0].strip().upper()

    if start_line.startswith("M-SEARCH"):
        return None  # a query, never an advertisement

    is_notify = start_line.startswith("NOTIFY")
    is_response = start_line.startswith("HTTP/1.1 200") or start_line.startswith("HTTP/1.0 200")
    if not (is_notify or is_response):
        return None

    headers = _parse_ssdp_headers(lines[1:])
    if headers is None:
        return None  # ambiguous duplicate identity headers

    usn = headers.get("usn", "")
    if not usn:
        return None  # no stable identity to key evidence on

    if is_response:
        message_type = "response"
        nt_or_st = headers.get("st")
    else:
        nts = headers.get("nts", "").lower()
        if nts == "ssdp:alive":
            message_type = "alive"
        elif nts == "ssdp:byebye":
            message_type = "byebye"
        elif nts == "ssdp:update":
            message_type = "update"
        else:
            return None  # an NT/M-SEARCH-adjacent NOTIFY subtype this module doesn't act on
        nt_or_st = headers.get("nt")

    boot_id = next((headers[h] for h in _BOOT_ID_HEADERS if h in headers and headers[h].isdigit()), None)
    config_id = next((headers[h] for h in _CONFIG_ID_HEADERS if h in headers and headers[h].isdigit()), None)

    return SsdpSighting(
        message_type=message_type,
        usn=usn,
        nt_or_st=nt_or_st or None,
        server=headers.get("server") or None,
        location=headers.get("location") or None,
        max_age=_parse_ssdp_max_age(headers.get("cache-control")) if message_type != "byebye" else None,
        boot_id=boot_id,
        config_id=config_id,
        interface=interface,
        source_ip=source_ip,
        source_mac=source_mac,
        family=family,
        seen_at=seen_at,
    )


# --- correlation and persistence --------------------------------------------


def process_mdns_record_sighting(sighting: MdnsRecordSighting, store: DeviceStore) -> None:
    """Fold one parsed mDNS record into the bounded, TTL-aware discovery
    tables (see :mod:`lanfence.db`). Never touches device presence/
    reachability, lifecycle events, alert dispatch, or trust/review state -
    an advertisement is inventory-enrichment evidence only (see the module
    docstring). ``ttl == 0`` withdraws matching evidence (RFC 6762 s10.1
    "goodbye" semantics) rather than recording a fresh entry.
    """

    if sighting.rtype == "PTR":
        if sighting.ttl == 0:
            store.withdraw_mdns_ptr(sighting.interface, sighting.service_type, sighting.fq_instance)
        else:
            store.record_mdns_ptr(
                interface=sighting.interface, service_type=sighting.service_type,
                instance_name=sighting.instance_name, fq_instance=sighting.fq_instance,
                ttl=sighting.ttl, seen_at=sighting.seen_at,
                source_ip=sighting.source_ip, source_mac=sighting.source_mac,
            )
    elif sighting.rtype == "SRV":
        if sighting.ttl == 0:
            store.withdraw_mdns_srv(sighting.interface, sighting.fq_instance)
        else:
            store.record_mdns_srv(
                interface=sighting.interface, fq_instance=sighting.fq_instance,
                target_host=sighting.target_host, port=sighting.target_port,
                ttl=sighting.ttl, seen_at=sighting.seen_at,
            )
    elif sighting.rtype == "TXT":
        if sighting.ttl == 0:
            store.withdraw_mdns_txt(sighting.interface, sighting.fq_instance)
        elif sighting.attributes:
            store.record_mdns_txt(
                interface=sighting.interface, fq_instance=sighting.fq_instance,
                attributes=sighting.attributes, ttl=sighting.ttl, seen_at=sighting.seen_at,
            )
    elif sighting.rtype in ("A", "AAAA"):
        family = "ipv4" if sighting.rtype == "A" else "ipv6"
        if sighting.ttl == 0:
            store.withdraw_mdns_addr(sighting.interface, sighting.address_owner, family, sighting.address)
        else:
            store.record_mdns_addr(
                interface=sighting.interface, target_host=sighting.address_owner, family=family,
                ip=sighting.address, ttl=sighting.ttl, seen_at=sighting.seen_at,
                cache_flush=sighting.cache_flush,
            )


def process_ssdp_sighting(sighting: SsdpSighting, store: DeviceStore) -> None:
    """Fold one parsed SSDP NOTIFY/response into ``ssdp_advertisements``.
    Same non-interaction guarantees as :func:`process_mdns_record_sighting`.
    """

    if sighting.message_type == "byebye":
        store.withdraw_ssdp_advertisement(sighting.interface, sighting.usn, seen_at=sighting.seen_at)
        return
    store.record_ssdp_advertisement(
        interface=sighting.interface, usn=sighting.usn, nt_or_st=sighting.nt_or_st,
        server=sighting.server, location=sighting.location, max_age=sighting.max_age,
        boot_id=sighting.boot_id, config_id=sighting.config_id, seen_at=sighting.seen_at,
        source_ip=sighting.source_ip, source_mac=sighting.source_mac, family=sighting.family,
    )
