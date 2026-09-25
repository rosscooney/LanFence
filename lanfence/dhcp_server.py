# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Unexpected DHCP server detection - passive, observation-only.

Ties :class:`lanfence.scanner.DhcpServerSighting` (one parsed DHCPOFFER/ACK/
NAK reply) to persistence (:mod:`lanfence.db`) and, for a server not on the
operator's approved list for its interface, a plain-language
:class:`~lanfence.models.Finding` - the same role :mod:`lanfence.engine`
plays for ordinary device sightings, kept separate because a DHCP server is
a network *role*, not a device: it has no reliable MAC (see
:class:`lanfence.scanner.DhcpServerSighting`'s docstring for why source/
relay/client-hardware-address are evidence only, never an identity) and
approving it is explicitly **not** the same as trusting a device.

Two independent cooldowns exist for a good reason - conflating them would
either flood findings from one noisy unapproved server, or let a busy
network's normal alert cadence silently swallow this finding type:

1. **Finding generation** (``dhcp_servers.alert_cooldown_seconds``, keyed by
   finding type + interface + server identifier) - gates whether a *new*
   :class:`~lanfence.models.Finding` (and its persisted evidence row) is
   created at all for a repeated reply from the same unapproved server.
2. **External dispatch** (the existing ``alerts.rate_limit_seconds``, via
   :func:`lanfence.engine.filter_rate_limited`) - once a finding exists,
   whether it's *sent* to configured alert channels, exactly like any other
   finding.

The server inventory itself (``dhcp_servers`` - first/last seen, latest
details) is updated on **every** valid observation regardless of either
cooldown or of ``dhcp_servers.enabled`` even being on, so `lanfence
dhcp-servers` always reflects what's actually been seen.
"""

from __future__ import annotations

from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.logging_config import get_logger
from lanfence.models import DhcpServerRecord, Finding
from lanfence.netutil import normalize_mac
from lanfence.scanner import DhcpServerSighting

log = get_logger("dhcp_server")


def _is_approved(interface: str, server_id: str, cfg: Config) -> bool:
    return any(
        entry.interface == interface and entry.server_ip == server_id
        for entry in cfg.dhcp_servers.approved
    )


def dhcp_server_detection_active(cfg: Config) -> bool:
    """Whether unexpected-server *findings* can actually be produced right
    now - not just ``dhcp_servers.enabled``, but also the passive DHCP
    capture it depends on. Used for the ``monitor``/``check`` banners so an
    inactive combination is stated plainly rather than silently doing
    nothing (see the module and README's "Visibility limitations")."""

    return bool(cfg.dhcp_servers.enabled and cfg.scan.passive and cfg.scan.dhcp_snooping)


def process_dhcp_server_sighting(
    sighting: DhcpServerSighting, store: DeviceStore, cfg: Config
) -> Finding | None:
    """Fold one DHCP server observation into the database and return an
    "Unexpected DHCP server observed" finding, if warranted right now.

    Always updates the ``dhcp_servers`` inventory (first/last seen, latest
    evidence), regardless of ``dhcp_servers.enabled`` or approval - a server
    already approved, or detection not enabled, still shows up in `lanfence
    dhcp-servers`. Returns ``None`` (no finding) when detection is disabled,
    the server is approved for this interface, or a finding for this exact
    (interface, server_id) was already generated within
    ``dhcp_servers.alert_cooldown_seconds``.
    """

    interface = sighting.interface or "(unknown interface)"
    store.record_dhcp_server_observation(
        interface=interface, server_id=sighting.server_id, message_type=sighting.message_type,
        observed_at=sighting.observed_at, source_ip=sighting.source_ip, source_mac=sighting.source_mac,
        relay_ip=sighting.relay_ip, router=sighting.router, dns=sighting.dns,
    )

    # A confirmed lease (ACK) is real address evidence for the *client* -
    # identified correctly via chaddr (client_mac_evidence), never the
    # relay/source MAC - independent of whether the server itself is
    # approved. Recorded as "lease_reported": a server's claim, not proof
    # the client is actually using or reachable at that address (see
    # DeviceStore.observe's docstring). This never touches the client's
    # presence/reachability tracking - only address evidence.
    if sighting.message_type == "ack" and sighting.offered_ip and sighting.client_mac_evidence:
        try:
            client_mac = normalize_mac(sighting.client_mac_evidence)
        except ValueError:
            client_mac = None
        if client_mac is not None:
            store.record_address_evidence(
                client_mac, sighting.offered_ip, interface=interface,
                source="dhcp_ack", kind="lease_reported", seen_at=sighting.observed_at,
            )
            store.refresh_preferred_fields(client_mac)

    if not cfg.dhcp_servers.enabled:
        return None

    approved = _is_approved(interface, sighting.server_id, cfg)
    if approved:
        return None  # visible in inventory/history; never a finding

    generation_key = f"dhcp-server-finding#{interface}#{sighting.server_id}"
    due = store.due_for_alert(
        generation_key, "medium", now=sighting.observed_at,
        cooldown_seconds=cfg.dhcp_servers.alert_cooldown_seconds, key=generation_key,
    )
    if not due:
        return None  # repeated reply within the cooldown - inventory already updated above

    store.record_dhcp_server_finding(
        interface=interface, server_id=sighting.server_id, observed_at=sighting.observed_at,
        approved_at_observation=False, message_type=sighting.message_type,
        source_ip=sighting.source_ip, source_mac=sighting.source_mac, relay_ip=sighting.relay_ip,
        router=sighting.router, dns=sighting.dns,
    )

    evidence = [
        f"Interface: {interface}",
        f"DHCP server identifier (option 54): {sighting.server_id}",
        f"Message type: {sighting.message_type.upper()}",
    ]
    if sighting.source_ip:
        evidence.append(f"Source IP: {sighting.source_ip}")
    if sighting.source_mac:
        evidence.append(
            f"Source MAC: {sighting.source_mac} (the sender of this frame - a relay's MAC if "
            "relayed, not necessarily the DHCP server itself)"
        )
    if sighting.relay_ip:
        evidence.append(f"Relay address (giaddr): {sighting.relay_ip} - this reply was relayed")
    if sighting.offered_ip:
        evidence.append(f"Offered/client address: {sighting.offered_ip}")
    if sighting.router:
        evidence.append(f"Advertised router: {sighting.router}")
    if sighting.dns:
        evidence.append(f"Advertised DNS server: {sighting.dns}")
    if sighting.client_mac_evidence:
        evidence.append(
            f"Client hardware address: {sighting.client_mac_evidence} (identifies the client this "
            "reply was for, not the server)"
        )

    return Finding(
        mac=None,
        kind="network_service",
        change_type="dhcp_server_unexpected",
        subject_id=f"{interface}/{sighting.server_id}",
        title="Unexpected DHCP server observed",
        severity="medium",
        rationale=(
            f"A DHCP {sighting.message_type} reply claiming server identifier "
            f"{sighting.server_id} was observed on {interface}, which is not on the approved "
            "DHCP server list for this interface. This may be a legitimate router, a backup/"
            "failover DHCP server, or a misconfiguration - this observation alone does not "
            "establish malicious intent."
        ),
        recommendation=(
            f"Check what {sighting.server_id} is on your network. If it's expected, add it to "
            "dhcp_servers.approved in your config to stop this finding."
        ),
        evidence=evidence,
    )


def dhcp_server_inventory(store: DeviceStore, cfg: Config) -> list[DhcpServerRecord]:
    """Every observed DHCP server (`lanfence dhcp-servers`) - a pure
    database read, joined with *current* approval status/configured name
    from config. Never scans or sends packets. An empty result means no
    server response has ever been observed at this capture point, not that
    no DHCP server exists on the network (see README's visibility
    limitations - a switched network can hide unicast replies entirely)."""

    approved_map = {(e.interface, e.server_ip): (e.name or None) for e in cfg.dhcp_servers.approved}
    records = []
    for record in store.dhcp_server_records():
        key = (record.interface, record.server_id)
        records.append(
            record.model_copy(update={"approved": key in approved_map, "name": approved_map.get(key)})
        )
    return records
