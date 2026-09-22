from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lanfence.classify import DeviceClassification
from lanfence.dossier import DeviceDossier, TriageSummary
from lanfence.models import (
    AdvertisedService,
    Device,
    DeviceEvent,
    DeviceMetadata,
    Digest,
    DigestActivity,
    DigestDeviceEntry,
    DigestSection,
    Finding,
    InspectedPort,
    InspectionResult,
    NameEvidence,
    ScanResult,
)
from lanfence.report import (
    exit_code_for,
    exit_code_for_findings,
    highest_severity,
    presence_label,
    render_advertised_services,
    render_device_detail,
    render_device_inventory,
    render_digest,
    render_dossier_compact,
    render_findings,
    render_inspection_result,
    render_scan_result,
    render_triage_summary,
    review_status_label,
)


def _now():
    return datetime.now(timezone.utc)


def _finding(severity, mac="aa:bb:cc:dd:ee:ff"):
    return Finding(mac=mac, title="t", severity=severity)


def test_highest_severity_picks_the_worst():
    assert highest_severity([_finding("info"), _finding("high"), _finding("medium")]) == "high"
    assert highest_severity([_finding("info")]) == "info"
    assert highest_severity([]) is None


def test_exit_code_for_findings():
    assert exit_code_for_findings([]) == 0
    assert exit_code_for_findings([_finding("info")]) == 0
    assert exit_code_for_findings([_finding("medium")]) == 10
    assert exit_code_for_findings([_finding("high")]) == 20


def test_exit_code_for_scan_result():
    result = ScanResult(started_at=_now(), ended_at=_now(), findings=[_finding("high")])
    assert exit_code_for(result) == 20
    clean = ScanResult(started_at=_now(), ended_at=_now())
    assert exit_code_for(clean) == 0


def test_render_findings_handles_a_finding_with_no_mac(capsys):
    finding = Finding(
        mac=None, title="Unexpected DHCP server observed", severity="medium",
        kind="network_service", subject_id="eth0/192.168.1.66",
    )
    text = render_findings([finding], plain=True)
    assert "eth0/192.168.1.66" in text  # subject shown in place of a MAC
    assert "None" not in text


def test_render_scan_result_plain_does_not_raise(capsys):
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now())
    result = ScanResult(
        started_at=_now(), ended_at=_now(), interface="eth0", subnet="10.0.0.0/24",
        devices=[device], findings=[_finding("medium")],
    )
    text = render_scan_result(result, plain=True)
    assert "LAN Fence scan result" in text
    assert "aa:bb:cc:dd:ee:ff" in text
    captured = capsys.readouterr()
    assert "LAN Fence scan result" in captured.out


def test_render_scan_result_with_errors_plain(capsys):
    result = ScanResult(started_at=_now(), ended_at=_now(), errors=["boom"])
    text = render_scan_result(result, plain=True)
    assert "boom" in text


# --- review_status_label ----------------------------------------------------


def test_review_status_label_trusted_takes_precedence():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(),
        allowlisted=True, review_state="investigating",
    )
    assert review_status_label(device, now=_now()) == "trusted"


def test_review_status_label_investigating():
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), review_state="investigating")
    assert review_status_label(device, now=_now()) == "investigating"


def test_review_status_label_snoozed_shows_expiry():
    now = _now()
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now,
        review_state="snoozed", snoozed_until=now + timedelta(hours=1),
    )
    label = review_status_label(device, now=now)
    assert label.startswith("snoozed until")


def test_review_status_label_expired_snooze_shows_pending():
    now = _now()
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now,
        review_state="snoozed", snoozed_until=now - timedelta(hours=1),
    )
    assert review_status_label(device, now=now) == "pending"


def test_review_status_label_pending_default():
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now())
    assert review_status_label(device, now=_now()) == "pending"


# --- render_device_inventory -------------------------------------------------


def test_render_device_inventory_plain(capsys):
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), hostname="my-host")
    text = render_device_inventory([device], now=_now(), plain=True)
    assert "aa:bb:cc:dd:ee:ff" in text
    assert "my-host" in text


def test_render_device_inventory_empty_database_message(capsys):
    render_device_inventory([], now=_now(), total_count=0, plain=False)
    captured = capsys.readouterr()
    assert "database yet" in captured.out.lower()


def test_render_device_inventory_no_filter_matches_message(capsys):
    render_device_inventory([], now=_now(), total_count=5, plain=False)
    captured = capsys.readouterr()
    assert "no devices match" in captured.out.lower()


def test_render_device_inventory_show_metadata_plain():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(),
        metadata=DeviceMetadata(mac="aa:bb:cc:dd:ee:ff", owner="Alice", group="staff"),
    )
    text = render_device_inventory([device], now=_now(), plain=True, show_metadata=True)
    assert "owner=Alice" in text
    assert "group=staff" in text
    assert "purpose=-" in text


def test_render_device_inventory_default_omits_metadata_plain():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(),
        metadata=DeviceMetadata(mac="aa:bb:cc:dd:ee:ff", owner="Alice"),
    )
    text = render_device_inventory([device], now=_now(), plain=True)
    assert "owner=" not in text


def test_render_device_inventory_show_metadata_handles_unjoined_metadata():
    """A Device that never went through build_inventory has metadata=None -
    rendering must not crash, treating it the same as all-unset."""

    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now())
    text = render_device_inventory([device], now=_now(), plain=True, show_metadata=True)
    assert "owner=-" in text


# --- render_device_detail -----------------------------------------------


def test_render_device_detail_plain_distinguishes_current_and_timeline(capsys):
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now, hostname="my-host")
    events = [DeviceEvent(mac="aa:bb:cc:dd:ee:ff", event_type="new_device", timestamp=now, ip="10.0.0.5")]
    text = render_device_detail(device, events, now - timedelta(days=1), now=now, plain=True)
    assert "Current details" in text
    assert "Lifecycle timeline" in text
    assert "not a complete history" in text.lower()


def test_render_device_detail_empty_timeline_plain():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "0 event(s)" in text


def test_render_device_detail_shows_metadata_when_set():
    now = _now()
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now,
        metadata=DeviceMetadata(
            mac="aa:bb:cc:dd:ee:ff", owner="Alice", purpose="Laptop", group="staff", location="Office",
        ),
    )
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "Owner:      Alice" in text
    assert "Purpose:    Laptop" in text
    assert "Group:      staff" in text
    assert "Location:   Office" in text


def test_render_device_detail_shows_not_set_when_metadata_absent():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "Owner:      Not set" in text
    assert "Purpose:    Not set" in text
    assert "Group:      Not set" in text
    assert "Location:   Not set" in text


# --- presence_label ----------------------------------------------------


def test_presence_label_unspecified():
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now())
    assert presence_label(device) == "Presence: unspecified"


def test_presence_label_intermittent():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), presence_policy="intermittent"
    )
    assert presence_label(device) == "Presence: intermittent"


def test_presence_label_always_on_shows_effective_duration_from_override():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(),
        presence_policy="always-on", offline_after_seconds=600.0,
    )
    label = presence_label(device, default_offline_after_seconds=180.0)
    assert "always-on" in label
    assert "600s" in label


def test_presence_label_always_on_falls_back_to_global_default():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), presence_policy="always-on",
    )
    label = presence_label(device, default_offline_after_seconds=180.0)
    assert "180s" in label


def test_render_device_inventory_shows_presence_column_plain():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), presence_policy="intermittent",
    )
    text = render_device_inventory([device], now=_now(), plain=True)
    assert "intermittent" in text


def test_render_device_detail_shows_presence_line_plain():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now, presence_policy="always-on")
    text = render_device_detail(
        device, [], now - timedelta(days=1), now=now, plain=True, default_offline_after_seconds=180.0
    )
    assert "Presence: always-on" in text
    assert "180s" in text


def test_render_device_detail_shows_address_and_name_evidence_plain():
    from lanfence.models import AddressEvidence, NameEvidence

    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    addresses = [
        AddressEvidence(mac=device.mac, ip="10.0.0.5", family="ipv4", interface="eth0",
                        source="arp", kind="observed", first_seen=now, last_seen=now),
        AddressEvidence(mac=device.mac, ip="fe80::1", family="ipv6", interface="eth0",
                        source="ipv6_nd", kind="observed", first_seen=now, last_seen=now),
    ]
    names = [
        NameEvidence(mac=device.mac, name="office-laptop", name_key="office-laptop",
                    source="dhcp_option_12", first_seen=now, last_seen=now),
    ]
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True,
                                addresses=addresses, names=names)
    assert "10.0.0.5" in text
    assert "fe80::1" in text
    assert "ARP" in text
    assert "IPv6 ND" in text
    assert "office-laptop" in text
    assert "DHCP option 12" in text


def test_render_device_detail_omits_evidence_sections_when_not_given():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "Addresses" not in text
    assert "Names (" not in text


def test_render_device_detail_empty_evidence_says_none():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True,
                                addresses=[], names=[])
    assert "Addresses (0 retained)" in text
    assert "Names (0 retained)" in text


# --- advertised services -----------------------------------------------


def _service(**overrides) -> AdvertisedService:
    now = _now()
    base = dict(
        protocol="mdns", interface="eth0", service_type="_ipp._tcp.local", service_label="Printing",
        instance_name="Office Printer", identity="Office Printer._ipp._tcp.local",
        target_host="printer.local", target_port=631, mac="aa:bb:cc:dd:ee:ff",
        attribution_basis="target_address_match", first_seen=now, last_seen=now,
        expires_at=now + timedelta(minutes=2), status="current",
    )
    base.update(overrides)
    return AdvertisedService(**base)


def test_render_device_detail_shows_advertised_services_plain():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(
        device, [], now - timedelta(days=1), now=now, plain=True, services=[_service()],
    )
    assert "Advertised services" in text
    assert "Printing" in text
    assert "Instance: Office Printer" in text
    assert "Target: printer.local:631" in text
    assert "target IP matched observed device address" in text


def test_render_device_detail_omits_services_section_when_not_given():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "Advertised services" not in text


def test_render_device_detail_unassociated_service_shows_clear_label():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    unassoc = _service(mac=None, attribution_basis=None)
    text = render_device_detail(
        device, [], now - timedelta(days=1), now=now, plain=True, services=[unassoc],
    )
    assert "unassociated" in text.lower()


def test_render_device_detail_withdrawn_service_shows_status():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    withdrawn = _service(status="withdrawn", expires_at=None)
    text = render_device_detail(
        device, [], now - timedelta(days=1), now=now, plain=True, services=[withdrawn],
    )
    assert "withdrawn" in text.lower()


def test_render_device_detail_ssdp_service_shows_server_and_location_labeled_unverified():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    ssdp = AdvertisedService(
        protocol="ssdp", service_type="urn:schemas-upnp-org:device:MediaRenderer:1",
        identity="uuid:xyz", server="Linux/3.0 UPnP/1.0", location="http://10.0.0.9/desc.xml",
        first_seen=now, last_seen=now,
    )
    text = render_device_detail(
        device, [], now - timedelta(days=1), now=now, plain=True, services=[ssdp],
    )
    assert "Linux/3.0 UPnP/1.0" in text
    assert "unverified" in text.lower()
    assert "never fetched" in text.lower()


def test_render_device_detail_txt_attributes_labeled_as_claims():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    svc = _service(attributes={"model": "Widget9000"})
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True, services=[svc])
    assert "model=Widget9000" in text
    assert "unverified" in text.lower()


# --- classification rendering (render_device_detail / render_dossier_compact) --


def test_render_device_detail_shows_classification_when_given():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    classification = DeviceClassification(device_type="Sonos speaker", confidence="high", reasons=["Vendor OUI: Sonos, Inc."])
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True, classification=classification)
    assert "Likely device: Sonos speaker" in text
    assert "Confidence:    High" in text
    assert "Vendor OUI: Sonos, Inc." in text


def test_render_device_detail_unknown_classification_says_no_supporting_evidence():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(
        device, [], now - timedelta(days=1), now=now, plain=True, classification=DeviceClassification(),
    )
    assert "Likely device: Unknown device (no supporting evidence)" in text


def test_render_device_detail_omits_classification_when_not_given():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "Likely device:" not in text


# --- render_dossier_compact (the `lanfence review` queue's per-device glance) --


def _dossier_for_report(**overrides) -> DeviceDossier:
    now = _now()
    device = overrides.pop("device", None) or Device(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", vendor="Sonos, Inc.", hostname="living-room-sonos",
        first_seen=now, last_seen=now,
    )
    base = dict(
        device=device,
        classification=DeviceClassification(device_type="Sonos speaker", confidence="high", reasons=["Vendor OUI: Sonos, Inc."]),
        fingerprint_matches=[],
        is_locally_administered_mac=False,
    )
    base.update(overrides)
    return DeviceDossier(**base)


def test_render_dossier_compact_shows_header_with_index_and_priority():
    text = render_dossier_compact(_dossier_for_report(), index=3, total=18, priority_label="Priority")
    assert "Device 3 of 18" in text
    assert "Priority" in text


def test_render_dossier_compact_omits_header_without_index_and_total():
    text = render_dossier_compact(_dossier_for_report())
    assert "Device" not in text.splitlines()[0]


def test_render_dossier_compact_shows_label_ip_and_vendor():
    text = render_dossier_compact(_dossier_for_report())
    assert "living-room-sonos" in text
    assert "10.0.0.5" in text
    assert "Sonos, Inc." in text


def test_render_dossier_compact_shows_classification_and_first_last_seen_and_status():
    text = render_dossier_compact(_dossier_for_report())
    assert "Likely device: Sonos speaker" in text
    assert "Confidence:    High" in text
    assert "First seen:" in text
    assert "Last seen:" in text
    assert "Status:     Online" in text


def test_render_dossier_compact_shows_observed_services():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    dossier = _dossier_for_report(device=device, services=[_service(service_label="AirPlay")])
    text = render_dossier_compact(dossier)
    assert "Observed / advertised services:" in text
    assert "AirPlay" in text


def test_render_dossier_compact_omits_services_section_when_none():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_dossier_compact(_dossier_for_report(device=device))
    assert "Observed / advertised services:" not in text


def test_render_dossier_compact_shows_evidence_bullets():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", vendor="Sonos, Inc.", first_seen=now, last_seen=now)
    names = [NameEvidence(mac=device.mac, name="office-hub", name_key="office-hub",
                          source="dhcp_option_12", first_seen=now, last_seen=now)]
    dossier = _dossier_for_report(device=device, names=names)
    text = render_dossier_compact(dossier)
    assert "Evidence:" in text
    assert "DHCP hostname: office-hub" in text
    assert "OUI: Sonos, Inc." in text


def test_render_dossier_compact_shows_locally_administered_mac_evidence():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    dossier = _dossier_for_report(device=device, classification=DeviceClassification(), is_locally_administered_mac=True)
    text = render_dossier_compact(dossier)
    assert "MAC is locally administered" in text


# --- render_triage_summary (the post-scan orientation summary) -------------


def test_render_triage_summary_matches_expected_shape():
    summary = TriageSummary(
        total=47, straightforward=31, needs_identification=9, private_mac=5, security_flagged=2, reviewed=0,
    )
    text = render_triage_summary(summary)
    assert "LAN Fence has discovered 47 devices." in text
    assert "31 appear straightforward" in text
    assert "9 need identification" in text
    assert "5 use private/randomised MAC addresses" in text
    assert "2 have higher-priority security characteristics" in text
    assert "None have been reviewed yet." in text
    assert "Run `lanfence review` to work through them." in text


def test_render_triage_summary_singular_device_wording():
    summary = TriageSummary(total=1, straightforward=1, reviewed=0)
    text = render_triage_summary(summary)
    assert "LAN Fence has discovered 1 device." in text


def test_render_triage_summary_omits_zero_count_categories():
    summary = TriageSummary(total=2, straightforward=2, reviewed=0)
    text = render_triage_summary(summary)
    assert "need identification" not in text
    assert "private/randomised" not in text
    assert "security characteristics" not in text


def test_render_triage_summary_all_reviewed_message_and_no_hint():
    summary = TriageSummary(total=3, straightforward=3, reviewed=3)
    text = render_triage_summary(summary)
    assert "All devices have been reviewed." in text
    assert "lanfence review" not in text


def test_render_triage_summary_partial_review_progress_message():
    summary = TriageSummary(total=4, straightforward=2, needs_identification=2, reviewed=1)
    text = render_triage_summary(summary)
    assert "1 of 4 have been reviewed." in text
    assert "Run `lanfence review` to work through them." in text


def test_render_triage_summary_empty_inventory_returns_empty_string():
    assert render_triage_summary(TriageSummary()) == ""


# --- render_inspection_result (`lanfence inspect`) --------------------------


def _inspection(**overrides) -> InspectionResult:
    now = _now()
    base = dict(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", method="nmap", observed_at=now,
        open_ports=[
            InspectedPort(port=22, service="ssh", banner="OpenSSH 8.2p1"),
            InspectedPort(port=80, service="http", banner="nginx 1.18.0"),
        ],
        platform_guess="Windows (RDP plus SMB/RPC exposed)", platform_confidence="medium",
        platform_reasons=["Open ports: 135, 445, 3389"],
    )
    base.update(overrides)
    return InspectionResult(**base)


def test_render_inspection_result_shows_confirmed_ports_and_inferred_services():
    text = render_inspection_result(_inspection(), now=_now())
    assert "Confirmed open ports:" in text
    assert "22/tcp" in text
    assert "inferred service: ssh" in text
    assert "80/tcp" in text
    assert "inferred service: http" in text


def test_render_inspection_result_shows_platform_guess_with_confidence_never_definitive():
    text = render_inspection_result(_inspection(), now=_now())
    assert "Probable platform: Windows (RDP plus SMB/RPC exposed)" in text
    assert "Confidence:        Medium" in text
    assert "not OS fingerprinting" in text
    assert "not a verified fact" in text


def test_render_inspection_result_unknown_platform_says_not_enough_evidence():
    inspection = _inspection(platform_guess=None, platform_confidence=None, platform_reasons=[])
    text = render_inspection_result(inspection, now=_now())
    assert "Probable platform: not enough evidence to guess" in text


def test_render_inspection_result_no_open_ports():
    inspection = _inspection(open_ports=[], platform_guess=None, platform_confidence=None, platform_reasons=[])
    text = render_inspection_result(inspection, now=_now())
    assert "No open ports found among the scanned ports." in text


def test_render_inspection_result_flags_stale_results():
    old = _now() - timedelta(hours=48)
    inspection = _inspection(observed_at=old)
    text = render_inspection_result(inspection, now=_now())
    assert "STALE" in text


def test_render_inspection_result_recent_result_not_flagged_stale():
    text = render_inspection_result(_inspection(observed_at=_now()), now=_now())
    assert "STALE" not in text


def test_render_device_detail_shows_inspection_summary_when_given():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(
        device, [], now - timedelta(days=1), now=now, plain=True, inspection=_inspection(observed_at=now),
    )
    assert "Active inspection" in text
    assert "Confirmed open ports: 22/tcp, 80/tcp" in text
    assert "Probable platform: Windows (RDP plus SMB/RPC exposed)" in text


def test_render_device_detail_omits_inspection_when_not_given():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "Active inspection" not in text


# --- render_advertised_services (the `lanfence services` command) ---------


def test_render_advertised_services_plain():
    text = render_advertised_services([_service()], now=_now(), plain=True)
    assert "Office Printer" in text or "_ipp._tcp" in text


def test_render_advertised_services_empty_database_message(capsys):
    render_advertised_services([], now=_now(), total_count=0, plain=False)
    captured = capsys.readouterr()
    assert "no advertised services" in captured.out.lower()


def test_render_advertised_services_no_filter_matches_message(capsys):
    render_advertised_services([], now=_now(), total_count=3, plain=False)
    captured = capsys.readouterr()
    assert "no advertised services match" in captured.out.lower()


# --- render_digest -------------------------------------------------------


def _digest(**overrides):
    now = _now()
    base = dict(
        generated_at=now, window_start=now - timedelta(hours=24), window_end=now,
    )
    base.update(overrides)
    return Digest(**base)


def test_render_digest_plain_shows_window_and_counts(capsys):
    entry = DigestDeviceEntry(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="phone.local")
    digest = _digest(
        known_devices=3, online_devices=2,
        new_devices=DigestSection(items=[entry], total_count=1),
        activity=DigestActivity(new_device_count=1),
    )
    text = render_digest(digest, plain=True)
    assert "LAN Fence digest" in text
    assert "Known devices: 3" in text
    assert "aa:bb:cc:dd:ee:ff" in text
    assert "phone.local" in text


def test_render_digest_shows_omitted_count(capsys):
    entry = DigestDeviceEntry(mac="aa:bb:cc:dd:ee:ff")
    digest = _digest(needs_review=DigestSection(items=[entry], total_count=5, omitted_count=4))
    text = render_digest(digest, plain=True)
    assert "and 4 more" in text


def test_render_digest_empty_sections_say_none(capsys):
    digest = _digest()
    text = render_digest(digest, plain=True)
    assert "(none)" in text


def test_render_digest_shows_owner_and_group_context():
    entry = DigestDeviceEntry(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", owner="Alice", group="staff")
    digest = _digest(new_devices=DigestSection(items=[entry], total_count=1))
    text = render_digest(digest, plain=True)
    assert "Alice, staff" in text


def test_render_digest_omits_context_parens_when_no_owner_or_group():
    entry = DigestDeviceEntry(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5")
    digest = _digest(new_devices=DigestSection(items=[entry], total_count=1))
    text = render_digest(digest, plain=True)
    assert "()" not in text
