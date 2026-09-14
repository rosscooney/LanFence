from __future__ import annotations

from lanfence.classify import classify_device


def test_no_evidence_yields_unknown_device_with_no_confidence():
    result = classify_device(vendor=None, hostname=None)
    assert result.device_type == "Unknown device"
    assert result.confidence is None
    assert result.reasons == []
    assert result.is_known is False


def test_raspberry_pi_fingerprint_category_is_high_confidence():
    result = classify_device(
        vendor="Raspberry Pi Foundation", hostname=None, fingerprint_categories=["raspberry_pi"],
    )
    assert result.device_type == "Raspberry Pi"
    assert result.confidence == "high"
    assert result.reasons


def test_ipp_service_advertisement_identifies_network_printer_at_high_confidence():
    result = classify_device(
        vendor=None, hostname=None, service_types=["_ipp._tcp.local."],
    )
    assert result.device_type == "Network printer"
    assert result.confidence == "high"


def test_printer_vendor_keyword_alone_is_only_medium_confidence():
    result = classify_device(vendor="Canon Inc.", hostname=None)
    assert result.device_type == "Network printer"
    assert result.confidence == "medium"


def test_sonos_vendor_with_airplay_service_is_high_confidence():
    result = classify_device(
        vendor="Sonos, Inc.", hostname=None, service_labels=["AirPlay"],
    )
    assert result.device_type == "Sonos speaker"
    assert result.confidence == "high"
    assert any("AirPlay" in r or "airplay" in r.lower() for r in result.reasons)


def test_apple_vendor_with_iphone_hostname_is_medium_confidence():
    result = classify_device(vendor="Apple, Inc.", hostname="Johns-iPhone")
    assert result.device_type == "Apple iPhone"
    assert result.confidence == "medium"


def test_apple_vendor_with_ipad_hostname_is_medium_confidence():
    result = classify_device(vendor="Apple, Inc.", hostname="Janes-iPad")
    assert result.device_type == "Apple iPad"
    assert result.confidence == "medium"


def test_apple_vendor_with_mac_hostname_is_medium_confidence():
    result = classify_device(vendor="Apple, Inc.", hostname="Bobs-MacBook-Pro")
    assert result.device_type == "Apple Mac"
    assert result.confidence == "medium"


def test_apple_vendor_without_recognizable_hostname_is_low_confidence():
    result = classify_device(vendor="Apple, Inc.", hostname=None)
    assert result.device_type == "Apple device"
    assert result.confidence == "low"


def test_windows_default_hostname_pattern_is_medium_confidence():
    result = classify_device(vendor=None, hostname="DESKTOP-AB12CD3")
    assert result.device_type == "Windows workstation"
    assert result.confidence == "medium"


def test_tv_vendor_keyword_is_medium_confidence():
    result = classify_device(vendor="Samsung Electronics Co.,Ltd", hostname=None)
    assert result.device_type == "Smart TV / media device"
    assert result.confidence == "medium"


def test_media_renderer_service_without_tv_vendor_is_medium_confidence():
    result = classify_device(vendor=None, hostname=None, service_types=["urn:schemas-upnp-org:device:MediaRenderer:1"])
    assert result.device_type == "Smart TV / media device"
    assert result.confidence == "medium"


def test_internet_gateway_device_service_identifies_router_at_high_confidence():
    result = classify_device(
        vendor=None, hostname=None, service_types=["urn:schemas-upnp-org:device:InternetGatewayDevice:1"],
    )
    assert result.device_type == "Router / gateway"
    assert result.confidence == "high"


def test_iot_chipset_category_is_low_confidence_and_only_used_as_a_last_resort():
    result = classify_device(vendor=None, hostname=None, fingerprint_categories=["esp32_esp8266"])
    assert result.device_type == "IoT / embedded device"
    assert result.confidence == "low"


def test_iot_chipset_category_is_not_used_when_a_more_specific_rule_already_matched():
    # A printer that happens to also match a generic IoT chipset category
    # should still be reported as a printer, not demoted to a vague guess.
    result = classify_device(
        vendor="Canon Inc.", hostname=None, fingerprint_categories=["esp32_esp8266"],
    )
    assert result.device_type == "Network printer"


def test_multiple_matches_prefer_the_highest_confidence_candidate():
    # Vendor alone would only earn "Apple device" (low); the iPhone hostname
    # pattern earns "Apple iPhone" (medium) - the higher-confidence result wins.
    result = classify_device(vendor="Apple, Inc.", hostname="my-iphone")
    assert result.confidence == "medium"
    assert result.device_type == "Apple iPhone"
