from __future__ import annotations

from pathlib import Path

import pytest

from lanfence.identity import (
    DeviceIdentity,
    IdentityEvidence,
    IdentityRuleSet,
    infer_identity,
)


def _rules() -> IdentityRuleSet:
    return IdentityRuleSet.load()


# --- rule loading --------------------------------------------------------


def test_packaged_rules_load_without_warnings(caplog):
    rules = _rules()
    assert len(rules) > 0
    assert "skipping malformed" not in caplog.text


def test_extra_rules_file_extends_packaged_set(tmp_path: Path):
    extra = tmp_path / "extra_identity.yaml"
    extra.write_text(
        "rules:\n"
        "  - id: my_lab_widget\n"
        "    weight: 40\n"
        "    when:\n"
        "      hostname_regex: 'labwidget'\n"
        "    category: 'Smart Home / IoT'\n"
        "    manufacturer: 'Acme Labs'\n"
        "    label: 'Hostname matches a lab-only widget'\n",
        encoding="utf-8",
    )
    rules = IdentityRuleSet.load(extra)
    identity = infer_identity(IdentityEvidence(hostname="labwidget-01"), rules)
    assert identity.manufacturer == "Acme Labs"
    assert identity.category == "Smart Home / IoT"
    # Packaged rules are still present alongside the extra one.
    apple = infer_identity(IdentityEvidence(vendor="Apple, Inc."), rules)
    assert apple.manufacturer == "Apple"


def test_malformed_rule_missing_when_is_skipped(tmp_path: Path, caplog):
    extra = tmp_path / "bad_identity.yaml"
    extra.write_text(
        "rules:\n"
        "  - id: no_conditions\n"
        "    weight: 40\n"
        "    when: {}\n"
        "    category: 'Printer'\n"
        "    label: 'would match everything'\n",
        encoding="utf-8",
    )
    rules = IdentityRuleSet.load(extra)
    identity = infer_identity(IdentityEvidence(), rules)
    assert identity.category == "Unknown"



def test_malformed_rule_invalid_regex_is_skipped_not_fatal(tmp_path: Path):
    extra = tmp_path / "bad_regex.yaml"
    extra.write_text(
        "rules:\n"
        "  - id: bad_regex\n"
        "    weight: 40\n"
        "    when:\n"
        "      hostname_regex: '(unclosed'\n"
        "    category: 'Printer'\n"
        "    label: 'bad regex'\n",
        encoding="utf-8",
    )
    rules = IdentityRuleSet.load(extra)
    assert len(rules) == len(_rules())  # packaged rules still load; only the bad one is dropped

def test_malformed_rule_bad_category_is_skipped(tmp_path: Path):
    extra = tmp_path / "bad_category.yaml"
    extra.write_text(
        "rules:\n"
        "  - id: bad_category_rule\n"
        "    weight: 40\n"
        "    when:\n"
        "      hostname_regex: 'widget'\n"
        "    category: 'Not A Real Category'\n"
        "    label: 'bad category'\n",
        encoding="utf-8",
    )
    rules = IdentityRuleSet.load(extra)
    identity = infer_identity(IdentityEvidence(hostname="widget-1"), rules)
    assert identity.category == "Unknown"


def test_malformed_rule_non_positive_weight_is_skipped(tmp_path: Path):
    extra = tmp_path / "bad_weight.yaml"
    extra.write_text(
        "rules:\n"
        "  - id: zero_weight\n"
        "    weight: 0\n"
        "    when:\n"
        "      hostname_regex: 'widget'\n"
        "    category: 'Printer'\n"
        "    label: 'zero weight'\n",
        encoding="utf-8",
    )
    rules = IdentityRuleSet.load(extra)
    identity = infer_identity(IdentityEvidence(hostname="widget-1"), rules)
    assert identity.category == "Unknown"


# --- unknown / no evidence ------------------------------------------------


def test_no_evidence_is_unknown_with_zero_confidence():
    identity = infer_identity(IdentityEvidence(), _rules())
    assert identity.category == "Unknown"
    assert identity.manufacturer is None
    assert identity.family is None
    assert identity.platform is None
    assert identity.confidence == 0
    assert identity.evidence == []
    assert identity.is_known is False


def test_unrecognised_vendor_and_hostname_stays_unknown():
    rules = _rules()
    identity = infer_identity(
        IdentityEvidence(vendor="Totally Fictional Widgets Ltd", hostname="thingy-42"), rules
    )
    assert identity.category == "Unknown"
    assert identity.confidence == 0


# --- single-source matching ------------------------------------------------


def test_vendor_only_identifies_manufacturer():
    identity = infer_identity(IdentityEvidence(vendor="Synology Incorporated"), _rules())
    assert identity.manufacturer == "Synology"
    assert identity.category == "Storage / NAS"
    assert identity.confidence > 0


def test_hostname_only_identifies_category():
    identity = infer_identity(IdentityEvidence(hostname="desktop-ab12cd3"), _rules())
    assert identity.platform == "Windows"
    assert identity.category == "Computer"


def test_fingerprint_category_only_identifies_raspberry_pi():
    identity = infer_identity(
        IdentityEvidence(fingerprint_categories=frozenset({"raspberry_pi"})), _rules()
    )
    assert identity.family == "Raspberry Pi"
    assert identity.category == "Development Board / SBC"


def test_service_type_only_identifies_printer():
    identity = infer_identity(IdentityEvidence(service_types=("_ipp._tcp.local",)), _rules())
    assert identity.category == "Printer"


def test_ssdp_server_only_identifies_infrastructure():
    identity = infer_identity(
        IdentityEvidence(ssdp_servers=("Linux/3.2 UPnP/1.0 MyRouter/1.0",)), _rules()
    )
    assert identity.category == "Network Infrastructure"


def test_open_port_only_identifies_camera():
    identity = infer_identity(IdentityEvidence(open_ports=frozenset({554})), _rules())
    assert identity.category == "Camera"


def test_locally_administered_only_is_low_confidence_and_unknown_category():
    identity = infer_identity(IdentityEvidence(locally_administered=True), _rules())
    assert identity.category == "Unknown"
    assert 0 < identity.confidence <= 10


# --- multiple evidence sources combining -----------------------------------


def test_iphone_worked_example_combines_every_signal():
    """The exact scenario from the feature's own worked example: an Apple
    OUI, a DHCP hostname, and two Apple-ecosystem mDNS services should all
    independently contribute to one coherent, high-confidence identity."""

    identity = infer_identity(
        IdentityEvidence(
            vendor="Apple, Inc.",
            hostname="Ross-iPhone",
            service_types=("_airplay._tcp.local", "_companion-link._tcp.local"),
        ),
        _rules(),
    )
    assert identity.category == "Phone"
    assert identity.manufacturer == "Apple"
    assert identity.family == "iPhone"
    assert identity.platform == "iOS"
    assert identity.probable_identity == "Apple iPhone"
    assert identity.confidence == 80
    labels = {item.label for item in identity.evidence}
    assert any("iPhone" in label for label in labels)
    assert any("Apple vendor OUI" in label for label in labels)
    assert any("AirPlay" in label for label in labels)
    assert any("companion-link" in label for label in labels)
    assert all(item.weight > 0 for item in identity.evidence)


def test_more_evidence_never_produces_lower_confidence_than_a_subset():
    rules = _rules()
    base = infer_identity(IdentityEvidence(vendor="Apple, Inc.", hostname="Ross-iPhone"), rules)
    fuller = infer_identity(
        IdentityEvidence(
            vendor="Apple, Inc.", hostname="Ross-iPhone", service_types=("_airplay._tcp.local",),
        ),
        rules,
    )
    assert fuller.confidence >= base.confidence


def test_evidence_list_sorted_by_contribution_descending():
    identity = infer_identity(
        IdentityEvidence(
            vendor="Apple, Inc.",
            hostname="Ross-iPhone",
            service_types=("_airplay._tcp.local", "_companion-link._tcp.local"),
        ),
        _rules(),
    )
    weights = [item.weight for item in identity.evidence]
    assert weights == sorted(weights, reverse=True)


# --- conflicting evidence ---------------------------------------------------


def test_conflicting_category_evidence_reduces_confidence_and_is_labelled():
    """A hostname strongly suggesting an iPhone but a vendor OUI that
    belongs to a TV/media-device manufacturer is a real contradiction -
    the losing rule's weight must be subtracted, not silently dropped."""

    rules = _rules()
    identity = infer_identity(
        IdentityEvidence(vendor="Samsung Electronics", hostname="my-iphone-clone"), rules
    )
    # The hostname signal (weight 30) beats the single conflicting vendor
    # rule (weight 20), so the category still resolves, just with much
    # lower confidence than the clean iPhone example above.
    assert identity.category == "Phone"
    assert identity.confidence < 30
    conflicting = [item for item in identity.evidence if item.weight < 0]
    assert len(conflicting) == 1
    assert "conflicts" in conflicting[0].label


def test_confidence_is_lower_with_conflicting_evidence_than_without_it():
    rules = _rules()
    clean = infer_identity(IdentityEvidence(hostname="my-iphone-clone"), rules)
    conflicted = infer_identity(
        IdentityEvidence(vendor="Samsung Electronics", hostname="my-iphone-clone"), rules
    )
    assert conflicted.confidence < clean.confidence


# --- confidence bounds -------------------------------------------------------


def test_confidence_never_exceeds_100_even_with_overwhelming_evidence():
    identity = infer_identity(
        IdentityEvidence(
            vendor="Apple, Inc.",
            hostname="Ross-iPhone",
            service_types=("_airplay._tcp.local", "_companion-link._tcp.local", "_hap._tcp.local"),
        ),
        _rules(),
    )
    assert identity.confidence <= 100


def test_device_identity_confidence_field_is_clamped_on_direct_construction():
    assert DeviceIdentity(confidence=250).confidence == 100
    assert DeviceIdentity(confidence=-50).confidence == 0


def test_confidence_never_negative_even_when_only_conflicting_evidence_present(tmp_path: Path):
    """Two rules that only ever conflict with each other (neither has any
    supporting evidence of its own) must still clamp at 0, not go negative."""

    extra = tmp_path / "pure_conflict.yaml"
    extra.write_text(
        "rules:\n"
        "  - id: claims_printer\n"
        "    weight: 10\n"
        "    when:\n"
        "      vendor_contains: ['widgetco']\n"
        "    category: 'Printer'\n"
        "    label: 'claims printer'\n"
        "  - id: claims_camera\n"
        "    weight: 50\n"
        "    when:\n"
        "      vendor_contains: ['widgetco']\n"
        "    category: 'Camera'\n"
        "    label: 'claims camera'\n",
        encoding="utf-8",
    )
    rules = IdentityRuleSet.load(extra)
    identity = infer_identity(IdentityEvidence(vendor="WidgetCo"), rules)
    assert identity.category == "Camera"
    assert identity.confidence >= 0


# --- probable_identity property ---------------------------------------------


def test_probable_identity_combines_manufacturer_and_family():
    identity = DeviceIdentity(manufacturer="Apple", family="iPhone", category="Phone", confidence=90)
    assert identity.probable_identity == "Apple iPhone"



def test_probable_identity_does_not_repeat_a_manufacturer_the_family_already_names():
    assert DeviceIdentity(manufacturer="Apple", family="Apple TV").probable_identity == "Apple TV"
    assert DeviceIdentity(manufacturer="Sonos", family="Sonos speaker").probable_identity == "Sonos speaker"
    assert (
        DeviceIdentity(manufacturer="Raspberry Pi Foundation", family="Raspberry Pi").probable_identity
        == "Raspberry Pi"
    )
    assert DeviceIdentity(manufacturer="Google", family="Chromecast").probable_identity == "Google Chromecast"

def test_probable_identity_falls_back_to_manufacturer_only():
    identity = DeviceIdentity(manufacturer="Synology", category="Storage / NAS", confidence=50)
    assert identity.probable_identity == "Synology"


def test_probable_identity_falls_back_to_category_when_nothing_else_known():
    identity = DeviceIdentity()
    assert identity.probable_identity == "Unknown"


# --- corroborating (zero-assertion) rules -----------------------------------


def test_corroborating_rule_never_conflicts():
    """A rule that asserts no field (e.g. AirPlay) can never be flagged as
    conflicting - it has no claim of its own to disagree with."""

    identity = infer_identity(
        IdentityEvidence(vendor="Sonos, Inc.", service_types=("_airplay._tcp.local",)), _rules()
    )
    assert all(
        "conflicts" not in item.label for item in identity.evidence if "AirPlay" in item.label
    )


@pytest.mark.parametrize("bad_weight", [0, -5])
def test_zero_or_negative_weight_rule_rejected(tmp_path: Path, bad_weight):
    extra = tmp_path / "bad.yaml"
    extra.write_text(
        "rules:\n"
        f"  - id: bad\n"
        f"    weight: {bad_weight}\n"
        "    when:\n"
        "      hostname_regex: 'x'\n"
        "    category: 'Printer'\n"
        "    label: 'bad'\n",
        encoding="utf-8",
    )
    rules = IdentityRuleSet.load(extra)
    identity = infer_identity(IdentityEvidence(hostname="x"), rules)
    assert identity.category == "Unknown"
