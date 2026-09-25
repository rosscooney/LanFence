from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from lanfence.risk import RISK_THRESHOLDS, RISK_WEIGHTS, RiskInputs, assess, level_for

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
OLD = NOW - timedelta(days=100)


def _labels(assessment):
    return {c.label: c.points for c in assessment.contributions}


def test_a_trusted_known_device_is_low_risk():
    result = assess(RiskInputs(
        trusted=True, first_seen=OLD, identity_category="Storage / NAS", identity_confidence=75,
        identity_manufacturer="Synology",
    ), now=NOW)
    assert (result.score, result.level) == (0, "low")
    assert result.recommendation == "No action needed."


def test_the_spec_example_untrusted_device_with_new_ssh_is_high():
    result = assess(RiskInputs(
        trusted=False, first_seen=NOW - timedelta(hours=2), private_mac=True, identity_category="Unknown",
        identity_confidence=20, identity_uncertain=True, identity_manufacturer="Raspberry Pi Foundation",
        new_admin_services=["SSH / TCP 22"],
    ), now=NOW)
    assert result.level == "high"
    labels = _labels(result)
    assert labels["Device is not trusted"] == 25
    assert labels["New administrative service: SSH / TCP 22"] == 25
    assert labels["Device first seen in the last 24 hours"] == 10
    assert labels["Locally administered (private) MAC address"] == 10
    assert labels["Device identity uncertain"] == 5
    assert labels["Known manufacturer (Raspberry Pi Foundation)"] == -5
    assert result.score == sum(labels.values())


def test_a_private_mac_on_a_phone_is_not_a_warning_sign():
    phone = assess(RiskInputs(
        trusted=True, first_seen=OLD, private_mac=True, identity_category="Phone", identity_confidence=80,
        identity_manufacturer="Apple",
    ), now=NOW)
    unknown = assess(RiskInputs(trusted=True, first_seen=OLD, private_mac=True), now=NOW)
    assert phone.level == "low"
    assert _labels(phone)["Private MAC address (normal for a phone)"] == RISK_WEIGHTS["private_mac_expected"]
    assert unknown.score > phone.score


def test_score_is_bounded_to_0_100():
    everything = assess(RiskInputs(
        trusted=False, investigating=True, first_seen=NOW, private_mac=True, signature_severities={"high"},
        new_admin_services=["a", "b", "c"], new_services=["d", "e", "f"], unexpected_change=True,
        identity_changed=True, identity_category="Network Infrastructure", dhcp_server=True, always_on=True,
        online=False, long_absence_return=True, recent_changes=9,
    ), now=NOW)
    assert everything.score == 100
    assert everything.level == "critical"
    only_negative = assess(RiskInputs(
        trusted=True, first_seen=OLD, identity_confidence=90, identity_manufacturer="Apple",
    ), now=NOW)
    assert only_negative.score == 0


def test_repeated_services_only_count_up_to_a_cap():
    many = assess(RiskInputs(trusted=True, first_seen=OLD, new_admin_services=["a", "b", "c", "d"]), now=NOW)
    assert sum(1 for c in many.contributions if c.factor == "new_admin_service") == 2


@pytest.mark.parametrize(("score", "level"), [(0, "low"), (19, "low"), (20, "moderate"), (39, "moderate"),
                                              (40, "high"), (74, "high"), (75, "critical"), (100, "critical")])
def test_thresholds(score, level):
    assert level_for(score) == level


def test_thresholds_are_ordered_and_start_at_zero():
    minimums = [minimum for minimum, _level in RISK_THRESHOLDS]
    assert minimums == sorted(minimums, reverse=True)
    assert minimums[-1] == 0


def test_contributions_are_ordered_by_impact():
    result = assess(RiskInputs(
        trusted=False, first_seen=OLD, identity_confidence=80, identity_manufacturer="Raspberry Pi Foundation",
        signature_severities={"medium"},
    ), now=NOW)
    points = [abs(c.points) for c in result.contributions]
    assert points == sorted(points, reverse=True)


def test_recommendations_never_claim_compromise():
    cases = [
        RiskInputs(trusted=False, first_seen=NOW, new_admin_services=["SSH / TCP 22"]),
        RiskInputs(trusted=False, first_seen=NOW, signature_severities={"high"}),
        RiskInputs(trusted=True, first_seen=OLD, dhcp_server=True),
        RiskInputs(trusted=False, first_seen=OLD),
    ]
    for inputs in cases:
        text = assess(inputs, now=NOW).recommendation.lower()
        assert text
        assert "compromis" not in text and "malicious" not in text and "hacked" not in text


def test_new_admin_service_recommendation_offers_accepting_it():
    result = assess(RiskInputs(trusted=True, first_seen=OLD, new_admin_services=["SSH / TCP 22"],
                               unexpected_change=True), now=NOW)
    assert result.level == "high"
    assert "SSH / TCP 22" in result.recommendation
    assert "accept" in result.recommendation
