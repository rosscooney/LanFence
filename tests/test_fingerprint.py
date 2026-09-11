from __future__ import annotations

from pathlib import Path

from lanfence.fingerprint import SignatureSet, fingerprint_device


def test_packaged_signatures_load():
    sigs = SignatureSet.load()
    assert len(sigs) > 0


def test_vendor_keyword_match_espressif():
    sigs = SignatureSet.load()
    matches = sigs.match(vendor="Espressif Inc.", hostname=None)
    assert any(m.category == "esp32_esp8266" for m in matches)


def test_hostname_keyword_match_pwnagotchi():
    sigs = SignatureSet.load()
    matches = sigs.match(vendor=None, hostname="pwnagotchi-abcd.local")
    assert any(m.category == "pwnagotchi" and m.severity == "high" for m in matches)


def test_no_match_for_ordinary_device():
    sigs = SignatureSet.load()
    matches = sigs.match(vendor="Apple, Inc.", hostname="johns-iphone")
    assert matches == []


def test_vendor_keyword_match_ai_thinker_shares_esp32_category():
    sigs = SignatureSet.load()
    matches = sigs.match(vendor="Shenzhen Ai-Thinker Technology Co.,Ltd", hostname=None)
    assert any(m.category == "esp32_esp8266" for m in matches)


def test_vendor_keyword_match_hisilicon_camera_soc():
    sigs = SignatureSet.load()
    matches = sigs.match(vendor="Hisilicon Technologies Co., Ltd", hostname=None)
    assert any(m.category == "hisilicon_camera_soc" and m.severity == "medium" for m in matches)


def test_vendor_keyword_match_allwinner():
    sigs = SignatureSet.load()
    matches = sigs.match(vendor="Allwinner Technology Co., Ltd", hostname=None)
    assert any(m.category == "allwinner_sbc_or_camera" for m in matches)


def test_vendor_keyword_match_orange_pi():
    sigs = SignatureSet.load()
    matches = sigs.match(vendor="SHENZHEN XUNLONG SOFTWARE CO.,LIMITED", hostname=None)
    assert any(m.category == "orange_pi" for m in matches)


def test_hostname_keyword_match_bash_bunny_and_lan_turtle():
    sigs = SignatureSet.load()
    assert any(m.category == "bash_bunny" for m in sigs.match(vendor=None, hostname="bunny-4821"))
    assert any(m.category == "lan_turtle" for m in sigs.match(vendor=None, hostname="turtle"))


def test_no_stale_signatures_for_corrected_or_removed_entries():
    """Regression test: `bashbunny`/`lanturtle` were replaced with the
    better-corroborated `bunny`/`turtle`, and `omg-cable`/`flipper` were
    removed outright after verification found no support for them - a
    hostname that only matches the old strings should no longer fire."""

    sigs = SignatureSet.load()
    assert sigs.match(vendor=None, hostname="omg-cable-01") == []
    assert sigs.match(vendor=None, hostname="flipper-zero") == []


def test_fingerprint_device_raspberry_pi_vendor():
    sigs = SignatureSet.load()
    vendor, matches = fingerprint_device("b8:27:eb:12:34:56", "nas.local", signatures=sigs)
    assert vendor == "Raspberry Pi Foundation"
    assert any(m.category == "raspberry_pi" for m in matches)


def test_fingerprint_device_locally_administered_mac_flagged():
    sigs = SignatureSet.load()
    vendor, matches = fingerprint_device("02:00:00:00:00:01", None, signatures=sigs)
    assert vendor is None
    assert any(m.category == "locally_administered_mac" for m in matches)


def test_fingerprint_device_no_signal_for_known_vendor_no_hostname():
    sigs = SignatureSet.load()
    vendor, matches = fingerprint_device("00:03:93:00:00:01", None, signatures=sigs)
    assert vendor == "Apple, Inc."
    assert matches == []


def test_extra_signatures_file_extends_packaged_set(tmp_path: Path):
    extra = tmp_path / "extra_sigs.yaml"
    extra.write_text(
        "hostname_keywords:\n"
        "  - match: myimplant\n"
        "    category: my_implant\n"
        "    severity: high\n"
        "    description: a custom lab signature\n",
        encoding="utf-8",
    )
    sigs = SignatureSet.load(extra)
    matches = sigs.match(vendor=None, hostname="myimplant-01")
    assert any(m.category == "my_implant" for m in matches)
    # packaged signatures are still present
    assert any(m.category == "esp32_esp8266" for m in sigs.match(vendor="Espressif Inc.", hostname=None))


def test_malformed_signature_entry_is_skipped(tmp_path: Path):
    extra = tmp_path / "bad_sigs.yaml"
    extra.write_text(
        "hostname_keywords:\n"
        "  - match: ok-one\n"
        "    category: fine\n"
        "    severity: nonsense-severity\n"
        "    description: bad severity value\n",
        encoding="utf-8",
    )
    sigs = SignatureSet.load(extra)
    assert sigs.match(vendor=None, hostname="ok-one") == []
