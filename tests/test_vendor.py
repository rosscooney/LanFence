from __future__ import annotations

from pathlib import Path

from lanfence.vendor import lookup_vendor


def test_lookup_known_vendor():
    assert lookup_vendor("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"


def test_lookup_unknown_vendor_returns_none():
    assert lookup_vendor("ff:ff:ff:ff:ff:fe") is None


def test_lookup_locally_administered_returns_none_even_if_oui_matches_a_table_entry():
    # 0a:27:eb happens to have the U/L bit set on its first octet (0x0a);
    # locally administered addresses carry no vendor meaning.
    assert lookup_vendor("0a:27:eb:12:34:56") is None


def test_lookup_extra_file_overrides_and_extends(tmp_path: Path):
    extra = tmp_path / "extra_vendors.txt"
    # 0x00 has the U/L bit clear, so this is a valid (fictional) vendor-assigned OUI.
    extra.write_text("00:11:22\tCustom Corp\n", encoding="utf-8")
    assert lookup_vendor("00:11:22:00:00:01", extra_file=extra) == "Custom Corp"
    # packaged entries remain available alongside the extra file
    assert lookup_vendor("b8:27:eb:00:00:01", extra_file=extra) == "Raspberry Pi Foundation"


def test_lookup_missing_extra_file_is_ignored(tmp_path: Path):
    missing = tmp_path / "nope.txt"
    assert lookup_vendor("b8:27:eb:00:00:01", extra_file=missing) == "Raspberry Pi Foundation"
