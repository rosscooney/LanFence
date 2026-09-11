from __future__ import annotations

import pytest

from lanfence.netutil import is_locally_administered, is_multicast, normalize_mac, oui_of


def test_normalize_mac_lowercases_and_converts_dashes():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_mac("not-a-mac")
    with pytest.raises(ValueError):
        normalize_mac("aa:bb:cc:dd:ee")


def test_oui_of():
    assert oui_of("b8:27:eb:12:34:56") == "b8:27:eb"


@pytest.mark.parametrize(
    "mac,expected",
    [
        ("b8:27:eb:12:34:56", False),  # vendor-assigned (bit clear)
        ("02:00:00:00:00:01", True),   # locally administered bit set
        ("06:00:00:00:00:01", True),
        ("00:00:00:00:00:00", False),
    ],
)
def test_is_locally_administered(mac, expected):
    assert is_locally_administered(mac) is expected


def test_is_multicast():
    assert is_multicast("01:00:5e:00:00:01") is True
    assert is_multicast("00:00:5e:00:00:01") is False
