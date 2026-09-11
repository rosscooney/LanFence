from __future__ import annotations

from pathlib import Path

import pytest

from lanfence.allowlist import Allowlist


def test_empty_when_no_path():
    al = Allowlist.load(None)
    assert len(al) == 0


def test_empty_when_file_missing(tmp_path: Path):
    al = Allowlist.load(tmp_path / "nope.yaml")
    assert len(al) == 0


def test_add_normalizes_mac_and_save_load_roundtrip(tmp_path: Path):
    path = tmp_path / "allowlist.yaml"
    al = Allowlist.load(path)
    al.path = path
    al.add("AA:BB:CC:DD:EE:FF", "My Router", "trusted gateway")
    al.save()

    reloaded = Allowlist.load(path)
    assert len(reloaded) == 1
    entry = reloaded.entries[0]
    assert entry.mac == "aa:bb:cc:dd:ee:ff"
    assert entry.name == "My Router"
    assert entry.notes == "trusted gateway"


def test_add_replaces_existing_entry_for_same_mac(tmp_path: Path):
    al = Allowlist.load(None)
    al.add("aa:bb:cc:dd:ee:ff", "First Name")
    al.add("AA:BB:CC:DD:EE:FF", "Renamed")
    assert len(al) == 1
    assert al.entries[0].name == "Renamed"


def test_match_is_case_insensitive():
    al = Allowlist.load(None)
    al.add("aa:bb:cc:dd:ee:ff", "Router")
    assert al.match("AA:BB:CC:DD:EE:FF") is not None
    assert al.match("11:22:33:44:55:66") is None


def test_remove(tmp_path: Path):
    al = Allowlist.load(None)
    al.add("aa:bb:cc:dd:ee:ff", "Router")
    removed = al.remove("aa:bb:cc:dd:ee:ff")
    assert removed is not None
    assert len(al) == 0
    assert al.remove("aa:bb:cc:dd:ee:ff") is None


def test_save_without_path_raises():
    al = Allowlist.load(None)
    with pytest.raises(ValueError):
        al.save()


def test_malformed_entries_are_skipped(tmp_path: Path):
    path = tmp_path / "allowlist.yaml"
    path.write_text(
        "allow:\n"
        "  - mac: not-a-mac\n"
        "    name: bad\n"
        "  - mac: aa:bb:cc:dd:ee:ff\n"
        "    name: good\n",
        encoding="utf-8",
    )
    al = Allowlist.load(path)
    assert len(al) == 1
    assert al.entries[0].name == "good"
