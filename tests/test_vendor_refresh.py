from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from lanfence.cli import app
from lanfence.vendor import format_vendor_table, lookup_vendor, parse_ieee_oui_csv

runner = CliRunner()

_SAMPLE_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    'MA-L,B827EB,"Raspberry Pi Foundation","Cambridge UK"\n'
    'MA-L,D48AFC,"Espressif Inc.","Shanghai CN"\n'
    'MA-M,0050430,"Some Sub-Block Vendor","Nowhere"\n'  # wrong tier - excluded
    'MA-L,ZZZZZZ,"Bad Hex Vendor","Nowhere"\n'  # not valid hex - excluded
    'MA-L,001122,"","Nowhere"\n'  # empty org name - excluded
)


def test_parse_ieee_oui_csv_keeps_only_valid_ma_l_rows():
    table = parse_ieee_oui_csv(_SAMPLE_CSV)
    assert table == {
        "B8:27:EB": "Raspberry Pi Foundation",
        "D4:8A:FC": "Espressif Inc.",
    }


def test_parse_ieee_oui_csv_collapses_whitespace_in_org_name():
    csv_text = (
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,AABBCC,"Weird   \n Spacing   Corp","Nowhere"\n'
    )
    table = parse_ieee_oui_csv(csv_text)
    assert table["AA:BB:CC"] == "Weird Spacing Corp"


def test_parse_ieee_oui_csv_empty_input():
    assert parse_ieee_oui_csv("") == {}
    assert parse_ieee_oui_csv("Registry,Assignment,Organization Name\n") == {}


def test_format_vendor_table_roundtrips_through_lookup(tmp_path: Path):
    # first octet's U/L bit (0x02) must be clear on both, or lookup_vendor
    # treats the address as locally administered and refuses to resolve it.
    table = {"00:11:22": "Widget Co", "00:33:44": "Gadget Inc"}
    text = format_vendor_table(table)
    extra = tmp_path / "extra.txt"
    extra.write_text(text, encoding="utf-8")
    assert lookup_vendor("00:11:22:00:00:01", extra_file=extra) == "Widget Co"
    assert lookup_vendor("00:33:44:00:00:01", extra_file=extra) == "Gadget Inc"


def test_format_vendor_table_is_sorted():
    table = {"FF:FF:FF": "Z Corp", "00:00:00": "A Corp"}
    text = format_vendor_table(table)
    assert text.index("00:00:00") < text.index("FF:FF:FF")


class _FakeResponse:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def test_vendor_refresh_writes_extra_table(tmp_path: Path):
    dest = tmp_path / "oui.txt"
    with patch("lanfence.cli.urllib.request.urlopen", return_value=_FakeResponse(_SAMPLE_CSV.encode())):
        result = runner.invoke(app, ["vendor-refresh", "--output", str(dest)])
    assert result.exit_code == 0, result.output
    assert "saved 2 vendor entries" in result.output
    assert dest.is_file()
    content = dest.read_text()
    assert "B8:27:EB\tRaspberry Pi Foundation" in content
    assert "vendor_file:" in result.output


def test_vendor_refresh_download_failure(tmp_path: Path):
    with patch("lanfence.cli.urllib.request.urlopen", side_effect=OSError("network down")):
        result = runner.invoke(app, ["vendor-refresh", "--output", str(tmp_path / "oui.txt")])
    assert result.exit_code == 1
    assert "could not download" in result.output


def test_vendor_refresh_unparseable_response(tmp_path: Path):
    with patch("lanfence.cli.urllib.request.urlopen", return_value=_FakeResponse(b"not a csv at all")):
        result = runner.invoke(app, ["vendor-refresh", "--output", str(tmp_path / "oui.txt")])
    assert result.exit_code == 1
    assert "did not parse" in result.output


def test_vendor_refresh_uses_config_vendor_file_as_default_destination(tmp_path: Path):
    dest = tmp_path / "configured.txt"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({"vendor_file": str(dest)}), encoding="utf-8")

    with patch("lanfence.cli.urllib.request.urlopen", return_value=_FakeResponse(_SAMPLE_CSV.encode())):
        result = runner.invoke(app, ["vendor-refresh", "--config", str(config_path)])
    assert result.exit_code == 0, result.output
    assert dest.is_file()
    # already the configured vendor_file - no need to tell the operator to add it
    assert "add this to your config" not in result.output


def test_vendor_refresh_no_such_path_error_reported(tmp_path: Path):
    unwritable = tmp_path / "no" / "such" / "dir" / "oui.txt"
    with patch("lanfence.cli.urllib.request.urlopen", return_value=_FakeResponse(_SAMPLE_CSV.encode())), \
         patch("lanfence.cli.atomic_write", side_effect=OSError("boom")):
        result = runner.invoke(app, ["vendor-refresh", "--output", str(unwritable)])
    assert result.exit_code == 1
    assert "could not write" in result.output
