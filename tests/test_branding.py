# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from lanfence import branding


def test_logo_svg_is_sized_and_valid_markup():
    svg = branding.logo_svg(42)
    assert svg.startswith("<svg")
    assert 'width="42"' in svg
    assert 'height="42"' in svg
    assert svg.count("<svg") == svg.count("</svg>")


def test_logo_svg_default_size():
    assert 'width="28"' in branding.logo_svg()


def test_footer_html_has_expected_links():
    assert "stablestate.co.uk" in branding.FOOTER_HTML
    assert "opensource.org/licenses/MIT" in branding.FOOTER_HTML
    assert "github.com/rosscooney/lanfence" in branding.FOOTER_HTML


def test_colors_has_expected_keys():
    for key in ("bg", "bg_alt", "panel", "border", "text", "muted", "accent", "accent2"):
        assert key in branding.COLORS
        assert branding.COLORS[key].startswith("#")


def test_render_logo_png_is_a_valid_png():
    import struct
    import zlib

    png = branding.render_logo_png(64)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"

    # IHDR immediately follows the signature: length(4) + b"IHDR" + 13 bytes of data.
    length = struct.unpack(">I", png[8:12])[0]
    assert length == 13
    assert png[12:16] == b"IHDR"
    width, height, bit_depth, color_type = struct.unpack(">IIBB", png[16:26])
    assert (width, height) == (64, 64)
    assert bit_depth == 8
    assert color_type == 2  # truecolor RGB, no alpha

    assert png.endswith(b"IEND" + struct.pack(">I", zlib.crc32(b"IEND")))


def test_render_logo_png_respects_requested_size():
    import struct

    png = branding.render_logo_png(32)
    width, height = struct.unpack(">II", png[16:24])
    assert (width, height) == (32, 32)


def test_render_logo_png_idat_decompresses_to_expected_scanline_count():
    import re
    import struct
    import zlib

    size = 16
    png = branding.render_logo_png(size)
    # Extract the IDAT chunk's data (length-prefixed, tag "IDAT").
    match = re.search(rb"IDAT", png)
    assert match is not None
    length = struct.unpack(">I", png[match.start() - 4:match.start()])[0]
    idat = png[match.end():match.end() + length]
    raw = zlib.decompress(idat)
    # One filter-type byte + 3 RGB bytes per pixel, per scanline.
    assert len(raw) == size * (1 + size * 3)
