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
