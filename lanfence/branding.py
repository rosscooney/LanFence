# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Shared LAN Fence visual identity - the logo mark, colour palette, and
footer copy used by both the web portal (``lanfence/web.py``) and the HTML
digest email (``lanfence/digest.py``), so the two never drift into two
different looks. Mirrors the public website's (lanfence.com) look and
feel. Constants only - no behavior, no dependencies beyond the stdlib.
"""

from __future__ import annotations

import struct
import zlib

#: The website's dark palette (see lanfence.com's own stylesheet).
COLORS = {
    "bg": "#0b1120",
    "bg_alt": "#0f172a",
    "panel": "#131c31",
    "border": "#23304d",
    "text": "#e6ecf7",
    "muted": "#9aa8c4",
    "accent": "#2dd4bf",
    "accent2": "#38bdf8",
}

#: Shared inline-CSS building blocks for every HTML email LAN Fence sends
#: (the digest, finding alerts, and channel test messages) - a single
#: source of truth so they can't visually drift apart from one another.
EMAIL_BODY_STYLE = (
    f"margin:0;background:{COLORS['bg']};color:{COLORS['text']};"
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
)
EMAIL_TABLE_STYLE = f"width:100%;max-width:640px;margin:0 auto;border-collapse:collapse;background:{COLORS['bg']};"
EMAIL_PANEL_STYLE = (
    f"background:{COLORS['panel']};border:1px solid {COLORS['border']};border-radius:12px;padding:16px 18px;"
)
EMAIL_MUTED_STYLE = f"color:{COLORS['muted']};"

#: The logo mark's inner content only (no fixed width/height) so callers
#: can size it with their own attributes - see :func:`logo_svg`.
_LOGO_INNER = """<linearGradient id="lf-logo-g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#2dd4bf"/>
    <stop offset="1" stop-color="#38bdf8"/>
  </linearGradient>
  <rect x="2" y="2" width="60" height="60" rx="14" fill="#0f172a" stroke="#23304d" stroke-width="2"/>
  <g stroke="#e6ecf7" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none">
    <path d="M13 38 V16 L16 11 L19 16 V38"/>
    <path d="M23 38 V16 L26 11 L29 16 V38"/>
    <path d="M33 38 V16 L36 11 L39 16 V38"/>
    <path d="M10 22 H41"/>
    <path d="M10 32 H41"/>
  </g>
  <circle cx="42" cy="40" r="11" fill="none" stroke="url(#lf-logo-g)" stroke-width="3.5"/>
  <line x1="50" y1="48" x2="57" y2="55" stroke="url(#lf-logo-g)" stroke-width="4" stroke-linecap="round"/>"""


def logo_svg(size: int = 28) -> str:
    """The LAN Fence logo mark as an inline ``<svg>`` of ``size`` pixels."""

    return f'<svg width="{size}" height="{size}" viewBox="0 0 64 64" role="img" aria-label="LAN Fence logo">{_LOGO_INNER}</svg>'


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def render_logo_png(size: int = 64) -> bytes:
    """A raster (PNG) rendition of the logo mark, pixel-drawn in pure
    Python (``struct``/``zlib`` only - no image library dependency) and
    hand-encoded as a real PNG file. Used only for the HTML digest email's
    inline logo (``lanfence/digest.py``): many mail clients (Gmail among
    them) strip inline ``<svg>`` markup from HTML email entirely, so the
    crisper :func:`logo_svg` used by the web portal isn't a safe choice
    there - a `Content-ID`-attached raster image is the one approach that
    reliably renders across mail clients, including older ones that also
    reject SVG and data-URI images alike.

    Deliberately a simplified approximation of the vector mark (flat
    fill, no gradient, no rounded corners) rather than a pixel-perfect
    match - correctness of the PNG format matters far more here than
    fidelity for a small decorative logo.
    """

    bg = (0x0F, 0x17, 0x2A)
    border = (0x23, 0x30, 0x4D)
    fence = (0xE6, 0xEC, 0xF7)
    accent = (0x2D, 0xD4, 0xBF)

    pixels = [[bg for _ in range(size)] for _ in range(size)]
    scale = size / 64.0

    def set_px(x: int, y: int, color: tuple[int, int, int]) -> None:
        if 0 <= x < size and 0 <= y < size:
            pixels[y][x] = color

    def fill_rect(x0: float, y0: float, x1: float, y1: float, color: tuple[int, int, int]) -> None:
        for y in range(round(y0 * scale), round(y1 * scale)):
            for x in range(round(x0 * scale), round(x1 * scale)):
                set_px(x, y, color)

    # Border ring.
    fill_rect(0, 0, 64, 2, border)
    fill_rect(0, 62, 64, 64, border)
    fill_rect(0, 0, 2, 64, border)
    fill_rect(62, 0, 64, 64, border)

    # Three fence-post bars and two rails, echoing the SVG mark's motif.
    for x0 in (12, 22, 32):
        fill_rect(x0, 11, x0 + 3, 38, fence)
    fill_rect(9, 21, 42, 24, fence)
    fill_rect(9, 31, 42, 34, fence)

    # Magnifier ring (a flat accent colour standing in for the SVG's
    # gradient stroke - solid fill is simpler and reads fine at this size).
    cx, cy, radius, thickness = 42.0, 40.0, 11.0, 3.2
    for y in range(size):
        for x in range(size):
            dx, dy = x / scale - cx, y / scale - cy
            dist = (dx * dx + dy * dy) ** 0.5
            if radius - thickness / 2 <= dist <= radius + thickness / 2:
                set_px(x, y, accent)

    # Magnifier handle: a short thick diagonal line.
    hx0, hy0, hx1, hy1 = 50.0, 48.0, 57.0, 55.0
    steps = size * 4
    for i in range(steps + 1):
        t = i / steps
        lx, ly = hx0 + (hx1 - hx0) * t, hy0 + (hy1 - hy0) * t
        for ox in (-1.5, -0.5, 0.5, 1.5):
            for oy in (-1.5, -0.5, 0.5, 1.5):
                set_px(round((lx + ox) * scale), round((ly + oy) * scale), accent)

    raw = bytearray()
    for row in pixels:
        raw.append(0)  # scanline filter type 0 ("None")
        for r, g, b in row:
            raw.extend((r, g, b))

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)  # 8-bit depth, colour type 2 = truecolor
    idat = zlib.compress(bytes(raw), 9)
    return signature + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")


#: Plain-HTML copyright/license/repo footer, shared verbatim by the web
#: portal's page footer (``lanfence/web.py``) and the HTML digest email
#: (``lanfence/digest.py``'s ``format_digest_html``) - license/source line
#: first, copyright line second.
FOOTER_HTML = (
    "LAN Fence is open-source software released under the "
    '<a href="https://opensource.org/licenses/MIT">MIT License</a>. '
    '<a href="https://github.com/rosscooney/lanfence">Source (GitHub)</a>.<br>'
    '&copy; 2026 <a href="https://www.stablestate.co.uk">Stable State Consulting Ltd</a>.'
)
