# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Shared LAN Fence visual identity - the logo mark, colour palette, and
footer copy used by both the web portal (``lanfence/web.py``) and the HTML
digest email (``lanfence/digest.py``), so the two never drift into two
different looks. Mirrors the public website's (lanfence.com) look and
feel. Constants only - no behavior, no dependencies beyond the stdlib.
"""

from __future__ import annotations

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


#: Plain-HTML copyright/license/repo line, reused verbatim in the web
#: portal's page footer and the HTML digest email.
FOOTER_HTML = (
    '&copy; 2026 <a href="https://www.stablestate.co.uk">Stable State Consulting Ltd</a>. '
    "LAN Fence is open-source software released under the "
    '<a href="https://opensource.org/licenses/MIT">MIT License</a>. '
    '<a href="https://github.com/rosscooney/lanfence">Source (GitHub)</a>.'
)
