# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Validation for operator-provided device inventory metadata (owner,
location, and Know Your Network's asset/ownership fields) - shared by
`lanfence device` and the web portal (`lanfence/web.py`) so the two never
drift apart on limits or sanitisation."""

from __future__ import annotations

from lanfence.models import ASSET_TYPES, DEVICE_CATEGORIES
from lanfence.sanitize import clean_text

#: Character limits for user-provided device metadata - long enough for a
#: real value, short enough to keep the database and rendering sane.
#: Overlong input is rejected with a clear error, never silently truncated.
METADATA_LIMITS = {
    "owner": 128,
    "location": 128,
    "asset_type": 32,
    "purpose": 256,
    "notes": 2000,
    "category_override": 32,
}

#: Fields whose value must be one of a fixed set of choices, not free text -
#: see :data:`lanfence.models.AssetType`/:data:`lanfence.models.DeviceCategory`.
METADATA_CHOICES: dict[str, tuple[str, ...]] = {
    "asset_type": ASSET_TYPES,
    "category_override": DEVICE_CATEGORIES,
}


def validate_metadata_value(field: str, value: str) -> str:
    """Trim, sanitise, and length-check one metadata field's new value -
    and, for :data:`METADATA_CHOICES` fields, check it's actually one of
    the allowed choices.

    Raises ``ValueError`` (caller renders it and exits/errors) for a blank
    value (clear the field explicitly instead), one over its limit, or an
    unrecognised choice - never silently truncates or substitutes a
    default.
    """

    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{field} must not be empty - clear it explicitly instead")
    limit = METADATA_LIMITS[field]
    if len(trimmed) > limit:
        raise ValueError(f"{field} must be at most {limit} characters (got {len(trimmed)})")
    choices = METADATA_CHOICES.get(field)
    if choices is not None and trimmed not in choices:
        raise ValueError(f"{field} must be one of: {', '.join(choices)} (got {trimmed!r})")
    return clean_text(trimmed, max_len=limit)
