# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Validation for operator-provided device inventory metadata
(owner/location) - shared by `lanfence device` and the web portal
(`lanfence/web.py`) so the two never drift apart on limits or
sanitisation."""

from __future__ import annotations

from lanfence.sanitize import clean_text

#: Character limits for user-provided device metadata - long enough for a
#: real value, short enough to keep the database and rendering sane.
#: Overlong input is rejected with a clear error, never silently truncated.
METADATA_LIMITS = {"owner": 128, "location": 128}


def validate_metadata_value(field: str, value: str) -> str:
    """Trim, sanitize, and length-check one metadata field's new value.

    Raises ``ValueError`` (caller renders it and exits/errors) for a blank
    value (clear the field explicitly instead) or one over its limit -
    never silently truncates.
    """

    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{field} must not be empty - clear it explicitly instead")
    limit = METADATA_LIMITS[field]
    if len(trimmed) > limit:
        raise ValueError(f"{field} must be at most {limit} characters (got {len(trimmed)})")
    return clean_text(trimmed, max_len=limit)
