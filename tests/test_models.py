# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lanfence.models import format_datetime


def test_format_datetime_is_human_readable_not_isoformat():
    dt = datetime(2026, 9, 21, 13, 5, 53, tzinfo=timezone.utc)
    assert format_datetime(dt) == "2026-09-21 13:05:53 UTC"
    assert "+00:00" not in format_datetime(dt)


def test_format_datetime_converts_non_utc_to_utc():
    tz = timezone(timedelta(hours=-5))
    dt = datetime(2026, 9, 21, 8, 5, 53, tzinfo=tz)  # 13:05:53 UTC
    assert format_datetime(dt) == "2026-09-21 13:05:53 UTC"


def test_format_datetime_treats_naive_datetime_as_utc():
    dt = datetime(2026, 9, 21, 13, 5, 53)
    assert format_datetime(dt) == "2026-09-21 13:05:53 UTC"


def test_format_datetime_drops_microseconds():
    dt = datetime(2026, 9, 21, 13, 5, 53, 123456, tzinfo=timezone.utc)
    assert format_datetime(dt) == "2026-09-21 13:05:53 UTC"
