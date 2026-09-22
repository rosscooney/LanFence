# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from lanfence.models import format_datetime


@contextmanager
def _local_timezone(name: str):
    """Temporarily set the process's local timezone (POSIX only, matching
    this project's Linux/macOS-only scope) so a local-time conversion can
    be asserted deterministically regardless of the machine running the
    test suite."""

    original = os.environ.get("TZ")
    os.environ["TZ"] = name
    time.tzset()
    try:
        yield
    finally:
        if original is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = original
        time.tzset()


@pytest.fixture
def new_york_tz():
    with _local_timezone("America/New_York"):  # UTC-4 (EDT) in September
        yield


def test_format_datetime_converts_to_local_timezone(new_york_tz):
    dt = datetime(2026, 9, 21, 13, 5, 53, tzinfo=timezone.utc)
    assert format_datetime(dt) == "2026-09-21 09:05:53 EDT"
    assert "+00:00" not in format_datetime(dt)


def test_format_datetime_converts_non_utc_source_to_local(new_york_tz):
    tz = timezone(timedelta(hours=-3))
    dt = datetime(2026, 9, 21, 16, 5, 53, tzinfo=tz)  # 19:05:53 UTC -> 15:05:53 EDT
    assert format_datetime(dt) == "2026-09-21 15:05:53 EDT"


def test_format_datetime_treats_naive_datetime_as_utc(new_york_tz):
    dt = datetime(2026, 9, 21, 13, 5, 53)
    assert format_datetime(dt) == "2026-09-21 09:05:53 EDT"


def test_format_datetime_drops_microseconds(new_york_tz):
    dt = datetime(2026, 9, 21, 13, 5, 53, 123456, tzinfo=timezone.utc)
    assert format_datetime(dt) == "2026-09-21 09:05:53 EDT"
