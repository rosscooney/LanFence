from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import patch

from lanfence.alert_worker import AlertDeliveryWorker
from lanfence.config import AlertConfig
from lanfence.models import Finding


def _finding() -> Finding:
    return Finding(mac="aa:bb:cc:dd:ee:ff", title="Unknown device connected", severity="medium")


def test_submit_delivers_in_the_background_not_on_the_caller_thread(tmp_path: Path):
    calls = []
    release = threading.Event()

    def fake_dispatch(findings, cfg, *, store=None, site_name=None, site_location=None):
        calls.append((findings, threading.current_thread()))
        release.set()
        return findings

    worker = AlertDeliveryWorker(tmp_path / "db.sqlite")
    try:
        with patch("lanfence.alert_worker.alerts.dispatch", side_effect=fake_dispatch):
            caller_thread = threading.current_thread()
            ok = worker.submit([_finding()], AlertConfig())
            assert ok is True
            assert release.wait(timeout=5.0), "delivery never happened"
        assert len(calls) == 1
        assert calls[0][1] is not caller_thread
    finally:
        worker.shutdown()


def test_submit_never_blocks_when_queue_is_full(tmp_path: Path):
    block = threading.Event()
    started = threading.Event()

    def blocking_dispatch(findings, cfg, *, store=None, site_name=None, site_location=None):
        started.set()
        block.wait(timeout=5.0)
        return findings

    worker = AlertDeliveryWorker(tmp_path / "db.sqlite", maxsize=1)
    try:
        with patch("lanfence.alert_worker.alerts.dispatch", side_effect=blocking_dispatch):
            # First submit is picked up by the worker and blocks there (on
            # `block`); the second fills the maxsize=1 queue; the third
            # must be dropped rather than block this thread. Waiting on
            # `started` (rather than a fixed sleep) proves the worker has
            # actually begun processing #1 before #2 is submitted - a
            # fixed sleep is not a reliable guarantee of thread scheduling
            # on a slow/loaded CI runner.
            worker.submit([_finding()], AlertConfig())
            assert started.wait(timeout=5.0), "worker never started processing the first item"
            worker.submit([_finding()], AlertConfig())

            start_time = time.monotonic()
            ok = worker.submit([_finding()], AlertConfig())
            elapsed = time.monotonic() - start_time

            assert ok is False
            assert elapsed < 1.0  # never blocked waiting for room
            assert worker.dropped == 1
    finally:
        block.set()
        worker.shutdown()


def test_dropped_counter_only_increments_on_overflow(tmp_path: Path):
    worker = AlertDeliveryWorker(tmp_path / "db.sqlite")
    try:
        assert worker.dropped == 0
        with patch("lanfence.alert_worker.alerts.dispatch", return_value=[]):
            for _ in range(5):
                assert worker.submit([_finding()], AlertConfig()) is True
        assert worker.dropped == 0
    finally:
        worker.shutdown()


def test_delivery_exception_does_not_kill_the_worker_thread(tmp_path: Path):
    calls = []

    def flaky_dispatch(findings, cfg, *, store=None, site_name=None, site_location=None):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("simulated transport failure")
        return findings

    worker = AlertDeliveryWorker(tmp_path / "db.sqlite")
    try:
        with patch("lanfence.alert_worker.alerts.dispatch", side_effect=flaky_dispatch):
            worker.submit([_finding()], AlertConfig())
            worker.submit([_finding()], AlertConfig())
            deadline = time.monotonic() + 5.0
            while len(calls) < 2 and time.monotonic() < deadline:
                time.sleep(0.02)
        assert len(calls) == 2  # the second delivery still ran despite the first raising
    finally:
        worker.shutdown()


def test_shutdown_is_idempotent_and_stops_the_thread(tmp_path: Path):
    worker = AlertDeliveryWorker(tmp_path / "db.sqlite")
    worker.shutdown()
    worker.shutdown()  # must not raise or hang
    assert not worker._thread.is_alive()


def test_worker_uses_its_own_devicestore_connection_not_the_callers(tmp_path: Path):
    """The worker must open its own DeviceStore (for Twilio's SMS budget)
    on its own thread - never share a connection object from another
    thread."""

    db_path = tmp_path / "db.sqlite"
    seen_stores = []

    def capturing_dispatch(findings, cfg, *, store=None, site_name=None, site_location=None):
        seen_stores.append(store)
        return findings

    worker = AlertDeliveryWorker(db_path)
    try:
        with patch("lanfence.alert_worker.alerts.dispatch", side_effect=capturing_dispatch):
            worker.submit([_finding()], AlertConfig())
            deadline = time.monotonic() + 5.0
            while not seen_stores and time.monotonic() < deadline:
                time.sleep(0.02)
        assert len(seen_stores) == 1
        assert seen_stores[0] is not None
        assert seen_stores[0].path == Path(db_path)
    finally:
        worker.shutdown()


def test_submit_is_robust_to_threading_thread_being_monkeypatched_elsewhere(tmp_path: Path, monkeypatch):
    """A test (or anything else) that monkeypatches threading.Thread
    globally for an unrelated purpose (e.g. faking a different background
    thread to run synchronously) must never turn this worker's background
    thread into an inline call - that would deadlock its blocking
    queue.get() loop. See lanfence/alert_worker.py's import-time binding."""

    class _FakeSyncThread:
        def __init__(self, target=None, **_kwargs):
            self._target = target

        def start(self):
            pass  # deliberately does NOT run target - proves real Thread was used instead

        def is_alive(self):
            return False

        def join(self, timeout=None):
            pass

    monkeypatch.setattr("threading.Thread", _FakeSyncThread)
    worker = AlertDeliveryWorker(tmp_path / "db.sqlite")
    try:
        # If alert_worker had looked up threading.Thread fresh, construction
        # would have used _FakeSyncThread and _run() would never actually be
        # running in the background - this call would then hang forever
        # waiting on a queue nothing drains. Reaching this line at all
        # (finishing within the test timeout) proves a real thread is used.
        with patch("lanfence.alert_worker.alerts.dispatch", return_value=[]) as dispatch_mock:
            worker.submit([_finding()], AlertConfig())
            deadline = time.monotonic() + 5.0
            while not dispatch_mock.called and time.monotonic() < deadline:
                time.sleep(0.02)
            assert dispatch_mock.called
    finally:
        worker.shutdown()
