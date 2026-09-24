# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Bounded, background external-alert delivery for `lanfence monitor`.

`monitor`'s main loop is also the *only* thread allowed to touch its
long-lived :class:`~lanfence.db.DeviceStore` connection (SQLite connections
are not safe to share across threads) - it must never block waiting on a
slow or failing SMTP/webhook/SMS call while doing so, since every passive
sighting, active sweep result, and DHCP/mDNS/SSDP observation is also
processed on that same thread. :class:`AlertDeliveryWorker` moves the
network I/O of :func:`lanfence.alerts.dispatch` onto its own background
thread, fed by a small bounded queue:

- Every already-filtered (snoozed/rate-limited) ``Finding`` batch handed to
  :meth:`AlertDeliveryWorker.submit` is plain, already-computed data - no
  ``DeviceStore`` reference ever crosses threads.
- The worker opens its *own* ``DeviceStore`` connection (a fresh
  ``sqlite3`` connection to the same file) purely to enforce Twilio's
  durable SMS budget (see :func:`lanfence.alerts.send_twilio`) - never the
  main loop's connection.
- ``submit`` never blocks: a full queue means the batch is dropped (see
  ``dropped`` below) rather than stalling the caller. Dropping a delivery
  never touches the database - the finding was already recorded (events,
  ``alert_log`` bookkeeping) before delivery was even attempted, so a drop
  only means the *notification* didn't go out, never a change to recorded
  device/absence state.
"""

from __future__ import annotations

import queue
from pathlib import Path
from threading import Lock, Thread

from lanfence import alerts
from lanfence.config import AlertConfig
from lanfence.db import DeviceStore
from lanfence.logging_config import get_logger
from lanfence.models import Finding

log = get_logger("alert_worker")

#: Small and bounded - a delivery batch is already-filtered/rate-limited
#: findings, so a healthy system rarely has more than a couple in flight at
#: once; this only needs enough headroom to absorb a burst while a slow
#: channel (e.g. SMTP) is catching up, not to buffer an unbounded backlog.
_DEFAULT_MAXSIZE = 100


class AlertDeliveryWorker:
    """Runs :func:`lanfence.alerts.dispatch` on a single background daemon
    thread, fed by a bounded queue. One instance per `monitor` process."""

    def __init__(
        self, db_path: Path | str, *, maxsize: int = _DEFAULT_MAXSIZE,
        site_name: str | None = None, site_location: str | None = None,
    ) -> None:
        self._db_path = db_path
        # Static for the life of this worker (one instance per `monitor`
        # process) - see lanfence.config.SiteConfig - so it's captured here
        # once rather than threaded through every submit()/queue item.
        self._site_name = site_name
        self._site_location = site_location
        self._queue: "queue.Queue[tuple[list[Finding], AlertConfig] | None]" = queue.Queue(maxsize=maxsize)
        self._dropped = 0
        self._lock = Lock()
        # Bound to the real threading.Thread at import time (see the
        # module-level `from threading import ... Thread` above) rather
        # than looked up as `threading.Thread` here - deliberately immune
        # to a test (or anything else) monkeypatching threading.Thread
        # globally for an unrelated purpose (e.g. faking the passive-sniff
        # thread to run synchronously): this worker's blocking delivery
        # loop must always run on a real background thread, never inline.
        self._thread = Thread(target=self._run, daemon=True, name="lanfence-alert-delivery")
        self._thread.start()

    def submit(self, findings: list[Finding], cfg: AlertConfig) -> bool:
        """Queue ``findings`` for background delivery under ``cfg``. Never
        blocks: returns ``False`` (and increments :attr:`dropped`) instead
        of waiting when the queue is full - a slow/stuck delivery thread
        must never stall the caller (the `monitor` main loop)."""

        try:
            self._queue.put_nowait((findings, cfg))
            return True
        except queue.Full:
            with self._lock:
                self._dropped += 1
            log.warning(
                "alert delivery queue is full - dropped 1 batch of %d finding(s); "
                "the underlying findings/events were still recorded", len(findings),
            )
            return False

    @property
    def dropped(self) -> int:
        """How many delivery batches have been dropped due to a full queue
        since this worker started - observable for tests/diagnostics, not
        just logged."""

        with self._lock:
            return self._dropped

    def _run(self) -> None:
        # This connection is owned exclusively by this thread - never
        # shared with the main loop's DeviceStore. Opened once, reused for
        # every delivery (mirrors the main loop's own long-lived
        # connection), rather than one short-lived connection per item.
        store = DeviceStore(self._db_path)
        try:
            while True:
                item = self._queue.get()
                try:
                    if item is None:
                        return
                    findings, cfg = item
                    try:
                        alerts.dispatch(
                            findings, cfg, store=store,
                            site_name=self._site_name, site_location=self._site_location,
                        )
                    except Exception:  # noqa: BLE001 - a delivery failure must never kill this thread
                        log.exception("unexpected error in background alert delivery")
                finally:
                    self._queue.task_done()
        finally:
            store.close()

    def shutdown(self, *, timeout: float = 5.0) -> None:
        """Signal the worker to stop after draining what's already queued,
        and wait up to ``timeout`` seconds for it to finish. Safe to call
        more than once; never raises."""

        try:
            self._queue.put_nowait(None)
        except queue.Full:
            # No room even for the sentinel - drain one slot so shutdown
            # can never hang forever waiting to enqueue it.
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
        self._thread.join(timeout=timeout)
