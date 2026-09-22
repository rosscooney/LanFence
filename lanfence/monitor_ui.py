# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Live terminal presentation for ``lanfence monitor`` - a bordered
dashboard (header / scrolling activity / statistics footer) built on the
Rich library already used elsewhere in this project (no new dependency).

Deliberately split from :mod:`lanfence.cli`'s scanning/database logic so
every piece here can be exercised without a terminal, a real network, or a
running monitor loop:

- :class:`MonitorStats` accumulates session counters from the *results* of
  scanning calls ``cli.py`` already makes (``process_sighting``'s returned
  event type, :class:`~lanfence.models.ScanResult`, inventory counts) - it
  never re-derives them from wall-clock guesses or database rows loaded
  just for the display.
- :class:`ActivityLog` is a small bounded ring buffer of human-readable
  lines, with repeated identical warnings/errors coalesced by count rather
  than spammed.
- The ``render_*``/``build_dashboard`` functions are pure: given a
  :class:`MonitorSnapshot` (an immutable copy of the current counters) and
  a tuple of :class:`ActivityEntry`, they return a Rich renderable with no
  side effects - safe to call from any thread, which is exactly what
  :class:`MonitorDisplay` relies on (see its docstring for why the
  snapshot/entries handed to Rich's background auto-refresh thread are
  always a fully-formed, already-copied object, never the mutable
  :class:`MonitorStats`/:class:`ActivityLog` themselves).
"""

from __future__ import annotations

import logging
import os
import select
import sys
import time
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Callable, Deque, Literal, Optional, TypeVar

from rich.console import Console, ConsoleDimensions, Group
from rich.panel import Panel
from rich.text import Text

from lanfence.sanitize import clean_text

ActivityLevel = Literal["info", "finding", "warning", "error"]

#: How many activity lines are retained in memory - well beyond what any
#: terminal can display at once, so scrolling back within one session
#: (a future feature) would have material to work with; bounded so a noisy
#: network can't grow this without limit.
ACTIVITY_LOG_MAXLEN = 500

_LEVEL_COLOR = {"info": "cyan", "finding": "white", "warning": "yellow", "error": "red"}
_LEVEL_MARKER = {"info": " ", "warning": "!", "error": "!!"}


def local_now() -> datetime:
    """The current time in the system's local timezone - every timestamp
    shown in the live display uses this (not UTC, unlike the rest of LAN
    Fence's stored/reported data) since it's meant to be read at a glance
    on the machine running `monitor`."""

    return datetime.now().astimezone()


@dataclass(frozen=True)
class ActivityEntry:
    """One line of the activity area. ``count``/``last_timestamp`` let a
    repeated identical warning/error be shown once with a count instead of
    flooding the log - see :meth:`ActivityLog.add`."""

    timestamp: datetime
    level: ActivityLevel
    label: str
    detail: str = ""
    count: int = 1
    last_timestamp: datetime | None = None

    def display_timestamp(self) -> datetime:
        return self.last_timestamp or self.timestamp


class ActivityLog:
    """A bounded ring buffer of :class:`ActivityEntry`. Only ``warning``/
    ``error`` entries are ever coalesced (a repeated identical operational
    error becomes one line with a growing count) - lifecycle/finding
    entries are always kept distinct, since each describes a different
    device/event even when their label text happens to match."""

    def __init__(self, maxlen: int = ACTIVITY_LOG_MAXLEN) -> None:
        self._entries: Deque[ActivityEntry] = deque(maxlen=maxlen)

    def add(self, entry: ActivityEntry) -> None:
        if entry.level in ("warning", "error") and self._entries:
            last = self._entries[-1]
            if last.level == entry.level and last.label == entry.label and last.detail == entry.detail:
                self._entries[-1] = ActivityEntry(
                    timestamp=last.timestamp, level=last.level, label=last.label, detail=last.detail,
                    count=last.count + 1, last_timestamp=entry.timestamp,
                )
                return
        self._entries.append(entry)

    def snapshot(self) -> tuple[ActivityEntry, ...]:
        return tuple(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


@dataclass(frozen=True)
class HeaderInfo:
    """Static-for-the-session facts shown in the header panel - computed
    once at `monitor` startup from actual resolved configuration, never
    fabricated. Kept deliberately free of anything sensitive (no
    credentials, notification URLs, or file paths)."""

    version: str
    interface: str
    network: str
    scan_interval_seconds: float
    passive: bool
    ipv6: bool
    dhcp: bool
    mdns: bool
    ssdp: bool
    dhcp_server_detection: bool
    quit_key_enabled: bool = False


@dataclass(frozen=True)
class MonitorSnapshot:
    """An immutable copy of :class:`MonitorStats` at one instant - see
    :meth:`MonitorStats.snapshot`. This, not ``MonitorStats`` itself, is
    what ever reaches a render function, so a render call (possibly made
    from Rich's own auto-refresh thread - see :class:`MonitorDisplay`)
    never touches the mutable counters another thread might be updating."""

    elapsed_seconds: float
    known: Optional[int]
    review: Optional[int]
    seen: int
    new: int
    findings: int
    sweeps_ok: int
    sweeps_failed: int
    scanning: bool
    next_sweep_seconds: Optional[float]
    passive_enabled: bool
    passive_ok: bool
    last_sweep_local: Optional[datetime]
    #: When the in-progress sweep started (monotonic clock) and how long
    #: it's expected to take - see :func:`scan_progress_fraction`. Both
    #: ``None``/``0.0`` when not currently scanning or the duration isn't
    #: known.
    sweep_start_monotonic: Optional[float] = None
    expected_sweep_seconds: float = 0.0

    @classmethod
    def empty(cls, *, passive_enabled: bool) -> "MonitorSnapshot":
        return cls(
            elapsed_seconds=0.0, known=None, review=None, seen=0, new=0, findings=0,
            sweeps_ok=0, sweeps_failed=0, scanning=False, next_sweep_seconds=None,
            passive_enabled=passive_enabled, passive_ok=True, last_sweep_local=None,
        )


class MonitorStats:
    """Mutable, main-thread-only session counters for `lanfence monitor`.

    Every counter here is filled in from the *actual result* of a real
    scanning call ``cli.py`` already makes - never inferred from wall-clock
    comparisons, and never by re-querying "everything" from the database on
    a timer. See each ``record_*`` method for exactly what feeds it.
    """

    def __init__(
        self, *, scan_interval_seconds: float, passive_enabled: bool, now_monotonic: float,
        expected_sweep_seconds: float = 0.0,
    ) -> None:
        self.scan_interval_seconds = scan_interval_seconds
        self.passive_enabled = passive_enabled
        self.passive_ok = True
        self.session_start_monotonic = now_monotonic
        #: Best-effort expected duration of one active sweep (e.g.
        #: `scan.active_scan_timeout_seconds`, doubled if IPv6 is also
        #: swept) - used only to estimate :func:`scan_progress_fraction`
        #: for the live dashboard's progress bar, never to cut a sweep
        #: short or claim it's actually done.
        self.expected_sweep_seconds = max(0.0, expected_sweep_seconds)
        self.sweep_start_monotonic: float | None = None
        self.seen: set[str] = set()
        self.new_macs: set[str] = set()
        self.findings_count = 0
        self.sweeps_ok = 0
        self.sweeps_failed = 0
        self.scanning = False
        self.last_sweep_monotonic: float | None = None
        self.last_sweep_local: datetime | None = None
        self.next_sweep_monotonic: float | None = None
        self.known: int | None = None
        self.review: int | None = None
        #: Cumulative count of observations dropped because a bounded
        #: processing queue was full (see `lanfence.cli`'s
        #: `_DropCountingQueue`) - observable for tests/diagnostics, and
        #: surfaced to the operator as a coalesced activity-log warning
        #: rather than a permanent dashboard column.
        self.dropped_observations = 0

    def record_event(self, mac: str, event_type: str | None) -> None:
        """One MAC positively observed (any source, any address family) -
        called once per real ``process_sighting``/active-sweep result, so
        "Seen" naturally dedupes across active/passive and multiple
        addresses (a `set`), and never counts a sighting that was never
        actually made (an offered DHCP address, an mDNS service target)."""

        self.seen.add(mac)
        if event_type == "new_device":
            self.new_macs.add(mac)

    def record_finding(self) -> None:
        self.findings_count += 1

    def mark_passive_failed(self) -> None:
        self.passive_ok = False

    def record_sweep_start(self, now_monotonic: float) -> None:
        self.scanning = True
        self.sweep_start_monotonic = now_monotonic

    def record_sweep_end(self, *, ok: bool, now_monotonic: float) -> None:
        self.scanning = False
        self.sweep_start_monotonic = None
        self.last_sweep_monotonic = now_monotonic
        self.last_sweep_local = local_now()
        self.next_sweep_monotonic = now_monotonic + self.scan_interval_seconds
        if ok:
            self.sweeps_ok += 1
        else:
            self.sweeps_failed += 1

    def set_inventory_counts(self, *, known: int, review: int) -> None:
        self.known = known
        self.review = review

    def snapshot(self, now_monotonic: float) -> MonitorSnapshot:
        next_in = None
        if not self.scanning and self.next_sweep_monotonic is not None:
            next_in = max(0.0, self.next_sweep_monotonic - now_monotonic)
        return MonitorSnapshot(
            elapsed_seconds=max(0.0, now_monotonic - self.session_start_monotonic),
            known=self.known, review=self.review,
            seen=len(self.seen), new=len(self.new_macs), findings=self.findings_count,
            sweeps_ok=self.sweeps_ok, sweeps_failed=self.sweeps_failed,
            scanning=self.scanning, next_sweep_seconds=next_in,
            passive_enabled=self.passive_enabled, passive_ok=self.passive_ok,
            last_sweep_local=self.last_sweep_local,
            sweep_start_monotonic=self.sweep_start_monotonic,
            expected_sweep_seconds=self.expected_sweep_seconds,
        )


# --- rendering (pure functions - no I/O, no thread affinity) ---------------


def scan_progress_fraction(snap: MonitorSnapshot, *, now_monotonic: float) -> Optional[float]:
    """Best-effort fraction (0.0-1.0) of the in-progress active sweep's
    expected duration elapsed so far, or ``None`` when not currently
    scanning or the expected duration isn't known. This is an *estimate*
    for the live dashboard's progress bar only - a real sweep can finish
    faster or slower than `scan.active_scan_timeout_seconds` implies (a
    quiet subnet returns early; a busy one may not) - clamped to 1.0 so it
    never claims to be over 100% while still actually running."""

    if not snap.scanning or snap.sweep_start_monotonic is None or snap.expected_sweep_seconds <= 0:
        return None
    elapsed = max(0.0, now_monotonic - snap.sweep_start_monotonic)
    return min(1.0, elapsed / snap.expected_sweep_seconds)


def progress_bar(fraction: float, *, width: int) -> str:
    """A block-character bar (``"████░░░░"``) for ``fraction`` (0.0-1.0) of
    ``width`` characters - shared by the live dashboard's in-progress-sweep
    footer and `lanfence scan`'s own progress display (see
    :func:`run_with_scan_progress`)."""

    width = max(4, width)
    filled = round(fraction * width)
    return "█" * filled + "░" * (width - filled)


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _safe(text: str | None, *, max_len: int = 120) -> str:
    """Bound and sanitize any network-derived or user-supplied string
    before it reaches a Rich renderable. Rich's own ``Text`` (used
    throughout this module instead of markup strings) already treats its
    input as literal text, never markup, so this is defense in depth
    against control characters and unbounded length, not against Rich
    markup injection specifically."""

    return clean_text(text or "", max_len=max_len)


def _one_line(text: str, *, width: int, style: str = "") -> Text:
    """A ``Text`` guaranteed to render as exactly one visual line, cropped
    with an ellipsis rather than word-wrapped - Rich's own line-wrapping
    would otherwise turn one logical header/footer/activity line into
    several visual ones at a narrow width, silently blowing the fixed
    line-budget :func:`build_dashboard` uses to keep the footer on
    screen (see its docstring)."""

    t = Text(text, style=style, no_wrap=True, overflow="ellipsis")
    t.truncate(max(1, width), overflow="ellipsis")
    return t


def render_header(header: HeaderInfo, snap: MonitorSnapshot, *, width: int, now_monotonic: float) -> Group:
    compact = width < 70
    parts = [
        f"Interface: {_safe(header.interface, max_len=32)}",
        f"Network: {_safe(header.network, max_len=32)}",
        f"Running: {format_duration(snap.elapsed_seconds)}",
    ]
    line1 = _one_line("  ·  ".join(parts), width=width, style="bold")

    if compact:
        return Group(line1)

    mechanisms = []
    if header.passive:
        extras = [n for n, on in (("ipv6", header.ipv6), ("dhcp", header.dhcp),
                                   ("mdns", header.mdns), ("ssdp", header.ssdp)) if on]
        mechanisms.append("passive" + (f" ({', '.join(extras)})" if extras else ""))
    else:
        mechanisms.append("active-only")
    if header.dhcp_server_detection:
        mechanisms.append("dhcp-server-detection")

    if snap.scanning:
        fraction = scan_progress_fraction(snap, now_monotonic=now_monotonic)
        sweep_state = f"scanning now ({round(fraction * 100)}%)" if fraction is not None else "scanning now"
    elif snap.last_sweep_local is not None:
        sweep_state = f"last sweep {snap.last_sweep_local.strftime('%H:%M:%S')}"
    else:
        sweep_state = "no sweep yet"

    line2 = _one_line(
        f"lanfence {header.version}  ·  {' + '.join(mechanisms)}  ·  {sweep_state}",
        width=width, style="dim",
    )
    return Group(line1, line2)


_LEVEL_LABEL_STYLE = {"info": "cyan", "finding": "bold", "warning": "yellow", "error": "bold red"}


def _activity_line(entry: ActivityEntry, *, width: int) -> Text:
    ts = entry.display_timestamp().strftime("%H:%M:%S")
    label = entry.label
    if entry.count > 1:
        label = f"{label} (x{entry.count})"
    style = _LEVEL_LABEL_STYLE.get(entry.level, "white")
    prefix = f"{ts}  {label:<10} "
    detail = _safe(entry.detail, max_len=max(10, width - len(prefix)))
    line = Text(f"{ts}  ", style="dim", no_wrap=True)
    line.append(f"{label:<10} ", style=style)
    line.append(detail)
    line.truncate(max(1, width), overflow="ellipsis")
    return line


def render_activity(entries: tuple[ActivityEntry, ...], *, height: int, width: int) -> Group:
    height = max(1, height)
    shown = entries[-height:]
    lines = [_activity_line(e, width=width) for e in shown]
    while len(lines) < height:
        lines.append(Text(""))
    return Group(*lines)


def render_footer(snap: MonitorSnapshot, *, width: int, now_monotonic: float) -> Text:
    def fmt(label: str, value) -> str:
        if value is None:
            return f"{label}: n/a"
        return f"{label}: {value}"

    if snap.scanning:
        fraction = scan_progress_fraction(snap, now_monotonic=now_monotonic)
        if fraction is not None:
            scan_field = f"Scan: [{progress_bar(fraction, width=12)}] {round(fraction * 100)}%"
        else:
            scan_field = "Scan: scanning"
    elif snap.next_sweep_seconds is not None:
        scan_field = f"Scan: {format_duration(snap.next_sweep_seconds)}"
    else:
        scan_field = "Scan: n/a"

    core = [
        fmt("Known", snap.known), fmt("Seen", snap.seen),
        f"New: {snap.new}", fmt("Review", snap.review), scan_field,
    ]

    if width < 60:
        core = core[:4]
    elif width >= 100:
        core.append(f"Findings: {snap.findings}")
        core.append(f"Sweeps ok/failed: {snap.sweeps_ok}/{snap.sweeps_failed}")
        if snap.passive_enabled:
            core.append(f"Passive: {'ok' if snap.passive_ok else 'FAILED'}")

    return _one_line(" · ".join(core), width=width, style="bold")


#: Below this width or height, there is no room for a header + activity +
#: footer layout that wouldn't itself push content off screen - fall back
#: to a single compact line rather than a garbled multi-panel attempt.
MIN_USABLE_WIDTH = 24
MIN_USABLE_HEIGHT = 8


def render_minimal(snap: MonitorSnapshot, *, width: int) -> Text:
    """A one-line fallback for a terminal too small for the full layout -
    still prioritizes Known/Seen/New, per the same "small terminals"
    priority as :func:`render_footer`."""

    core = [f"K:{snap.known if snap.known is not None else '?'}",
            f"S:{snap.seen}", f"N:{snap.new}"]
    return _one_line("LAN Fence  " + " ".join(core), width=width, style="bold")


def build_dashboard(
    header: HeaderInfo, snap: MonitorSnapshot, entries: tuple[ActivityEntry, ...],
    *, size: ConsoleDimensions, now_monotonic: float,
) -> Panel | Text:
    """Assemble the full bordered dashboard - a single Rich renderable
    computed fresh from ``snap``/``entries`` (both already-immutable
    snapshots) every time it's called, so it always reflects the terminal's
    *current* size (handles resize) with no cached layout state. ``now_monotonic``
    is likewise taken fresh at each call (see :class:`MonitorDisplay`), not
    read from ``snap``, so the in-progress-sweep percentage keeps advancing
    on Rich's own auto-refresh timer even while the main thread is blocked
    inside the sweep itself and can't update ``snap`` again until it
    returns. Falls back to :func:`render_minimal` below
    :data:`MIN_USABLE_WIDTH`/:data:`MIN_USABLE_HEIGHT` rather than
    attempting a layout with no room for one, which would otherwise push
    the footer off screen."""

    width = max(1, size.width)
    height = max(1, size.height)
    if width < MIN_USABLE_WIDTH or height < MIN_USABLE_HEIGHT:
        hint = "q: quit" if header.quit_key_enabled else "Ctrl+C: quit"
        return _one_line(hint + " · " + render_minimal(snap, width=width).plain, width=width)

    # Panel border (2) + header (up to 2 lines + 1 blank) + divider (1) +
    # footer (1) - whatever's left goes to the activity area. Every header/
    # footer/activity line is independently truncated to one visual row
    # (see `_one_line`/`_activity_line`), so this budget is exact, not an
    # estimate that word-wrapping could silently blow.
    header_group = render_header(header, snap, width=width - 4, now_monotonic=now_monotonic)
    header_lines = len(header_group.renderables)
    chrome = 2 + header_lines + 1 + 1 + 1
    activity_height = max(1, height - chrome)

    body = Group(
        header_group,
        Text(""),
        render_activity(entries, height=activity_height, width=width - 4),
        Text("─" * max(1, width - 4), style="dim"),
        render_footer(snap, width=width - 4, now_monotonic=now_monotonic),
    )
    hint = "Press q to quit · Ctrl+C also works" if header.quit_key_enabled else "Ctrl+C to quit"
    return Panel(body, title="LAN Fence · Monitoring", subtitle=hint, border_style="green", expand=True)


def should_use_live(explicit: Optional[bool], console: Console) -> tuple[bool, Optional[str]]:
    """Whether to use the live dashboard, and (if falling back from an
    explicit request) one clear reason why.

    Live mode needs a real interactive terminal - redirected output,
    pipes, ``TERM=dumb``, and similar are never suitable, matching the
    same check Rich itself uses to decide whether to emit control
    sequences at all (``console.is_terminal``/``is_dumb_terminal``).
    """

    supported = console.is_terminal and not console.is_dumb_terminal
    if explicit is True:
        if not supported:
            return False, "stdout is not an interactive terminal (or TERM is unsupported) - using plain output"
        return True, None
    if explicit is False:
        return False, None
    return supported, None


def make_console() -> Console:
    """A Console honoring ``NO_COLOR`` explicitly (rather than assuming
    Rich's own default detection matches every version in use)."""

    return Console(no_color=bool(os.environ.get("NO_COLOR")))


class _ActivityLogHandler(logging.Handler):
    """Routes WARNING+ log records (e.g. an alert-delivery failure logged
    by :mod:`lanfence.alerts`/``digest``) into the live activity log
    instead of the real terminal - installed only while live mode's
    alternate screen is active (see :class:`MonitorDisplay`), since a
    stray write straight to the real stderr while the alt-screen is up
    would corrupt the display. Never raises - a logging handler failing
    must not crash monitoring."""

    def __init__(self, log: ActivityLog) -> None:
        super().__init__(level=logging.WARNING)
        self._log = log

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: ActivityLevel = "error" if record.levelno >= logging.ERROR else "warning"
            label = record.name.rsplit(".", 1)[-1].upper()
            self._log.add(ActivityEntry(timestamp=local_now(), level=level, label=label, detail=record.getMessage()))
        except Exception:  # noqa: BLE001 - a logging handler must never raise
            pass


class QuitKey:
    """Nonblocking single-key input on a POSIX TTY; never consume piped input.

    Cbreak leaves signal handling enabled, so Ctrl+C still works. Restore
    the original terminal attributes on every exit, including exceptions.
    """

    def __init__(self, stream=None):
        self.stream = stream if stream is not None else sys.stdin
        self.fd = None
        self.saved = None

    def __enter__(self):
        import termios
        import tty
        try:
            if not self.stream.isatty():
                return self
            fd = self.stream.fileno()
            saved = termios.tcgetattr(fd)
            # Do not flush input that arrived immediately before startup.
            tty.setcbreak(fd, termios.TCSANOW)
            self.fd, self.saved = fd, saved
        except (OSError, ValueError, termios.error):
            self.fd = None
        return self

    def check(self):
        if self.fd is not None and select.select([self.fd], [], [], 0)[0]:
            data = os.read(self.fd, 1024)
            if b"q" in data.lower():
                raise KeyboardInterrupt

    def __exit__(self, *args):
        if self.fd is not None:
            import termios
            try:
                termios.tcsetattr(self.fd, termios.TCSANOW, self.saved)
            finally:
                self.fd = None


class MonitorDisplay:
    """Owns the Rich ``Live`` alternate-screen session for `lanfence
    monitor`.

    ``update()`` (called from the main thread once per loop tick, roughly
    once a second - see ``cli.py``) takes a snapshot of the current
    ``MonitorStats``/``ActivityLog`` and atomically swaps it in; Rich's own
    auto-refresh thread repaints using whatever snapshot is currently
    assigned, via a plain attribute read (safe without a lock - a single
    reference assignment is atomic under the GIL) rather than ever reading
    the mutable stats/log objects themselves. This is what keeps the
    display alive and correctly sized (Rich re-queries the console's
    current width/height on every repaint) even while the main thread is
    blocked inside a real active sweep.

    While active, also redirects WARNING+ log output into the activity log
    (see :class:`_ActivityLogHandler`) so a delivery-failure log message
    can't corrupt the alternate screen; the original logging handlers are
    restored on exit.
    """

    def __init__(
        self, header: HeaderInfo, activity_log: ActivityLog, *,
        passive_enabled: bool, console: Console | None = None,
    ) -> None:
        from rich.live import Live

        self._quit_key = QuitKey()
        self._header = header
        self._activity_log = activity_log
        self._console = console or make_console()
        self._snapshot = MonitorSnapshot.empty(passive_enabled=passive_enabled)
        self._entries: tuple[ActivityEntry, ...] = ()
        self._live = Live(
            console=self._console, screen=True, auto_refresh=True, refresh_per_second=1,
            get_renderable=self._render, transient=True,
        )
        self._saved_handlers: list[logging.Handler] | None = None

    def _render(self) -> Panel:
        return build_dashboard(
            self._header, self._snapshot, self._entries,
            size=self._console.size, now_monotonic=time.monotonic(),
        )

    def update(self, stats: MonitorStats, log: ActivityLog, *, now_monotonic: float) -> None:
        self._snapshot = stats.snapshot(now_monotonic)
        self._entries = log.snapshot()

    def check_quit(self) -> None:
        self._quit_key.check()

    def __enter__(self) -> "MonitorDisplay":
        self._quit_key.__enter__()
        self._header = replace(self._header, quit_key_enabled=self._quit_key.fd is not None)
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        root.handlers = [_ActivityLogHandler(self._activity_log)]
        try:
            self._live.__enter__()
        except BaseException:
            self._quit_key.__exit__()
            root.handlers = self._saved_handlers
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> bool | None:
        try:
            return self._live.__exit__(exc_type, exc, tb)
        finally:
            self._quit_key.__exit__()
            if self._saved_handlers is not None:
                logging.getLogger().handlers = self._saved_handlers
                self._saved_handlers = None


_T = TypeVar("_T")


def run_with_scan_progress(
    fn: Callable[[], _T], *, expected_seconds: float, console: Console, label: str = "scanning",
) -> _T:
    """Run zero-argument ``fn`` (a blocking active sweep) while showing a
    ticking, elapsed-time-estimated progress bar - the same trick
    :class:`MonitorDisplay` uses for the live dashboard's in-progress-sweep
    bar: Rich's own ``Live(auto_refresh=True)`` repaints on its own
    background thread by calling ``get_renderable`` fresh each tick, so the
    bar keeps advancing even while ``fn`` blocks the calling thread for the
    whole sweep. ``fn`` itself runs entirely on the calling thread with no
    concurrency of its own - unlike actually threading the sweep, this is
    safe for an ``fn`` that touches a database connection (see
    `lanfence.cli.scan`, which passes one that does).

    Used only when the caller has already confirmed stdout is a real
    interactive terminal (see :func:`should_use_live`) - a percentage
    estimate, not a report of how many hosts have actually responded (a
    real sweep can finish faster or slower than ``expected_seconds``
    implies), clamped so it never claims to be over 100% while still
    running.
    """

    from rich.live import Live
    from rich.text import Text

    start = time.monotonic()

    def _render() -> Text:
        elapsed = max(0.0, time.monotonic() - start)
        fraction = min(1.0, elapsed / expected_seconds) if expected_seconds > 0 else 0.0
        bar = progress_bar(fraction, width=30)
        return Text(f"{label}... [{bar}] {round(fraction * 100)}%", style="cyan")

    with Live(console=console, get_renderable=_render, auto_refresh=True, refresh_per_second=4, transient=True):
        return fn()
