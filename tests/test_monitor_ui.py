from __future__ import annotations

import logging

from rich.console import Console, ConsoleDimensions

from lanfence.monitor_ui import (
    MIN_USABLE_HEIGHT,
    MIN_USABLE_WIDTH,
    ActivityEntry,
    ActivityLog,
    HeaderInfo,
    MonitorDisplay,
    MonitorSnapshot,
    MonitorStats,
    build_dashboard,
    format_duration,
    local_now,
    render_activity,
    render_footer,
    render_header,
    render_minimal,
    should_use_live,
)


def _header(**overrides) -> HeaderInfo:
    base = dict(
        version="0.3.10", interface="eth0", network="192.168.1.0/24", scan_interval_seconds=60.0,
        passive=True, ipv6=True, dhcp=True, mdns=False, ssdp=False, dhcp_server_detection=False,
    )
    base.update(overrides)
    return HeaderInfo(**base)


def _console(width: int, height: int) -> Console:
    return Console(width=max(width, 1), height=max(height, 1), no_color=True)


def _rendered_lines(renderable, *, width: int, height: int) -> list[str]:
    console = _console(width, height)
    lines = console.render_lines(renderable, console.options.update(height=None))
    return ["".join(seg.text for seg in line) for line in lines]


# --- ActivityLog: coalescing, bounding -------------------------------------


def test_activity_log_add_and_snapshot_order():
    log = ActivityLog()
    log.add(ActivityEntry(timestamp=local_now(), level="info", label="A", detail="first"))
    log.add(ActivityEntry(timestamp=local_now(), level="info", label="B", detail="second"))
    snap = log.snapshot()
    assert [e.label for e in snap] == ["A", "B"]


def test_activity_log_coalesces_identical_repeated_errors():
    log = ActivityLog()
    for _ in range(5):
        log.add(ActivityEntry(timestamp=local_now(), level="error", label="SCAN", detail="permission denied"))
    snap = log.snapshot()
    assert len(snap) == 1
    assert snap[0].count == 5


def test_activity_log_does_not_coalesce_different_details():
    log = ActivityLog()
    log.add(ActivityEntry(timestamp=local_now(), level="error", label="SCAN", detail="permission denied"))
    log.add(ActivityEntry(timestamp=local_now(), level="error", label="SCAN", detail="timeout"))
    assert len(log.snapshot()) == 2


def test_activity_log_never_coalesces_info_or_finding_entries():
    """Two devices producing the identical label/detail text must still be
    two distinct lines - only warning/error operational noise coalesces."""

    log = ActivityLog()
    log.add(ActivityEntry(timestamp=local_now(), level="info", label="NEW", detail="Unknown device"))
    log.add(ActivityEntry(timestamp=local_now(), level="info", label="NEW", detail="Unknown device"))
    assert len(log.snapshot()) == 2


def test_activity_log_is_bounded():
    log = ActivityLog(maxlen=10)
    for i in range(50):
        log.add(ActivityEntry(timestamp=local_now(), level="info", label=f"L{i}", detail=""))
    assert len(log.snapshot()) == 10
    assert log.snapshot()[-1].label == "L49"


def test_activity_log_coalesced_entry_keeps_original_timestamp_and_updates_last():
    log = ActivityLog()
    t0 = local_now()
    log.add(ActivityEntry(timestamp=t0, level="warning", label="W", detail="x"))
    t1 = local_now()
    log.add(ActivityEntry(timestamp=t1, level="warning", label="W", detail="x"))
    entry = log.snapshot()[0]
    assert entry.timestamp == t0
    assert entry.display_timestamp() == t1


# --- MonitorStats: Known/Seen/New/Online/Review semantics ------------------


def test_record_event_deduplicates_across_multiple_sightings_same_mac():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_event("aa:bb:cc:dd:ee:ff", None)  # e.g. ARP sighting, routine refresh
    stats.record_event("aa:bb:cc:dd:ee:ff", None)  # e.g. IPv6 ND sighting, same sweep
    snap = stats.snapshot(now_monotonic=1.0)
    assert snap.seen == 1


def test_record_event_new_device_increments_new_and_seen():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_event("aa:bb:cc:dd:ee:ff", "new_device")
    snap = stats.snapshot(now_monotonic=1.0)
    assert snap.seen == 1
    assert snap.new == 1


def test_known_device_returning_does_not_increment_new():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_event("aa:bb:cc:dd:ee:ff", "reappeared")
    snap = stats.snapshot(now_monotonic=1.0)
    assert snap.seen == 1
    assert snap.new == 0


def test_seen_never_decreases_when_device_goes_offline():
    """The session Seen set is retained even after a device is later
    marked offline - Seen answers "was this device observed this
    session," not "is it currently online.\""""

    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_event("aa:bb:cc:dd:ee:ff", "new_device")
    # A subsequent sweep sees it go offline - `record_event` is never
    # called for a mac that a sweep did NOT see, so nothing here undoes
    # the earlier record; Seen must not shrink.
    snap = stats.snapshot(now_monotonic=100.0)
    assert snap.seen == 1


def test_seen_and_new_are_independent_counters_across_many_devices():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_event("aa:bb:cc:dd:ee:ff", "new_device")
    stats.record_event("11:22:33:44:55:66", "new_device")
    stats.record_event("77:88:99:aa:bb:cc", "reappeared")
    stats.record_event("77:88:99:aa:bb:cc", None)  # a later routine refresh, same mac
    snap = stats.snapshot(now_monotonic=1.0)
    assert snap.seen == 3
    assert snap.new == 2


def test_inventory_counts_are_only_set_explicitly_not_inferred():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    snap = stats.snapshot(now_monotonic=1.0)
    assert snap.known is None
    assert snap.online is None
    assert snap.review is None
    stats.set_inventory_counts(known=10, online=7, review=2)
    snap = stats.snapshot(now_monotonic=2.0)
    assert (snap.known, snap.online, snap.review) == (10, 7, 2)


def test_findings_counter_and_sweep_counters():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_finding()
    stats.record_finding()
    stats.record_sweep_end(ok=True, now_monotonic=5.0)
    stats.record_sweep_end(ok=False, now_monotonic=10.0)
    snap = stats.snapshot(now_monotonic=11.0)
    assert snap.findings == 2
    assert snap.sweeps_ok == 1
    assert snap.sweeps_failed == 1


def test_mark_passive_failed_reflected_in_snapshot():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    assert stats.snapshot(now_monotonic=1.0).passive_ok is True
    stats.mark_passive_failed()
    assert stats.snapshot(now_monotonic=1.0).passive_ok is False


# --- countdown / scanning states, injected clock ---------------------------


def test_countdown_reflects_time_remaining_until_next_sweep():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_sweep_end(ok=True, now_monotonic=100.0)  # next sweep due at 160.0
    snap = stats.snapshot(now_monotonic=130.0)
    assert snap.next_sweep_seconds == 30.0
    assert snap.scanning is False


def test_countdown_never_negative_past_due():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_sweep_end(ok=True, now_monotonic=100.0)
    snap = stats.snapshot(now_monotonic=999.0)  # way past due (e.g. a slow tick)
    assert snap.next_sweep_seconds == 0.0


def test_scanning_state_true_during_a_sweep_regardless_of_countdown_math():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_sweep_start(now_monotonic=10.0)
    snap = stats.snapshot(now_monotonic=999.0)  # a long blocking sweep in progress
    assert snap.scanning is True
    assert snap.next_sweep_seconds is None  # never a misleading negative countdown


def test_no_sweep_yet_has_no_countdown():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    snap = stats.snapshot(now_monotonic=5.0)
    assert snap.next_sweep_seconds is None
    assert snap.scanning is False


def test_elapsed_seconds_uses_monotonic_clock():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=1000.0)
    snap = stats.snapshot(now_monotonic=1042.5)
    assert snap.elapsed_seconds == 42.5


def test_format_duration():
    assert format_duration(0) == "00:00:00"
    assert format_duration(65) == "00:01:05"
    assert format_duration(3661) == "01:01:01"
    assert format_duration(-5) == "00:00:00"  # never negative


# --- rendering: footer stays visible at every size --------------------------


def _snap(stats: MonitorStats | None = None, **overrides) -> MonitorSnapshot:
    if stats is None:
        stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
        stats.set_inventory_counts(known=10, online=5, review=1)
    snap = stats.snapshot(now_monotonic=10.0)
    if overrides:
        snap = MonitorSnapshot(**{**snap.__dict__, **overrides})
    return snap


def test_footer_visible_at_wide_size():
    header = _header()
    snap = _snap()
    log = ActivityLog()
    panel = build_dashboard(header, snap, log.snapshot(), size=ConsoleDimensions(100, 24))
    lines = _rendered_lines(panel, width=100, height=24)
    assert len(lines) == 24
    assert "Known: 10" in lines[-2]  # last line is the panel's bottom border


def test_footer_visible_at_narrow_size():
    header = _header()
    snap = _snap()
    log = ActivityLog()
    panel = build_dashboard(header, snap, log.snapshot(), size=ConsoleDimensions(30, 12))
    lines = _rendered_lines(panel, width=30, height=12)
    assert len(lines) == 12
    assert any("Known" in line for line in lines)


def test_footer_visible_even_with_long_activity_detail():
    header = _header()
    snap = _snap()
    log = ActivityLog()
    log.add(ActivityEntry(
        timestamp=local_now(), level="finding", label="NEW",
        detail="x" * 500,  # a pathologically long line
    ))
    panel = build_dashboard(header, snap, log.snapshot(), size=ConsoleDimensions(60, 15))
    lines = _rendered_lines(panel, width=60, height=15)
    assert len(lines) == 15
    assert any("Known" in line for line in lines)


def test_render_falls_back_to_minimal_below_min_usable_size():
    header = _header()
    snap = _snap()
    log = ActivityLog()
    panel = build_dashboard(header, snap, log.snapshot(), size=ConsoleDimensions(10, 3))
    lines = _rendered_lines(panel, width=10, height=3)
    assert len(lines) <= 3


def test_render_does_not_crash_on_zero_dimensions():
    header = _header()
    snap = _snap()
    log = ActivityLog()
    panel = build_dashboard(header, snap, log.snapshot(), size=ConsoleDimensions(0, 0))
    console = _console(1, 1)
    console.render_lines(panel, console.options.update(height=None))  # must not raise


def test_minimal_render_prioritizes_known_seen_online_new():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_event("aa:bb:cc:dd:ee:ff", "new_device")
    stats.set_inventory_counts(known=5, online=3, review=9)
    snap = stats.snapshot(now_monotonic=1.0)
    text = render_minimal(snap, width=40).plain
    assert "K:5" in text
    assert "S:1" in text
    assert "O:3" in text
    assert "N:1" in text
    assert "9" not in text  # review is lower priority, omitted at minimal size


def test_min_usable_thresholds_are_positive():
    assert MIN_USABLE_WIDTH > 0
    assert MIN_USABLE_HEIGHT > 0


# --- untrusted content: markup injection, control characters ---------------


def test_activity_detail_sanitizes_control_characters():
    log = ActivityLog()
    log.add(ActivityEntry(timestamp=local_now(), level="info", label="NEW", detail="evil\x1b[31mred\x1b[0m"))
    lines = _rendered_lines(render_activity(log.snapshot(), height=3, width=60), width=60, height=3)
    assert "\x1b" not in "\n".join(lines)


def test_activity_detail_does_not_interpret_rich_markup():
    """A device-supplied hostname containing literal ``[bold]``-looking
    text must render as plain text, never as markup - Text() objects treat
    their input as literal, unlike a markup string passed to console.print."""

    log = ActivityLog()
    log.add(ActivityEntry(timestamp=local_now(), level="info", label="NEW", detail="[bold red]INJECTED[/bold red]"))
    lines = _rendered_lines(render_activity(log.snapshot(), height=3, width=60), width=60, height=3)
    joined = "\n".join(lines)
    assert "[bold red]INJECTED" in joined  # shown literally
    assert "INJECTED" in joined


def test_header_sanitizes_and_bounds_interface_and_network_strings():
    header = _header(interface="eth0\x00; rm -rf /", network="A" * 500)
    snap = _snap()
    text = render_header(header, snap, width=200)
    joined = "\n".join(t.plain for t in text.renderables)
    assert "\x00" not in joined
    assert len(joined) < 600  # bounded, not a raw 500+-char dump


def test_activity_line_truncates_predictably_never_wraps():
    entry = ActivityEntry(timestamp=local_now(), level="info", label="NEW", detail="y" * 300)
    log = ActivityLog()
    log.add(entry)
    group = render_activity(log.snapshot(), height=1, width=40)
    lines = _rendered_lines(group, width=40, height=1)
    assert len(lines) == 1
    assert len(lines[0]) <= 40


# --- should_use_live ---------------------------------------------------


class _FakeConsole:
    def __init__(self, *, is_terminal: bool, is_dumb: bool = False):
        self.is_terminal = is_terminal
        self.is_dumb_terminal = is_dumb


def test_should_use_live_defaults_to_terminal_detection():
    use, reason = should_use_live(None, _FakeConsole(is_terminal=True))
    assert use is True
    assert reason is None
    use, reason = should_use_live(None, _FakeConsole(is_terminal=False))
    assert use is False


def test_should_use_live_no_live_explicit_always_false():
    use, reason = should_use_live(False, _FakeConsole(is_terminal=True))
    assert use is False
    assert reason is None


def test_should_use_live_explicit_live_on_non_tty_falls_back_with_reason():
    use, reason = should_use_live(True, _FakeConsole(is_terminal=False))
    assert use is False
    assert reason is not None
    assert "terminal" in reason.lower()


def test_should_use_live_dumb_terminal_is_unsupported():
    use, _reason = should_use_live(None, _FakeConsole(is_terminal=True, is_dumb=True))
    assert use is False


def test_should_use_live_explicit_live_succeeds_on_real_terminal():
    use, reason = should_use_live(True, _FakeConsole(is_terminal=True))
    assert use is True
    assert reason is None


# --- MonitorDisplay: logging handler swap, cleanup --------------------------


def test_monitor_display_restores_logging_handlers_on_exit():
    original_handler = logging.StreamHandler()
    root = logging.getLogger()
    saved = root.handlers[:]
    root.handlers = [original_handler]
    try:
        header = _header()
        log = ActivityLog()
        display = MonitorDisplay(header, log, passive_enabled=True, console=_console(80, 24))
        with display:
            assert root.handlers != [original_handler]
        assert root.handlers == [original_handler]
    finally:
        root.handlers = saved


def test_monitor_display_restores_logging_handlers_on_exception():
    original_handler = logging.StreamHandler()
    root = logging.getLogger()
    saved = root.handlers[:]
    root.handlers = [original_handler]
    try:
        header = _header()
        log = ActivityLog()
        display = MonitorDisplay(header, log, passive_enabled=True, console=_console(80, 24))
        try:
            with display:
                raise ValueError("boom")
        except ValueError:
            pass
        assert root.handlers == [original_handler]
    finally:
        root.handlers = saved


def test_monitor_display_routes_warning_logs_into_activity_log():
    header = _header()
    log = ActivityLog()
    display = MonitorDisplay(header, log, passive_enabled=True, console=_console(80, 24))
    test_logger = logging.getLogger("lanfence.alerts")
    with display:
        test_logger.error("delivery failed: connection refused")
    entries = log.snapshot()
    assert any("delivery failed" in e.detail for e in entries)
    assert any(e.level == "error" for e in entries)


def test_monitor_display_render_is_safe_without_calling_update():
    """The renderable Rich's background auto-refresh thread would fetch
    before the first `update()` call must not crash - it should show the
    empty/default snapshot."""

    header = _header()
    log = ActivityLog()
    display = MonitorDisplay(header, log, passive_enabled=True, console=_console(80, 24))
    renderable = display._render()  # noqa: SLF001 - exactly what get_renderable calls
    console = _console(80, 24)
    console.render_lines(renderable, console.options.update(height=None))  # must not raise


def test_monitor_display_update_reflects_in_render():
    header = _header()
    log = ActivityLog()
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.set_inventory_counts(known=42, online=1, review=0)
    display = MonitorDisplay(header, log, passive_enabled=True, console=_console(80, 24))
    display.update(stats, log, now_monotonic=1.0)
    lines = _rendered_lines(display._render(), width=80, height=24)  # noqa: SLF001
    assert any("Known: 42" in line for line in lines)


def test_render_footer_hides_zero_findings_only_at_wide_width_never_fabricated():
    """Optional wide-terminal stats appear only at sufficient width, and
    n/a (never 0) is shown for an unavailable stat."""

    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    snap = stats.snapshot(now_monotonic=1.0)  # known/online/review never set
    narrow = render_footer(snap, width=40).plain
    assert "Known: n/a" in narrow
    assert "Online: n/a" in narrow
    assert "Seen: 0" in narrow  # a real, legitimate zero - not fabricated


def test_render_footer_scanning_state_overrides_countdown_text():
    stats = MonitorStats(scan_interval_seconds=60.0, passive_enabled=True, now_monotonic=0.0)
    stats.record_sweep_start(now_monotonic=5.0)
    snap = stats.snapshot(now_monotonic=999.0)
    text = render_footer(snap, width=100).plain
    assert "scanning" in text.lower()
    assert "-" not in text.split("Scan:")[1][:5]  # no stray negative countdown


def test_quit_key_single_press_and_terminal_restoration():
    import os
    import pty
    import termios
    from lanfence.monitor_ui import QuitKey

    master, slave = pty.openpty()
    try:
        with os.fdopen(os.dup(slave), 'r') as stream:
            original = termios.tcgetattr(slave)
            with QuitKey(stream) as keys:
                assert not termios.tcgetattr(slave)[3] & termios.ICANON
                os.write(master, b'x')
                keys.check()
                os.write(master, b'q')
                import pytest
                with pytest.raises(KeyboardInterrupt):
                    keys.check()
            restored = termios.tcgetattr(slave)
            # macOS sets the kernel-managed PENDIN flag after input arrives.
            restored[3] &= ~getattr(termios, "PENDIN", 0)
            original[3] &= ~getattr(termios, "PENDIN", 0)
            assert restored == original
    finally:
        os.close(master)
        os.close(slave)


def test_quit_key_does_not_read_redirected_input():
    from io import StringIO
    from lanfence.monitor_ui import QuitKey
    stream = StringIO('q')
    with QuitKey(stream) as keys:
        keys.check()
        assert keys.fd is None
    assert stream.read() == 'q'


def test_dashboard_quit_hint_normal_and_small():
    snap = MonitorSnapshot.empty(passive_enabled=False)
    for width, height in ((80, 24), (35, 12), (20, 3)):
        rendered = build_dashboard(_header(quit_key_enabled=True), snap, (),
                                   size=ConsoleDimensions(width, height))
        text = '\n'.join(_rendered_lines(rendered, width=width, height=height))
        assert 'q' in text and 'quit' in text
