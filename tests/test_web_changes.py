# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""The web portal's Know When It Changes pages: What Changed?, a change's
detail and review actions, and the device page's Risk / Changes /
Services / Baseline sections."""

from __future__ import annotations

import http.cookiejar
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from lanfence import web
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.models import BaselineItem, ChangeEvent, DeviceBaseline

NAS = "00:11:32:aa:bb:01"
PHONE = "3c:22:fb:aa:bb:02"


@pytest.fixture
def portal(tmp_path: Path):
    now = datetime.now(timezone.utc)
    db_path = tmp_path / "db.sqlite"
    with DeviceStore(db_path) as store:
        store.observe(mac=NAS, ip="192.168.1.10", hostname="diskstation", vendor="Synology Incorporated",
                      seen_at=now - timedelta(days=30))
        store.observe(mac=NAS, ip="192.168.1.10", hostname="diskstation", vendor="Synology Incorporated", seen_at=now)
        store.observe(mac=PHONE, ip="192.168.1.45", hostname="janes-iphone", vendor="Apple, Inc.", seen_at=now)
        store.save_baseline(DeviceBaseline(
            mac=NAS, started_at=now - timedelta(days=30), established_at=now - timedelta(days=23),
        ), now=now)
        for value, in_baseline in (("tcp/443", True), ("tcp/22", False)):
            store.save_baseline_item(BaselineItem(
                mac=NAS, signal="port", value=value, in_baseline=in_baseline,
                origin="initial" if in_baseline else "observed", first_seen=now - timedelta(days=1), last_seen=now,
            ))
        ssh = store.record_change_event(ChangeEvent(
            mac=NAS, change_type="service_new", occurred_at=now - timedelta(hours=2), signal="port", subject="tcp/22",
            source="inspection", significance="high", current={"baseline": ["HTTPS / TCP 443"], "established": True},
        ))
        ip = store.record_change_event(ChangeEvent(
            mac=PHONE, change_type="ip_changed", occurred_at=now - timedelta(days=3), signal="ip",
            subject="192.168.1.45", source="arp", significance="info",
            previous={"ipv4": "192.168.1.20"}, current={"ipv4": "192.168.1.45"},
        ))

    password_hash, password_salt = web.hash_password("s3cret-pw")
    cfg = Config(db_path=str(db_path), allowlist_file=str(tmp_path / "allowlist.yaml"))
    cfg.web.enabled = True
    cfg.web.password_hash = password_hash
    cfg.web.password_salt = password_salt
    context = web._WebContext(cfg=cfg, sessions=web._SessionStore(), throttle=web._LoginThrottle())
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web._make_handler(context))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    opener.open(f"{base}/login", data=urllib.parse.urlencode({"password": "s3cret-pw"}).encode())
    try:
        yield {"base": base, "open": opener.open, "cfg": cfg, "ssh": ssh.id, "ip": ip.id}
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(portal, path: str) -> str:
    return portal["open"](portal["base"] + path).read().decode()


def _post(portal, path: str, **form: str) -> str:
    return portal["open"](portal["base"] + path, data=urllib.parse.urlencode(form).encode()).read().decode()


# --- What Changed? ---------------------------------------------------------------


def test_what_changed_lists_recent_changes_newest_first(portal):
    body = _get(portal, "/changes")
    assert "What Changed?" in body
    assert body.index("New service detected: SSH / TCP 22") < body.index("IP address changed")


def test_what_changed_filters(portal):
    assert "IP address changed" not in _get(portal, "/changes?since=24h")
    high = _get(portal, "/changes?severity=high")
    assert "SSH / TCP 22" in high and "IP address changed" not in high
    phone = _get(portal, f"/changes?mac={urllib.parse.quote(PHONE)}")
    assert "IP address changed" in phone and "SSH / TCP 22" not in phone
    typed = _get(portal, "/changes?type=ip_changed")
    assert "IP address changed" in typed and "SSH / TCP 22" not in typed


def test_what_changed_ignores_bad_filter_values(portal):
    body = _get(portal, "/changes?since=forever&type=port_delta&mac=not-a-mac")
    assert "SSH / TCP 22" in body


def test_change_detail_explains_and_escapes(portal):
    body = _get(portal, f"/changes/{portal['ssh']}")
    assert "New service detected: SSH / TCP 22" in body
    assert "Previous baseline: HTTPS / TCP 443" in body
    assert "Accept as expected" in body


def test_unknown_change_is_not_found(portal):
    for path in ("/changes/99999", "/changes/abc"):
        with pytest.raises(urllib.error.HTTPError) as exc:
            _get(portal, path)
        assert exc.value.code == 404


def test_accepting_a_change_updates_the_baseline_and_keeps_the_note(portal):
    _post(portal, f"/changes/{portal['ssh']}", action="accepted", note="<b>Enabled for backups</b>")
    with DeviceStore(portal["cfg"].resolved_db_path()) as store:
        event = store.get_change_event(portal["ssh"])
        ssh = next(i for i in store.baseline_items(NAS) if i.value == "tcp/22")
    assert event.review_state == "accepted"
    assert event.review_note == "<b>Enabled for backups</b>"
    assert (ssh.in_baseline, ssh.origin) == (True, "accepted")
    body = _get(portal, f"/changes/{portal['ssh']}")
    assert "&lt;b&gt;Enabled for backups&lt;/b&gt;" in body


def test_snoozing_hides_a_change_from_needs_attention(portal):
    _post(portal, f"/changes/{portal['ssh']}", action="snooze_1d")
    with DeviceStore(portal["cfg"].resolved_db_path()) as store:
        event = store.get_change_event(portal["ssh"])
    assert event.review_state == "snoozed" and event.snoozed_until is not None
    assert "SSH / TCP 22" not in _get(portal, "/changes?review=attention")


# --- device page ------------------------------------------------------------------


def test_device_page_shows_risk_changes_services_and_baseline(portal):
    body = _get(portal, f"/device/{NAS}")
    for heading in ("<h2>Risk</h2>", "<h2>Changes</h2>", "<h2>Services</h2>", "<h2>Baseline</h2>"):
        assert heading in body
    assert body.index("<h2>Risk</h2>") < body.index("<h2>Changes</h2>") < body.index("<h2>Services</h2>")
    assert "Why this risk?" in body and "Recommended action:" in body
    assert f'href="/changes/{portal["ssh"]}"' in body
    assert "<strong>New</strong> - pending review" in body
    assert "<strong>Established</strong>" in body
    assert "Accept all 1 pending" in body


def test_device_without_a_baseline_says_so(portal):
    body = _get(portal, f"/device/{PHONE}")
    assert "Not started yet" in body
    assert "None observed yet" in body


def test_accept_pending_from_the_device_page(portal):
    body = _post(portal, f"/device/{NAS}", action="accept_pending")
    assert "Accepted 1 pending item(s)" in body
    with DeviceStore(portal["cfg"].resolved_db_path()) as store:
        assert all(i.in_baseline for i in store.baseline_items(NAS))
        assert store.get_change_event(portal["ssh"]).review_state == "accepted"


def test_excluding_signals_from_the_device_page(portal):
    _post(portal, f"/device/{NAS}", action="baseline_exclude", exclude_ip="1", exclude_hostname="1", exclude_bogus="1")
    with DeviceStore(portal["cfg"].resolved_db_path()) as store:
        assert store.get_baseline(NAS).excluded_signals == ["hostname", "ip"]
    body = _post(portal, f"/device/{PHONE}", action="baseline_exclude", exclude_ip="1")
    assert "No baseline yet" in body


def test_resetting_the_baseline_keeps_history(portal):
    body = _post(portal, f"/device/{NAS}", action="baseline_reset")
    assert "Baseline reset" in body
    with DeviceStore(portal["cfg"].resolved_db_path()) as store:
        assert store.get_baseline(NAS) is None
        assert store.get_change_event(portal["ssh"]) is not None
        assert any(e.change_type == "baseline_reset" for e in store.change_events(mac=NAS))


# --- dashboard and inventory ------------------------------------------------------


def _save_risk(portal, mac: str, score: int, level: str) -> None:
    from lanfence.models import RiskAssessment

    with DeviceStore(portal["cfg"].resolved_db_path()) as store:
        store.save_risk(mac, RiskAssessment(score=score, level=level), now=datetime.now(timezone.utc))


def test_dashboard_security_overview_counts_link_to_the_lists(portal):
    _save_risk(portal, NAS, 57, "high")
    _save_risk(portal, PHONE, 5, "low")
    body = _get(portal, "/")
    assert "Network security" in body
    assert "1 normal" in body  # the phone: low risk, nothing awaiting review
    assert '<a href="/changes?since=7d&amp;review=attention&amp;severity=low">1 need review</a>' in body
    assert '<a href="/?risk=high">1 high risk</a>' in body
    assert "1 changed behaviour</a>" in body
    assert "1 service change(s)</a>" in body


def test_inventory_risk_column_and_filter(portal):
    _save_risk(portal, NAS, 57, "high")
    _save_risk(portal, PHONE, 5, "low")
    everything = _get(portal, "/")
    assert "<th><a href=\"/?sort=risk" in everything
    high = _get(portal, "/?risk=high")
    assert NAS in high and PHONE not in high.split("<tbody>")[1]
    by_risk = _get(portal, "/?sort=risk&dir=desc").split("<tbody>")[1]
    assert by_risk.index(NAS) < by_risk.index(PHONE)
