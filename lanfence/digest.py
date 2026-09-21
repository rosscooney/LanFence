# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Digest: one concise, side-effect-free summary of recent network activity.

``build_digest`` is a pure aggregation layer - a database read plus the
existing ``engine.build_inventory``/``is_review_needed`` logic, with no
writes and no interaction with the immediate-alert pipeline (``alerts.py``).
Its output (:class:`~lanfence.models.Digest`) is shared unchanged by the
console renderer (``report.render_digest``), JSON output, and delivery
(below) - one model, three views.

Two capabilities the wider spec for this feature described are *not*
implemented here, by design, because the underlying data does not exist
anywhere in this codebase to draw on:

- Historical security findings are not persisted (only lifecycle events and
  alert-cooldown bookkeeping are) - "new devices" and the activity summary
  are built from persisted ``events``, not reconstructed findings, and the
  digest never claims to show historical severity.
- There is no durable monitor-health/alert-delivery-success record, so
  ``Digest.monitoring_health`` always reads "Monitoring health unavailable"
  rather than guessing.

Delivery reuses ``lanfence/alerts.py``'s transport helpers (``_post_json``,
the same SMTP pattern) rather than duplicating HTTP/SMTP handling - digest
payloads differ from finding-list alert payloads, so these are new
functions, not new calls into the existing ``send_*`` ones.
"""

from __future__ import annotations

import html
import json
import smtplib
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage

from lanfence import branding
from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.engine import build_inventory, is_review_needed
from lanfence.logging_config import get_logger
from lanfence.models import Device, Digest, DigestActivity, DigestDeviceEntry, DigestSection
from lanfence.safe_errors import summarize_error
from lanfence.smtp_utils import SmtpAuthWithoutTlsError, send_smtp_message
from lanfence.web import PORTAL_NOT_RUNNING_NOTE

log = get_logger("digest")


def _service_summary(store: DeviceStore, mac: str, *, now: datetime) -> str | None:
    """A terse, bounded one-liner of a device's *current* advertised
    services (see :meth:`lanfence.db.DeviceStore.advertised_services`), for
    new-device digest rows only - e.g. ``"Printing, AirPlay"``. ``None`` if
    nothing is currently advertised for this MAC (not evidence nothing is
    advertised at all - only that this capture point hasn't seen it)."""

    current = store.advertised_services(mac=mac, now=now)
    if not current:
        return None
    shown = current[:3]
    summary = ", ".join(s.service_label or s.service_type for s in shown)
    if len(current) > len(shown):
        summary += f" (+{len(current) - len(shown)} more)"
    return summary


def _to_entry(device: Device, *, services_summary: str | None = None) -> DigestDeviceEntry:
    metadata = device.metadata
    return DigestDeviceEntry(
        mac=device.mac,
        name=device.allowlist_name,
        ip=device.ip,
        hostname=device.hostname,
        vendor=device.vendor,
        trusted=device.allowlisted,
        presence_policy=device.presence_policy,
        review_state=device.review_state,
        review_notes=device.review_notes,
        first_seen=device.first_seen,
        last_seen=device.last_seen,
        owner=metadata.owner if metadata else None,
        group=metadata.group if metadata else None,
        services_summary=services_summary,
    )


def _section(
    devices: list[Device], *, store: DeviceStore | None = None, now: datetime | None = None,
) -> DigestSection:
    """``store``/``now`` are given only for the ``new_devices`` section -
    see :func:`_service_summary`. Every other section leaves
    ``services_summary`` ``None`` to keep routine review/investigating/
    missing-always-on rows terse.

    Lists every device, never truncated - a digest is only useful if it's
    complete."""

    ordered = sorted(devices, key=lambda d: d.mac)
    items = [
        _to_entry(d, services_summary=_service_summary(store, d.mac, now=now) if store and now else None)
        for d in ordered
    ]
    return DigestSection(items=items, total_count=len(ordered), omitted_count=0)


def build_digest(
    store: DeviceStore,
    allowlist: Allowlist,
    *,
    since: datetime,
    until: datetime,
    portal_url: str | None = None,
) -> Digest:
    """Aggregate one digest for the window ``since``..``until``.

    ``until`` is used as both the window's end boundary and
    ``Digest.generated_at`` - one UTC timestamp captured by the caller and
    used consistently throughout, per the digest's own accuracy
    requirements. Pure read: never writes to the database, never changes
    trust/review/presence state, and never touches alert-dispatch cooldowns.

    ``portal_url`` is passed straight through onto ``Digest.portal_url`` -
    this function never computes it itself (that needs a live network
    probe, not a database read; see :func:`lanfence.web.build_portal_url`).
    """

    inventory = build_inventory(store, allowlist)
    by_mac = {d.mac: d for d in inventory}

    new_device_events = store.events_between(since, until, event_type="new_device")
    new_macs: list[str] = []
    seen_new: set[str] = set()
    for event in new_device_events:
        if event.mac not in seen_new:
            seen_new.add(event.mac)
            new_macs.append(event.mac)
    # A device event-logged as "new" within the window but since deleted
    # (e.g. `lanfence reset`) has nothing left to report on - skip it rather
    # than fabricate a row.
    new_devices = [by_mac[mac] for mac in new_macs if mac in by_mac]

    needs_review = [d for d in inventory if is_review_needed(d, now=until)]
    investigating = [d for d in inventory if d.review_state == "investigating"]
    missing_always_on = [
        d for d in inventory if d.status == "offline" and d.presence_policy == "always-on"
    ]

    reappeared = store.events_between(since, until, event_type="reappeared")
    disconnected = store.events_between(since, until, event_type="disconnected")
    activity = DigestActivity(
        reappeared_device_count=len({e.mac for e in reappeared}),
        disconnected_device_count=len({e.mac for e in disconnected}),
        new_device_count=len(new_macs),
    )

    return Digest(
        generated_at=until,
        window_start=since,
        window_end=until,
        known_devices=len(inventory),
        online_devices=sum(1 for d in inventory if d.status == "online"),
        new_devices=_section(new_devices, store=store, now=until),
        needs_review=_section(needs_review),
        investigating=_section(investigating),
        missing_always_on=_section(missing_always_on),
        activity=activity,
        omitted_capabilities=[
            "historical security-finding severity (not persisted; only lifecycle events are)",
            "monitor uptime / alert-delivery health tracking (not persisted)",
        ],
        portal_url=portal_url,
    )


# --- delivery ----------------------------------------------------------


def _format_section_plain(title: str, section: DigestSection) -> list[str]:
    lines = [f"{title} ({section.total_count}):"]
    if not section.items:
        lines.append("  (none)")
    for entry in section.items:
        label = entry.name or entry.mac
        context = ""
        if entry.owner or entry.group:
            bits = [b for b in (entry.owner, entry.group) if b]
            context = f"  ({', '.join(bits)})"
        line = f"  - {label} ({entry.mac})  {entry.ip or '-'}  {entry.hostname or '[unknown]'}{context}"
        if entry.services_summary:
            line += f"  advertises: {entry.services_summary}"
        lines.append(line)
    if section.omitted_count:
        lines.append(f"  ... and {section.omitted_count} more")
    return lines


def format_digest_text(digest: Digest) -> str:
    """Readable plain-text body shared by email and every text-based channel."""

    lines = [
        f"LAN Fence digest - {digest.window_start.isoformat()} to {digest.window_end.isoformat()}",
        f"Generated: {digest.generated_at.isoformat()}",
        "",
        f"Known devices: {digest.known_devices}   Online now: {digest.online_devices}",
        f"New in window: {digest.activity.new_device_count}   "
        f"Reappeared: {digest.activity.reappeared_device_count}   "
        f"Disconnected: {digest.activity.disconnected_device_count}",
        f"Needs review: {digest.needs_review.total_count}   "
        f"Investigating: {digest.investigating.total_count}   "
        f"Missing always-on: {digest.missing_always_on.total_count}",
        f"{digest.monitoring_health}",
    ]
    lines.append(f"Manage devices: {digest.portal_url}" if digest.portal_url else PORTAL_NOT_RUNNING_NOTE)
    lines.append("")
    lines += _format_section_plain("New devices", digest.new_devices)
    lines.append("")
    lines += _format_section_plain("Needs review", digest.needs_review)
    lines.append("")
    lines += _format_section_plain("Investigating", digest.investigating)
    lines.append("")
    lines += _format_section_plain("Missing always-on devices", digest.missing_always_on)
    return "\n".join(lines).rstrip() + "\n"


#: Inline styles only (no <style> block, no external assets) - many email
#: clients strip <head>/<style> or block remote resources, so this follows
#: old-school HTML-email conventions: a single fixed-width table, colors
#: and spacing set directly on each element. Palette/logo/footer are
#: shared with the web portal via lanfence.branding, so the two never
#: drift into two different looks.
_EMAIL_BODY_STYLE = f"margin:0;background:{branding.COLORS['bg']};color:{branding.COLORS['text']};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
_EMAIL_TABLE_STYLE = f"width:100%;max-width:640px;margin:0 auto;border-collapse:collapse;background:{branding.COLORS['bg']};"
_EMAIL_PANEL_STYLE = f"background:{branding.COLORS['panel']};border:1px solid {branding.COLORS['border']};border-radius:12px;padding:16px 18px;"
_EMAIL_MUTED_STYLE = f"color:{branding.COLORS['muted']};"


def _html_section_table(title: str, section: DigestSection) -> str:
    rows = ""
    if not section.items:
        rows = f'<tr><td style="padding:8px 0;{_EMAIL_MUTED_STYLE}">none</td></tr>'
    else:
        for entry in section.items:
            label = html.escape(entry.name or entry.mac)
            context = ""
            if entry.owner or entry.group:
                bits = [html.escape(b) for b in (entry.owner, entry.group) if b]
                context = f" &middot; {', '.join(bits)}"
            rows += (
                '<tr><td style="padding:8px 0;border-top:1px solid '
                f'{branding.COLORS["border"]};font-size:14px;">'
                f'<strong>{label}</strong> '
                f'<span style="{_EMAIL_MUTED_STYLE}font-size:12px;">({html.escape(entry.mac)})</span><br>'
                f'<span style="{_EMAIL_MUTED_STYLE}font-size:13px;">'
                f'{html.escape(entry.ip or "-")} &middot; {html.escape(entry.hostname or "[unknown]")}{context}'
                "</span></td></tr>"
            )
        if section.omitted_count:
            rows += (
                f'<tr><td style="padding:8px 0;{_EMAIL_MUTED_STYLE}font-size:13px;">'
                f"... and {section.omitted_count} more</td></tr>"
            )
    return f"""
<tr><td style="padding:20px 0 0;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="{_EMAIL_PANEL_STYLE}">
    <tr><td style="font-size:15px;font-weight:700;padding-bottom:4px;">{html.escape(title)} ({section.total_count})</td></tr>
    {rows}
  </table>
</td></tr>
"""


def format_digest_html(digest: Digest) -> str:
    """Branded HTML alternative to :func:`format_digest_text`, sent
    alongside the plain-text body (see :func:`send_digest_email`) so mail
    clients that prefer HTML get LAN Fence's own look and feel, and
    plain-text-only clients still get a complete, readable body either
    way. Every value that could come from an untrusted device (a name,
    hostname, owner label, ...) is HTML-escaped - the same devices this
    tool exists to be suspicious of can set their own DHCP hostname.
    """

    colors = branding.COLORS
    portal_line = (
        f'<a href="{html.escape(digest.portal_url)}" style="color:{colors["accent2"]};">'
        f"{html.escape(digest.portal_url)}</a>"
        if digest.portal_url else html.escape(PORTAL_NOT_RUNNING_NOTE)
    )
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="{_EMAIL_BODY_STYLE}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="{_EMAIL_TABLE_STYLE}">
<tr><td style="padding:24px 20px 0;">
  <table role="presentation" cellpadding="0" cellspacing="0"><tr>
    <td style="padding-right:8px;">{branding.logo_svg(28)}</td>
    <td style="font-size:18px;font-weight:700;">LAN Fence digest</td>
  </tr></table>
  <p style="{_EMAIL_MUTED_STYLE}font-size:13px;margin:8px 0 0;">
    {html.escape(digest.window_start.isoformat(timespec="seconds"))} to
    {html.escape(digest.window_end.isoformat(timespec="seconds"))}
    &middot; generated {html.escape(digest.generated_at.isoformat(timespec="seconds"))}
  </p>
</td></tr>
<tr><td style="padding:16px 20px 0;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="{_EMAIL_PANEL_STYLE}">
    <tr><td style="font-size:14px;">
      Known devices: <strong>{digest.known_devices}</strong> &middot;
      Online now: <strong>{digest.online_devices}</strong><br>
      New: <strong>{digest.activity.new_device_count}</strong> &middot;
      Reappeared: <strong>{digest.activity.reappeared_device_count}</strong> &middot;
      Disconnected: <strong>{digest.activity.disconnected_device_count}</strong><br>
      Needs review: <strong>{digest.needs_review.total_count}</strong> &middot;
      Investigating: <strong>{digest.investigating.total_count}</strong> &middot;
      Missing always-on: <strong>{digest.missing_always_on.total_count}</strong>
    </td></tr>
    <tr><td style="padding-top:10px;{_EMAIL_MUTED_STYLE}font-size:13px;">{html.escape(digest.monitoring_health)}</td></tr>
    <tr><td style="padding-top:6px;font-size:13px;">{portal_line}</td></tr>
  </table>
</td></tr>
{_html_section_table("New devices", digest.new_devices)}
{_html_section_table("Needs review", digest.needs_review)}
{_html_section_table("Investigating", digest.investigating)}
{_html_section_table("Missing always-on devices", digest.missing_always_on)}
<tr><td style="padding:20px 20px 28px;{_EMAIL_MUTED_STYLE}font-size:12px;border-top:1px solid {colors['border']};margin-top:8px;">
  {branding.FOOTER_HTML}
</td></tr>
</table>
</body>
</html>
"""


def _digest_summary_line(digest: Digest) -> str:
    return (
        f"LAN Fence digest: {digest.activity.new_device_count} new, "
        f"{digest.needs_review.total_count} need review, "
        f"{digest.missing_always_on.total_count} always-on device(s) missing"
    )


#: Discord's per-message content cap (see alerts.py); reused here since the
#: digest can legitimately be longer than any single finding alert.
_DISCORD_MAX_CONTENT_LEN = 2000


def send_digest_email(digest: Digest, cfg: Config) -> bool:
    email_cfg = cfg.alerts.email
    if not email_cfg.enabled:
        log.warning("digest: email channel not enabled under alerts.email; skipping")
        return False
    if not email_cfg.to_addrs or not email_cfg.from_addr:
        log.warning("digest: email enabled but from_addr/to_addrs not configured; skipping")
        return False

    msg = EmailMessage()
    msg["Subject"] = _digest_summary_line(digest)
    msg["From"] = email_cfg.from_addr
    msg["To"] = ", ".join(email_cfg.to_addrs)
    # Plain text first (the primary/fallback body for text-only clients),
    # HTML as the alternative - most mail clients then render the HTML
    # version, but nothing is lost for one that can't/won't.
    msg.set_content(format_digest_text(digest))
    msg.add_alternative(format_digest_html(digest), subtype="html")

    try:
        send_smtp_message(msg, email_cfg)
        return True
    except SmtpAuthWithoutTlsError as exc:
        # Our own static, non-server-controlled message - safe to log as-is.
        log.error("failed to send digest email: %s", exc)
        return False
    except (smtplib.SMTPException, OSError) as exc:
        # An SMTP server's response line (or a resolver/connection error)
        # can carry server-controlled text - never logged raw.
        log.error("failed to send digest email: %s", summarize_error(exc))
        return False


def send_digest_webhook(digest: Digest, cfg: Config) -> bool:
    webhook_cfg = cfg.alerts.webhook
    if not webhook_cfg.enabled:
        log.warning("digest: webhook channel not enabled under alerts.webhook; skipping")
        return False
    if not webhook_cfg.url:
        log.warning("digest: webhook enabled but no url configured; skipping")
        return False
    payload = {"type": "lanfence.digest", "schema_version": digest.schema_version, "digest": digest.model_dump(mode="json")}
    return _post_json_ok(webhook_cfg.url, payload, timeout=webhook_cfg.timeout_seconds, label="digest webhook")


def send_digest_slack(digest: Digest, cfg: Config) -> bool:
    slack_cfg = cfg.alerts.slack
    if not slack_cfg.enabled:
        log.warning("digest: slack channel not enabled under alerts.slack; skipping")
        return False
    if not slack_cfg.webhook_url:
        log.warning("digest: slack enabled but no webhook_url configured; skipping")
        return False
    return _post_json_ok(
        slack_cfg.webhook_url, {"text": format_digest_text(digest)},
        timeout=slack_cfg.timeout_seconds, label="digest Slack",
    )


def send_digest_discord(digest: Digest, cfg: Config) -> bool:
    discord_cfg = cfg.alerts.discord
    if not discord_cfg.enabled:
        log.warning("digest: discord channel not enabled under alerts.discord; skipping")
        return False
    if not discord_cfg.webhook_url:
        log.warning("digest: discord enabled but no webhook_url configured; skipping")
        return False
    text = format_digest_text(digest)
    if len(text) > _DISCORD_MAX_CONTENT_LEN:
        cutoff = _DISCORD_MAX_CONTENT_LEN - len("\n... (truncated)")
        text = text[:cutoff].rstrip() + "\n... (truncated)"
    return _post_json_ok(
        discord_cfg.webhook_url, {"content": text}, timeout=discord_cfg.timeout_seconds, label="digest Discord"
    )


def send_digest_teams(digest: Digest, cfg: Config) -> bool:
    teams_cfg = cfg.alerts.teams
    if not teams_cfg.enabled:
        log.warning("digest: teams channel not enabled under alerts.teams; skipping")
        return False
    if not teams_cfg.webhook_url:
        log.warning("digest: teams enabled but no webhook_url configured; skipping")
        return False
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": _digest_summary_line(digest),
        "text": format_digest_text(digest),
    }
    return _post_json_ok(teams_cfg.webhook_url, payload, timeout=teams_cfg.timeout_seconds, label="digest Teams")


def send_digest_ntfy(digest: Digest, cfg: Config) -> bool:
    ntfy_cfg = cfg.alerts.ntfy
    if not ntfy_cfg.enabled:
        log.warning("digest: ntfy channel not enabled under alerts.ntfy; skipping")
        return False
    if not ntfy_cfg.url:
        log.warning("digest: ntfy enabled but no url configured; skipping")
        return False
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "User-Agent": "lanfence",
        "Title": _digest_summary_line(digest),
    }
    if ntfy_cfg.priority:
        headers["Priority"] = ntfy_cfg.priority
    request = urllib.request.Request(
        ntfy_cfg.url, data=format_digest_text(digest).encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=ntfy_cfg.timeout_seconds) as resp:  # noqa: S310
            resp.read()
        return True
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.error("failed to send digest ntfy notification: %s", summarize_error(exc))
        return False


def _post_json_ok(url: str, payload: dict, *, timeout: float, label: str) -> bool:
    """POST ``payload`` as JSON and report whether it actually succeeded.

    Deliberately its own implementation rather than reusing
    ``alerts._post_json`` - that helper logs a transport failure and
    returns ``None`` either way, which is right for the fire-and-forget
    immediate-alert pipeline but wrong here: digest delivery must return a
    real per-channel result and never report a swallowed transport error as
    successful delivery (see ``lanfence digest --send``'s exit status).
    """

    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": "lanfence"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - https literal
            resp.read()
        return True
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.error("failed to send %s: %s", label, summarize_error(exc))
        return False


_SENDERS = {
    "email": send_digest_email,
    "webhook": send_digest_webhook,
    "slack": send_digest_slack,
    "discord": send_digest_discord,
    "teams": send_digest_teams,
    "ntfy": send_digest_ntfy,
}


def dispatch_digest(digest: Digest, cfg: Config, *, channels: list[str]) -> dict[str, bool]:
    """Send ``digest`` to each of ``channels`` (already validated - see
    ``lanfence/cli.py``), independently: one channel failing never stops the
    others. Returns ``{channel: succeeded}`` for every requested channel."""

    results: dict[str, bool] = {}
    for name in channels:
        sender = _SENDERS[name]
        try:
            results[name] = bool(sender(digest, cfg))
        except Exception as exc:  # noqa: BLE001 - one destination's bug must not block the rest
            log.error("digest channel %s raised unexpectedly: %s", name, summarize_error(exc))
            results[name] = False
    return results
