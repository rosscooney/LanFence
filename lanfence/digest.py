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

import json
import smtplib
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage

from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.engine import build_inventory, is_review_needed
from lanfence.logging_config import get_logger
from lanfence.models import Device, Digest, DigestActivity, DigestDeviceEntry, DigestSection

log = get_logger("digest")


def _to_entry(device: Device) -> DigestDeviceEntry:
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
    )


def _bounded_section(devices: list[Device], *, limit: int) -> DigestSection:
    ordered = sorted(devices, key=lambda d: d.mac)
    total = len(ordered)
    shown = ordered[:limit]
    return DigestSection(
        items=[_to_entry(d) for d in shown],
        total_count=total,
        omitted_count=max(0, total - limit),
    )


def build_digest(
    store: DeviceStore,
    allowlist: Allowlist,
    *,
    since: datetime,
    until: datetime,
    max_devices_per_section: int = 20,
) -> Digest:
    """Aggregate one digest for the window ``since``..``until``.

    ``until`` is used as both the window's end boundary and
    ``Digest.generated_at`` - one UTC timestamp captured by the caller and
    used consistently throughout, per the digest's own accuracy
    requirements. Pure read: never writes to the database, never changes
    trust/review/presence state, and never touches alert-dispatch cooldowns.
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
        new_devices=_bounded_section(new_devices, limit=max_devices_per_section),
        needs_review=_bounded_section(needs_review, limit=max_devices_per_section),
        investigating=_bounded_section(investigating, limit=max_devices_per_section),
        missing_always_on=_bounded_section(missing_always_on, limit=max_devices_per_section),
        activity=activity,
        omitted_capabilities=[
            "historical security-finding severity (not persisted; only lifecycle events are)",
            "monitor uptime / alert-delivery health tracking (not persisted)",
        ],
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
        lines.append(f"  - {label} ({entry.mac})  {entry.ip or '-'}  {entry.hostname or '[unknown]'}{context}")
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
        "",
    ]
    lines += _format_section_plain("New devices", digest.new_devices)
    lines.append("")
    lines += _format_section_plain("Needs review", digest.needs_review)
    lines.append("")
    lines += _format_section_plain("Investigating", digest.investigating)
    lines.append("")
    lines += _format_section_plain("Missing always-on devices", digest.missing_always_on)
    return "\n".join(lines).rstrip() + "\n"


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
    msg.set_content(format_digest_text(digest))

    try:
        with smtplib.SMTP(email_cfg.smtp_host, email_cfg.smtp_port, timeout=10) as smtp:
            if email_cfg.use_tls:
                smtp.starttls()
            if email_cfg.username and email_cfg.password:
                smtp.login(email_cfg.username, email_cfg.password)
            smtp.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        log.error("failed to send digest email: %s", exc)
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
        log.error("failed to send digest ntfy notification: %s", exc)
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
        log.error("failed to send %s: %s", label, exc)
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
            log.error("digest channel %s raised unexpectedly: %s", name, exc)
            results[name] = False
    return results
