# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Alert dispatch: syslog, email, webhook, Slack, Discord, Teams, ntfy, Twilio.

LAN Fence never calls out to any third-party service on its own - the
operator opts into each channel explicitly in config, and every channel here
is a destination *they* configured (their own syslog daemon, mail relay,
webhook endpoint, or messaging/SMS account).
"""

from __future__ import annotations

import base64
import html
import json
import math
import smtplib
import syslog
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage

from lanfence import branding
from lanfence.config import AlertConfig
from lanfence.db import DeviceStore
from lanfence.logging_config import get_logger
from lanfence.models import Finding
from lanfence.safe_errors import summarize_error
from lanfence.smtp_utils import SmtpAuthWithoutTlsError, send_smtp_message

log = get_logger("alerts")

_SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}

_SYSLOG_FACILITIES = {
    "user": syslog.LOG_USER,
    "daemon": syslog.LOG_DAEMON,
    "local0": syslog.LOG_LOCAL0,
    "local1": syslog.LOG_LOCAL1,
    "local2": syslog.LOG_LOCAL2,
    "local3": syslog.LOG_LOCAL3,
    "local4": syslog.LOG_LOCAL4,
    "local5": syslog.LOG_LOCAL5,
    "local6": syslog.LOG_LOCAL6,
    "local7": syslog.LOG_LOCAL7,
}

_SYSLOG_SEVERITY = {
    "critical": syslog.LOG_CRIT,
    "high": syslog.LOG_ALERT,
    "medium": syslog.LOG_WARNING,
    "info": syslog.LOG_INFO,
}


def findings_to_alert(findings: list[Finding], cfg: AlertConfig) -> list[Finding]:
    """Findings at or above ``cfg.min_severity``, worth dispatching."""

    threshold = _SEVERITY_RANK[cfg.min_severity]
    return [f for f in findings if _SEVERITY_RANK[f.severity] >= threshold]


def _finding_subject(finding: Finding) -> str:
    """A finding's identity for display - its MAC for an ordinary device
    finding, or its ``subject_id`` (e.g. an interface/DHCP-server-identifier
    pair) for one that isn't about any single device."""

    return finding.mac or finding.subject_id or "[no device]"


def send_syslog(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.syslog.enabled or not findings:
        return
    facility = _SYSLOG_FACILITIES.get(cfg.syslog.facility, syslog.LOG_USER)
    syslog.openlog(ident="lanfence", facility=facility)
    try:
        for finding in findings:
            priority = _SYSLOG_SEVERITY.get(finding.severity, syslog.LOG_INFO)
            syslog.syslog(
                priority, f"[{finding.severity.upper()}] {finding.title} (mac={_finding_subject(finding)})"
            )
    finally:
        syslog.closelog()


def _site_line(site_name: str | None, site_location: str | None) -> str | None:
    """The operator-set site label (see :class:`lanfence.config.SiteConfig`),
    shown at the top of every alert email so a multi-site operator can tell
    them apart at a glance - ``None`` when neither field is set. Mirrors
    :func:`lanfence.digest._site_line` (kept as a separate, tiny copy here
    rather than a cross-import, since alerts/digest formatting is already
    entirely independent per channel)."""

    if not site_name and not site_location:
        return None
    if site_name and site_location:
        return f"Site: {site_name} ({site_location})"
    return f"Site: {site_name or site_location}"


def _format_findings_text(
    findings: list[Finding], *, heading: str | None, site_name: str | None = None,
    site_location: str | None = None,
) -> str:
    """A multi-line human-readable summary, shared by every text-based channel.

    ``finding.evidence`` (the device's name - its allowlist name, when
    trusted - MAC/IP/hostname/vendor, plus operator-set owner/purpose/
    group/location when set - see :func:`lanfence.engine._device_evidence_lines`
    - and any signature-match detail) is listed in full, the same
    bullet-point convention `lanfence`'s own console renderer already
    uses (:func:`lanfence.report._render_findings`) - previously this
    showed only the bare MAC on its own line above the evidence list,
    which duplicated it.
    """

    lines: list[str] = []
    site_line = _site_line(site_name, site_location)
    if site_line:
        lines.append(site_line)
    if heading:
        lines.append(f"{heading}: {len(findings)} finding(s)")
        lines.append("")
    for finding in findings:
        lines.append(f"[{finding.severity.upper()}] {finding.title}")
        if finding.rationale:
            lines.append(f"  {finding.rationale}")
        if finding.recommendation:
            lines.append(f"  Recommendation: {finding.recommendation}")
        for line in finding.evidence:
            lines.append(f"    • {line}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _format_findings_compact(findings: list[Finding], *, max_len: int) -> str:
    """A single-line, length-capped summary for channels billed per message
    (SMS) or with tight size limits."""

    parts = [f"LAN Fence: {len(findings)} finding(s)"]
    parts.extend(f"[{f.severity.upper()}] {f.title} (mac={_finding_subject(f)})" for f in findings)
    text = " | ".join(parts)
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


#: Severity → accent colour for the HTML email's per-finding panel border
#: and badge. Not part of `branding.COLORS` (that palette has no reds/ambers
#: of its own) - chosen to read clearly against the dark panel background.
_SEVERITY_COLORS = {"critical": "#ef4444", "high": "#f87171", "medium": "#fbbf24", "info": branding.COLORS["accent2"]}


def _html_finding_panel(finding: Finding) -> str:
    color = _SEVERITY_COLORS.get(finding.severity, branding.COLORS["muted"])
    rationale_row = (
        f'<tr><td style="padding-top:8px;font-size:13px;">{html.escape(finding.rationale)}</td></tr>'
        if finding.rationale else ""
    )
    recommendation_row = (
        f'<tr><td style="padding-top:6px;font-size:13px;{branding.EMAIL_MUTED_STYLE}">'
        f"Recommendation: {html.escape(finding.recommendation)}</td></tr>"
        if finding.recommendation else ""
    )
    # finding.evidence (the device's name - its allowlist name, when
    # trusted - MAC/IP/hostname/vendor, plus operator-set owner/purpose/
    # group/location when set, and any signature-match detail - see
    # lanfence.engine._device_evidence_lines) listed in full, the same
    # bullet-point convention the console renderer already uses
    # (lanfence.report._render_findings) - previously this panel also
    # showed the bare MAC on its own line above, duplicating it.
    evidence_row = ""
    if finding.evidence:
        items = "".join(f'<li style="margin:2px 0;">{html.escape(line)}</li>' for line in finding.evidence)
        evidence_row = (
            f'<tr><td style="padding-top:6px;font-size:13px;{branding.EMAIL_MUTED_STYLE}">'
            f'<ul style="margin:4px 0 0;padding-left:18px;">{items}</ul></td></tr>'
        )
    return f"""
<tr><td style="padding:12px 0 0;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="{branding.EMAIL_PANEL_STYLE}border-left:4px solid {color};">
    <tr><td style="font-size:11px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;color:{color};">{html.escape(finding.severity)}</td></tr>
    <tr><td style="font-size:15px;font-weight:700;padding-top:2px;">{html.escape(finding.title)}</td></tr>
    {rationale_row}
    {recommendation_row}
    {evidence_row}
  </table>
</td></tr>
"""


def format_findings_html(
    findings: list[Finding], *, heading: str = "LAN Fence", site_name: str | None = None,
    site_location: str | None = None,
) -> str:
    """Branded HTML alternative to :func:`_format_findings_text`, sent
    alongside the plain-text body (see :func:`send_email`) - the same
    look and feel as the digest email (:func:`lanfence.digest.format_digest_html`),
    built from the same shared style constants in :mod:`lanfence.branding`.
    Every value that could come from an untrusted device (a finding's
    title/rationale/recommendation) is HTML-escaped, the same as the
    digest - a device this tool is being suspicious of can set its own
    DHCP hostname, which can end up inside a finding's text.
    """

    panels = "".join(_html_finding_panel(f) for f in findings)
    colors = branding.COLORS
    site_text = _site_line(site_name, site_location)
    site_row = (
        f'<tr><td style="padding:10px 20px 0;font-size:13px;font-weight:700;">'
        f"{html.escape(site_text)}</td></tr>"
        if site_text else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="{branding.EMAIL_BODY_STYLE}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="{branding.EMAIL_TABLE_STYLE}">
{site_row}
<tr><td style="padding:24px 20px 0;">
  <table role="presentation" cellpadding="0" cellspacing="0"><tr>
    <td style="padding-right:8px;">
      <img src="cid:lanfence-logo" width="28" height="28" alt="LAN Fence" style="display:block;border:0;">
    </td>
    <td style="font-size:18px;font-weight:700;">{html.escape(heading)}</td>
  </tr></table>
  <p style="{branding.EMAIL_MUTED_STYLE}font-size:13px;margin:8px 0 0;">{len(findings)} finding(s)</p>
</td></tr>
{panels}
<tr><td style="padding:20px 20px 28px;{branding.EMAIL_MUTED_STYLE}font-size:12px;border-top:1px solid {colors['border']};margin-top:8px;">
  {branding.FOOTER_HTML}
</td></tr>
</table>
</body>
</html>
"""


def _post_json(url: str, payload: dict, *, timeout: float, label: str) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "lanfence"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - https literal
            resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.error("failed to send %s alert: %s", label, summarize_error(exc))


def send_email(
    findings: list[Finding], cfg: AlertConfig, *, site_name: str | None = None,
    site_location: str | None = None,
) -> None:
    if not cfg.email.enabled or not findings:
        return
    if not cfg.email.to_addrs or not cfg.email.from_addr:
        log.warning("email alerts enabled but from_addr/to_addrs not configured; skipping")
        return

    subject_prefix = f"[{site_name}] " if site_name else ""
    msg = EmailMessage()
    msg["Subject"] = f"{subject_prefix}LAN Fence: {len(findings)} finding(s) on your network"
    msg["From"] = cfg.email.from_addr
    msg["To"] = ", ".join(cfg.email.to_addrs)
    # Plain text first (the primary/fallback body for text-only clients),
    # HTML as the alternative - same structure as the digest email.
    msg.set_content(
        _format_findings_text(findings, heading="LAN Fence", site_name=site_name, site_location=site_location)
    )
    msg.add_alternative(format_findings_html(findings, site_name=site_name, site_location=site_location), subtype="html")
    # Content-ID-attached logo, not inline <svg> - see
    # lanfence.digest.send_digest_email's docstring note for why.
    html_part = msg.get_payload()[-1]
    html_part.add_related(branding.render_logo_png(64), maintype="image", subtype="png", cid="<lanfence-logo>")

    try:
        send_smtp_message(msg, cfg.email)
    except SmtpAuthWithoutTlsError as exc:
        # Our own static, non-server-controlled message - safe to log as-is.
        log.error("failed to send email alert: %s", exc)
    except (smtplib.SMTPException, OSError) as exc:
        # An SMTP server's response line (or a resolver/connection error)
        # can carry server-controlled text - never logged raw.
        log.error("failed to send email alert: %s", summarize_error(exc))


def send_webhook(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.webhook.enabled or not findings:
        return
    if not cfg.webhook.url:
        log.warning("webhook alerts enabled but no url configured; skipping")
        return
    payload = {"findings": [f.model_dump(mode="json") for f in findings]}
    _post_json(cfg.webhook.url, payload, timeout=cfg.webhook.timeout_seconds, label="webhook")


def send_slack(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.slack.enabled or not findings:
        return
    if not cfg.slack.webhook_url:
        log.warning("slack alerts enabled but no webhook_url configured; skipping")
        return
    text = _format_findings_text(findings, heading="LAN Fence")
    _post_json(cfg.slack.webhook_url, {"text": text}, timeout=cfg.slack.timeout_seconds, label="Slack")


#: Discord hard-caps a webhook message's `content` at 2000 characters; leave
#: headroom for the truncation suffix itself rather than exceeding the cap.
_DISCORD_MAX_CONTENT_LEN = 2000
_DISCORD_TRUNCATION_SUFFIX = "\n… (truncated)"


def send_discord(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.discord.enabled or not findings:
        return
    if not cfg.discord.webhook_url:
        log.warning("discord alerts enabled but no webhook_url configured; skipping")
        return
    text = _format_findings_text(findings, heading="LAN Fence")
    if len(text) > _DISCORD_MAX_CONTENT_LEN:
        cutoff = _DISCORD_MAX_CONTENT_LEN - len(_DISCORD_TRUNCATION_SUFFIX)
        text = text[:cutoff].rstrip() + _DISCORD_TRUNCATION_SUFFIX
    _post_json(cfg.discord.webhook_url, {"content": text}, timeout=cfg.discord.timeout_seconds, label="Discord")


def send_teams(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.teams.enabled or not findings:
        return
    if not cfg.teams.webhook_url:
        log.warning("teams alerts enabled but no webhook_url configured; skipping")
        return
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"LAN Fence: {len(findings)} finding(s)",
        "text": _format_findings_text(findings, heading="LAN Fence"),
    }
    _post_json(cfg.teams.webhook_url, payload, timeout=cfg.teams.timeout_seconds, label="Teams")


def send_ntfy(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.ntfy.enabled or not findings:
        return
    if not cfg.ntfy.url:
        log.warning("ntfy alerts enabled but no url configured; skipping")
        return

    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "User-Agent": "lanfence",
        "Title": f"LAN Fence: {len(findings)} finding(s)",
    }
    if cfg.ntfy.priority:
        headers["Priority"] = cfg.ntfy.priority
    text = _format_findings_text(findings, heading=None)
    request = urllib.request.Request(
        cfg.ntfy.url, data=text.encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=cfg.ntfy.timeout_seconds) as resp:  # noqa: S310
            resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.error("failed to send ntfy alert: %s", summarize_error(exc))


#: Twilio bills SMS per ~153-character segment; cap the body so one alert
#: can't silently balloon into a dozen billed segments.
_TWILIO_MAX_BODY_LEN = 480
#: The concatenated-SMS (multi-segment) body length per segment - the
#: GSM-7 single-segment limit (160) drops to 153 once a message needs more
#: than one segment, to make room for each segment's concatenation header.
_SMS_SEGMENT_LEN = 153
_TWILIO_API_URL = "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"


def _sms_segment_count(body: str) -> int:
    return max(1, math.ceil(len(body) / _SMS_SEGMENT_LEN))


def send_twilio(findings: list[Finding], cfg: AlertConfig, *, store: DeviceStore | None = None) -> None:
    """Send ``findings`` via Twilio SMS to every configured recipient.

    ``store`` (when given) enforces ``cfg.twilio.max_segments_per_day`` - a
    durable, per-calendar-day budget on total SMS segments across every
    recipient (see :meth:`lanfence.db.DeviceStore.consume_sms_budget`).
    Budget is consumed per-recipient: once exhausted, remaining recipients
    in this call are skipped (not sent), rather than refusing the whole
    batch outright, so recipients already within budget still get their
    message. ``store=None`` (a caller with no durable store handy) means
    the budget is not enforced for this call - callers that can provide a
    store should.
    """

    if not cfg.twilio.enabled or not findings:
        return
    if not (
        cfg.twilio.account_sid and cfg.twilio.auth_token
        and cfg.twilio.from_number and cfg.twilio.to_numbers
    ):
        log.warning(
            "twilio alerts enabled but account_sid/auth_token/from_number/to_numbers "
            "not fully configured; skipping"
        )
        return

    body = _format_findings_compact(findings, max_len=_TWILIO_MAX_BODY_LEN)
    segments = _sms_segment_count(body)
    url = _TWILIO_API_URL.format(sid=cfg.twilio.account_sid)
    auth = base64.b64encode(f"{cfg.twilio.account_sid}:{cfg.twilio.auth_token}".encode()).decode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {auth}",
        "User-Agent": "lanfence",
    }

    total_recipients = len(cfg.twilio.to_numbers)
    for index, to_number in enumerate(cfg.twilio.to_numbers, start=1):
        if store is not None and not store.consume_sms_budget(
            segments, now=datetime.now(timezone.utc), max_segments_per_day=cfg.twilio.max_segments_per_day,
        ):
            log.warning("twilio SMS budget exhausted for today; skipping remaining recipient(s)")
            break
        payload = urllib.parse.urlencode(
            {"From": cfg.twilio.from_number, "To": to_number, "Body": body}
        ).encode("utf-8")
        request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=cfg.twilio.timeout_seconds) as resp:  # noqa: S310
                resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Recipient number deliberately omitted - not logged even
            # masked, per "no unnecessary recipient details"; the
            # recipient index is enough to distinguish which of several
            # configured numbers failed without identifying who they are.
            log.error(
                "failed to send Twilio SMS to recipient %d of %d: %s",
                index, total_recipients, summarize_error(exc),
            )


def dispatch(
    findings: list[Finding], cfg: AlertConfig, *, store: DeviceStore | None = None,
    site_name: str | None = None, site_location: str | None = None,
) -> list[Finding]:
    """Send every finding at or above ``cfg.min_severity`` to every enabled
    channel. Returns the findings that were dispatched.

    ``store`` (optional) is used only to enforce Twilio's durable SMS
    budget (see :func:`send_twilio`) - every other channel here is pure
    network I/O with no database access, which is what lets a caller
    (e.g. `lanfence monitor`'s background alert-delivery worker) safely
    call this from a thread other than the one that owns its main
    ``DeviceStore`` connection: pass either ``None`` or a ``DeviceStore``
    opened on *that same* (delivery) thread, never the owning thread's
    connection shared across threads.

    ``site_name``/``site_location`` (see :class:`lanfence.config.SiteConfig`)
    are passed straight through to :func:`send_email` only - the other
    channels here don't have an equivalent "top of message" convention to
    put it in.
    """

    to_send = findings_to_alert(findings, cfg)
    if not to_send:
        return []
    send_syslog(to_send, cfg)
    send_email(to_send, cfg, site_name=site_name, site_location=site_location)
    send_webhook(to_send, cfg)
    send_slack(to_send, cfg)
    send_discord(to_send, cfg)
    send_teams(to_send, cfg)
    send_ntfy(to_send, cfg)
    send_twilio(to_send, cfg, store=store)
    return to_send
