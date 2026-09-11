# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Alert dispatch: syslog, email, webhook.

LAN Fence never calls out to any third-party service on its own - the
operator opts into each channel explicitly in config, and every channel here
is a destination *they* configured (their own syslog daemon, mail relay, or
webhook endpoint).
"""

from __future__ import annotations

import json
import smtplib
import syslog
import urllib.error
import urllib.request
from email.message import EmailMessage

from lanfence.config import AlertConfig
from lanfence.logging_config import get_logger
from lanfence.models import Finding

log = get_logger("alerts")

_SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2}

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
    "high": syslog.LOG_ALERT,
    "medium": syslog.LOG_WARNING,
    "info": syslog.LOG_INFO,
}


def findings_to_alert(findings: list[Finding], cfg: AlertConfig) -> list[Finding]:
    """Findings at or above ``cfg.min_severity``, worth dispatching."""

    threshold = _SEVERITY_RANK[cfg.min_severity]
    return [f for f in findings if _SEVERITY_RANK[f.severity] >= threshold]


def send_syslog(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.syslog.enabled or not findings:
        return
    facility = _SYSLOG_FACILITIES.get(cfg.syslog.facility, syslog.LOG_USER)
    syslog.openlog(ident="lanfence", facility=facility)
    try:
        for finding in findings:
            priority = _SYSLOG_SEVERITY.get(finding.severity, syslog.LOG_INFO)
            syslog.syslog(priority, f"[{finding.severity.upper()}] {finding.title} (mac={finding.mac})")
    finally:
        syslog.closelog()


def send_email(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.email.enabled or not findings:
        return
    if not cfg.email.to_addrs or not cfg.email.from_addr:
        log.warning("email alerts enabled but from_addr/to_addrs not configured; skipping")
        return

    lines = [f"LAN Fence: {len(findings)} finding(s)\n"]
    for finding in findings:
        lines.append(f"[{finding.severity.upper()}] {finding.title}")
        lines.append(f"  MAC: {finding.mac}")
        if finding.rationale:
            lines.append(f"  {finding.rationale}")
        if finding.recommendation:
            lines.append(f"  Recommendation: {finding.recommendation}")
        lines.append("")

    msg = EmailMessage()
    msg["Subject"] = f"LAN Fence: {len(findings)} finding(s) on your network"
    msg["From"] = cfg.email.from_addr
    msg["To"] = ", ".join(cfg.email.to_addrs)
    msg.set_content("\n".join(lines))

    try:
        with smtplib.SMTP(cfg.email.smtp_host, cfg.email.smtp_port, timeout=10) as smtp:
            if cfg.email.use_tls:
                smtp.starttls()
            if cfg.email.username and cfg.email.password:
                smtp.login(cfg.email.username, cfg.email.password)
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        log.error("failed to send email alert: %s", exc)


def send_webhook(findings: list[Finding], cfg: AlertConfig) -> None:
    if not cfg.webhook.enabled or not findings:
        return
    if not cfg.webhook.url:
        log.warning("webhook alerts enabled but no url configured; skipping")
        return

    payload = json.dumps({"findings": [f.model_dump(mode="json") for f in findings]}).encode("utf-8")
    request = urllib.request.Request(
        cfg.webhook.url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "lanfence"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=cfg.webhook.timeout_seconds) as resp:  # noqa: S310
            resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.error("failed to send webhook alert: %s", exc)


def dispatch(findings: list[Finding], cfg: AlertConfig) -> list[Finding]:
    """Send every finding at or above ``cfg.min_severity`` to every enabled
    channel. Returns the findings that were dispatched."""

    to_send = findings_to_alert(findings, cfg)
    if not to_send:
        return []
    send_syslog(to_send, cfg)
    send_email(to_send, cfg)
    send_webhook(to_send, cfg)
    return to_send
