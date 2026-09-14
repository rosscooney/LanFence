# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""The one SMTP delivery implementation shared by every email-sending path
in LAN Fence (:func:`lanfence.alerts.send_email`,
:func:`lanfence.digest.send_digest_email`, and the "email" branch of
:func:`lanfence.channels.send_channel_test_message`) - so all three verify
the destination server's certificate identically, and reject plaintext
credential submission identically. Kept as its own leaf module (no
dependency on ``alerts``/``digest``/``channels``) so any of them can import
it without introducing a cycle.

``smtplib.SMTP.starttls()`` called with no explicit ``context=`` builds an
*unverified* context internally (``ssl._create_stdlib_context()``, the same
shape as :func:`ssl._create_unverified_context`) - hostname and certificate
verification are silently skipped, exactly the condition that lets an
on-path attacker intercept the STARTTLS upgrade and read (or inject)
whatever is sent next, credentials included. Every call site here always
passes an explicit :func:`ssl.create_default_context` context instead.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage

from lanfence.config import EmailAlertConfig


class SmtpAuthWithoutTlsError(ValueError):
    """Raised by :func:`send_smtp_message` when SMTP username/password
    authentication is configured but ``use_tls`` is disabled - sending a
    password over an unencrypted connection. Distinguished from
    ``smtplib.SMTPException``/``OSError`` (real delivery failures) so
    callers can report it as a configuration problem, not a transient
    delivery error."""


def build_smtp_context(cfg: EmailAlertConfig) -> ssl.SSLContext:
    """A hostname- and certificate-verifying TLS context for SMTP
    STARTTLS - :func:`ssl.create_default_context`'s ordinary verifying
    behavior, optionally extended to also trust ``cfg.ca_file`` (a PEM
    bundle) for a relay using a private/internal CA. Never disables or
    weakens verification: there is deliberately no "skip verification"
    option here - a private CA is supported by adding a trust anchor, not
    by turning verification off.
    """

    ca_file = os.path.expanduser(cfg.ca_file) if cfg.ca_file else None
    return ssl.create_default_context(cafile=ca_file)


def send_smtp_message(msg: EmailMessage, cfg: EmailAlertConfig, *, timeout: float = 10.0) -> None:
    """Deliver ``msg`` via the SMTP relay described by ``cfg``.

    Raises :class:`SmtpAuthWithoutTlsError` before opening any connection
    if ``cfg.username``/``cfg.password`` are set while ``cfg.use_tls`` is
    False - refusing to send a password in the clear. An explicitly
    configured unauthenticated relay (``use_tls=False`` with no
    username/password - e.g. a trusted local relay on ``localhost``) is
    left untouched; only the credential-over-plaintext combination is
    refused.

    Raises ``smtplib.SMTPException``/``OSError`` (which
    :class:`ssl.SSLError`, including a certificate verification failure,
    is a subclass of) on any other delivery failure - a caller that wants
    per-channel error handling catches those the same way it always has.
    """

    if not cfg.use_tls and (cfg.username or cfg.password):
        raise SmtpAuthWithoutTlsError(
            "SMTP username/password are configured but use_tls is disabled - "
            "refusing to send credentials over an unencrypted connection"
        )

    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=timeout) as smtp:
        if cfg.use_tls:
            smtp.starttls(context=build_smtp_context(cfg))
        if cfg.username and cfg.password:
            smtp.login(cfg.username, cfg.password)
        smtp.send_message(msg)
