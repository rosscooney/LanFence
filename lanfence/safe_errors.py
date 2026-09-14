# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Safe, consistent error summaries for transport/delivery failures.

A raw transport exception's ``str()``/``args`` can carry server-controlled
text (an HTTP "reason phrase" an attacker-influenced endpoint chose, an SMTP
server's response line) or configuration-derived values an exception
implementation happens to embed (a full webhook URL, a recipient
address/number, a `SMTPRecipientsRefused.recipients` dict). None of that is
safe to log or show an operator verbatim - it can leak credentials baked
into a URL, enable log injection, or simply be noise a hostile endpoint
crafted on purpose.

:func:`summarize_error` reduces any exception to a short, safe, still
actionable summary: its class name, plus a validated *numeric* code where
the exception type provides one (``HTTPError.code``, ``smtplib.
SMTPResponseException.smtp_code``, ``OSError.errno``) - each just a small
integer the transport/OS assigns, never attacker/server-supplied free text.
Used by every alert channel (:mod:`lanfence.alerts`, :mod:`lanfence.digest`,
:mod:`lanfence.channels`) and CLI network calls that report a delivery or
fetch failure, so error reporting is uniform everywhere.
"""

from __future__ import annotations


def _numeric_code(exc: BaseException) -> int | None:
    for attr in ("code", "smtp_code", "errno"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    return None


def summarize_error(exc: BaseException) -> str:
    """A safe-to-log-or-display one-line summary of ``exc`` - its class
    name, plus a validated numeric code (see the module docstring) where
    available. Never touches ``str(exc)``/``exc.args`` or any other
    exception attribute that might carry server-controlled text,
    credentials, a full URL, or recipient details.
    """

    name = exc.__class__.__name__
    code = _numeric_code(exc)
    return f"{name} (code {code})" if code is not None else name
