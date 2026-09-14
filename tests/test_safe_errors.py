from __future__ import annotations

import smtplib
import urllib.error

from lanfence.safe_errors import summarize_error

_SENTINEL = "SENTINEL_SECRET_DO_NOT_LEAK_hunter2"


def test_summarize_error_plain_exception_is_just_the_class_name():
    assert summarize_error(ValueError("boom")) == "ValueError"


def test_summarize_error_http_error_includes_status_code_never_reason():
    exc = urllib.error.HTTPError(
        url=f"https://user:{_SENTINEL}@evil.example.com/hook", code=418, msg=_SENTINEL, hdrs=None, fp=None,
    )
    result = summarize_error(exc)
    assert result == "HTTPError (code 418)"
    assert _SENTINEL not in result
    assert "evil.example.com" not in result


def test_summarize_error_smtp_response_exception_includes_code_never_message():
    exc = smtplib.SMTPResponseException(535, f"{_SENTINEL} authentication failed".encode())
    result = summarize_error(exc)
    assert result == "SMTPResponseException (code 535)"
    assert _SENTINEL not in result


def test_summarize_error_smtp_recipients_refused_never_leaks_recipient_dict():
    exc = smtplib.SMTPRecipientsRefused({f"{_SENTINEL}@example.com": (550, b"mailbox unavailable")})
    result = summarize_error(exc)
    assert result == "SMTPRecipientsRefused"
    assert _SENTINEL not in result


def test_summarize_error_oserror_with_errno_includes_errno_never_strerror():
    # OSError(errno, ...) auto-selects a specific subclass (e.g.
    # ConnectionRefusedError) when the errno maps to one on the current
    # platform - errno *values* themselves differ across platforms too
    # (111 is ECONNREFUSED on Linux, not on macOS), so assert against the
    # exception actually constructed rather than a hardcoded class name.
    exc = OSError(111, f"{_SENTINEL} connection refused")
    result = summarize_error(exc)
    assert result == f"{type(exc).__name__} (code 111)"
    assert _SENTINEL not in result


def test_summarize_error_nested_urlerror_never_touches_the_wrapped_reason():
    inner = OSError(f"{_SENTINEL} name resolution failed for evil.example.com")
    exc = urllib.error.URLError(inner)
    result = summarize_error(exc)
    assert result == "URLError"
    assert _SENTINEL not in result
    assert "evil.example.com" not in result


def test_summarize_error_never_includes_str_of_the_exception():
    """General property: whatever exception is passed, the sentinel never
    survives into the summary, even if some future exception type embeds
    it somewhere summarize_error doesn't explicitly know about."""

    class _WeirdException(Exception):
        def __str__(self) -> str:
            return f"totally unexpected {_SENTINEL} leak"

    result = summarize_error(_WeirdException("anything"))
    assert result == "_WeirdException"
    assert _SENTINEL not in result
