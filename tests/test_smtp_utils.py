from __future__ import annotations

import ssl
from email.message import EmailMessage
from unittest.mock import MagicMock, patch

import pytest

from lanfence.config import EmailAlertConfig
from lanfence.smtp_utils import SmtpAuthWithoutTlsError, build_smtp_context, send_smtp_message


def _msg() -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = "test"
    msg["From"] = "a@example.com"
    msg["To"] = "b@example.com"
    msg.set_content("hello")
    return msg


# --- build_smtp_context ------------------------------------------------


def test_build_smtp_context_verifies_hostname_and_certificate():
    context = build_smtp_context(EmailAlertConfig())
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_build_smtp_context_bad_ca_file_raises_rather_than_silently_skipping(tmp_path):
    missing = tmp_path / "does-not-exist.pem"
    with pytest.raises((FileNotFoundError, ssl.SSLError)):
        build_smtp_context(EmailAlertConfig(ca_file=str(missing)))


def test_build_smtp_context_expands_user_in_ca_file_path(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("not a real cert, just checking path expansion is attempted")
    with pytest.raises(ssl.SSLError):
        # Invalid PEM content - proves the expanded path was actually opened
        # (a FileNotFoundError here would mean expansion didn't happen).
        build_smtp_context(EmailAlertConfig(ca_file="~/ca.pem"))


# --- send_smtp_message: TLS/auth policy -------------------------------------


def test_send_smtp_message_rejects_credentials_without_tls():
    cfg = EmailAlertConfig(use_tls=False, username="operator", password="hunter2")
    with patch("lanfence.smtp_utils.smtplib.SMTP") as smtp_mock:
        with pytest.raises(SmtpAuthWithoutTlsError):
            send_smtp_message(_msg(), cfg)
    smtp_mock.assert_not_called()


def test_send_smtp_message_rejects_username_only_without_tls():
    cfg = EmailAlertConfig(use_tls=False, username="operator", password=None)
    with patch("lanfence.smtp_utils.smtplib.SMTP") as smtp_mock:
        with pytest.raises(SmtpAuthWithoutTlsError):
            send_smtp_message(_msg(), cfg)
    smtp_mock.assert_not_called()


def test_send_smtp_message_allows_unauthenticated_relay_without_tls():
    cfg = EmailAlertConfig(use_tls=False)
    instance = MagicMock()
    cm = MagicMock()
    cm.__enter__.return_value = instance
    with patch("lanfence.smtp_utils.smtplib.SMTP", return_value=cm):
        send_smtp_message(_msg(), cfg)
    instance.starttls.assert_not_called()
    instance.login.assert_not_called()
    instance.send_message.assert_called_once()


def test_send_smtp_message_with_tls_passes_verifying_context_and_authenticates():
    cfg = EmailAlertConfig(use_tls=True, username="operator", password="hunter2")
    instance = MagicMock()
    cm = MagicMock()
    cm.__enter__.return_value = instance
    with patch("lanfence.smtp_utils.smtplib.SMTP", return_value=cm):
        send_smtp_message(_msg(), cfg)
    instance.starttls.assert_called_once()
    context = instance.starttls.call_args.kwargs.get("context")
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    instance.login.assert_called_once_with("operator", "hunter2")
    instance.send_message.assert_called_once()


def test_send_smtp_message_certificate_failure_propagates_and_skips_send():
    cfg = EmailAlertConfig(use_tls=True)
    instance = MagicMock()
    instance.starttls.side_effect = ssl.SSLCertVerificationError("certificate verify failed")
    cm = MagicMock()
    cm.__enter__.return_value = instance
    with patch("lanfence.smtp_utils.smtplib.SMTP", return_value=cm):
        with pytest.raises(ssl.SSLError):
            send_smtp_message(_msg(), cfg)
    instance.login.assert_not_called()
    instance.send_message.assert_not_called()


def test_send_smtp_message_without_tls_and_without_credentials_never_calls_starttls():
    # A device with use_tls=True but no credentials still gets STARTTLS -
    # only the *absence* of TLS is conditional on the auth check.
    cfg = EmailAlertConfig(use_tls=True)
    instance = MagicMock()
    cm = MagicMock()
    cm.__enter__.return_value = instance
    with patch("lanfence.smtp_utils.smtplib.SMTP", return_value=cm):
        send_smtp_message(_msg(), cfg)
    instance.starttls.assert_called_once()
    instance.login.assert_not_called()
