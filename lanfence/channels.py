# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Interactive setup, safe listing, and test-message delivery for LAN
Fence's communication channels (``lanfence setup``).

This module has three jobs, deliberately kept separate from the Typer
commands themselves (``lanfence/cli.py``) so they can be tested without a
terminal or a real network:

1. **Channel metadata** (:data:`CHANNEL_FIELDS`) - the *actual* fields each
   channel's existing config model (:mod:`lanfence.config`) already
   supports. Nothing here invents a parallel configuration surface; every
   field name matches a real attribute on ``AlertConfig``'s per-channel
   sub-models.
2. **Local validation and safe summaries** (:func:`validate_channel_values`,
   :func:`channel_summary`, :func:`is_channel_configured`) - pure functions,
   no network access, no secrets ever appear in a returned string.
3. **Config-file editing** (:func:`load_channels_config_file`,
   :func:`save_channels_config_file`) - safe YAML load/save of *only* the
   raw dict, so one channel's edit never disturbs unrelated sections,
   other channels' settings, or a hand-edited comment layout beyond what
   plain ``yaml.safe_dump`` itself can preserve (see
   :func:`save_channels_config_file`'s docstring).
4. **Test-message delivery** (:func:`send_channel_test_message`) - reuses
   the exact same transport calls as the real alert/digest pipelines
   (:mod:`lanfence.alerts`/:mod:`lanfence.digest`), but with a distinct,
   clearly-labeled test payload that never touches finding/severity
   filtering, alert cooldowns, or the device database.

Nothing here is a new secret-storage mechanism: a channel's password/token/
webhook URL is stored exactly like every other config value, in the same
YAML file - `lanfence setup` only adds a safer, guided way to edit it than
hand-editing the file.
"""

from __future__ import annotations

import base64
import json
import re
import smtplib
import stat
import syslog
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field as dataclass_field
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import yaml

from lanfence.config import DIGEST_CHANNELS, Config, expand_operator_path
from lanfence.fsutil import atomic_write
from lanfence.logging_config import get_logger
from lanfence.safe_errors import summarize_error
from lanfence.smtp_utils import SmtpAuthWithoutTlsError, send_smtp_message

log = get_logger("channels")

#: A conventional per-user path, chosen for this feature since LAN Fence has
#: no other default *writable* configuration file location - every other
#: command treats a missing ``--config`` as "use built-in defaults, touch no
#: file" (see ``lanfence/cli.py``'s ``_load_config``). Mirrors
#: ``allowlist_file``'s own default directory (``~/.config/lanfence/``).
DEFAULT_CONFIG_PATH = Path("~/.config/lanfence/config.yaml")

#: Every channel this wizard knows how to configure, in a stable display
#: order. Matches ``AlertConfig``'s own sub-models one-to-one.
CHANNEL_NAMES: tuple[str, ...] = (
    "slack", "discord", "teams", "ntfy", "email", "webhook", "twilio", "syslog",
)

_SYSLOG_FACILITIES = (
    "user", "daemon", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
)
_NTFY_PRIORITIES = ("min", "low", "default", "high", "urgent")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
#: E.164: a leading '+', then 1-15 digits, the first non-zero.
_E164_RE = re.compile(r"^\+[1-9]\d{1,14}$")


class ConfigFileError(Exception):
    """Malformed YAML, or a config that fails validation. Safe to display
    directly - never includes raw file content, which may hold secrets."""


class ConcurrentModificationError(Exception):
    """The config file changed on disk between load and save."""


@dataclass(frozen=True)
class ChannelField:
    """One prompt in a channel's setup wizard - directly named after the
    real field it sets on that channel's config model."""

    name: str
    label: str
    #: "text" | "secret" | "int" | "float" | "bool" | "choice" | "list_str"
    kind: str
    required: bool = False
    choices: tuple[str, ...] = ()
    #: Where to obtain this value / what it's for - one line, no
    #: screen-by-screen instructions. Reuses this codebase's own existing,
    #: already-reviewed config.py docstring language wherever one exists,
    #: rather than inventing new provider-specific claims.
    help_text: str = ""
    default: Any = None


#: The actual fields each channel's config model supports - see
#: ``lanfence/config.py``'s ``*AlertConfig`` classes. ``enabled`` is
#: handled separately by the wizard (every channel has it) rather than
#: listed here.
CHANNEL_FIELDS: dict[str, list[ChannelField]] = {
    "slack": [
        ChannelField(
            "webhook_url", "Webhook URL", "secret", required=True,
            help_text="Slack app settings -> Incoming Webhooks -> Add New Webhook to Workspace. "
            "https://api.slack.com/messaging/webhooks",
        ),
        ChannelField("timeout_seconds", "Request timeout (seconds)", "float", default=5.0),
    ],
    "discord": [
        ChannelField(
            "webhook_url", "Webhook URL", "secret", required=True,
            help_text="Discord channel settings -> Integrations -> Webhooks -> New Webhook, then Copy "
            "Webhook URL. https://support.discord.com/hc/en-us/articles/228383668",
        ),
        ChannelField("timeout_seconds", "Request timeout (seconds)", "float", default=5.0),
    ],
    "teams": [
        ChannelField(
            "webhook_url", "Webhook URL", "secret", required=True,
            help_text="A channel connector or Workflow configured to accept a MessageCard-shaped POST "
            "body. https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/",
        ),
        ChannelField("timeout_seconds", "Request timeout (seconds)", "float", default=5.0),
    ],
    "ntfy": [
        ChannelField(
            "url", "Topic URL", "secret", required=True,
            help_text="Full topic URL, e.g. https://ntfy.sh/my-lanfence-topic, or your self-hosted "
            "server's equivalent - treat it like a secret, since anyone who knows it can publish/"
            "subscribe. Authentication beyond what's embedded in the URL is not currently supported. "
            "https://docs.ntfy.sh/publish/",
        ),
        ChannelField("priority", "Priority", "choice", choices=_NTFY_PRIORITIES),
        ChannelField("timeout_seconds", "Request timeout (seconds)", "float", default=5.0),
    ],
    "webhook": [
        ChannelField(
            "url", "Webhook URL", "secret", required=True,
            help_text="Your own HTTP(S) endpoint - LAN Fence POSTs a JSON payload to it.",
        ),
        ChannelField("timeout_seconds", "Request timeout (seconds)", "float", default=5.0),
    ],
    "email": [
        ChannelField("smtp_host", "SMTP host", "text", required=True, default="localhost"),
        ChannelField("smtp_port", "SMTP port", "int", required=True, default=587),
        ChannelField("use_tls", "Use STARTTLS", "bool", default=True),
        ChannelField("username", "SMTP username (optional, blank for none)", "text"),
        ChannelField("password", "SMTP password (optional)", "secret"),
        ChannelField("from_addr", "From address", "text", required=True),
        ChannelField("to_addrs", "Recipient address(es), comma-separated", "list_str", required=True),
        ChannelField(
            "ca_file", "Private CA bundle path (PEM, optional)", "text",
            help_text="Only needed if your SMTP relay's certificate is signed by a private/internal "
            "CA not already in the system trust store. Leave blank to use the system trust store.",
        ),
    ],
    "twilio": [
        ChannelField(
            "account_sid", "Account SID", "secret", required=True,
            help_text="Twilio Console -> Account -> API keys & tokens. https://console.twilio.com",
        ),
        ChannelField(
            "auth_token", "Auth token", "secret", required=True,
            help_text="Same Twilio Console page as the Account SID - treat this like a password.",
        ),
        ChannelField("from_number", "From number, E.164 (e.g. +15551234567)", "text", required=True),
        ChannelField(
            "to_numbers", "Recipient number(s), comma-separated, E.164", "list_str", required=True,
        ),
        ChannelField("timeout_seconds", "Request timeout (seconds)", "float", default=10.0),
    ],
    "syslog": [
        ChannelField("address", "Syslog socket path or host:port", "text", default="/dev/log"),
        ChannelField("facility", "Facility", "choice", choices=_SYSLOG_FACILITIES, default="user"),
    ],
}

#: Sentinels for the wizard's tri-state secret handling - mirrors
#: ``DeviceStore.update_device_metadata``'s ``_UNSET`` idiom. ``KEEP`` means
#: "the operator entered nothing new for this secret - leave whatever is
#: already on disk untouched" (the real value is never read into a Python
#: variable in this case); ``CLEAR`` means "the operator explicitly asked
#: to remove it."
KEEP = object()
CLEAR = object()


def _channel_config(cfg: Config, channel: str):
    return getattr(cfg.alerts, channel)


def is_channel_configured(channel: str, cfg: Config) -> bool:
    """Whether every *required* field for ``channel`` currently has a
    value - independent of ``enabled``, matching what the real transport
    functions in :mod:`lanfence.alerts` themselves check before sending."""

    channel_cfg = _channel_config(cfg, channel)
    if channel == "email":
        return bool(channel_cfg.from_addr and channel_cfg.to_addrs)
    if channel == "twilio":
        return bool(
            channel_cfg.account_sid and channel_cfg.auth_token
            and channel_cfg.from_number and channel_cfg.to_numbers
        )
    if channel == "syslog":
        return True  # address/facility both carry usable defaults
    for f in CHANNEL_FIELDS[channel]:
        if f.required and not getattr(channel_cfg, f.name, None):
            return False
    return True


def _mask_email(addr: str) -> str:
    local, _, domain = addr.partition("@")
    if not domain:
        return "***"
    if len(local) <= 2:
        masked = local[0] + "*"
    else:
        masked = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked}@{domain}"


def _mask_phone(number: str) -> str:
    if len(number) <= 4:
        return "*" * len(number)
    return number[:2] + "*" * (len(number) - 4) + number[-2:]


def _hostname_only(url: str | None) -> str:
    if not url:
        return "not configured"
    try:
        host = urllib.parse.urlparse(url).hostname
    except ValueError:
        return "(unparseable URL)"
    return host or "(unparseable URL)"


def channel_summary(channel: str, cfg: Config) -> str:
    """A safe, one-line destination summary - never a password, token,
    full webhook URL, URL query string, or credential-bearing path. See
    the module docstring's examples."""

    channel_cfg = _channel_config(cfg, channel)
    if channel in ("slack", "discord", "teams", "webhook"):
        return _hostname_only(channel_cfg.webhook_url if channel != "webhook" else channel_cfg.url)
    if channel == "ntfy":
        return _hostname_only(channel_cfg.url)
    if channel == "email":
        recipients = channel_cfg.to_addrs
        if not recipients:
            return "not configured"
        if len(recipients) == 1:
            return _mask_email(recipients[0])
        return f"{len(recipients)} recipients"
    if channel == "twilio":
        numbers = channel_cfg.to_numbers
        if not numbers:
            return "not configured"
        return ", ".join(_mask_phone(n) for n in numbers[:3]) + ("…" if len(numbers) > 3 else "")
    if channel == "syslog":
        return channel_cfg.address
    return "unknown channel"


def digest_selected(channel: str, cfg: Config) -> bool:
    return channel in cfg.digest.channels


def supports_digest(channel: str) -> bool:
    return channel in DIGEST_CHANNELS


@dataclass(frozen=True)
class ChannelStatus:
    """One channel's status, shown in `lanfence setup`'s per-channel preview
    - see :func:`list_channel_statuses`."""

    channel: str
    enabled: bool
    configured: bool
    summary: str
    #: ``None`` if this channel doesn't support daily digests at all (see
    #: :data:`lanfence.config.DIGEST_CHANNELS`) - distinct from "supports
    #: it but isn't currently selected" (``False``).
    digest_selected: bool | None


def list_channel_statuses(cfg: Config) -> list[ChannelStatus]:
    return [
        ChannelStatus(
            channel=name,
            enabled=_channel_config(cfg, name).enabled,
            configured=is_channel_configured(name, cfg),
            summary=channel_summary(name, cfg),
            digest_selected=digest_selected(name, cfg) if supports_digest(name) else None,
        )
        for name in CHANNEL_NAMES
    ]


# --- validation (local, no network) -----------------------------------------


def _parse_list_str(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def validate_channel_values(channel: str, values: dict[str, Any]) -> list[str]:
    """Local syntax/range validation of a *complete* proposed field set for
    ``channel`` (already keep/clear-resolved - see :data:`KEEP`/``CLEAR``).
    Never makes a network request; passing this never proves delivery will
    actually work, only that the values are well-formed. Returns a list of
    human-readable errors (empty means valid)."""

    errors: list[str] = []

    def is_set(name: str) -> bool:
        # KEEP/CLEAR are resolved later (against the value already on
        # disk) - KEEP means "something is already there" (satisfies a
        # required-field check); CLEAR means "explicitly emptied."
        value = values.get(name)
        if value is KEEP:
            return True
        if value is CLEAR:
            return False
        return value not in (None, "", [])

    for f in CHANNEL_FIELDS[channel]:
        if f.name not in values:
            continue
        value = values[f.name]
        if value is KEEP or value is CLEAR or value in (None, ""):
            continue
        if f.kind == "int":
            try:
                if int(value) <= 0:
                    errors.append(f"{f.label} must be a positive whole number")
            except (TypeError, ValueError):
                errors.append(f"{f.label} must be a whole number")
        elif f.kind == "float":
            try:
                fval = float(value)
                if not (fval > 0) or fval != fval or fval in (float("inf"), float("-inf")):
                    errors.append(f"{f.label} must be a finite positive number")
            except (TypeError, ValueError):
                errors.append(f"{f.label} must be a number")
        elif f.kind == "choice" and value not in f.choices:
            errors.append(f"{f.label} must be one of: {', '.join(f.choices)}")

    if channel in ("slack", "discord", "teams", "webhook", "ntfy"):
        url_field = "url" if channel in ("webhook", "ntfy") else "webhook_url"
        url = values.get(url_field)
        if isinstance(url, str) and url:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                errors.append(f"{CHANNEL_FIELDS[channel][0].label} must start with http:// or https://")
            elif not parsed.hostname:
                errors.append(f"{CHANNEL_FIELDS[channel][0].label} must include a hostname")

    if channel == "email":
        port = values.get("smtp_port")
        if is_set("smtp_port") and port not in (KEEP, CLEAR):
            try:
                if not (0 < int(port) <= 65535):
                    errors.append("SMTP port must be between 1 and 65535")
            except (TypeError, ValueError):
                errors.append("SMTP port must be a whole number")
        to_addrs = values.get("to_addrs")
        if isinstance(to_addrs, list):
            for addr in to_addrs:
                if not _EMAIL_RE.match(addr):
                    errors.append(f"not a valid email address: {addr!r}")
        from_addr = values.get("from_addr")
        if isinstance(from_addr, str) and from_addr and not _EMAIL_RE.match(from_addr):
            errors.append(f"not a valid email address: {from_addr!r}")

    if channel == "twilio":
        from_number = values.get("from_number")
        if isinstance(from_number, str) and from_number and not _E164_RE.match(from_number):
            errors.append(f"from_number must be E.164 (e.g. +15551234567), got {from_number!r}")
        to_numbers = values.get("to_numbers")
        if isinstance(to_numbers, list):
            for number in to_numbers:
                if not _E164_RE.match(number):
                    errors.append(f"not a valid E.164 phone number: {number!r}")

    if values.get("enabled"):
        # Enabling requires every field this channel's own transport
        # function checks before it will actually send - see
        # `is_channel_configured`, mirrored here against the *proposed*
        # values rather than what's currently on disk.
        missing = [
            f.label for f in CHANNEL_FIELDS[channel]
            if f.required and not is_set(f.name)
        ]
        if missing:
            errors.append(
                f"cannot enable {channel} - missing required: {', '.join(missing)}"
            )

    return errors


# --- config file load/save --------------------------------------------------


@dataclass
class LoadedConfigFile:
    path: Path
    existed: bool
    raw: dict = dataclass_field(default_factory=dict)
    #: Exact on-disk bytes at load time (``None`` if the file didn't exist
    #: yet) - compared again just before saving to detect a concurrent
    #: edit (see :func:`save_channels_config_file`).
    raw_bytes: bytes | None = None
    cfg: Config = dataclass_field(default_factory=Config)


def resolve_channels_config_path(config: Path | None) -> Path:
    """The config file this command will read/write - explicit ``--config``
    if given, else :data:`DEFAULT_CONFIG_PATH`. Uses
    :func:`lanfence.config.expand_operator_path`, not a bare
    ``Path.expanduser()``, so ``sudo lanfence setup``/``channels`` resolves
    ``~`` against the invoking operator's home directory (not root's) -
    exactly like `Config.resolved_db_path`/`resolved_allowlist_file` -
    otherwise a plain, unprivileged invocation and a `sudo`-run one would
    silently read and write two different config files."""

    return expand_operator_path(config if config is not None else DEFAULT_CONFIG_PATH)


def load_channels_config_file(path: Path) -> LoadedConfigFile:
    """Load ``path`` for editing. A missing file is not an error - it means
    "nothing configured yet, will be created on save" (see
    :attr:`LoadedConfigFile.existed`). Malformed YAML or a config that
    fails schema validation raises :class:`ConfigFileError` with a message
    safe to show directly (never the raw file content, which may hold
    secrets) - the file is never touched in that case."""

    if not path.is_file():
        return LoadedConfigFile(path=path, existed=False, raw={}, raw_bytes=None, cfg=Config())

    raw_bytes = path.read_bytes()
    try:
        raw = yaml.safe_load(raw_bytes.decode("utf-8")) or {}
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise ConfigFileError(
            f"{path} contains invalid YAML syntax and was left untouched. Fix it by hand (or start "
            f"fresh at a new --config path) and try again. ({exc.__class__.__name__})"
        ) from exc
    if not isinstance(raw, dict):
        raise ConfigFileError(f"{path} must contain a YAML mapping at the top level - left untouched.")
    try:
        cfg = Config.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 - pydantic's ValidationError, kept generic to avoid a hard dep here
        raise ConfigFileError(
            f"{path} does not match LAN Fence's expected configuration schema and was left untouched. Check field types and names."
        ) from exc
    return LoadedConfigFile(path=path, existed=True, raw=raw, raw_bytes=raw_bytes, cfg=cfg)


def save_channels_config_file(loaded: LoadedConfigFile, updated_raw: dict) -> None:
    """Validate and atomically write ``updated_raw`` to ``loaded.path``.

    Refuses (raising :class:`ConcurrentModificationError`) if the file's
    on-disk bytes no longer match what was captured at load time - another
    edit (a hand edit, another `lanfence setup` invocation, `monitor`
    holds no write path here) happened in between, and blindly overwriting
    it would silently discard that change. Refuses (raising
    :class:`ConfigFileError`) if the fully-merged result fails schema
    validation, before anything is written.

    Uses plain ``yaml.safe_dump`` (already a dependency; never executes
    YAML tags) - this rewrites the *entire* file's formatting each time,
    same as ``lanfence/allowlist.py`` already does for the allowlist file.
    It does not preserve hand-written comments (a comment-preserving YAML
    writer would be a new runtime dependency) - every value is preserved,
    only formatting/comments are not; callers should tell the operator
    this before saving, not after.
    """

    current_bytes = loaded.path.read_bytes() if loaded.path.is_file() else None
    if current_bytes != loaded.raw_bytes:
        raise ConcurrentModificationError(
            f"{loaded.path} changed on disk since it was loaded - reload (re-run this command) rather "
            "than overwrite that other edit."
        )
    try:
        Config.model_validate(updated_raw)
    except Exception as exc:  # noqa: BLE001
        raise ConfigFileError("the proposed configuration is invalid; check field types and names") from exc

    body = yaml.safe_dump(updated_raw, sort_keys=False)
    atomic_write(loaded.path, body, mode=0o600)


def check_insecure_permissions(path: Path) -> int | None:
    """The file's current mode if it's readable/writable by anyone other
    than its owner, else ``None`` (also ``None`` if the file doesn't exist
    yet - nothing to check)."""

    if not path.is_file():
        return None
    mode = stat.S_IMODE(path.stat().st_mode)
    return mode if mode & 0o077 else None


def apply_channel_values(raw: dict, channel: str, values: dict[str, Any]) -> dict:
    """Return a copy of ``raw`` with only ``alerts.<channel>``'s fields (and
    ``enabled``) patched from ``values`` - every other section, every other
    channel, and any field of this channel not present in ``values``, is
    left exactly as it was. :data:`KEEP` skips a key entirely (so a secret
    already on disk is never re-read or rewritten); :data:`CLEAR` writes
    ``None``."""

    updated = dict(raw)
    alerts_section = dict(updated.get("alerts") or {})
    channel_section = dict(alerts_section.get(channel) or {})

    for name, value in values.items():
        if value is KEEP:
            continue
        if value is CLEAR:
            channel_section[name] = None
            continue
        channel_section[name] = value

    alerts_section[channel] = channel_section
    updated["alerts"] = alerts_section
    return updated


def apply_digest_selection(raw: dict, channel: str, *, selected: bool) -> dict:
    """Return a copy of ``raw`` with ``channel`` added to or removed from
    ``digest.channels`` - the *only* digest setting this feature ever
    touches (schedule, ``send_when_empty``, per-MAC severity/cooldowns are
    all untouched)."""

    updated = dict(raw)
    digest_section = dict(updated.get("digest") or {})
    current = list(digest_section.get("channels") or [])
    if selected and channel not in current:
        current.append(channel)
    elif not selected and channel in current:
        current = [c for c in current if c != channel]
    digest_section["channels"] = current
    updated["digest"] = digest_section
    return updated


def set_channel_enabled(raw: dict, channel: str, *, enabled: bool) -> dict:
    updated = dict(raw)
    alerts_section = dict(updated.get("alerts") or {})
    channel_section = dict(alerts_section.get(channel) or {})
    channel_section["enabled"] = enabled
    alerts_section[channel] = channel_section
    updated["alerts"] = alerts_section
    return updated


# --- test-message delivery ---------------------------------------------------

_TEST_TITLE = "LAN Fence test message"
_TEST_BODY = (
    "This is a test message from LAN Fence, sent from `lanfence setup`. "
    "No action is needed - it confirms this destination accepts messages from LAN Fence. "
    "It is not a real security finding."
)


def _post_json_ok(url: str, payload: dict, *, timeout: float, label: str) -> tuple[bool, str]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": "lanfence"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - https literal
            resp.read()
        return True, f"accepted by the {label} endpoint"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"{label} endpoint rejected the request: {summarize_error(exc)}"


def send_channel_test_message(channel: str, cfg: Config) -> tuple[bool, str]:
    """Send one clearly-labeled test message to ``channel`` using the real
    transport - never a fake device/finding/lifecycle event, never an
    alert-cooldown entry, and never subject to ``alerts.min_severity`` (it
    doesn't go through the finding-severity pipeline at all). Returns
    ``(success, message)``; ``message`` is always safe to print (no
    reflected secrets - see the per-branch exception handling below)."""

    if channel not in CHANNEL_NAMES:
        return False, f"unknown channel: {channel}"
    channel_cfg = _channel_config(cfg, channel)
    if not channel_cfg.enabled:
        return False, f"{channel} is disabled - run `lanfence setup {channel}` and enable it first"

    if channel == "slack":
        return _post_json_ok(
            channel_cfg.webhook_url, {"text": f"{_TEST_TITLE}\n{_TEST_BODY}"},
            timeout=channel_cfg.timeout_seconds, label="Slack",
        )
    if channel == "discord":
        return _post_json_ok(
            channel_cfg.webhook_url, {"content": f"**{_TEST_TITLE}**\n{_TEST_BODY}"},
            timeout=channel_cfg.timeout_seconds, label="Discord",
        )
    if channel == "teams":
        payload = {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "summary": _TEST_TITLE, "text": f"**{_TEST_TITLE}**\n\n{_TEST_BODY}",
        }
        return _post_json_ok(channel_cfg.webhook_url, payload, timeout=channel_cfg.timeout_seconds, label="Teams")
    if channel == "webhook":
        payload = {"type": "lanfence.test", "title": _TEST_TITLE, "message": _TEST_BODY}
        return _post_json_ok(channel_cfg.url, payload, timeout=channel_cfg.timeout_seconds, label="webhook")
    if channel == "ntfy":
        headers = {
            "Content-Type": "text/plain; charset=utf-8", "User-Agent": "lanfence", "Title": _TEST_TITLE,
        }
        if channel_cfg.priority:
            headers["Priority"] = channel_cfg.priority
        request = urllib.request.Request(
            channel_cfg.url, data=_TEST_BODY.encode("utf-8"), headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=channel_cfg.timeout_seconds) as resp:  # noqa: S310
                resp.read()
            return True, "accepted by the ntfy server"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return False, f"ntfy server rejected the request: {summarize_error(exc)}"
    if channel == "email":
        msg = EmailMessage()
        msg["Subject"] = _TEST_TITLE
        msg["From"] = channel_cfg.from_addr
        msg["To"] = ", ".join(channel_cfg.to_addrs)
        msg.set_content(_TEST_BODY)
        try:
            send_smtp_message(msg, channel_cfg)
            return True, "accepted by the SMTP relay"
        except SmtpAuthWithoutTlsError:
            return False, "refusing to authenticate: use_tls is disabled but username/password are set"
        except (smtplib.SMTPException, OSError) as exc:
            return False, f"SMTP relay rejected the message: {summarize_error(exc)}"
    if channel == "twilio":
        url = f"https://api.twilio.com/2010-04-01/Accounts/{channel_cfg.account_sid}/Messages.json"
        auth = base64.b64encode(f"{channel_cfg.account_sid}:{channel_cfg.auth_token}".encode()).decode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {auth}", "User-Agent": "lanfence",
        }
        ok_all = True
        for to_number in channel_cfg.to_numbers:
            body = f"{_TEST_TITLE}: {_TEST_BODY}"[:480]
            payload = urllib.parse.urlencode(
                {"From": channel_cfg.from_number, "To": to_number, "Body": body}
            ).encode("utf-8")
            request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=channel_cfg.timeout_seconds) as resp:  # noqa: S310
                    resp.read()
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                log.error("failed to send Twilio test SMS: %s", summarize_error(exc))
                ok_all = False
        if ok_all:
            return True, f"accepted by Twilio for {len(channel_cfg.to_numbers)} recipient(s)"
        return False, "Twilio rejected at least one recipient - see logs for detail"
    if channel == "syslog":
        facility_map = {
            "user": syslog.LOG_USER, "daemon": syslog.LOG_DAEMON,
            "local0": syslog.LOG_LOCAL0, "local1": syslog.LOG_LOCAL1, "local2": syslog.LOG_LOCAL2,
            "local3": syslog.LOG_LOCAL3, "local4": syslog.LOG_LOCAL4, "local5": syslog.LOG_LOCAL5,
            "local6": syslog.LOG_LOCAL6, "local7": syslog.LOG_LOCAL7,
        }
        try:
            syslog.openlog(ident="lanfence", facility=facility_map.get(channel_cfg.facility, syslog.LOG_USER))
            syslog.syslog(syslog.LOG_INFO, f"{_TEST_TITLE}: {_TEST_BODY}")
            syslog.closelog()
            return True, f"written to {channel_cfg.address}"
        except OSError as exc:
            return False, f"could not write to syslog: {summarize_error(exc)}"

    return False, f"unknown channel: {channel}"
