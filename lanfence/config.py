# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Configuration models for LAN Fence.

Configuration is layered:

1. Built-in defaults (this module).
2. An optional YAML config file (``--config``).
3. Command-line overrides.
"""

from __future__ import annotations

import ipaddress
import math
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class ScanConfig(BaseModel):
    """Network scan settings."""

    model_config = {"extra": "forbid"}

    #: Network interface to scan/sniff on. ``None`` -> auto-detect.
    interface: str | None = None
    #: CIDR subnet to actively ARP-scan, e.g. "192.168.1.0/24". ``None`` ->
    #: derive from the interface's own address.
    subnet: str | None = None
    #: How often `monitor` repeats an active ARP sweep, in seconds.
    scan_interval_seconds: float = 60.0
    #: Timeout waiting for ARP replies during one active sweep.
    active_scan_timeout_seconds: float = 3.0
    #: Also passively sniff ARP traffic between active sweeps (catches devices
    #: that would be missed between sweeps, at the cost of needing a promiscuous
    #: capture).
    passive: bool = True
    #: Also discover devices via IPv6 neighbor discovery (a multicast ping to
    #: the link-local all-nodes address), catching an IPv6-only device an
    #: ARP-only sweep would miss entirely.
    ipv6: bool = True
    #: While passive monitoring, also parse DHCP traffic for a device's
    #: self-reported hostname (option 12) - often available (and faster to
    #: get, and more reliable) than reverse-DNS, especially for a brand-new
    #: device announcing itself at join time. Only takes effect when
    #: ``passive`` is also true.
    dhcp_snooping: bool = True
    #: Try a reverse-DNS lookup for each device's hostname.
    resolve_hostnames: bool = True
    dns_timeout_seconds: float = 1.0
    #: How long a previously-online device may go unconfirmed before it can
    #: be marked offline, once ``offline_after_missed_scans`` consecutive
    #: *eligible* active sweeps have also missed it - both conditions must
    #: hold (see :func:`lanfence.db.DeviceStore.mark_offline`). "Online"
    #: during this window means "not yet confirmed absent," not necessarily
    #: still connected - a transition can only happen when an active sweep
    #: actually runs, so scan cadence (``scan_interval_seconds``) sets the
    #: soonest a device can ever be confirmed gone. ``0`` restores immediate
    #: eligibility on the elapsed-time side (pair with
    #: ``offline_after_missed_scans: 1`` for the old one-miss-and-you're-out
    #: behavior).
    offline_grace_seconds: float = 180.0
    #: Consecutive eligible missed active sweeps required before a device
    #: can be marked offline. A sweep only counts as a "miss" for a device
    #: if it actually covered that device's known discovery path(s)
    #: (interface, address family, and - for IPv4 - subnet); a failed,
    #: skipped, or out-of-scope sweep never counts, and any positive
    #: sighting (active or passive) resets the count to zero. ``1`` restores
    #: the old immediate-disconnect-on-first-miss behavior.
    offline_after_missed_scans: int = 3
    #: Before actually transitioning a device to offline (see
    #: ``offline_grace_seconds``/``offline_after_missed_scans`` above), send
    #: it one direct unicast ARP "who-has" (:func:`lanfence.scanner.arp_probe`)
    #: and count an answer as a fresh sighting instead. A subnet-wide
    #: broadcast sweep is a lot of simultaneous requests/replies at once,
    #: which a busy switch/AP or an oversubscribed device can answer
    #: unreliably under that contention even though it's genuinely still
    #: on the network - an isolated, individually-addressed retry often
    #: succeeds where the broadcast sweep's reply was lost or rate-limited.
    #: IPv4 only (ARP has no IPv6 equivalent - IPv6 devices are unaffected
    #: either way). Only ever probes a device already about to be marked
    #: offline this sweep, never every absent device on every sweep.
    offline_retry_probe: bool = True
    #: Timeout for one such probe - deliberately short (one host, not a
    #: whole subnet) so a handful of unresponsive candidates can't
    #: meaningfully delay the sweep.
    offline_retry_timeout_seconds: float = 1.0
    #: Max items buffered per passive processing queue (sightings, DHCP
    #: server observations, mDNS records, SSDP advertisements) between
    #: `monitor` drain ticks - bounds memory against a packet flood that
    #: outpaces processing. Once full, a new item is dropped (counted, not
    #: blocking the capture thread) rather than growing without limit.
    passive_queue_maxsize: int = 2000

    @field_validator("passive_queue_maxsize")
    @classmethod
    def _positive_queue_maxsize(cls, value: int) -> int:
        if value < 1:
            raise ValueError("passive_queue_maxsize must be at least 1")
        return value

    @field_validator(
        "scan_interval_seconds", "active_scan_timeout_seconds", "dns_timeout_seconds",
        "offline_retry_timeout_seconds",
    )
    @classmethod
    def _positive(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("must be greater than zero seconds")
        return value

    @field_validator("offline_grace_seconds")
    @classmethod
    def _finite_non_negative_grace(cls, value: float) -> float:
        if not math.isfinite(value) or value < 0:
            raise ValueError("offline_grace_seconds must be a finite number >= 0")
        return value

    @field_validator("offline_after_missed_scans")
    @classmethod
    def _at_least_one_missed_scan(cls, value: int) -> int:
        if value < 1:
            raise ValueError("offline_after_missed_scans must be an integer >= 1")
        return value


class SyslogAlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    address: str = "/dev/log"
    facility: str = "user"


class EmailAlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    use_tls: bool = True
    username: str | None = None
    password: str | None = None
    from_addr: str | None = None
    to_addrs: list[str] = Field(default_factory=list)
    #: Extra CA bundle (PEM file path) to trust in addition to the system
    #: trust store, for an SMTP relay with a private/internal CA - never a
    #: way to disable certificate verification itself. See
    #: :func:`lanfence.smtp_utils.build_smtp_context`.
    ca_file: str | None = None


class WebhookAlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    url: str | None = None
    timeout_seconds: float = 5.0


class SlackAlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    #: Slack "Incoming Webhook" URL (Slack app settings -> Incoming Webhooks).
    webhook_url: str | None = None
    timeout_seconds: float = 5.0


class DiscordAlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    #: Discord channel webhook URL (channel settings -> Integrations -> Webhooks).
    webhook_url: str | None = None
    timeout_seconds: float = 5.0


class TeamsAlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    #: Microsoft Teams incoming webhook URL (a channel connector or Workflow
    #: configured to accept a MessageCard-shaped POST body).
    webhook_url: str | None = None
    timeout_seconds: float = 5.0


class NtfyAlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    #: Full topic URL, e.g. "https://ntfy.sh/my-lanfence-topic" or a
    #: self-hosted server's equivalent.
    url: str | None = None
    #: ntfy priority header: min | low | default | high | urgent.
    priority: str | None = None
    timeout_seconds: float = 5.0


class TwilioAlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool = False
    account_sid: str | None = None
    #: Sensitive - treat this config file like a credential once this is set.
    auth_token: str | None = None
    #: A Twilio phone number in E.164 format, e.g. "+15551234567".
    from_number: str | None = None
    to_numbers: list[str] = Field(default_factory=list)
    timeout_seconds: float = 10.0
    #: Durable (survives a restart) daily cap on total SMS segments sent,
    #: counting every recipient and every ~153-character segment of each
    #: message - a cost-safety guardrail against a flood of findings
    #: driving unbounded SMS billing. 0 disables the budget (unlimited).
    #: See :meth:`lanfence.db.DeviceStore.consume_sms_budget`.
    max_segments_per_day: int = 200

    @field_validator("max_segments_per_day")
    @classmethod
    def _non_negative_segment_budget(cls, value: int) -> int:
        if value < 0:
            raise ValueError("max_segments_per_day must be zero or greater")
        return value


class AlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    #: Minimum severity that triggers an alert dispatch.
    min_severity: Literal["info", "medium", "high"] = "medium"
    #: Minimum time between alert dispatches for the same MAC, unless a new
    #: finding's severity is higher than what was last alerted for it (an
    #: escalation always bypasses the cooldown). 0 disables rate limiting -
    #: every qualifying finding is dispatched every time. Only throttles
    #: external channels below; the CLI/JSON output and the database are
    #: always complete.
    rate_limit_seconds: float = 900.0
    #: A *global* cap (independent of the per-MAC cooldown above) on how
    #: many external alert dispatches may fire within
    #: ``global_rate_limit_window_seconds`` - bounds total alert volume
    #: even when many distinct/rotating identities (e.g. randomized MACs)
    #: each individually pass their own per-MAC cooldown. 0 disables it.
    global_rate_limit_max: int = 20
    global_rate_limit_window_seconds: float = 60.0
    syslog: SyslogAlertConfig = Field(default_factory=SyslogAlertConfig)
    email: EmailAlertConfig = Field(default_factory=EmailAlertConfig)
    webhook: WebhookAlertConfig = Field(default_factory=WebhookAlertConfig)
    slack: SlackAlertConfig = Field(default_factory=SlackAlertConfig)
    discord: DiscordAlertConfig = Field(default_factory=DiscordAlertConfig)
    teams: TeamsAlertConfig = Field(default_factory=TeamsAlertConfig)
    ntfy: NtfyAlertConfig = Field(default_factory=NtfyAlertConfig)
    twilio: TwilioAlertConfig = Field(default_factory=TwilioAlertConfig)

    @field_validator("rate_limit_seconds")
    @classmethod
    def _non_negative_rate_limit(cls, value: float) -> float:
        if value < 0:
            raise ValueError("rate_limit_seconds must be zero or greater")
        return value

    @field_validator("global_rate_limit_max")
    @classmethod
    def _non_negative_global_max(cls, value: int) -> int:
        if value < 0:
            raise ValueError("global_rate_limit_max must be zero or greater")
        return value

    @field_validator("global_rate_limit_window_seconds")
    @classmethod
    def _non_negative_global_window(cls, value: float) -> float:
        if value < 0:
            raise ValueError("global_rate_limit_window_seconds must be zero or greater")
        return value


#: Digest delivery reuses these alert destinations. SMS (Twilio) and syslog
#: are deliberately excluded from the first version of digest delivery - see
#: ``lanfence/digest.py``.
DIGEST_CHANNELS: tuple[str, ...] = ("email", "webhook", "slack", "discord", "teams", "ntfy")


class DigestConfig(BaseModel):
    """`lanfence digest` settings - a periodic summary, independent of the
    immediate-alert pipeline above (its own destinations, no interaction
    with ``alerts.min_severity`` or per-MAC cooldowns)."""

    model_config = {"extra": "forbid"}

    #: Which of the existing alert destinations also receive a digest when
    #: `--send` is used with no `--channel` override. Enabling a channel
    #: under `alerts:` does NOT by itself add it here - a digest is opt-in
    #: per destination.
    channels: list[str] = Field(default_factory=list)
    #: Send even when the digest has no window activity, no outstanding
    #: review/investigation items, and no missing always-on devices.
    send_when_empty: bool = False

    @field_validator("channels")
    @classmethod
    def _valid_channels(cls, value: list[str]) -> list[str]:
        for name in value:
            if name not in DIGEST_CHANNELS:
                raise ValueError(
                    f"unsupported digest channel {name!r}; must be one of {', '.join(DIGEST_CHANNELS)}"
                )
        return value


class SiteConfig(BaseModel):
    """An optional label for *which* LAN this installation is watching -
    useful once you run more than one LAN Fence instance (different sites,
    sides of a building, or client networks) and need to tell their alerts,
    digests, and monitor sessions apart at a glance. Purely descriptive:
    never validated against reality, never affects scanning/matching
    behaviour, and both fields may be left unset."""

    model_config = {"extra": "forbid"}

    name: str | None = None
    location: str | None = None


class WebConfig(BaseModel):
    """`lanfence web`'s local device-browsing/labeling portal - see
    ``lanfence/web.py``. Configured entirely through `lanfence setup`'s Web
    portal section (there is no separate `lanfence web set-password` or
    similar command) - `lanfence web` only starts the server this section
    already describes, and refuses to start if ``enabled`` is false or no
    password has been set yet.

    ``password_hash``/``password_salt`` are a salted ``hashlib.scrypt``
    digest, never the password itself - the same "never store the literal
    secret in memory/logs longer than needed" posture as every other
    credential this project handles."""

    model_config = {"extra": "forbid"}

    enabled: bool = False
    #: High by default so the portal never needs root to bind - unlike
    #: scanning, nothing here needs a raw socket or a privileged port.
    port: int = 8080
    password_hash: str | None = None
    password_salt: str | None = None

    @field_validator("port")
    @classmethod
    def _valid_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("port must be between 1 and 65535")
        return value

    @model_validator(mode="after")
    def _hash_and_salt_paired(self) -> "WebConfig":
        if (self.password_hash is None) != (self.password_salt is None):
            raise ValueError("password_hash and password_salt must both be set, or both left unset")
        return self


class ApprovedDhcpServer(BaseModel):
    """One DHCP server approved to answer on a given interface.

    ``interface`` is the sole network scope - a VLAN sub-interface (e.g.
    ``eth0.20``) is just its own interface name at the OS level, so it's
    already supported with no separate VLAN field; this project does not
    parse raw 802.1Q tags from captured frames, so it makes no VLAN-isolation
    claim beyond what the configured interface name itself expresses.
    """

    model_config = {"extra": "forbid"}

    interface: str
    #: DHCP option 54 (server identifier) this server answers with.
    server_ip: str
    name: str = ""

    @field_validator("interface")
    @classmethod
    def _nonempty_interface(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("interface must not be empty")
        return value

    @field_validator("server_ip")
    @classmethod
    def _valid_ipv4(cls, value: str) -> str:
        try:
            ipaddress.IPv4Address(value)
        except ValueError as exc:
            raise ValueError(f"server_ip must be a valid IPv4 address, got {value!r}") from exc
        return value


class DhcpServerConfig(BaseModel):
    """`lanfence dhcp-servers` / unexpected-DHCP-server detection settings.

    Purely opt-in and observation-only: enabling this only changes which
    *already-captured* DHCP replies (passive DHCP capture must itself be on
    - see ``scan.passive``/``scan.dhcp_snooping``) get checked against
    ``approved`` and turned into a finding; it never sends DHCP traffic.
    """

    model_config = {"extra": "forbid"}

    enabled: bool = False
    approved: list[ApprovedDhcpServer] = Field(default_factory=list)
    #: Minimum time between repeated "unexpected DHCP server" findings for
    #: the same (interface, server identifier) pair, so a flood of replies
    #: from one unapproved server doesn't flood findings/alerts.
    alert_cooldown_seconds: float = 3600.0

    @field_validator("alert_cooldown_seconds")
    @classmethod
    def _finite_non_negative_cooldown(cls, value: float) -> float:
        if not math.isfinite(value) or value < 0:
            raise ValueError("alert_cooldown_seconds must be a finite number >= 0")
        return value

    @model_validator(mode="after")
    def _no_duplicate_approvals(self) -> "DhcpServerConfig":
        seen: set[tuple[str, str]] = set()
        for entry in self.approved:
            key = (entry.interface, entry.server_ip)
            if key in seen:
                raise ValueError(
                    f"duplicate approved DHCP server entry: interface={entry.interface!r} "
                    f"server_ip={entry.server_ip!r}"
                )
            seen.add(key)
        return self


class DiscoveryConfig(BaseModel):
    """Passive advertised-service discovery (mDNS/DNS-SD, SSDP/UPnP) - see
    :mod:`lanfence.discovery`. Both protocols are opt-in and observation-
    only: enabling either only changes what LAN Fence *parses* out of
    traffic already being captured; it never sends an mDNS query, an SSDP
    M-SEARCH request, or any other discovery traffic.

    Effective only when ``scan.passive`` is also true - there is no
    separate "discovery capture," only a narrow extension of the existing
    passive capture filter for UDP ports 5353 (mDNS) and 1900 (SSDP). An
    ``mdns``/``ssdp: true`` with ``scan.passive: false`` is a valid but
    inert combination (``monitor`` prints a warning rather than silently
    doing nothing - see ``lanfence/cli.py``). Config is read once at
    ``monitor`` startup, same as every other ``scan.*``/``discovery.*``
    setting - a change here needs a monitor restart to take effect.
    """

    model_config = {"extra": "forbid"}

    mdns: bool = False
    ssdp: bool = False


def _operator_home() -> Path | None:
    """The invoking operator's home directory, even when running as root
    via ``sudo`` - ``sudo`` resets ``$HOME`` to root's home by default
    (Debian/Ubuntu's stock sudoers: ``env_reset`` + ``always_set_home``),
    so a bare :meth:`Path.expanduser` under ``sudo lanfence scan``/
    ``monitor`` would otherwise silently resolve every ``~``-relative
    default below to ``/root`` while a plain, unprivileged `lanfence
    devices`/`review`/`allow` resolves the *same* ``~`` to the real
    operator's home - two different files, no error, and every
    previously-seen device apparently gone (or ``reset`` in one seeming
    to have no effect in the other).

    ``None`` unless running as root *via sudo* with ``SUDO_USER`` naming a
    real, different local account - a genuine root login or system service
    is left alone, since there ``/root`` legitimately is the operator's
    home."""

    if os.geteuid() != 0:
        return None
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or sudo_user == "root":
        return None
    try:
        import pwd

        return Path(pwd.getpwnam(sudo_user).pw_dir)
    except (KeyError, ImportError):  # not a real local account / non-POSIX
        return None


def expand_operator_path(path: Path) -> Path:
    """Expand a leading ``~`` in ``path`` against :func:`_operator_home`
    rather than blindly trusting ``$HOME`` - see its docstring. Anything
    else (an absolute path, a relative path with no ``~``, or an explicit
    ``~otheruser/...`` reference) is left to :meth:`Path.expanduser`'s
    ordinary behavior."""

    text = str(path)
    if text != "~" and not text.startswith("~/"):
        return path.expanduser()
    home = _operator_home()
    if home is None:
        return path.expanduser()
    return home if text == "~" else home / text[2:]


class RetentionConfig(BaseModel):
    """Bounds on how much attacker-controlled data (spoofed/rotating
    identities, flooded advertisements) the database can accumulate,
    independent of the time-based expiry already applied to passive
    discovery evidence - see :class:`lanfence.db.DeviceStore`'s
    ``max_evidence_rows_per_mac``/``max_dhcp_server_findings``/
    ``max_discovery_rows_per_table`` constructor parameters, which these
    values are passed into by `scan`/`monitor`."""

    model_config = {"extra": "forbid"}

    #: Max retained address/name evidence rows kept per MAC - oldest (by
    #: last_seen) pruned first once exceeded.
    max_evidence_rows_per_mac: int = 100
    #: Max total DHCP-server-finding rows retained - oldest pruned first.
    max_dhcp_server_findings: int = 5000
    #: Max total rows retained per passive-discovery table (mDNS/SSDP) -
    #: oldest (by last_seen) pruned first, on top of (not instead of) the
    #: existing time-based expiry.
    max_discovery_rows_per_table: int = 5000

    @field_validator("max_evidence_rows_per_mac", "max_dhcp_server_findings", "max_discovery_rows_per_table")
    @classmethod
    def _at_least_one(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be at least 1")
        return value


#: LAN Fence's one conventional per-user config file location. Every
#: command consults this when ``--config`` isn't given and it exists - so a
#: setting saved via ``lanfence setup`` (which writes here by default) takes
#: effect everywhere, not only for commands that were given ``--config``
#: explicitly. With no ``--config`` and no file here, built-in defaults are
#: used and no file is touched.
DEFAULT_CONFIG_PATH = Path("~/.config/lanfence/config.yaml")


class Config(BaseModel):
    model_config = {"extra": "forbid"}

    site: SiteConfig = Field(default_factory=SiteConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    digest: DigestConfig = Field(default_factory=DigestConfig)
    dhcp_servers: DhcpServerConfig = Field(default_factory=DhcpServerConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    #: Where the persistent device database lives.
    db_path: Path = Path("~/.local/share/lanfence/lanfence.db")
    #: YAML allowlist of trusted devices; findings about them are downgraded to info.
    allowlist_file: Path = Path("~/.config/lanfence/allowlist.yaml")
    #: Extra vendor OUI table, merged with the packaged one.
    vendor_file: Path | None = None
    #: Extra rogue-device signatures, merged with the packaged ones.
    rogue_signatures_file: Path | None = None
    #: Extra Know Your Network identity rules, merged with the packaged ones.
    identity_rules_file: Path | None = None

    @classmethod
    def load(cls, path: Path | str | None) -> "Config":
        """Load configuration from a YAML file.

        With no ``path``, falls back to :data:`DEFAULT_CONFIG_PATH` when it
        exists - the same file `lanfence setup` writes to by default - so a
        setting saved there is picked up everywhere without needing
        ``--config`` on every command. Otherwise (no ``path``, and no file at
        that default location) returns built-in defaults, touching no file.
        """

        if path is None:
            default = expand_operator_path(DEFAULT_CONFIG_PATH)
            if not default.is_file():
                return cls()
            path = default
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"config file not found: {path}")
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise ValueError("config file must contain a YAML mapping at the top level")
        return cls.model_validate(raw)

    def resolved_db_path(self) -> Path:
        return expand_operator_path(self.db_path)

    def resolved_allowlist_file(self) -> Path:
        return expand_operator_path(self.allowlist_file)

    def as_metadata(self) -> dict[str, Any]:
        """A JSON-serialisable snapshot of the effective config for the report."""

        return self.model_dump(mode="json")
