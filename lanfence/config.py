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

    @field_validator("scan_interval_seconds", "active_scan_timeout_seconds", "dns_timeout_seconds")
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
    #: Cap on how many devices are listed per digest section before
    #: truncating with an explicit "and N more".
    max_devices_per_section: int = 20

    @field_validator("channels")
    @classmethod
    def _valid_channels(cls, value: list[str]) -> list[str]:
        for name in value:
            if name not in DIGEST_CHANNELS:
                raise ValueError(
                    f"unsupported digest channel {name!r}; must be one of {', '.join(DIGEST_CHANNELS)}"
                )
        return value

    @field_validator("max_devices_per_section")
    @classmethod
    def _positive_section_limit(cls, value: int) -> int:
        if value < 1:
            raise ValueError("max_devices_per_section must be an integer >= 1")
        return value


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


class Config(BaseModel):
    model_config = {"extra": "forbid"}

    scan: ScanConfig = Field(default_factory=ScanConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    digest: DigestConfig = Field(default_factory=DigestConfig)
    dhcp_servers: DhcpServerConfig = Field(default_factory=DhcpServerConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    #: Where the persistent device database lives.
    db_path: Path = Path("~/.local/share/lanfence/lanfence.db")
    #: YAML allowlist of trusted devices; findings about them are downgraded to info.
    allowlist_file: Path = Path("~/.config/lanfence/allowlist.yaml")
    #: Extra vendor OUI table, merged with the packaged one.
    vendor_file: Path | None = None
    #: Extra rogue-device signatures, merged with the packaged ones.
    rogue_signatures_file: Path | None = None

    @classmethod
    def load(cls, path: Path | str | None) -> "Config":
        """Load configuration from a YAML file, or return defaults if ``path`` is None."""

        if path is None:
            return cls()
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
        return self.db_path.expanduser()

    def resolved_allowlist_file(self) -> Path:
        return self.allowlist_file.expanduser()

    def as_metadata(self) -> dict[str, Any]:
        """A JSON-serialisable snapshot of the effective config for the report."""

        return self.model_dump(mode="json")
