# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Configuration models for LAN Fence.

Configuration is layered:

1. Built-in defaults (this module).
2. An optional YAML config file (``--config``).
3. Command-line overrides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator


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
    #: Try a reverse-DNS lookup for each device's hostname.
    resolve_hostnames: bool = True
    dns_timeout_seconds: float = 1.0

    @field_validator("scan_interval_seconds", "active_scan_timeout_seconds", "dns_timeout_seconds")
    @classmethod
    def _positive(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("must be greater than zero seconds")
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


class AlertConfig(BaseModel):
    model_config = {"extra": "forbid"}

    #: Minimum severity that triggers an alert dispatch (syslog/email/webhook).
    min_severity: Literal["info", "medium", "high"] = "medium"
    syslog: SyslogAlertConfig = Field(default_factory=SyslogAlertConfig)
    email: EmailAlertConfig = Field(default_factory=EmailAlertConfig)
    webhook: WebhookAlertConfig = Field(default_factory=WebhookAlertConfig)


class Config(BaseModel):
    model_config = {"extra": "forbid"}

    scan: ScanConfig = Field(default_factory=ScanConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
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
