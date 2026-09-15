# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Staged application settings inside the existing communications wizard."""
from __future__ import annotations

from copy import deepcopy
import ipaddress
import math
from pathlib import Path
import re
import sqlite3
from typing import Literal, get_args, get_origin

from pydantic import TypeAdapter, ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import typer

from lanfence.channels import (
    CHANNEL_NAMES, CHANNEL_FIELDS, apply_channel_values, apply_digest_selection,
    check_insecure_permissions, list_channel_statuses, supports_digest,
    validate_channel_values,
)
from lanfence.config import Config, ApprovedDhcpServer, DIGEST_CHANNELS
from lanfence.sanitize import clean_text

# Only real model fields appear here; field types/defaults stay in config.py.
SECTIONS = {
    "Scanning": [f"scan.{name}" for name in type(Config().scan).model_fields if not name.startswith("offline_")],
    "Offline detection": ["scan.offline_grace_seconds", "scan.offline_after_missed_scans"],
    "DHCP servers": ["dhcp_servers.enabled", "dhcp_servers.alert_cooldown_seconds"],
    "Service discovery": ["discovery.mdns", "discovery.ssdp"],
    "Daily digest": ["digest.channels", "digest.send_when_empty"],
    "Storage": ["db_path", "allowlist_file", "vendor_file", "rogue_signatures_file"],
    "Alert delivery": ["alerts.min_severity", "alerts.rate_limit_seconds"],
}
MISSING = object()


def value_at(raw, path, default=MISSING):
    value = raw
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def patch_value(raw, path, value=MISSING):
    result = deepcopy(raw)
    node = result
    parts = path.split(".")
    parents = []
    for part in parts[:-1]:
        parents.append((node, part))
        node = node.setdefault(part, {})
    if value is MISSING:
        node.pop(parts[-1], None)
        for parent, key in reversed(parents):
            if not parent[key]:
                del parent[key]
    else:
        node[parts[-1]] = value
    return result


def field_info(path):
    model = Config
    for part in path.split("."):
        field = model.model_fields[part]
        model = field.annotation
    return field


def safe_value(value):
    if value is MISSING:
        return "[inherited default]"
    if value is None:
        return "null (auto/unset)"
    return clean_text(str(value), max_len=300)


def validation_errors(raw, *, complete=False):
    try:
        cfg = Config.model_validate(raw)
    except ValidationError as exc:
        # Pydantic messages and input snapshots can contain passwords/URLs.
        return [f"{'.'.join(map(str, e['loc']))}: {e['type']}" for e in exc.errors()]
    errors = []
    for path in sum(SECTIONS.values(), []):
        value = value_at(cfg.model_dump(mode="json"), path)
        if isinstance(value, float) and not math.isfinite(value):
            errors.append(f"{path}: must be finite")
    if cfg.scan.subnet:
        try:
            ipaddress.IPv4Network(cfg.scan.subnet, strict=False)
        except ValueError:
            errors.append("scan.subnet: enter an IPv4 CIDR subnet")
    if cfg.scan.interface is not None and not cfg.scan.interface.strip():
        errors.append("scan.interface: must not be blank; use null for auto")
    if complete:
        for channel in CHANNEL_NAMES:
            values = getattr(cfg.alerts, channel).model_dump()
            if values["enabled"] and validate_channel_values(channel, values):
                errors.append(f"alerts.{channel}: invalid or incomplete enabled destination; edit Communications")
    return errors


def warnings_for(cfg):
    warnings = []
    if cfg.dhcp_servers.enabled:
        if not cfg.scan.passive or not cfg.scan.dhcp_snooping:
            warnings.append("DHCP server detection is inactive: enable passive capture and DHCP snooping.")
        if not cfg.dhcp_servers.approved:
            warnings.append("No DHCP servers approved: every observed server identifier will be unexpected.")
    if not cfg.scan.passive and (cfg.discovery.mdns or cfg.discovery.ssdp):
        warnings.append("Service discovery is inactive while passive capture is disabled.")
    for name in cfg.digest.channels:
        if not getattr(cfg.alerts, name).enabled:
            warnings.append(f"Digest destination {name} is disabled; delivery to it is inactive.")
    return warnings


def diff_lines(before, after):
    lines = []
    paths = sum(SECTIONS.values(), []) + ["dhcp_servers.approved"]
    for channel in CHANNEL_NAMES:
        paths += [f"alerts.{channel}.{f.name}" for f in CHANNEL_FIELDS[channel]]
        paths.append(f"alerts.{channel}.enabled")
    for path in paths:
        old, new = value_at(before, path), value_at(after, path)
        if old == new:
            continue
        if path == "dhcp_servers.approved":
            old_rows = [] if old is MISSING else old
            new_rows = [] if new is MISSING else new
            for row in old_rows:
                if row not in new_rows:
                    lines.append(f"{path}: removed {safe_value(row)}")
            for row in new_rows:
                if row not in old_rows:
                    lines.append(f"{path}: added {safe_value(row)}")
            if new is MISSING:
                lines.append(f"{path}: reset to default")
            continue
        # All channel field values are hidden in diffs, including extension-like URLs.
        if path.startswith("alerts.") and len(path.split(".")) == 3 and not path.endswith(".enabled"):
            old_text = "[configured]" if old is not MISSING and old is not None else "[not configured]"
            new_text = "[replaced]" if new is not MISSING and new is not None else "[cleared/default]"
        else:
            old_text, new_text = safe_value(old), safe_value(new)
        action = "reset to default" if new is MISSING else "added" if old is MISSING else "edited"
        lines.append(f"{path} ({action}): {old_text} → {new_text}")
    return lines


def parse_field(path, text):
    field = field_info(path)
    annotation = field.annotation
    if text == "null":
        return TypeAdapter(annotation).validate_python(None)
    if get_origin(annotation) is Literal:
        text = text.lower()
    if get_origin(annotation) is list:
        text = [part.strip() for part in text.split(",") if part.strip()]
    elif isinstance(text, str) and path.endswith("seconds"):
        match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd])", text)
        if match:
            text = float(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    value = TypeAdapter(annotation).validate_python(text)
    return str(value) if isinstance(value, Path) else value


def edit_field(raw, path):
    cfg = Config.model_validate(raw).model_dump(mode="json")
    typer.echo(f"{path}: {safe_value(value_at(cfg, path))}")
    typer.echo("Origin: " + ("inherited default" if value_at(raw, path) is MISSING else "explicit configuration"))
    field = field_info(path)
    if path.endswith("seconds"):
        typer.echo("Seconds; also accepts durations such as 30s, 5m, 2h. Zero only where supported.")
    if field.annotation is int:
        typer.echo("Enter a whole number >= 1.")
    if field.annotation is bool:
        typer.echo("Allowed: yes / no")
    elif get_origin(field.annotation) is Literal:
        typer.echo("Allowed: " + ", ".join(get_args(field.annotation)))
    elif path == "digest.channels":
        typer.echo("Comma-separated destinations: " + ", ".join(DIGEST_CHANNELS))
    if type(None) in get_args(field.annotation):
        typer.echo("Type null for explicit auto/unset; reset removes the key to inherit its default.")
    typer.echo(f"Default: {safe_value(field.get_default(call_default_factory=True))}")
    if path in SECTIONS["Storage"]:
        typer.echo("Changing a path does not move or copy data. No files are created until normal use.")
    while True:
        answer = typer.prompt("Value (blank keeps it; reset = default; back = return)", default="", show_default=False).strip()
        if not answer or answer == "back":
            return raw
        try:
            candidate = patch_value(raw, path, MISSING if answer == "reset" else parse_field(path, answer))
            errors = validation_errors(candidate)
        except (ValueError, TypeError):
            errors = [f"{path}: invalid value for this setting"]
        if errors:
            for error in errors:
                typer.echo(error)
            continue
        return candidate


def observed_servers(cfg):
    """Read-only SQLite connection: no DeviceStore initialization/migrations."""
    path = cfg.resolved_db_path().absolute()
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
    try:
        connection.row_factory = sqlite3.Row
        return [dict(r) for r in connection.execute(
            "SELECT interface, server_id, last_source_ip, last_relay_ip, last_seen FROM dhcp_servers ORDER BY interface, server_id"
        ).fetchall()]
    finally:
        connection.close()


def edit_approvals(raw):
    while True:
        entries = deepcopy(value_at(raw, "dhcp_servers.approved", []))
        typer.echo("\nApproved DHCP servers (role approval, separate from device trust)")
        for i, row in enumerate(entries, 1):
            typer.echo(f"{i}  {safe_value(row.get('name', ''))}  {safe_value(row['interface'])}  {safe_value(row['server_ip'])}")
        action = typer.prompt("Add / Edit / Remove / Observed / Reset / Back", default="back").lower()
        if action == "back":
            return raw
        if action == "reset":
            if typer.confirm("Remove explicit approvals and inherit the default empty list?", default=False):
                raw = patch_value(raw, "dhcp_servers.approved")
            continue
        row = {}
        index = None
        if action in ("edit", "remove"):
            number = typer.prompt("Entry number", type=int)
            if not 1 <= number <= len(entries):
                typer.echo("No such entry.")
                continue
            index = number - 1
            row = entries[index]
            if action == "remove":
                if typer.confirm(f"Remove {safe_value(row)}?", default=False):
                    entries.pop(index)
                    raw = patch_value(raw, "dhcp_servers.approved", entries)
                continue
        elif action == "observed":
            try:
                records = observed_servers(Config.model_validate(raw))
            except (OSError, sqlite3.Error):
                typer.echo("Observed inventory unavailable; use Add for manual entry.")
                continue
            for i, record in enumerate(records, 1):
                typer.echo(f"{i}  {safe_value(record)}")
            if not records:
                typer.echo("No observed servers; use Add for manual entry.")
                continue
            number = typer.prompt("Observed entry number (0 cancels)", type=int, default=0)
            if not 1 <= number <= len(records):
                continue
            record = records[number - 1]
            row = {"interface": record['interface'], "server_ip": record['server_id']}
        elif action != "add":
            typer.echo("Choose Add, Edit, Remove, Observed, Reset, or Back.")
            continue
        typer.echo("server_ip is DHCP option 54, not necessarily the source or relay. Interface scopes approval (e.g. eth0.20).")
        proposal = dict(row)
        for key in ("name", "interface", "server_ip"):
            proposal[key] = typer.prompt(key, default=row.get(key, ""), show_default=True).strip()
        try:
            ApprovedDhcpServer.model_validate(proposal)
            if index is None:
                entries.append(proposal)
            else:
                entries[index] = proposal
            candidate = patch_value(raw, "dhcp_servers.approved", entries)
            errors = validation_errors(candidate)
        except ValidationError:
            errors = ["Enter a nonempty interface and valid IPv4 server identifier."]
        if errors:
            typer.echo("Invalid approval (check duplicates, interface and IPv4 identifier).")
        elif typer.confirm(f"Stage approval {safe_value(proposal)}?", default=False):
            raw = candidate


def edit_section(raw, section):
    while True:
        cfg = Config.model_validate(raw).model_dump(mode="json")
        for i, path in enumerate(SECTIONS[section], 1):
            origin = "default" if value_at(raw, path) is MISSING else "explicit"
            typer.echo(f"{i}  {path}: {safe_value(value_at(cfg, path))} ({origin})")
        if section == "DHCP servers":
            typer.echo("a  Approved DHCP servers")
        choice = typer.prompt("Setting number, or back", default="back").lower()
        if choice == "back":
            return raw
        if choice == "a" and section == "DHCP servers":
            raw = edit_approvals(raw)
        elif choice.isdigit() and 1 <= int(choice) <= len(SECTIONS[section]):
            raw = edit_field(raw, SECTIONS[section][int(choice) - 1])
        else:
            typer.echo("Choose a listed setting.")


def stage_channel(raw):
    # Reuse channel prompts and validators, including secret keep/clear behavior.
    from lanfence import cli
    cfg = Config.model_validate(raw)
    cli.render_channels_table(list_channel_statuses(cfg))
    channel = typer.prompt("Channel name (or back)", default="back").lower()
    if channel == "back":
        return raw
    if channel not in CHANNEL_NAMES:
        typer.echo("Unknown channel.")
        return raw
    values = cli._prompt_channel_fields(channel, getattr(cfg.alerts, channel))
    cli._wizard_webhook_scheme_note(channel, values)
    values["enabled"] = typer.confirm("Enable this channel?", default=getattr(cfg.alerts, channel).enabled)
    candidate = apply_channel_values(raw, channel, values)
    # Keep inherited defaults inherited, and leave unrelated raw keys untouched.
    current = getattr(cfg.alerts, channel).model_dump()
    for key in values:
        if value_at(raw, f"alerts.{channel}.{key}") is MISSING and value_at(candidate, f"alerts.{channel}.{key}") == current.get(key):
            candidate = patch_value(candidate, f"alerts.{channel}.{key}")
    try:
        channel_values = getattr(Config.model_validate(candidate).alerts, channel).model_dump()
        errors = validate_channel_values(channel, channel_values)
    except (ValueError, TypeError):
        errors = ["invalid fields"]
    if errors:
        typer.echo(f"{channel}: invalid or incomplete settings; nothing staged. Reopen Communications to retry.")
        return raw
    if supports_digest(channel):
        selected = typer.confirm("Use this channel for daily digests too?", default=channel in cfg.digest.channels)
        if selected != (channel in cfg.digest.channels):
            candidate = apply_digest_selection(candidate, channel, selected=selected)
    typer.echo(f"{channel}: staged (not saved).")
    return candidate


def render_overview(console, path, original, draft):
    cfg = Config.model_validate(draft)
    table = Table(expand=True, box=None)
    table.add_column("Choice", no_wrap=True)
    table.add_column("Section")
    table.add_column("Effective settings")
    enabled = ", ".join(n for n in CHANNEL_NAMES if getattr(cfg.alerts, n).enabled) or "none enabled"
    summaries = [enabled, f"{cfg.scan.interface or 'auto'} · every {cfg.scan.scan_interval_seconds:g}s",
                 f"{cfg.scan.offline_grace_seconds:g}s · {cfg.scan.offline_after_missed_scans} misses",
                 f"enabled={cfg.dhcp_servers.enabled} · {len(cfg.dhcp_servers.approved)} approved",
                 f"mDNS={cfg.discovery.mdns} · SSDP={cfg.discovery.ssdp}",
                 ", ".join(cfg.digest.channels) or "no destinations", "Paths only; no data migration",
                 f"{cfg.alerts.min_severity} · cooldown {cfg.alerts.rate_limit_seconds:g}s"]
    for i, (section, summary) in enumerate(zip(["Communications", *SECTIONS], summaries), 1):
        table.add_row(str(i), section, Text(clean_text(summary, max_len=300)))
    console.print(Panel(table, title="LAN Fence setup"))
    console.print(Text(f"File: {path}\nStatus: {'Invalid' if validation_errors(draft, complete=True) else 'Valid'} · Unsaved changes: {'Yes' if draft != original else 'No'}"))
    for warning in warnings_for(cfg):
        console.print(Text("Warning: " + warning, style="yellow"))


def run_setup(path, loaded, explicit_config):
    from lanfence import cli
    console = Console()
    draft = deepcopy(loaded.raw)
    sections = ["Communications", *SECTIONS]
    while True:
        render_overview(console, path, loaded.raw, draft)
        choice = typer.prompt("Section number / Review / Save / Discard / Exit", default="exit").lower()
        exiting = choice == "exit"
        if exiting:
            if draft == loaded.raw:
                return
            choice = typer.prompt("Unsaved changes: Save / Discard / Return", default="return").lower()
            if choice == "discard":
                return
            if choice != "save":
                continue
        if choice.isdigit() and 1 <= int(choice) <= len(sections):
            section = sections[int(choice) - 1]
            draft = stage_channel(draft) if section == "Communications" else edit_section(draft, section)
        elif choice == "review":
            for line in diff_lines(loaded.raw, draft) or ["No changes."]:
                typer.echo(line)
        elif choice == "discard":
            draft = deepcopy(loaded.raw)
        elif choice == "save":
            if draft == loaded.raw:
                typer.echo("No changes; file not rewritten.")
                continue
            errors = validation_errors(draft, complete=True)
            if errors:
                typer.echo("Cannot save:\n" + "\n".join(errors))
                continue
            for line in diff_lines(loaded.raw, draft):
                typer.echo(line)
            for warning in warnings_for(Config.model_validate(draft)):
                typer.echo("Warning: " + warning)
            typer.echo("Saving rewrites YAML formatting/comments; values are preserved. Monitor needs restart with this --config path.")
            if path.is_symlink():
                typer.echo("Refusing to replace a configuration symlink; rerun with its intended target path.")
                continue
            if check_insecure_permissions(path) is not None:
                typer.echo("Saving will restrict this file to owner-only permissions (0600).")
            if not typer.confirm("Save these changes?", default=False):
                continue
            changed_channels = [n for n in CHANNEL_NAMES if value_at(loaded.raw, f"alerts.{n}") != value_at(draft, f"alerts.{n}")]
            cli._channels_new_file_notice(path, loaded.existed, explicit_config)
            try:
                cli._channels_save_or_exit(path, loaded, draft)
            except OSError:
                typer.echo(f"Could not save {path}; check permissions and rerun with the intended --config path.")
                continue
            loaded.raw = deepcopy(draft)
            loaded.raw_bytes = path.read_bytes()
            loaded.cfg = Config.model_validate(draft)
            loaded.existed = True
            for channel in changed_channels:
                if not getattr(loaded.cfg.alerts, channel).enabled:
                    continue
                if channel == "twilio":
                    typer.echo("A test SMS may incur provider charges.")
                if typer.confirm(f"Send a test message to {channel}?", default=False):
                    ok, _ = cli.send_channel_test_message(channel, loaded.cfg)
                    typer.echo(f"{channel}: {'accepted by destination' if ok else 'test failed; check destination settings'}")
            if exiting:
                return
        else:
            typer.echo("Choose a listed section or action.")
