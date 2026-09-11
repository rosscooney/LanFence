<!--
Copyright (c) 2026-present Stable State Consulting Ltd
SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to LAN Fence are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).
Each release is also published to
[PyPI](https://pypi.org/project/lanfence/) and tagged on
[GitHub](https://github.com/rosscooney/lanfence/releases).

## [Unreleased]

## [0.2.0] - 2026-09-11

### Added

- `lanfence upgrade` - checks PyPI directly for a newer release (so a stale
  local pip index cache can't hide it), works out how this copy was installed
  (`pipx`, plain `pip`/venv, or an editable source checkout) and runs the
  matching upgrade command. For a `pipx` install this runs
  `pipx upgrade lanfence --pip-args=--no-cache-dir`, bypassing the cache for
  that one upgrade so a release that just published on PyPI is never masked
  by a stale cached wheel. `--check` reports whether an update is available
  (exit code `10`) without installing it. Running as root against a `pipx`
  install (e.g. `sudo lanfence upgrade`) correctly drops back to the
  invoking/owning user via `sudo -u`, since a pipx venv lives in a user's
  home and is invisible to `pipx` run as root.

## [0.1.1] - 2026-09-11

### Changed

- Recommended install is now the single command `pipx install "lanfence[scan]"`
  (previously `pipx install lanfence` followed by a separate
  `pipx inject lanfence 'lanfence[scan]'`, which a real-world install missed -
  `lanfence check` reported scapy missing after a plain `pipx install
  lanfence`). The "scapy is not installed" messages in `lanfence check` and
  the scanner now suggest `pipx inject lanfence scapy` for an existing
  install, alongside the `pip install` form.

## [0.1.0] - 2026-09-11

Initial release. MVP scope: ARP scanning (active + passive), MAC tracking, an
allowlist, basic device fingerprinting, CLI + JSON output, and syslog/email/
webhook alerting.

### Added

- `lanfence scan` - one-time active ARP sweep of the local subnet (auto-
  detected, or `--interface`/`--subnet`); records every device to a
  persistent SQLite database and prints a device table plus any findings.
- `lanfence monitor` - continuous watch: repeats an active ARP sweep on an
  interval (`scan.scan_interval_seconds`) and, in parallel, passively sniffs
  ARP traffic between sweeps for lower-latency detection of a device that
  joins mid-interval. Runs until interrupted (Ctrl+C).
- `lanfence allow <mac>` / `--list` / `--remove` - manage a YAML allowlist of
  devices you trust; findings about an allowlisted device are downgraded to
  `info` instead of alerting every time it reconnects.
- `lanfence report --since <30m|24h|7d>` - summarizes connect/disconnect/
  reappear events and findings recorded in the database over a time window,
  for scheduled (cron/systemd-timer) daily or weekly reports.
- `lanfence check` - verifies the host can run LAN Fence: root/raw-socket
  access, whether `scapy` is installed, interface/subnet auto-detection, and
  that the database path is writable.
- Device lifecycle tracking (`new_device` / `reappeared` / `disconnected`)
  persisted to SQLite, keyed by MAC address.
- Built-in device fingerprinting: a curated offline OUI → vendor table
  (`lanfence/data/oui_vendors.txt`) plus a rogue-device signature set
  (`lanfence/data/rogue_signatures.yaml`) covering Espressif (ESP32/ESP8266 -
  common in DIY hidden cameras and Wi-Fi implants), Raspberry Pi hardware,
  USB-Ethernet gadget chipsets, and hostname signatures for Pwnagotchi, Hak5
  Bash Bunny/LAN Turtle/WiFi Pineapple, Flipper Zero and O.MG Cable. Both
  files are extensible via `vendor_file:` / `rogue_signatures_file:` in
  config. A locally-administered (randomized/spoofed) MAC is flagged on its
  own as a low-grade signal.
- Plain-language findings with `high` / `medium` / `info` severity, a
  rationale, a recommendation, and supporting evidence lines.
- Alert dispatch to syslog, email (SMTP) and/or a webhook (JSON POST), gated
  by `alerts.min_severity`; `--alert` on `scan`/`monitor` triggers dispatch.
- JSON export (`--format json`) on `scan` and `report`, and
  `--fail-on-findings` exit codes (`0`/`10`/`20` for info/medium/high) for CI
  use.
- YAML configuration (`--config`) for scan settings, alert channels, database
  path, allowlist path, and extra vendor/signature files.
- No telemetry and no calls to any third-party service; every network
  destination (syslog target, SMTP host, webhook URL) is one the operator
  configures themselves.

[Unreleased]: https://github.com/rosscooney/lanfence/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rosscooney/lanfence/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/rosscooney/lanfence/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rosscooney/lanfence/releases/tag/v0.1.0
