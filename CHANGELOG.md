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

### Added

- New rogue-device vendor signatures, each backed by a real, confirmed
  vendor string in the now-full `oui_vendors.txt`: `hisilicon_camera_soc`
  (HiSilicon Hi3516/Hi3518-family SoCs - the dominant chipset behind cheap
  white-label IP cameras/DVRs and widely reported behind the Mirai botnet
  and successors), `allwinner_sbc_or_camera` (Allwinner - budget SBCs,
  Android TV boxes, cheap Wi-Fi cameras), `orange_pi` (Shenzhen Xunlong -
  same rationale as the existing Raspberry Pi signature), and an
  `ai-thinker` vendor match folded into the existing `esp32_esp8266`
  category (Ai-Thinker modules are ESP8266/ESP32 silicon under their own
  OUI block).
- The bundled `lanfence/data/oui_vendors.txt` is now a full snapshot
  (~40,000 entries) of the IEEE's public MA-L OUI registry, up from a
  curated ~150-entry subset - fetched directly from
  `https://standards-oui.ieee.org/oui/oui.csv` and converted with the new
  `lanfence.vendor.parse_ieee_oui_csv`. Only the MA-L (24-bit block) tier is
  included; the finer-grained MA-M/MA-S tiers reassign parts of one OUI-24 to
  several different organisations, which this table's 3-octet-key format
  can't represent.
- `lanfence vendor-refresh` - downloads a current copy of that same registry
  on demand and saves it as an extra `vendor_file:` (merged on top of, never
  overwriting, the packaged table), so a device assigned an OUI after this
  copy of LAN Fence was built can still be recognised without waiting for a
  new release. This is a deliberate, operator-triggered exception to "no
  network calls" - the same pattern as `lanfence upgrade` checking PyPI - and
  runs only when explicitly invoked.

### Changed

- `bashbunny`/`lanturtle` hostname signatures corrected to `bunny`/`turtle`
  after verification found no support for the original strings and
  better - though still not officially documented - corroboration for the
  shorter ones (from Hak5's own community forum and third-party write-ups).
  Both are now `medium` rather than `high` severity, and their descriptions
  note they're not sourced from an official spec and can coincidentally
  match an unrelated device's hostname (e.g. a "TurtleBot" robotics
  platform). `pineapple` similarly downgraded to `medium` pending
  confirmation of its actual default value. `pwnagotchi` is unchanged and
  was independently confirmed against the project's own `defaults.toml`.

### Removed

- The `omg-cable` hostname signature: verification found the O.MG Cable's
  actual identifying signal is its Wi-Fi access point's SSID ("O.MG"), not a
  DHCP/mDNS hostname - something ARP-based scanning structurally can't
  observe, so the signature could never have matched anything real. The
  `flipper` hostname signature was also removed: no source (official docs,
  project source, or community forum) could be found confirming any default
  hostname/SSID for a Flipper Zero's optional Wi-Fi dev board.

### Fixed

- `lanfence upgrade` no longer reports "upgraded" when nothing actually
  changed. Both `pipx upgrade` and `pip install --upgrade` exit `0` even when
  they find nothing newer than what's already installed - which can happen
  right after a fresh release, since PyPI's package index (what `pip`
  actually resolves against) can lag a minute or two behind the JSON API this
  command checks first. It now re-reads the installed package version after
  running the upgrade command and only reports success if it actually
  changed; otherwise it says so plainly and exits `10` (same code as
  `--check` finding an update) instead of falsely claiming success. Reported
  from a real pipx install where the first `lanfence upgrade` correctly said
  "up to date" (stale JSON API) and the second said "upgraded" despite
  `pipx` itself reporting "already at latest version 0.3.3".

## [0.3.4] - 2026-09-11

### Changed

- `lanfence check` now creates an empty allowlist file (`allow: []`) if none
  exists yet, instead of just reporting "not created yet" - matching what it
  already does for the device database.

### Fixed

- `lanfence link` no longer refuses a normal pipx install on Debian /
  Raspberry Pi OS. Those default new users to `umask 002`, so a fresh pipx
  venv (`~/.local/share/pipx/venvs/lanfence/...`) is group-writable by the
  user's own primary group - a group nobody else belongs to on a typical
  single-user Pi, not a real tampering risk. `_trusted_to_run_as_root()` now
  only rejects group-writability when the group actually has another member;
  world-writable is unaffected and still rejected outright. Reported from a
  real pipx install.

## [0.3.3] - 2026-09-11

### Added

- `SECURITY.md` - private vulnerability reporting via GitHub's Security
  advisories or contributors@lanfence.com, and a scope statement specific to
  LAN Fence's attack surface (sanitisation of device-supplied hostnames/
  vendor strings, the observation-only guarantee, database/allowlist file
  handling, no unconfigured network calls, and `lanfence link`'s `sudo`
  self-elevation). Now bundled in the sdist via `MANIFEST.in`.

## [0.3.2] - 2026-09-11

### Changed

- Project homepage is now <https://lanfence.com> (`pyproject.toml` `Homepage`
  and the README); contact address is now contributors@lanfence.com.

## [0.3.1] - 2026-09-11

### Fixed

- `lanfence link`'s self-elevation (`sudo lanfence link`) could loop forever
  - repeatedly re-invoking `sudo` and re-prompting for a password - if the
  re-exec'd process still wasn't root afterward (a non-standard/wrapped
  `sudo`, an unusual configuration). It now marks the re-exec attempt via an
  environment variable and fails once with a clear error instead of retrying
  indefinitely. Found via a simulated-`sudo` test while verifying the
  escalation flow end-to-end, not reported from a real install.

## [0.3.0] - 2026-09-11

### Added

- `lanfence link` - symlinks the launcher into a directory on root's `PATH`
  (default `/usr/local/bin`, `--bin-dir` to choose) so a bare
  `sudo lanfence scan` / `sudo lanfence monitor` works. Without it, a pipx /
  `pip install --user` install (launcher in `~/.local/bin`) fails under
  `sudo` with "command not found", since `sudo` resets `PATH` to a fixed
  `secure_path`. Re-execs itself under `sudo` (prompting for a password) when
  writing to the target directory needs root; `--no-sudo` skips that,
  `--remove` undoes the link. Refuses to link (or self-escalate through) a
  launcher whose file or containing directory is group-/world-writable.

### Changed

- The "not running as root" warning on `scan`/`monitor`/`check` now prints
  copy-pasteable `sudo` commands that actually work for a pipx / `--user`
  install (`sudo <full path> …` or `sudo env "PATH=$PATH" lanfence …`,
  matching whichever `sudo lanfence …` alone would fail with "command not
  found" for), plus a pointer to `lanfence link` for a permanent fix.

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

[Unreleased]: https://github.com/rosscooney/lanfence/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/rosscooney/lanfence/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/rosscooney/lanfence/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/rosscooney/lanfence/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/rosscooney/lanfence/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/rosscooney/lanfence/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rosscooney/lanfence/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/rosscooney/lanfence/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rosscooney/lanfence/releases/tag/v0.1.0
