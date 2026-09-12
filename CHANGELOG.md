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

- **Multiple device addresses and historical names, with provenance.**
  LAN Fence now retains every address and name a device has presented,
  not just the latest - each tagged with its source (`arp`, `ipv6_nd`,
  `dhcp_ack`, or `legacy_snapshot` for pre-upgrade data; names additionally
  `dhcp_option_12`/`reverse_dns`), the interface it was seen on, and when
  it was first/most recently observed. `Device.ip`/`Device.hostname` (and
  `lanfence devices`/`device`) now show a **preferred value** computed from
  this evidence - directly-observed addresses always outrank a DHCP-
  reported lease or imported legacy data regardless of recency, and a
  DHCP-reported name always outranks reverse-DNS - rather than simply
  whatever was written most recently. A dual-stack device correctly
  retains both its IPv4 and IPv6 addresses (previously, sighting it via
  both mechanisms in the same sweep silently discarded one). A DHCP
  client's own request/offer is deliberately never trusted as address
  evidence (only a confirmed server ACK, or a direct ARP/ND observation,
  is) - it still counts as the device being alive on the network. `lanfence
  device <MAC>` shows the full retained history in new Addresses/Names
  sections (and `--format json` in new `addresses`/`names` arrays); an
  existing database's `ip`/`hostname` are imported once as
  `legacy_snapshot` evidence, timestamped as of the import (not backdated),
  the first time it's opened after upgrading.

## [0.3.9] - 2026-09-12

### Added

- **Unexpected DHCP server detection.** Passively detects a DHCPOFFER/ACK/
  NAK reply from a server not on the approved list for the interface it
  answered on - opt-in via `dhcp_servers.enabled`/`dhcp_servers.approved`,
  reusing the existing passive DHCP capture (needs `scan.passive`/
  `scan.dhcp_snooping`). Approval is scoped by interface (a VLAN
  sub-interface like `eth0.20` is already its own interface name; no raw
  802.1Q tag parsing is added or claimed) and never inferred from device
  trust - an already-allowlisted device acting as an unapproved server still
  raises this finding, and enabling detection with no approvals means every
  server seen is unexpected (never auto-approving the first responder). The
  finding has no MAC address - a DHCP server's identity is its option 54
  server identifier, not a relay's or client's Ethernet address, both of
  which are easy to conflate with the server's own identity (RFC 2131) -
  `Finding.mac` is now optional and a new `Finding.subject_id` carries this
  kind of non-device finding's identity instead. `lanfence dhcp-servers`
  lists every observed server and its current approval status (a database
  read; never scans or sends packets); repeated replies from the same
  unapproved server are coalesced with their own cooldown
  (`dhcp_servers.alert_cooldown_seconds`) so one noisy server can't flood
  findings, and historical evidence for a finding already raised is never
  rewritten by a later approval.

- **`lanfence digest`.** A concise, side-effect-free summary of recent
  network activity - new devices, devices needing review, current
  investigations, and (with presence policies) missing always-on devices -
  as an alternative to a notification for every routine event. Defaults to
  a rolling 24h window, a preview that sends nothing; `--send` delivers
  through `digest.channels` (reusing the existing email/webhook/Slack/
  Discord/Teams/ntfy destinations - SMS and syslog are not available for
  digests), `--channel` limits one run to a subset, and an empty digest is
  suppressed unless `digest.send_when_empty`/`--send-empty`. Each requested
  channel is attempted independently and reported per-channel; delivery is
  entirely independent of the immediate-alert pipeline (`alerts.min_severity`,
  per-MAC cooldowns are untouched). Historical accuracy comes from the
  persisted lifecycle event log, not from re-deriving security severity out
  of current allowlist/signature state; this version has no durable
  monitor-health record, so it always reports "Monitoring health
  unavailable" rather than guessing. See README's "Digest" section for cron
  and systemd-timer scheduling examples.

- **Per-device presence policies.** `lanfence device <MAC> --presence
  unspecified|intermittent|always-on` lets you tell LAN Fence what "normal"
  looks like for a device - separate from trust. `intermittent` (routine
  come-and-go, e.g. laptops/phones) suppresses only the routine "it came
  back" lifecycle finding/notification - first discoveries and independent
  security findings are never suppressed, and status/history tracking is
  unaffected. `always-on` (e.g. servers, NAS, printers) keeps the existing
  offline-detection rules for *when* a device is confirmed offline, and adds
  one medium-severity availability finding once it's been absent for the
  effective delay (`--offline-after`, default the global
  `scan.offline_grace_seconds`) plus one info-severity recovery finding on
  its return - persisted per absence episode so a restart never duplicates
  either. `lanfence devices --presence ...` filters by policy, and
  `lanfence review`'s interactive flow asks about presence right after
  trusting a device. Policy is stored in a new, backward-compatible
  `device_presence` table; editing it alone never fabricates a lifecycle
  event or fires an alert.

## [0.3.8] - 2026-09-11

### Added

- **`lanfence reset`** permanently deletes all previously scanned devices -
  history, lifecycle events, alert cooldowns, and review/snooze state - and,
  unless `--keep-allowlist` is given, the allowlist too. Asks for
  confirmation (requires a terminal) unless `--yes` is passed for
  noninteractive/scripted use.

- **LAN Fence now identifies and trusts itself.** The host running
  `scan`/`monitor`/`devices`/`device`/`review` is inevitably on the network
  it's watching - its own MAC shows up in its own active-sweep ARP request,
  and in whatever a concurrent passive capture sees. Its own MAC on the
  interface it's using is now detected automatically (via the OS, not a
  network probe) and trusted the same way an `allow`-ed device is - findings
  about it are downgraded to `info`, and it never occupies the `review`
  queue. Computed fresh each run and never written to the allowlist file, so
  moving to different hardware never leaves a stale entry; an operator's own
  explicit `allow` entry for the same MAC is never overwritten.

### Fixed

- **`lanfence monitor` could crash on a real DHCP hostname.** On at least
  some scapy versions/platforms, the DHCP "hostname" option (option 12)
  comes back as raw `bytes` rather than an already-decoded `str`, which
  crashed fingerprint matching (`TypeError: a bytes-like object is required,
  not 'str'`) the moment a real device's hostname was compared against a
  rogue-device signature keyword. DHCP-sourced hostnames are now decoded
  defensively (UTF-8, invalid bytes replaced) before use.

## [0.3.7] - 2026-09-11

### Added

- **Configurable offline grace periods.** A device is no longer marked
  offline the instant one active sweep misses it. New `scan.offline_grace_seconds`
  (default `180`) and `scan.offline_after_missed_scans` (default `3`) require
  BOTH a consecutive-miss threshold and an elapsed-time grace period before a
  `disconnected` event fires - "online" during that window means "not yet
  confirmed absent." Only a completed active sweep ever evaluates an offline
  transition (elapsed wall time alone never does), and only a sweep that
  actually covered a device's known discovery path (interface, address
  family, and IPv4 subnet) counts as an eligible miss - a failed, skipped, or
  out-of-scope sweep never does, so a successful IPv6 scan can't disconnect
  an IPv4-only device whose IPv4 scan failed (and vice versa), and switching
  interface/subnet can't disconnect devices from another network. Any
  positive sighting (active or passive) resets the miss counter and always
  keeps a device online; `last_seen` is never advanced by an offline
  transition itself. Discovery provenance (missed-scan count, address
  family, interface, IPv4 subnet) is tracked in new, backward-compatible
  `devices` table columns, added idempotently to an existing database; a
  pre-upgrade device record with no provenance yet is treated conservatively
  (never counted as missed) until a fresh sighting establishes real
  coverage. `lanfence monitor`'s passive-sighting queue is now drained
  before each tick's active-sweep absence check, so a device already
  positively (but not yet drained) sighted can't be wrongly marked
  disconnected and then immediately reappeared in the same tick. Set
  `offline_grace_seconds: 0` and `offline_after_missed_scans: 1` to restore
  the previous immediate-disconnect-on-first-miss behavior.

- **Device inventory and review.** Three new commands work the database
  without touching the network: `lanfence devices` lists every previously
  observed device (`--status online|offline`, `--untrusted`,
  `--review-needed`, `--format table|json`, AND-combined); `lanfence device
  <MAC>` shows one device's current details plus its lifecycle timeline
  (`--since`, `--format table|json`); and `lanfence review` walks devices
  needing attention - untrusted, not snoozed, not already flagged - offering
  trust/snooze/investigate/skip/quit in a stable order, with noninteractive
  equivalents (`review <MAC> --trust ...`, `--snooze 24h`, `--investigate
  ...`, `--clear`) for scripts. Trust is still only ever recorded in the
  existing YAML allowlist and only ever added by a human; review state,
  notes, and snooze expiry live in a new, backward-compatible `device_review`
  SQLite table. Snoozing suppresses external alert dispatch only - findings
  keep recording and keep showing up in CLI/JSON output, and are filtered out
  before alert cooldown bookkeeping so a suppressed finding never consumes a
  cooldown slot a real alert would need. A `lanfence monitor` process already
  running now reloads the allowlist on its normal sweep cadence, so trust
  changes made from another terminal take effect without a restart.

- **DHCP snooping.** `lanfence monitor` (`--dhcp/--no-dhcp`, on by default,
  effective only when `passive` is also enabled) now also parses DHCP
  traffic in its existing passive capture for a device's self-reported
  hostname (option 12) - added to the same `"arp or icmp6"` filter, now
  `"arp or icmp6 or (udp and (port 67 or port 68))"`, one capture stream for
  all three. Reverse-DNS fails often in practice (phones/IoT devices without
  a PTR record, routers that don't register client hostnames, mDNS-only
  devices); a DHCP-observed hostname is used directly instead of a reverse-
  DNS lookup when available, and is often present at the exact moment a
  brand-new device joins and sends its first DHCP request - frequently
  faster than the next ARP broadcast, and with a name reverse-DNS would
  never have produced. `lanfence scan` (a one-shot active sweep) is
  unaffected - DHCP is inherently passive; there's no legitimate "please
  DHCPDISCOVER for me" active probe. Deliberately scoped to option 12 only:
  DHCP option 55 (parameter-request-list OS fingerprinting) would need a
  maintained mapping table this project has no authoritative source for.

- **`lanfence run`** is a new exact alias for `lanfence scan`, for anyone who
  reaches for "run" instead of "scan" - same options, same behavior.

### Fixed

- **`lanfence link` falsely refused a normal pipx install.** Its
  writable-by-others check ran *after* `link` had already re-exec'd itself
  under `sudo`, so it asked "is this file's group just me?" while running as
  root - and root is never a member of the original user's own private
  group, so a completely standard umask-002 pipx venv was rejected as
  "writable by other users." The check now resolves the actual invoking
  user via `SUDO_UID` (set by `sudo`) instead of the post-escalation euid.

## [0.3.6] - 2026-09-11

### Changed

- **Alert dispatch is now rate-limited by default.** New `alerts.rate_limit_seconds`
  (default 900 - 15 minutes) is a per-MAC cooldown on external alert channels:
  once a device has triggered a dispatch, further alerts about it are
  suppressed until the cooldown elapses, unless a new finding's severity is
  higher than what was last alerted (an escalation always gets through
  immediately). This is a behavior change for anyone upgrading - previously
  every qualifying finding was dispatched every time, so a flapping device
  (a phone's Wi-Fi cycling, a laptop sleeping/waking) could trigger a fresh
  alert on every scan interval, and now that Twilio SMS is billed per
  message, that had a real dollar cost with no added security value. Only
  the external channels are throttled - the CLI table, JSON output, and the
  database's event history remain complete. Set `rate_limit_seconds: 0` to
  restore the old "alert every time" behavior. Backed by a new `alert_log`
  table in the device database and `lanfence.engine.filter_rate_limited`.

### Added

- Five new alert channels, alongside the existing syslog/email/webhook:
  **Slack** and **Discord** (incoming webhook, posting a text summary -
  Discord's is truncated to its 2000-character message cap), **Microsoft
  Teams** (a `MessageCard`-shaped webhook payload), **ntfy**
  (`alerts.ntfy.url`/`priority`, posted as plain text with a `Title`
  header), and **Twilio SMS** (`account_sid`/`auth_token`/`from_number`/
  `to_numbers`, authenticated via HTTP Basic Auth against Twilio's REST
  API - one message per recipient). All five are disabled by default, gated
  by the same `alerts.min_severity` threshold as every other channel, and
  each is its own opt-in exception to "no network calls" the same way
  webhook/email already were. Twilio's message body is capped at ~480
  characters (a compact one-line summary, not the full multi-line report)
  since SMS is billed per segment. Alert dispatch (previously untested) now
  has full unit test coverage across all eight channels.

### Internal

- Added a CI workflow (`.github/workflows/tests.yml`) running `pytest` on
  every push to `main` and every pull request, across Python 3.11/3.12/3.13
  - previously only a publish-on-release workflow existed, so nothing caught
  a broken test before it was tagged. It immediately caught a real flake:
  `test_trusted_to_run_as_root_false_for_group_writable_dir` relied on the
  real test runner's own primary group having other members, true of
  macOS's default "staff" group but false of Ubuntu's per-user private
  groups - fixed to mock `_group_write_is_self_only` instead.
- `CONTRIBUTING.md`/`DISTRIBUTING.md` no longer describe
  `lanfence/data/oui_vendors.txt` as "a small curated subset" - stale since
  0.3.5 replaced it with a generated full snapshot of the IEEE MA-L registry.

## [0.3.5] - 2026-09-11

### Added

- **IPv6 neighbor discovery.** `scan`/`monitor` (`--ipv6/--no-ipv6`, on by
  default via the new `scan.ipv6` config field) now discover devices over
  IPv6 as well as ARP: an active sweep pings the link-local all-nodes
  multicast address (`ff02::1`) - the standard alternative to an ARP-style
  address sweep, since a /64 can't be brute-forced - and passive monitoring
  additionally parses Neighbor Solicitation/Advertisement traffic (the
  ARP/ND capture filter is now `"arp or icmp6"`, one capture stream for
  both). This closes a real gap: a device that is IPv6-only, or one
  deliberately configured off IPv4 specifically to evade an ARP-only
  monitor, was previously invisible. Discovery is link-local only (stable
  per-interface, unlike rotating global-scope privacy addresses) and needs
  no on-link prefix/subnet knowledge. Every discovered MAC feeds the exact
  same allowlist/fingerprint/finding pipeline ARP sightings already do - no
  changes needed there. `lanfence check` reports IPv6 availability on the
  scanning interface.
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

- `run_active_sweep` no longer marks every known device "disconnected" when
  a sweep can't run at all (most commonly: `scan`/`monitor` invoked without
  root). Previously, a scan failure was caught, treated as "zero devices
  seen", and fed straight into the offline-marking step - so every real,
  still-connected device in the database got a false `disconnected` event
  each sweep. It now only marks devices offline when at least one scan
  mechanism (ARP or IPv6) actually completed; a sweep where everything
  failed leaves existing device state untouched. Found while reasoning
  through how a second (IPv6) scan mechanism should interact with the
  existing offline-marking logic, not reported from a live install.
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

[Unreleased]: https://github.com/rosscooney/lanfence/compare/v0.3.9...HEAD
[0.3.9]: https://github.com/rosscooney/lanfence/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/rosscooney/lanfence/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/rosscooney/lanfence/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/rosscooney/lanfence/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/rosscooney/lanfence/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/rosscooney/lanfence/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/rosscooney/lanfence/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/rosscooney/lanfence/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/rosscooney/lanfence/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/rosscooney/lanfence/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rosscooney/lanfence/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/rosscooney/lanfence/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rosscooney/lanfence/releases/tag/v0.1.0
