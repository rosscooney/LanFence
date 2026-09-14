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

### Security

- **SMTP STARTTLS now verifies the relay's certificate and hostname.**
  `smtplib.SMTP.starttls()` called with no explicit context builds an
  *unverified* context internally, silently accepting any certificate -
  every email send path (`lanfence` alerts, digests, and `channels test
  email`) now passes an explicit `ssl.create_default_context()`-based
  context (`lanfence.smtp_utils.build_smtp_context`), consolidated into
  one shared implementation so all three verify identically. A new
  `alerts.email.ca_file` setting lets a relay with a private/internal CA
  be trusted (an added trust anchor, never a verification bypass).
  `email.username`/`password` are now refused when `use_tls` is disabled,
  preventing a password from being sent in the clear; an explicitly
  configured unauthenticated relay (no username/password) is unaffected.
- **Bounded `lanfence monitor` resource usage and alert volume.** Passive
  processing queues (`scan.passive_queue_maxsize`, default 2000) are now
  bounded - a packet flood drops excess items (counted, and reported as a
  coalesced warning) instead of growing memory without limit or blocking
  the capture thread. Repeated identical sightings within one drain batch
  are safely coalesced (`lanfence.engine.coalesce_sightings`) without
  losing any distinct evidence. External alert delivery now runs on a
  bounded background thread (`lanfence.alert_worker`) so a slow or
  unreachable destination can no longer stall the main loop's sighting
  processing; SQLite access stays on its owning thread throughout. A new
  *global* alert-dispatch cap (`alerts.global_rate_limit_max`/
  `global_rate_limit_window_seconds`) bounds total external alert volume
  even from many distinct or rotating identities (e.g. randomized MACs),
  which the existing per-MAC cooldown alone cannot. Twilio SMS gets a
  durable daily segment budget (`alerts.twilio.max_segments_per_day`,
  default 200) accounting for every recipient and message segment,
  surviving process restarts (not `lanfence reset`, deliberately - it's a
  billing safeguard, not device inventory). Retained per-MAC address/name
  evidence and DHCP-server/discovery-advertisement rows are now capped
  (`retention.*`), independent of and tighter than the existing time-based
  expiry, bounding how much a burst of spoofed/rotating observations can
  grow the database before any of them individually expire.
- **Restricted database and state-directory permissions.** Under a
  permissive umask (e.g. `022`), the device database and its containing
  directory could previously end up world/group-readable. LAN Fence's own
  state directory is now created (or tightened, if already owned by the
  expected user) to `0700` and the database file to `0600`, regardless of
  umask - reasserted explicitly rather than trusted to `mkdir`/file
  creation defaults - with the same applied to any pre-existing SQLite
  `-wal`/`-shm`/`-journal` sidecar file. Only the directory LAN Fence
  itself owns is ever touched, never a shared ancestor (e.g.
  `~/.local/share`). A directory or file unexpectedly owned by a
  different user, or one that is actually a symlink, is refused with a
  clear error rather than silently used - correctly accounting for
  `sudo lanfence scan`/`monitor` legitimately writing into the invoking
  operator's (not root's) directory, per the `$HOME`-under-`sudo` fix in
  0.4.2.
- **Closed a symlink-following race in database access.** `sqlite3.connect`
  follows a symlink at the configured path; combined with privileged
  (`sudo`) execution, an attacker who could place a symlink at that exact
  path (or race a legitimate file into becoming one) could redirect LAN
  Fence's writes to an unintended target. The database file, its
  containing directory, and its SQLite `-wal`/`-shm`/`-journal` sidecar
  files are now all opened with a single atomic, symlink-refusing syscall
  (`O_NOFOLLOW` for anything expected to already exist, `O_CREAT|O_EXCL`
  for first-ever creation) rather than a separate `exists()`/
  `is_symlink()` check followed by an ordinary open - eliminating the
  race window between the two. Verified: a dangling symlink at the
  database path is refused without ever creating its target; a symlink
  to an existing file is refused without ever touching that file's
  contents; a symlinked sidecar is refused the same way; a legitimate
  symlinked *ancestor* directory (a platform alias, an intentional
  bind-mount-style setup) is left completely untouched, since only the
  final path components LAN Fence actually owns are ever checked.

## [0.4.2] - 2026-09-14

### Fixed

- **`sudo lanfence scan`/`monitor` and a plain `lanfence devices`/`review`/
  `allow` could silently read and write two different databases.** The
  default `db_path`/`allowlist_file` (`~/.local/share/lanfence/...`,
  `~/.config/lanfence/...`) now expand `~` against the actual invoking
  operator's home directory even when running as root via `sudo` (which
  resets `$HOME` to root's home by default), instead of ending up in
  `/root`. This also explains `lanfence monitor`'s live stats appearing
  not to reset after `lanfence reset` when the two commands were run with
  different privilege levels - they were simply looking at different
  files. A genuine root login/system service (no `SUDO_USER`) is
  unaffected.

### Changed

- Removed the **Online** stat from `lanfence monitor`'s live dashboard
  footer (redundant with `Known`/`Review` at a glance, and could look
  stale between sweeps) - a narrow terminal now shows `Review` instead in
  its place.

## [0.4.1] - 2026-09-14

### Added

- **Device dossier and conservative device classification.** Every device
  now gets a consolidated view of everything already retained about it
  (addresses, names, advertised services, fingerprint matches, operator
  metadata) plus a "likely device" guess (e.g. "Sonos speaker", "Windows
  workstation") built entirely from that existing evidence, always labeled
  with a confidence (High/Medium/Low) and the specific reasons behind it -
  never presented as verified identity, since MAC OUIs/hostnames/mDNS/SSDP
  remain trivially spoofable. `lanfence device <MAC>` shows a new "Likely
  device" section.
- **`lanfence review`'s interactive queue** now shows this dossier
  compactly before asking what to do, with a richer action menu
  (`[T]rust`/`[I]nvestigate`/`[S]nooze`/`[X] Inspect`/`[D] Full details`/
  `[N]ext`/`[Q]uit`), and walks the queue in **review-priority order**
  (Priority / Needs identification / Likely familiar - a deterministic,
  plain-language tier, never a numeric risk score) instead of MAC order.
- **`lanfence allow <MAC>`** shows the same compact dossier before asking
  for confirmation when trusting an already-observed device at an
  interactive terminal; a new `--yes` flag skips the prompt, and
  non-interactive/scripted use is unaffected.
- **First-run/ongoing triage summary** after `lanfence scan`: a short,
  categorized orientation ("N appear straightforward", "N need
  identification", "N use private/randomised MAC addresses", "N have
  higher-priority security characteristics", plus how many are already
  reviewed) shown alongside the existing compact device table - not new
  table columns, and not part of the stable JSON output.
- **`lanfence inspect <MAC>`: optional active device inspection.** A
  bounded TCP connect-scan of a short, curated list of common service ports
  on one already-known device - a dependency-free built-in scan always
  works, and the optional `nmap` binary is used automatically when present
  for better service labels (`--no-nmap` to force the built-in scan
  either way). Confirmed open ports are always shown separately from
  inferred service labels and an overall, confidence-labeled "probable
  platform" guess (never OS fingerprinting, never definitive). Never run
  automatically by `scan`/`monitor`/passive discovery/`review` - only an
  explicit `lanfence inspect` invocation, or an explicit yes to the offer
  `lanfence review` makes (with a clear warning) for the device on screen.
  Results are persisted per MAC and shown again, labeled with their age
  and flagged stale past 24 hours, by `lanfence device <MAC>` and
  `review`'s `[D] Full details` view. `lanfence check` now also reports
  whether nmap is installed (never a failure if it isn't).

## [0.3.13] - 2026-09-12

### Added

- Press `q` (without Enter) to exit the live monitor through its normal
  cleanup and session summary. A visible border hint explains the shortcut;
  Ctrl+C remains available and redirected input is never consumed.

## [0.3.12] - 2026-09-12

### Added

- Expanded `lanfence channels setup` into a numbered application setup menu
  with a shared unsaved draft for communications, scanning, offline detection,
  DHCP approvals, passive service discovery, digests, storage paths, and alert
  delivery. Review redacted changes, reset individual settings to defaults,
  save atomically, or discard; direct channel setup remains available.
  DHCP approvals can be selected explicitly from read-only observed inventory.

### Fixed

- Channel configuration validation and test failures no longer include raw
  Pydantic input or transport exception text that could expose credentials.

## [0.3.11] - 2026-09-12

### Added

- **Live bordered dashboard for `lanfence monitor`.** A continuously-
  updating terminal display (Rich `Live`, alternate screen) with a compact
  header (interface, network, elapsed time, active discovery mechanisms,
  last sweep), a scrolling recent-activity feed, and an always-visible
  statistics footer (`Known`/`Seen`/`Online`/`New`/`Review`/`Scan`
  countdown, plus finding/sweep/passive-listener status at wider
  terminals). `Seen`/`New` are exact session counters derived from real
  scanning results (deduplicated across active/passive sources and
  addresses, never inferred or double-counted from indirect evidence like
  a DHCP-offered address or an mDNS service target); `Known`/`Online`/
  `Review` come from efficient aggregate database queries refreshed after
  each sweep and on a periodic cadence, not a per-frame full scan. A
  finding is shown once (in the activity feed, not also via the old
  console renderer); repeated identical operational errors are coalesced
  with a count. Small terminals shorten labels and drop optional
  statistics, falling back to a minimal one-line display below a usable
  size; presentation state and rendering are unit-tested independently of
  any terminal or network. `--live`/`--no-live` control it explicitly
  (default: auto-detect an interactive terminal); an explicit `--live` on
  unsupported output (a pipe, a log file, `TERM=dumb`) falls back to plain
  append-only output with one clear message instead of emitting raw
  control sequences. Ctrl+C exits the alternate screen cleanly before
  printing a short session summary with real counters. Plain/append-only
  mode's existing output is unchanged.

- **`lanfence channels` - interactive communication-channel setup.**
  Configure Slack/Discord/Teams/ntfy/email/webhook/Twilio/syslog without
  hand-editing YAML: `lanfence channels` shows a status table (enabled/
  configured/safe destination summary/digest selection - never a password,
  token, full webhook URL, or credential-bearing path); `channels setup
  [channel]` walks through each channel's real config fields with local
  validation, existing-value defaults, a sanitized preview, and an optional
  post-save test message (defaults to no; Twilio warns about SMS charges);
  `channels enable/disable <channel>` toggle delivery noninteractively
  without touching stored credentials; `channels test <channel>` sends one
  clearly-labeled message via the real transport and reports its actual
  success/failure (bypassing `alerts.min_severity`, creating no device/
  finding/lifecycle event/cooldown entry). A secret is never echoed - only
  "already configured," with an explicit keep/replace/`clear`. Saves are
  atomic, refuse to overwrite malformed YAML or a concurrent edit, preserve
  every unrelated setting and disabled channel's own secrets, and restrict
  the file to owner-only permissions. Uses a new conventional default
  config path (`~/.config/lanfence/config.yaml`) when `--config` isn't
  given, since no other command has a default writable config file to
  reuse - `monitor` needs a restart to pick up a change made this way.

### Fixed

- Commit passive service-discovery retention cleanup together with each
  observation. Previously cleanup left an open SQLite write transaction,
  allowing an idle monitor to block reset or another monitor with
  `database is locked`, even when cleanup removed no rows.

## [0.3.10] - 2026-09-12

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

- **User-managed device inventory metadata.** `lanfence device <MAC>` now
  accepts `--owner`/`--purpose`/`--group`/`--location` (and matching
  `--clear-*` flags) to attach your own notes to a device - who owns it,
  what it's for, its group, and where it lives. Entirely separate from
  observed hostname/vendor and from trust/review/presence; edits never
  scan, alert, or create a lifecycle event. `lanfence devices` gained
  matching `--owner`/`--group`/`--location` filters (exact,
  case-insensitive) and an opt-in `--details` flag adding metadata columns
  to the table; JSON output always includes metadata. The interactive
  `lanfence review` queue offers an optional "Add device details?" step
  after trusting a device. Owner/group appear as brief context in
  `lanfence digest` device rows (purpose/location are left out to keep
  rows terse). `lanfence reset` clears metadata along with the rest of a
  device's history.

- **Passive advertised-service discovery (mDNS/DNS-SD, SSDP/UPnP).**
  Enriches inventory with services a device advertises about itself
  (printing, AirPlay, remote audio, cast, generic web service, and any
  other valid service type retained with its raw name) - opt-in via
  `discovery.mdns`/`discovery.ssdp`, narrowly extending the existing
  passive capture filter (UDP 5353/1900); needs `scan.passive` too, and
  `monitor` warns if enabled without it. Strictly passive: no mDNS query,
  SSDP `M-SEARCH`, or other discovery traffic is ever sent, and an SSDP
  `LOCATION` URL is never fetched. Attribution to a device is deliberately
  conservative - a service's target address (or, for SSDP, its packet
  source) is matched only against *directly-observed* (ARP/IPv6 ND)
  address evidence, never the transmitting frame's own Ethernet/IP source
  (an mDNS proxy/reflector can advertise on behalf of other hosts) and
  never an ambiguous or merely historical IP association; unmatched
  services are shown as unassociated rather than guessed. TTL/`ssdp:byebye`/
  goodbye semantics are honored per-record, independently, with a small
  documented allowlist for mDNS TXT attributes (bounded count/size, never a
  raw TXT blob) - all advertised claims, never verified capabilities.
  `lanfence device <MAC>` shows a new "Advertised services" section (and
  `--format json` a new `services` array); a new `lanfence services`
  command lists everything observed (`--protocol`, `--unassociated`,
  `--include-expired`). New-device digest rows get a terse services
  summary; no new findings/alerts are raised by this feature.

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

[Unreleased]: https://github.com/rosscooney/lanfence/compare/v0.3.13...HEAD
[0.3.13]: https://github.com/rosscooney/lanfence/compare/v0.3.12...v0.3.13
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
