# LAN Fence

**LAN Fence is an open-source defensive network device monitor for Linux**
(developed and tested on Raspberry Pi OS / Debian, and reasonably portable to
other Debian/Ubuntu systems).

- Home page: <https://lanfence.com>
- Source & downloads: <https://github.com/rosscooney/lanfence>
  ([releases](https://github.com/rosscooney/lanfence/releases))
- Package: [`lanfence` on PyPI](https://pypi.org/project/lanfence/)

LAN Fence runs on a small Linux box (a Raspberry Pi is the common case) sitting
on your network. It continuously scans for connected devices via ARP and IPv6
neighbor discovery, maintains an allowlist of devices you already trust, and
alerts in plain language when something unknown joins - a rogue device,
unauthorized hardware, or a supply-chain implant on your LAN.

LAN Fence **only observes**. It sends nothing beyond a standard ARP "who-has"
request or IPv6 multicast ping (the same things every device on your LAN does
routinely) and never touches, blocks, deauthenticates or spoofs anything.

> ⚠️ LAN Fence **cannot prove a device is malicious, or that a MAC address is
> genuine.** MAC vendor prefixes and hostnames are trivially spoofed by anyone
> deliberately trying to blend in. A finding is a lead worth checking by hand,
> not a verdict - use it as one input to your own judgement.

## How it works

1. **Active scanning** - LAN Fence periodically ARP-sweeps your IPv4 subnet
   and, unless disabled, pings the IPv6 all-nodes multicast address to reach
   every IPv6-enabled host on the link too (`lanfence scan` for one sweep, or
   on an interval inside `lanfence monitor`) - so a device that's IPv6-only,
   or deliberately configured off IPv4 to dodge an ARP-only monitor, doesn't
   go unseen. Every discovered MAC/IP pairing feeds the same pipeline
   regardless of address family.
2. **Passive monitoring** - between active sweeps, `lanfence monitor` also
   listens for ARP and IPv6 neighbor-discovery traffic on the wire, so a
   device that joins mid-interval is caught sooner rather than waiting for
   the next sweep. It also snoops DHCP traffic for a device's self-reported
   hostname (option 12) - often available, faster, and more reliable than
   reverse-DNS, and especially useful right when a brand-new device joins and
   sends its first DHCP request.
3. Every sighting is folded into a persistent **SQLite database** keyed by MAC
   address, which tracks each device's lifecycle: `new_device` the first time
   it's ever seen, `reappeared` if it had gone offline and came back, and
   `disconnected` once an active sweep has confirmed it's actually gone (see
   "Offline detection and grace periods" below - one missed reply doesn't
   mean gone).
4. Each device is **fingerprinted**: an offline OUI → vendor lookup, a set of
   built-in rogue-device signatures (see below), and a check of whether its
   MAC is locally administered (randomized/spoofed rather than
   vendor-assigned).
5. Each device is checked against your **allowlist**
   (`lanfence allow <mac>`). A brand-new or reappearing device not on the
   allowlist produces a plain-language **finding** with a severity
   (`high`/`medium`/`info`), a rationale, and a recommendation; an allowlisted
   device is downgraded to `info` so your own hardware stops shouting every
   time it reconnects. LAN Fence also automatically identifies and trusts
   **itself** - its own MAC address on the interface it's using - so its own
   ARP traffic during a sweep, or its own frames a passive capture inevitably
   sees, is never mistaken for an unknown device (see below).
6. Findings can be dispatched to **syslog, email, a generic webhook, Slack,
   Discord, Microsoft Teams, ntfy, or Twilio SMS**, and everything is
   available as a CLI table or JSON for automation.

## Built-in rogue-device signatures

Heuristics, not proof - a match is a lead to check by hand:

| Signal | Category | Why it matters |
|---|---|---|
| Vendor: Espressif / Ai-Thinker | `esp32_esp8266` | ESP32/ESP8266 - the chipset behind most cheap DIY hidden cameras, rogue APs, and ESP32-based Wi-Fi implants (as well as plenty of legitimate IoT). |
| Vendor: Raspberry Pi | `raspberry_pi` | Legitimate everywhere, but also the common hardware basis for rogue network-tap / implant projects (P4wnP1, home-built taps). |
| Vendor: Orange Pi (Shenzhen Xunlong) | `orange_pi` | Same rationale as Raspberry Pi - a legitimate SBC also common in DIY implant projects. |
| Vendor: Allwinner | `allwinner_sbc_or_camera` | Common in budget SBCs, Android TV boxes, and cheap white-label Wi-Fi cameras. |
| Vendor: HiSilicon | `hisilicon_camera_soc` | The Hi3516/Hi3518-family SoC behind huge numbers of cheap white-label IP cameras/DVRs - and the hardware base widely reported behind the Mirai botnet and its successors. |
| Vendor: ASIX Electronics | `usb_ethernet_gadget` | USB-Ethernet chipset used both by ordinary dongles and by BadUSB tools (Bash Bunny, LAN Turtle, O.MG cable) presenting as a network adapter. |
| Hostname contains `pwnagotchi` | `pwnagotchi` | Pwnagotchi's own default hostname (`main.name` in its default config) - confirmed from the project's source. |
| Hostname contains `bunny` / `turtle` / `pineapple` | Hak5 tooling | Commonly-reported default hostnames for Bash Bunny / LAN Turtle / WiFi Pineapple - corroborated from Hak5's own community forum and docs, not an official spec page, and short enough to occasionally match an unrelated device. |
| Locally administered MAC | `locally_administered_mac` | No vendor OUI - common for privacy MAC-randomization on phones/laptops, but also for spoofed or gadget hardware. |

Extend or override these with your own `rogue_signatures_file:` (same YAML
shape as `lanfence/data/rogue_signatures.yaml`) and `vendor_file:` (same
tab-separated shape as `lanfence/data/oui_vendors.txt`) in config.

## LAN Fence trusts itself

The host running `lanfence scan`/`monitor` is on the network it's watching,
so its own MAC address inevitably shows up - in its own ARP request during
an active sweep, and in whatever a concurrent passive capture sees. LAN
Fence detects its own MAC on the interface it's using (via the OS, not a
network probe) and treats it as trusted automatically, the same way an
`lanfence allow`-ed device is: findings about it are downgraded to `info`,
and it never occupies the `lanfence review` queue.

This self-trust is **never written to your allowlist file** - it's computed
fresh each run from the live interface, so moving LAN Fence to different
hardware or a different NIC never leaves a stale entry behind. If you've
already explicitly `lanfence allow`-ed this same MAC yourself under your own
name, that choice is left alone rather than overwritten.

## Vendor lookups

The bundled `lanfence/data/oui_vendors.txt` is a full snapshot (~40,000
entries) of the IEEE's public MA-L OUI registry, taken when this version was
built. LAN Fence makes no network calls on its own and does not auto-update
it; run `lanfence vendor-refresh` to pull a current copy on demand:

```bash
lanfence vendor-refresh                       # -> ~/.config/lanfence/oui_vendors.txt
lanfence vendor-refresh --output my_ouis.txt  # or choose where to save it
```

It's saved as an *extra* table (never overwriting the packaged one) - add
`vendor_file: <path it printed>` to your config to have `scan`/`monitor`
merge it on top of the built-in table. This is the one deliberate,
operator-triggered exception to "no network calls", the same as `lanfence
upgrade` checking PyPI - it only ever runs when you type the command.

## Install

```bash
pipx install "lanfence[scan]"     # isolated, recommended - includes scapy for scanning
```

`scan`/`monitor` need the `scan` extra (`scapy`) to actually send/receive ARP
packets; `allow`, `report` and `check` work without it. Already installed
without the extra? Add it in place:

```bash
pipx inject lanfence scapy
```

or, without pipx:

```bash
python3 -m venv ~/.venvs/lanfence
~/.venvs/lanfence/bin/pip install 'lanfence[scan]'
```

Scanning needs raw-socket access, so `scan`/`monitor` typically need `sudo`
(or `CAP_NET_RAW` on the interpreter). `allow`, `device`/`digest` and `check` do not.

## Commands

```text
lanfence scan                  # one-time active ARP scan; table + findings
lanfence scan --format json    # same, machine-readable
lanfence monitor                # continuous: active sweeps + passive sniffing
lanfence allow <MAC> --name X   # trust a device; its findings become info
lanfence allow <MAC> --yes      # skip the device-context confirmation prompt (scripted use)
lanfence allow --list           # show the allowlist
lanfence allow --remove <MAC>   # untrust a device
lanfence reset                  # permanently wipe scanned device history (and allowlist)
lanfence device                 # list previously observed devices - no scan
lanfence device --review-needed --format json
lanfence device <MAC>           # one device's details, trust state, timeline
lanfence device <MAC> --presence intermittent   # set a presence policy (separate from trust)
lanfence device --presence always-on
lanfence review                 # interactively work through devices needing review
lanfence review <MAC> --trust --name "Kitchen speaker"
lanfence review <MAC> --snooze 24h
lanfence review <MAC> --investigate --notes "..."
lanfence review <MAC> --clear
lanfence inspect <MAC>          # optional: actively probe one known device's open ports
lanfence inspect <MAC> --no-nmap  # force the built-in scan, skip the optional nmap integration
lanfence digest                 # preview a 24h summary; add --send to deliver it
lanfence digest --verbose       # also list every event/finding in the window (formerly `lanfence report`)
lanfence digest --since 7d --send --channel email
lanfence dhcp-servers            # observed DHCP servers and their approval status
lanfence setup                  # interactive setup: communications and application settings
lanfence web                    # run the local web portal (enable/configure it via `lanfence setup` first)
lanfence check                  # verify permissions, scapy, nmap, interface, storage
lanfence upgrade                # check PyPI and install a newer release, if any
lanfence upgrade --check        # only report whether an update is available
lanfence link                   # make `sudo lanfence` work (pipx/--user installs)
lanfence vendor-refresh         # pull a current copy of the IEEE OUI registry
```

`scan` and `upgrade` also have exact hidden aliases, `run` and `update`
respectively - not shown in `--help` (to keep the command list short), but
fully supported for anyone who reaches for those names instead.

`scan`/`monitor` warn (and show copy-pasteable fixes) if not run as root, since
ARP scanning needs raw-socket access. A pipx / `pip install --user` install
puts the `lanfence` launcher in `~/.local/bin`, which `sudo` does not see by
default - `sudo lanfence scan` then fails with "command not found". Run
`lanfence link` once (no `sudo` needed up front - it re-execs itself under
`sudo` and prompts for your password) to symlink the launcher onto root's
`PATH`; after that, a bare `sudo lanfence scan` / `sudo lanfence monitor`
works. `lanfence link --remove` undoes it.

Mixing `sudo lanfence scan`/`monitor` (needs root for raw sockets) with a
plain, unprivileged `lanfence device`/`review`/`allow`/`digest` is the
normal way to use LAN Fence, and both read/write the same database and
allowlist: the default `~/.local/share/lanfence/...`/`~/.config/lanfence/...`
paths resolve against your own home directory even under `sudo` (which
would otherwise reset `$HOME` to root's), not root's.

### Example: an unknown device joins

```text
$ sudo lanfence scan

Devices seen (4)
┌───────────────────┬──────────────┬──────────────┬────────────────────┬────────┬─────────┐
│ MAC                │ IP           │ Hostname     │ Vendor              │ Status │ Trusted │
├───────────────────┼──────────────┼──────────────┼────────────────────┼────────┼─────────┤
│ b8:27:eb:12:34:56  │ 192.168.1.10 │ nas.local    │ Raspberry Pi        │ online │ yes (NAS)│
│ 52:8a:1c:99:f4:2d  │ 192.168.1.47 │ [unknown]    │ [unknown]           │ online │ no      │
└───────────────────┴──────────────┴──────────────┴────────────────────┴────────┴─────────┘

Findings (1)

  MEDIUM Unknown device connected
    MAC: 52:8a:1c:99:f4:2d
    The vendor bit pattern indicates a locally administered address rather
    than one assigned by a hardware vendor. Common causes: MAC-randomization
    privacy features on modern phones/laptops, virtual machines/containers,
    or a device deliberately spoofing its address.
    Recommendation: Verify this device belongs on your network. If it's
    yours, run `lanfence allow 52:8a:1c:99:f4:2d` to stop future alerts.
      • MAC: 52:8a:1c:99:f4:2d
      • IP: 192.168.1.47
      • Hostname: [unknown]
      • Vendor: [unknown]
      • mac = 52:8a:1c:99:f4:2d (U/L bit set, no vendor OUI match)

Overall: 1 finding(s), highest severity: medium
```

## Monitor's live dashboard

`lanfence monitor` shows a bordered, continuously-updating dashboard by
default when run at an interactive terminal - a compact header, a scrolling
feed of recent activity, and a statistics footer that's always visible:

```text
┌─ LAN Fence · Monitoring ───────────────────────────────────────────┐
│ Interface: eth0  ·  Network: 192.168.1.0/24  ·  Running: 00:14:32  │
│ lanfence 0.3.10  ·  passive (ipv6, dhcp)  ·  last sweep 10:41:58   │
│                                                                    │
│ 10:42:03  NEW         Unknown device · 192.168.1.42                │
│ 10:42:10  RETURNED    Office laptop · 192.168.1.10                 │
│ 10:44:01  WARNING     scan.passive is on but discovery.mdns is...  │
│                                                                    │
├────────────────────────────────────────────────────────────────────┤
│ Known: 38 · Seen: 24 · New: 2 · Review: 3 · Scan: 8s               │
└────────────────────────────────────────────────────────────────────┘
```

```text
lanfence monitor            # live dashboard if the terminal supports it, plain output otherwise
lanfence monitor --live     # force the live dashboard (fails helpfully, not silently, if unsupported)
lanfence monitor --no-live  # force plain, append-only output (e.g. when redirecting to a log file)
```

**Header**: interface, network scope, elapsed session time, LAN Fence's
version, which discovery mechanisms are active (from actual config, not
guessed), and the last completed sweep time (or "scanning now" while one is
in progress). **Activity feed**: new/reappeared/disconnected devices and
findings, most recent first - a device that also produced a security
finding gets one combined line, not two, and a routine "still online"
sighting never adds a line at all. Every timestamp is your system's local
time. A repeated identical operational error (e.g. a failing sweep) is
shown once with a growing count rather than flooding the feed.

**Footer statistics** (a device is identified the same way everywhere else
in LAN Fence - see [Device inventory and review](#device-inventory-and-review)):

- **Known**: distinct devices in the database right now.
- **Seen**: distinct devices this `monitor` process has *itself* positively
  observed this session (active or passive, deduplicated across every
  address/mechanism) - retained even if a device later goes offline. A
  reported DHCP-offered address or an mDNS/SSDP service target is never
  counted here; only a direct sighting is.
- **New**: devices this session's positive observations inserted into the
  database for the first time - a previously-known device reappearing is
  never counted as new.
- **Review**: the same needs-review count `lanfence device --review-needed`
  uses (trust/snooze/investigation rules included).
- **Scan**: time until the next scheduled active sweep, or "scanning" while
  one is running - computed from the real scheduler, never a separate UI
  timer. A wide enough terminal also shows this session's finding count,
  sweep success/failure counts, and passive-listener status. An unavailable
  statistic is always shown as such (e.g. "n/a"), never as a fabricated 0.

Refreshes about once a second and never triggers a scan on its own. On a
narrow terminal, labels shorten and lower-priority statistics drop off
(Known/Seen/New are kept longest); a terminal too small for any
usable layout falls back to one compact line rather than a garbled one.
`--live` on output that isn't a real interactive terminal (a pipe, a
redirected log file, `TERM=dumb`) falls back to plain output with one clear
message rather than emitting raw control sequences into a file; the default
(no `--live`/`--no-live`) auto-detects this the same way. Plain/append-only
mode's output is unchanged from previous versions. Press **q** (no Enter needed) to exit the live dashboard; the bottom border
shows the shortcut. **Ctrl+C** also works, including in plain output mode.
A queued quit takes effect after the current scan or delivery operation
finishes. Terminal input settings are restored on exit. On shutdown, the dashboard
exits cleanly (restoring your normal terminal) before printing a short
session summary with real counters:

```text
Monitoring stopped after 00:42:18.
Seen this session: 24 devices · Newly discovered: 2 · Findings: 3
```

## Device inventory and review

`scan`/`monitor` find devices; `device` and `review` let you work through
what's already in the database, without touching the network.

```text
lanfence device                            # every observed device, no scan
lanfence device --status online            # combine filters with AND
lanfence device --untrusted --review-needed --format json
lanfence device aa:bb:cc:dd:ee:ff          # one device's details + timeline
lanfence device aa:bb:cc:dd:ee:ff --since 7d --format json
lanfence device --delete-new-offline       # bulk-delete never-reviewed, offline devices
lanfence review                           # walk the review queue interactively
lanfence review <MAC> --trust --name "Kitchen speaker" --notes "..."
lanfence review <MAC> --snooze 24h
lanfence review <MAC> --investigate --notes "..."
lanfence review <MAC> --clear
```

`lanfence device` with no MAC argument lists every device ever observed,
straight from SQLite - it never scans. Each row's trusted/untrusted state is
looked up fresh against the *current* allowlist file, not whatever it was on
that device's last scan. `--status online|offline`, `--untrusted`, and
`--review-needed` combine with AND: `--status online --untrusted` shows only
devices that are both online and off the allowlist. **Review-needed** means
untrusted, not currently snoozed, and not already flagged investigating -
trusting, an active snooze, or an investigation flag all take it out of the
queue.

`lanfence device <MAC>` shows one device in two clearly separated parts:
*current details* (IP/hostname/vendor/status/trust/review state), which
reflect only the most recent sighting, and a *lifecycle timeline* of
connect/reappear/disconnect events since `--since` (default `30d`). The
timeline is an append-only event log, not a full history of every address a
MAC has ever held - LAN Fence does not retain that. An invalid or
never-before-seen MAC exits non-zero with a clear error. A dual-stack
device (both an IPv4 and an IPv6 address currently retained as evidence)
shows both, side by side (`192.168.1.5 / fe80::1234`), in this view and in
the no-MAC listing above - not just whichever address LAN Fence would
otherwise treat as the single "preferred" one.

`lanfence device --delete-new-offline` permanently deletes every device
that's never been reviewed at all (still "pending" - never trusted,
snoozed, or flagged investigating), is currently offline, and isn't on the
allowlist - a bulk cleanup for one-off devices (a visitor's phone, a
delivery scanner) that showed up once and aren't coming back. It never
touches a device you've already snoozed or flagged investigating, since
that reflects a deliberate decision already made about it, nor a currently
trusted or online one. Lists the matching devices and asks for
confirmation first (`--yes` skips this for scripted/cron use); this cannot
be undone, and never touches the allowlist (a matching device is by
definition not on it).

`lanfence review` is how you act on the queue. With no MAC, it walks devices
needing review one at a time, ordered by **review priority** (see
[Device classification and review priority](#device-classification-and-review-priority)
below - stronger security signals and weaker identity evidence first, never a
numeric score), showing a compact dossier before asking what to do:

```text
Device 3 of 18  ·  Needs identification

52:8a:1c:99:f4:2d
192.168.1.47

Likely device: Unknown device (no supporting evidence)

First seen: 14 Sep 2026 09:10
Last seen:  14 Sep 2026 09:41
Status:     Online

Evidence:
  - MAC is locally administered (randomized or manually set) - no vendor to identify

Actions: [T]rust  [I]nvestigate  [S]nooze  [D] Full details  [N]ext  [Q]uit
  choice:
```

- **[T]rust** - prompts for a friendly name and optional notes, then adds the
  device to the same allowlist `lanfence allow` writes to. LAN Fence never
  trusts a device on its own; a human always makes this call.
- **[I]nvestigate** - records an investigation flag and optional notes
  without trusting the device or suppressing its alerts.
- **[S]nooze** - suppresses *external* alert dispatch (Slack/Discord/Teams/
  Twilio/webhook/etc.) for this MAC for a bounded duration (default `24h`).
  Findings keep being recorded and still show up in `scan`/`report`/`devices`
  output and JSON - snoozing hides notifications, not the device.
- **[D] Full details** - shows the same full report `lanfence device <MAC>`
  does (all retained address/name evidence, advertised services, findings),
  then returns to this same device's menu - it makes no decision by itself.
- **[N]ext** (the default - just press Enter) - no changes; the device stays
  in the queue for next time.
- **[Q]uit** - stops the session immediately; every decision made so far is
  already persisted.

It requires a real terminal and exits with a helpful error instead of
hanging if stdin isn't interactive (e.g. in a script or cron job) - use the
noninteractive form there instead, passing exactly one of `--trust`,
`--snooze`, `--investigate`, or `--clear` alongside a MAC. `--clear` removes
a snooze/investigation flag and returns the device to "pending"; it does
**not** remove allowlist membership - `lanfence allow --remove <MAC>` is
still what untrusts a device.

`lanfence allow <MAC>` shows this same compact dossier before asking you to
confirm trusting an already-observed device, but only when run at an
interactive terminal - a never-before-seen MAC (nothing to show yet) and any
non-interactive invocation (scripts, cron, CI) skip the prompt entirely and
behave exactly as before, so existing automation needs no changes. Pass
`--yes` to skip the confirmation even at an interactive terminal.

## Device classification and review priority

Every device gets a conservative **"likely device"** guess, built only from
evidence LAN Fence already retains elsewhere (vendor OUI, self-reported
hostname, advertised mDNS/SSDP services, an existing rogue-signature match) -
never fabricated, always labeled with a confidence (**High**/**Medium**/
**Low**) and the specific evidence behind it, and defaulting to "Unknown
device" with no confidence when the evidence doesn't reasonably support more:

```text
$ lanfence device b8:e9:37:aa:bb:cc

Likely device: Sonos speaker
Confidence:    High
  - Vendor OUI: Sonos, Inc.
  - Advertises AirPlay/remote-audio services
```

None of this evidence is authenticated - a MAC's vendor prefix, a
self-reported hostname, and anything advertised over mDNS/SSDP are all
trivially spoofable by a device that wants to blend in, exactly like the
[rogue-device signatures](#built-in-rogue-device-signatures) this
classification reuses. It is always a labeled inference, never presented as
verified identity.

`lanfence review`'s queue is ordered by **review priority**, a deterministic,
plain-language tier built from existing signals (an existing medium/high
rogue-signature match, a locally-administered/randomized MAC, how confident
the classification is, whether a hostname or service corroborates it) -
**never a numeric risk score** claiming a precision this evidence doesn't
support:

- **Priority** - an existing medium/high-severity rogue-signature match, or a
  locally-administered/randomized MAC (no vendor identity to go on at all).
- **Needs identification** - nothing (or only a low-confidence guess)
  reasonably identifies the device.
- **Likely familiar** - a known manufacturer, ideally corroborated by a
  hostname or advertised service.

After a scan, the same three tiers (plus the security-flagged case) drive a
short orientation summary alongside the usual compact device table - the
table stays a compact inventory view; this is a separate, human-readable
breakdown of what deserves a closer look:

```text
$ sudo lanfence scan

Devices seen (47)
...

LAN Fence has discovered 47 devices.

31 appear straightforward
 9 need identification
 5 use private/randomised MAC addresses
 2 have higher-priority security characteristics

None have been reviewed yet.

Run `lanfence review` to work through them.
```

Only shown for `--format table` (the default) - `--format json`'s
`ScanResult` payload is unchanged.

Trust, snooze, and investigate are mutually exclusive persisted states
(`pending` is the default); if a device is both trusted and, say, mid-snooze
from before it was trusted, "trusted" always wins for display purposes. A
snooze that expires simply lets the device fall back into the review queue -
expiry alone never fabricates a new connect/disconnect event or fires a
retroactive alert. A `lanfence monitor` process already running reloads the
allowlist on its normal sweep cadence, so a `review --trust` or `allow` made
from another terminal takes effect without restarting it; review/snooze
state itself is read fresh from the database on every finding, so it needs
no such reload.

## Active device inspection

Everything above is built entirely from **passive** evidence - LAN Fence
never sends traffic aimed at a specific device during `scan`, `monitor`,
passive discovery, or `review`. `lanfence inspect <MAC>` is the one
explicit, opt-in exception: a bounded TCP connect-scan of a short, curated
list of common service ports on one already-known device, to help answer
"what is this thing" when passive evidence isn't enough.

```text
$ lanfence inspect aa:bb:cc:dd:ee:ff

Sending active inspection probes to 192.168.1.47 (aa:bb:cc:dd:ee:ff)...

Active inspection of aa:bb:cc:dd:ee:ff (192.168.1.47)
Method: nmap  ·  Observed: 14 Sep 2026 09:41 (just now)

Confirmed open ports:
  22/tcp   inferred service: ssh
  80/tcp   inferred service: http

Probable platform: not enough evidence to guess

This is an inference from which ports responded, not OS fingerprinting -
treat it as a hint, not a verified fact.
```

**Confirmed vs. inferred, always kept separate**: an open port is a fact -
the TCP handshake succeeded. The service label next to it, and any overall
"Probable platform" guess, are inferences from the port number and (for a
couple of cleartext protocols) a passively-read greeting banner or a single
harmless `HEAD /` request - never a verified capability, and never OS
fingerprinting. A platform guess is always labeled Medium or Low confidence,
never presented as definitive.

**Two ways to scan, no hard dependency**: a dependency-free, bounded
`ThreadPoolExecutor` connect-scan (pure standard library) always works; if
the optional [`nmap`](https://nmap.org/) binary is installed, `inspect`
prefers it (`-sT -sV`, no raw sockets, no root required) for better service
labels, falling back to the built-in scan if nmap is missing or fails to
run. Pass `--no-nmap` to force the built-in scan. Neither path ever shells
out with untrusted text - the target is validated as a literal IP address
before either scan runs.

**Never automatic**: `inspect` only ever runs when you explicitly invoke it,
or explicitly accept the offer `lanfence review` makes for the device
currently on screen:

```text
Actions: [T]rust  [I]nvestigate  [S]nooze  [X] Inspect  [D] Full details  [N]ext  [Q]uit
  choice: x

  More information may be available by actively inspecting this device.
  Active inspection sends probe traffic directly to 192.168.1.47.
  Run active inspection? [y/N]:
```

Declining leaves the device untouched and returns you to its menu. Results
are persisted (one row per MAC, the latest run replacing any earlier one)
and shown again - labeled with their age, and flagged `STALE` past 24
hours - by `lanfence device <MAC>` and inside `review`'s `[D] Full details`
view, so old inspection data is never presented as current.

Identification only, by design: no exploitation, no credential testing, no
protocol negotiation beyond a bare connect and reading a greeting a service
sends unprompted - the same defensive scope as the rest of LAN Fence.

## Address and name history

Older versions of LAN Fence only ever showed a device's *latest* IP and
hostname. Every address and name a device has ever presented is now
retained as durable evidence, each entry tagged with **where it came
from**, **when** it was first and most recently observed, and **which
interface** it was seen on:

```text
$ lanfence device aa:bb:cc:dd:ee:ff

...
Addresses (2 retained)
  10.0.0.5
    Source: ARP · Interface: eth0
    First observed: 2026-01-01T09:00:00+00:00   Last observed: 2026-01-05T08:00:00+00:00
  fe80::1234
    Source: IPv6 ND · Interface: eth0
    First observed: 2026-01-02T10:00:00+00:00   Last observed: 2026-01-02T10:00:00+00:00

Names (2 retained)
  office-laptop
    Source: DHCP option 12
    First observed: 2026-01-01T09:00:00+00:00   Last observed: 2026-01-05T08:00:00+00:00
  office-laptop.lan
    Source: reverse DNS for 10.0.0.5
    First observed: 2026-01-03T09:00:00+00:00   Last observed: 2026-01-03T09:00:00+00:00
```

The plain `IP:`/`Hostname:` fields in "Current details" (and `Device.ip`/
`Device.hostname` in JSON, everywhere a device is returned) are **preferred
values** computed from this evidence, not simply "whichever was written
last": a directly-observed address (ARP or IPv6 neighbor discovery) always
outranks a DHCP-reported lease, which outranks data imported from an
older database, regardless of which is more recent - only *within* the
same tier does recency decide. Names work the same way: a DHCP-reported
name (option 12) always outranks a reverse-DNS name. A failed reverse-DNS
lookup never erases a name already on file. This is a convenience for a
quick glance, not a claim that other retained addresses/names are wrong or
gone - see the full evidence list for that.

A dual-stack device correctly retains **both** its IPv4 and IPv6 addresses
- they are never collapsed to "whichever was seen last" the way earlier
versions' one-value-per-device model forced. A DHCP client merely
*requesting* or being *offered* an address is deliberately **not** treated
as evidence the device is using it (only a server's confirmed lease - an
ACK - or LAN Fence directly observing the address via ARP/ND counts); it
still counts as the device being alive on the network, just not as proof
of that specific address.

**History, not lease tracking**: first/last-observed timestamps summarize
when a specific piece of evidence was seen, not a continuous assignment
interval - an old-looking entry does not mean that address was released,
only that nothing has re-confirmed it recently, and LAN Fence never
invents a "device moved networks" or "address changed" narrative from
this alone.

**Upgrading an existing database**: a device's pre-existing `ip`/
`hostname` are imported once as `legacy_snapshot` evidence (lowest
preference tier, since its original source is no longer known) the first
time the database is opened after upgrading - timestamped as of that
import, not backdated to the device's original first-seen time, and never
re-imported on a later restart.

## Device inventory metadata

Beyond what LAN Fence observes on the wire, you can attach your own notes to
a device - who owns it, what it's for, which group it belongs to, and where
it physically lives:

```text
$ lanfence device aa:bb:cc:dd:ee:ff --owner "Alice" --purpose "Work laptop" \
    --group staff --location "Office"
metadata for aa:bb:cc:dd:ee:ff updated: owner, purpose, group, location

...
Inventory details (user-provided)
Owner:      Alice
Purpose:    Work laptop
Group:      staff
Location:   Office
```

Any combination of `--owner`/`--purpose`/`--group`/`--location` may be set
in one call; an omitted field is left unchanged. `--clear-owner` (and the
`--clear-purpose`/`--clear-group`/`--clear-location` equivalents) removes a
field - setting and clearing the same field in one call is rejected.
Metadata edits never scan, alert, fire a lifecycle event, or interact with
trust/review/presence in any way - they are pure inventory bookkeeping.

`lanfence device` (with no MAC) supports matching filters (`--owner`, `--group`,
`--location` - exact match, case-insensitive) and an opt-in `--details` flag
that adds Owner/Purpose/Group/Location columns to the table without
bloating the default view. JSON output always includes metadata (nested
under `"metadata"`) regardless of `--details`.

The interactive `lanfence review` queue offers an optional "Add device
details?" step (default no) right after trusting a device, pre-populated
with any existing values; skipping it, or aborting partway through, never
undoes the trust or presence decisions already made in that same session.

Owner/group also appear as brief context alongside a device's row in
`lanfence digest` output - purpose and location are left out there to keep
digest rows terse; the full detail is one `lanfence device <MAC>` away.

Like the allowlist name, none of this is authoritative or derived from
network traffic - it's exactly what you typed, unvalidated against reality,
and `lanfence reset` clears it along with the rest of a device's history.

## Starting over

```text
lanfence reset                    # asks for confirmation first
lanfence reset --yes              # noninteractive - for scripts
lanfence reset --yes --keep-allowlist
```

`lanfence reset` permanently deletes every previously scanned device: its
history, lifecycle events, alert cooldowns, and review/snooze state - and,
unless `--keep-allowlist` is given, the allowlist too, so trust decisions
start over from scratch as well. This cannot be undone. It asks for
confirmation and requires a terminal to do so; pass `--yes` to run it
noninteractively (e.g. before re-provisioning a device, or in a script).
Nothing about your configuration (`config.yaml`) is touched.

## Offline detection and grace periods

```yaml
scan:
  offline_grace_seconds: 180     # default
  offline_after_missed_scans: 3  # default
```

By default, LAN Fence does not mark a device offline the moment one active
sweep misses it - a single missed ARP reply is normal noise (a device asleep,
a busy Wi-Fi channel, a dropped packet), not proof a device disconnected. A
device is only actually marked offline once **both** conditions are true:

1. It has been missed by this many **consecutive eligible** active sweeps in
   a row (`offline_after_missed_scans`, default `3`); and
2. At least this much time has passed since it was last actually seen
   (`offline_grace_seconds`, default `180`).

"Online" during that window means **"not yet confirmed absent," not
necessarily still connected** - and only an active sweep ever confirms
absence; elapsed wall-clock time alone never disconnects a device, no matter
how long `monitor` has been running. That also means **scan cadence sets the
floor**: with the defaults, a device can't be confirmed offline sooner than
`offline_after_missed_scans` x `scan_interval_seconds` (3 x the default 60s =
3 minutes), even though `offline_grace_seconds` is also 180s - raise
`scan_interval_seconds` and the wait grows accordingly. Any positive sighting
(from an active sweep *or* passive ARP/ND/DHCP traffic) immediately resets
the missed-sweep count back to zero and keeps the device online; only a
completed active sweep is ever authoritative for absence.

A sweep only counts as a genuine "miss" for a device when it actually
examined that device's known network path - interface, address family, and
(for IPv4) subnet. A failed, skipped, or out-of-scope sweep never counts:

- If every scan mechanism failed this round (e.g. no root), there is no
  information at all, and no device is ever marked offline on that basis.
- A **successful but empty** scan still counts as real evidence of absence
  for devices within its coverage.
- If IPv4 scanning failed but IPv6 succeeded (or vice versa), only a device
  known through the *failed* family is spared - a device known through both
  needs both covered before a miss counts at all.
- Switching `--interface`/`--subnet` (or moving to a different network)
  never marks devices from the *other* network offline - it's simply outside
  what the current sweep examined.
- A device's own `last_seen` timestamp is never advanced by going offline -
  it stays the time it was actually last seen; the `disconnected` event's own
  timestamp records when the absence was confirmed instead.

**Compatibility**: set `offline_grace_seconds: 0` and
`offline_after_missed_scans: 1` to restore the pre-grace-period behavior of
disconnecting on the very first eligible missed sweep.

**Upgrading an existing database**: devices recorded before this feature
existed have no discovery-path information on file yet. LAN Fence treats
that conservatively - such a device is never marked offline via the
missed-scan logic until a fresh sighting (from either an active sweep or
passive traffic) establishes its real coverage; from then on, normal
grace-period rules apply. The database schema itself is upgraded
automatically and idempotently the next time it's opened - no data is lost
or reset.

## Presence policies

Laptops, phones, and tablets routinely leave and rejoin the network - that's
normal, not a problem. A server, printer, or NAS staying connected is the
opposite: its absence *is* the problem. Presence policies let you tell LAN
Fence which is which, per device - **separate from trust**. Trusting a
device (the allowlist) says "I recognize this device"; a presence policy
says "here's what normal looks like for it." A device can be trusted and
have any presence policy, or neither, independently.

```text
lanfence device <MAC> --presence intermittent    # normal to come and go
lanfence device <MAC> --presence always-on       # sustained absence is unexpected
lanfence device <MAC> --presence always-on --offline-after 10m
lanfence device <MAC> --presence unspecified     # back to the default
lanfence device <MAC> --clear-offline-after      # restore the global default delay
lanfence device --presence intermittent          # (no MAC) list devices with that policy
```

Three policies, per device:

- **`unspecified`** (the default) - no change from existing behavior.
- **`intermittent`** - routine absence and return are expected. LAN Fence
  keeps tracking real online/offline status and keeps recording
  disconnected/reappeared events in the timeline exactly as before; what's
  suppressed is only the *routine* "it came back" notification and finding -
  a finding whose sole purpose is announcing an ordinary return. A brand-new
  device's first-ever discovery is **never** suppressed, and neither is any
  independent security signal (e.g. a rogue-device signature match) carried
  alongside a reappearance - only the routine announcement itself is
  dropped. Setting this never trusts, snoozes, or otherwise approves the
  device.
- **`always-on`** - sustained absence is unexpected. Online/offline status
  still comes from the same scan-coverage rules, consecutive-miss threshold,
  and global `offline_grace_seconds` as every other device (see above) -
  presence policy doesn't change *when* a device is confirmed offline, only
  what happens next. Once confirmed offline, if it stays absent for the
  **effective absence duration** - its own `--offline-after` override, or
  `scan.offline_grace_seconds` when no override is set - LAN Fence emits one
  medium-severity availability finding ("this device has been gone longer
  than expected"), and exactly one info-severity recovery finding the moment
  it's seen again. **`--offline-after` is an alert delay, not a grace
  period**: it does not affect when a device is marked offline (that's still
  purely the coverage/miss-threshold/grace-period logic above) - it only
  controls how much *additional* time an already-offline always-on device
  gets before its absence is treated as noteworthy. If that delay elapses
  while a device is already offline, the alert fires on the next eligible
  sweep - no new disconnect is needed to trigger it. Trust is irrelevant
  here: even an allowlisted always-on device gets its availability finding.

Editing a policy never fabricates a lifecycle event or fires an alert by
itself - it only changes how *future* observations are interpreted. Setting
`always-on` on a device that's already offline makes it eligible for
evaluation on the very next qualifying sweep; switching a device *away* from
`always-on` clears any pending absence-alert state without firing a
recovery (there's nothing to recover from once it's no longer being
watched). A `lanfence monitor` process already running picks up a policy
edit made from another terminal immediately, on the next sighting - no
restart needed, the same as trust and review state.

`lanfence review`'s interactive flow asks about presence right after you
choose to trust a device ("Should this device always be online, or is it
normal for it to come and go?") - answering is optional and defaults to
whatever the device's policy already was (`unspecified` if never set);
exiting that follow-up prompt never undoes the trust decision you just made.

## Digest

`lanfence digest --verbose` and `scan --alert` are about *every* event as it
happens; `lanfence digest` (without `--verbose`) is the opposite - one
concise summary of a rolling window (default 24h) so you can check in
without a notification for every routine connect/reappear. It never scans
the network and never changes trust, review, snooze, or lifecycle state - a
pure read of what's already in the database, same as `lanfence device`.

```text
lanfence digest                        # preview only - sends nothing
lanfence digest --since 7d             # a longer window
lanfence digest --format json          # machine-readable
lanfence digest --send                 # also deliver, via digest.channels
lanfence digest --send --channel email
lanfence digest --send --channel email --channel ntfy --send-empty
lanfence digest --verbose               # also list every event/finding in the window
lanfence digest --verbose --fail-on-findings   # exit non-zero when medium+ findings are present
```

A digest reports, clearly separated:

- **Activity in the window**: new devices (name, MAC, IP, hostname, vendor,
  *current* trust status, and first-seen time), and a compact count of
  devices that reappeared or disconnected (each device counted once per
  activity type, even if it flapped repeatedly).
- **Current inventory/review state as of generation time** (not scoped to
  the window - a device flagged for review last month still shows up until
  it's resolved): devices needing review, current investigations (with
  notes and last-seen time), and - if presence policies are in use -
  currently-missing `always-on` devices.
- **Monitoring health**: this version has no durable record of monitor
  uptime or alert-delivery success/failure to draw on, so this always reads
  *"Monitoring health unavailable"* rather than guessing "healthy" - a
  known, documented gap, not a bug.
- **Monitor status**: separately, whether `lanfence monitor` is running on
  this host *right now* ("Monitor: running"/"Monitor: not running"),
  checked via the same pidfile convention as the web portal - a live,
  present-tense check, not the historical record "Monitoring health"
  above still doesn't have.

A device can legitimately appear in more than one section (e.g. new *and*
still needing review) since each section states a different fact; within a
single section a device is never duplicated. Every section lists every
matching device - there is no cap or "and N more" truncation. Historical
accuracy matters: "new devices" and the activity summary come from the
persisted lifecycle event log, not from re-deriving security severity out
of today's allowlist/signatures - a device trusted *after* it was recorded
as new-in-window still correctly shows as new-in-window, just with its
now-current trust status alongside it. Security findings themselves aren't
persisted anywhere in this version, so the summary above never claims to
show historical finding severity - only current trust/review state, exactly
what's actually stored. `--verbose` additionally lists every
connect/disconnect/reappearance event in the window and its findings
(computed fresh from that window's events, unlike the summary above) - the
detail formerly shown by the separate `lanfence report` command, which no
longer exists.

### Sending a digest

```yaml
digest:
  channels: [email]        # which existing alert destinations also get a digest
  send_when_empty: false
```

Delivery reuses your existing `alerts.<channel>` destinations (email,
webhook, Slack, Discord, Teams, ntfy) - enabling a channel under `alerts:`
does **not** by itself add it to digests; list it under `digest.channels`
(or pass `--channel` explicitly, which limits `--send` to just those,
still requiring each to already be enabled and configured). SMS (Twilio)
and syslog are not available for digest delivery and are rejected with a
clear error if requested. `--send` with no `digest.channels` configured and
no `--channel` given fails with a helpful error rather than silently doing
nothing; a preview with no destinations configured still works fine.

The **email** digest is a branded HTML email (LAN Fence's own logo and dark
color palette, matching the web portal - see below) - sent as a standard
multipart message with a plain-text alternative alongside it, so a
text-only mail client still gets a complete, readable body either way.
Every value that could come from an untrusted device (a hostname, a name)
is HTML-escaped before it's ever put in the email body. The logo is a
small raster image attached with a `Content-ID` and referenced as
`cid:lanfence-logo` in the HTML - not an inline `<svg>` - since several
mail clients (Gmail among them) strip inline SVG from HTML email entirely;
a `Content-ID`-attached image is the one approach that reliably renders
across mail clients, including older ones. It's generated at send time
with the standard library only (no image-library dependency).

A digest is **empty** when there's no window activity, no outstanding
review/investigation items, no missing always-on devices, and no known
monitoring/delivery problems - an unchanged device count alone does not
make it nonempty, and it never invents a problem just because monitoring
health is unavailable. `--send` on an empty digest is suppressed by default
(`digest.send_when_empty: false`); pass `--send-empty` to override for one
run, or set `send_when_empty: true` to always send.

Every requested channel is attempted independently - one failing (a bad
webhook URL, an SMTP timeout) never stops the others, and `lanfence digest
--send` exits non-zero if *any* requested channel failed, with a per-channel
`sent`/`FAILED` line. Digest delivery is entirely independent of the
immediate-alert pipeline: it ignores `alerts.min_severity` and never reads
or writes the per-MAC alert cooldown, so sending a digest can never suppress
(or be suppressed by) an immediate alert for the same device.

## Communication channels

Configuring Slack/Discord/Teams/ntfy/email/webhook/Twilio/syslog by hand
means editing YAML and hunting down each provider's webhook-setup screen.
`lanfence setup` is an interactive wizard for the same `alerts.<channel>`
settings above - it doesn't add a new configuration system, just a safer,
guided way to edit the one that already exists. It needs a real terminal;
for scripted/noninteractive use, edit the config file directly instead.

```text
lanfence setup                    # unified setup: communications and application settings
lanfence setup --config /etc/lanfence/config.yaml
lanfence setup slack              # go directly to Slack's own setup wizard
```

`lanfence setup` (no argument) opens a numbered application setup menu.
Choose Communications to edit destinations, or Scanning, Offline detection,
DHCP servers, Service discovery, Daily digest, Storage, or Alert delivery.
All sections share an unsaved draft: **Review** shows a redacted before/after
summary; **Save** validates everything and asks for confirmation; **Discard**
restores the last saved configuration. Exit with unsaved edits offers Save,
Discard, or Return. Ctrl+C/EOF discards only edits since the last save.
Opening setup, reviewing changes, or saving never scans or sends messages.

Fields show their effective value and whether it is explicit or inherited.
Blank keeps a value; `reset` removes the override; nullable fields accept
`null` for explicit auto/unset. Time fields accept seconds or durations such
as `5m`. Enumerations show their choices; digest destinations are a
comma-separated list. Cross-setting warnings identify inactive discovery and
disabled digest destinations. Save does not rewrite a file when nothing changed.

The DHCP server section includes **a — Approved DHCP servers**, with Add,
Edit, Remove, Observed, Reset, and Back actions. Observed opens a read-only
inventory: select a server, review its identifier/interface and explicitly
confirm approval. Its `server_ip` is option 54, not necessarily the source or
relay IP. VLAN interfaces such as `eth0.20` have separate approval scope.
Approving a DHCP role does not trust a device. An unavailable inventory never
prevents manual entry.

Storage edits change paths only: existing databases are not migrated, moved,
or deleted. Retention periods are currently fixed in code and change-notification
settings are not implemented; neither is offered as a setting. Schema-unknown
keys are rejected by the existing configuration model, so files containing them
are left untouched rather than silently dropping their data. Supported settings
and unrelated raw values are preserved when editing valid files.

The unified editor refuses to save through a configuration symlink; rerun with
its intended target path. It warns before replacing comments/formatting or
restricting file permissions. A running monitor must be restarted with the same
`--config` path to load saved application/channel settings. No restart or
schedule installation happens automatically. After saving changed enabled
channels, it offers an optional test for each destination, defaulting to no.

`lanfence setup slack` still goes directly to the channel wizard, prompting
for its real config fields (existing values shown as defaults where it's
safe to display them), a one-line pointer to where to obtain each setting,
local validation (URL scheme/hostname, port range, E.164 phone numbers,
email syntax, timeouts, supported priorities/facilities - never a network
request, so passing this never proves delivery will actually work), a
sanitized preview, and a save/cancel prompt. A secret (webhook URL, SMTP/
Twilio credentials) is never echoed back: an existing one shows as "already
configured", and you choose to leave it, type a new value, or type `clear`
to remove it - leaving the prompt blank always preserves what's already
there. Digest-eligible channels (email, webhook, Slack, Discord, Teams,
ntfy - not Twilio/syslog) get one extra "use this for daily digests too?"
prompt, touching only `digest.channels`; the digest schedule, severity
thresholds, and per-MAC cooldowns are never touched by this command. After a
successful save you can optionally send a test message (defaults to **no**;
Twilio warns that a test SMS may incur provider charges) - the only way to
trigger a test message; there is no separate standalone test/enable/disable
command, so toggling a channel outside the wizard means hand-editing
`alerts.<channel>.enabled` in the config file.

**Email/SMTP**: every email send path (alerts, digests, and setup's
post-save test message) verifies the SMTP relay's certificate and hostname
before authenticating or sending anything - `email.use_tls: true` (the
default) never falls back to an unverified STARTTLS upgrade. If your
relay's certificate is signed by a private/internal CA, set `email.ca_file`
to a PEM bundle to trust it in addition to the system trust store; there is
no setting to disable verification itself. `email.username`/`password` are
refused (delivery aborts rather than sending a password in the clear) if
`use_tls` is disabled - an explicitly configured unauthenticated local
relay (`use_tls: false` with no username/password) is unaffected.

**Config file location**: LAN Fence has no other default *writable* config
file (every other command treats a missing `--config` as "built-in
defaults, touch no file"), so `setup` uses a conventional per-user path,
`~/.config/lanfence/config.yaml`, when `--config` isn't given - shown before
saving, along with a reminder to pass the same `--config` path to `monitor`
(config is read once at startup, not while running, so a running `monitor`
needs a restart to pick up a change here); resolved against your own home
directory even under `sudo`, so `sudo lanfence setup` and a plain `lanfence
setup` edit the *same* file. Saving is atomic and safe: existing unrelated
sections, other channels, and disabled channels' own settings/secrets are
always preserved; malformed YAML is never overwritten (the file is left
untouched with a clear error instead); a concurrent edit between load and
save is detected and refused rather than clobbered; a newly-written file is
owner-readable/writable only (`0600`), and an existing file found more
permissive than that is tightened with a clear note. Values are always
preserved, but - like `lanfence allow`'s own YAML writer - hand-written
comments and formatting are not, since that would need a new dependency
this project avoids.

## Web portal

`lanfence web` is a small local web server for browsing the device
inventory and trusting/untrusting/renaming/labeling a device from a
browser instead of the CLI - the same underlying operations as `lanfence
allow`/`lanfence allow --remove`/`device --owner`/etc., just with a
clickable interface. Built on the standard library only (no new
dependency): a handful of small pages, not a general web application. A
trusted device's page has an "Untrust this device" action (with a
confirmation prompt) - the same effect as `lanfence allow --remove <MAC>`.

The device list is sortable by clicking any column heading (Name, MAC, IP,
Vendor, Status, Trust) - clicking again reverses direction. This is plain
server-rendered HTML (`?sort=<column>&dir=asc|desc`), no JavaScript
required. IP addresses sort numerically (`10.0.0.2` before `10.0.0.10`),
not as plain text. A dual-stack device shows both its IPv4 and IPv6
address, side by side, in both the list and its own detail page - the
same as the CLI's `lanfence device`.

```text
lanfence setup       # Web portal section: enable it, set a password
lanfence web         # start the already-configured portal (foreground)
```

There is no separate `lanfence web enable`/`set-password` command -
everything is configured through `lanfence setup`'s **Web portal** section
(`web.enabled`, `web.port`, and a "Set/change password" action listed
alongside them). `lanfence web` only starts what that section already
describes, and refuses to start if the portal isn't enabled or no password
has been set yet. Right after enabling it and setting a password, `setup`
checks for an active local firewall (`ufw`/`firewalld`) that could block
other LAN devices from reaching the port even though the portal itself is
running, and offers to open it; it then offers to start the portal
immediately for convenience. Disabling the portal again stops whatever's
currently running automatically.

**Security posture, by design:**

- **Binds only to this host's own detected LAN address** (found the same
  way a browser or any other LAN client would resolve "my own address" -
  never `0.0.0.0` or a public interface), and refuses to start if that
  can't be confirmed as a private address. A device on your own LAN is
  exactly the population this whole tool exists to distrust, so the portal
  is never reachable from anywhere else, including the internet, even if
  this host also has a public interface.
- **Always HTTPS, via a self-signed certificate generated on first run -
  there is no plain-HTTP mode.** "On your own LAN" doesn't mean
  "trustworthy" - the whole premise of this tool is that other devices on
  the LAN might not be, so the login password must never go out in
  cleartext to them. There's deliberately no setting to turn TLS off; an
  optional insecure mode just recreates the problem for whoever leaves it
  off. Because the certificate is self-signed rather than CA-issued, every
  browser shows a one-time "connection is not private" warning to click
  through the first time - the same experience as any router or NAS admin
  panel on your LAN. Generating the certificate needs the `openssl` CLI
  (not a new Python dependency - present on essentially every Linux/macOS
  install already); it's cached under the state directory and only
  regenerated if the host's LAN address changes.
- **Single shared login**, no per-user accounts - this is a household tool,
  not a multi-tenant one. The password is stored as a salted `scrypt` hash
  in `config.yaml` (`web.password_hash`/`web.password_salt`), never the
  password itself; sessions are an in-memory cookie only (a restart means
  logging in again, rather than ever persisting a session token to disk).
  Repeated failed logins from the same address are locked out for a short
  period, the same as any internet-facing login would be.

**Reachable from other devices, not just this host**: binding to the LAN
address is necessary but not sufficient - a local firewall (`ufw`,
`firewalld`) can still block other devices on your LAN from reaching the
port even though the process itself is up and the host responds to a
`ping` (this shows up in a browser as something like
`ERR_ADDRESS_UNREACHABLE`, distinct from the portal simply not running).
Right after `setup` enables the portal, it checks for one of these two
firewall managers being active and, if so, offers to open the port for
you (scoped to the bound LAN address for `ufw`); if it can't (most
commonly because `lanfence setup` itself isn't running as root), it
prints the exact `sudo` command to run yourself. An nftables/iptables
setup managed directly, or a filter on an upstream router, isn't
something this can see or fix automatically.

**Starting it for real, not just "right now"**: the convenience start
offered by `setup` is exactly that - a background process that won't
survive a reboot or come back automatically after a crash. For anything
long-lived, install the packaged systemd unit instead:

```bash
cp packaging/lanfence-web.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lanfence-web
```

See the comments at the top of `packaging/lanfence-web.service` for the
one-time setup (the same dedicated, unprivileged service account
`lanfence.service` uses - this one needs no raw-socket capability at all).
Disabling the portal via `lanfence setup` stops it correctly either
way - a running systemd-managed instance is stopped with `systemctl stop`
(so it doesn't just get restarted by the unit's own restart policy),
never sent a raw kill signal directly.

**In a digest**: every delivered digest (email, Slack, Discord, Teams,
ntfy, and the `webhook` JSON payload) always mentions the portal one way
or the other. If it's actually running right now, the digest includes a
link to it - "here's where to go label that new device." If it isn't
(never enabled, enabled but not started, or stopped), the digest says so
instead ("Web portal is not running - enable it with `lanfence setup`")
rather than a broken or absent link, which doubles as a reminder the
feature exists even if you've never touched it. This is deliberately keyed
off whether the process is actually running, not just `web.enabled` in
config - a stale "enabled" with nothing behind it would be a dead link.
The link itself is never a fixed, configured address either: since the
portal's bind address can change under DHCP, it's recomputed fresh each
time a digest is generated, the same "as of now, not cached" posture the
digest already applies to monitoring health elsewhere.

## Unexpected DHCP servers

Passively detects a DHCP server (a DHCPOFFER/ACK/NAK reply) that isn't on
your approved list for the interface it answered on - a rogue or
misconfigured DHCP server on your LAN can silently redirect every new
client's traffic through itself. Purely observation: LAN Fence never sends
a DHCP request of its own, and this reuses the existing passive DHCP
capture rather than opening a new one.

```yaml
dhcp_servers:
  enabled: false                 # opt-in - off by default
  approved:
    - interface: eth0
      server_ip: 192.168.1.1     # DHCP option 54 - the server identifier
      name: Main router
    - interface: eth0
      server_ip: 192.168.1.2
      name: Backup DHCP
  alert_cooldown_seconds: 3600   # per (interface, server) - don't flood findings from one noisy server
```

```text
lanfence dhcp-servers            # every observed server + approval status - a database read, no scan
lanfence dhcp-servers --format json
```

Approval is scoped by **interface** - a VLAN sub-interface (e.g. `eth0.20`)
is already its own interface name at the OS level, so it's covered with no
separate VLAN setting; this project does not parse raw 802.1Q tags from
captured frames, so no VLAN-isolation claim is made beyond what the
interface name itself expresses. Multiple servers can be approved per
interface (a primary and a failover, say). **Turning this on with an empty
`approved` list means every server observed is treated as unexpected** -
LAN Fence never auto-approves the first responder, and an existing device
allowlist entry never implies DHCP server approval either; they're
independent trust decisions, checked separately. This version has no
config-writing workflow for approval - add entries to `dhcp_servers.approved`
by hand and (since this config is only read at startup) restart `monitor`
for the change to take effect.

Detection only ever runs during `lanfence monitor` (`scan`, a one-shot
active sweep, has no equivalent - DHCP servers only speak when spoken to by
a real client, which nothing here simulates) and depends on the *same*
passive DHCP capture the hostname-snooping feature uses
(`scan.passive`/`scan.dhcp_snooping`) - if `dhcp_servers.enabled` is true
but that capture is off, `monitor`'s startup banner says so plainly rather
than silently providing no protection.

An unapproved server produces one medium-severity **"Unexpected DHCP server
observed"** finding, explaining that this alone doesn't establish malicious
intent (it might be a legitimate second router, a failover server, or a
misconfiguration) and recommending you check it and approve it if expected.
This finding has **no MAC address** - a DHCP server's identity is its option
54 server identifier, not any one Ethernet address (a relayed reply's
source MAC belongs to the *relay*, not the server, and `BOOTP.chaddr`
identifies the *client* the reply was for) - so it's shown by its interface
and server identifier instead. Role approval is independent of device
trust: a device already on your allowlist that starts answering DHCP
requests without approval still produces this finding, and an intermittent
presence policy has no bearing on it either (it isn't about a device at
all). A server's approval status is computed fresh each time from current
config - approving a server later never rewrites the evidence already
recorded for findings raised while it was still unapproved.

**Visibility limitations** - detection only covers replies actually visible
at the capture interface: a switched network can hide a unicast reply
entirely, and a quiet network may produce no observations until a client
next renews or joins. Multiple DHCP servers/relays on a network can be
entirely legitimate (redundancy, VLAN-specific scopes). Server identifiers
and MAC addresses seen on the wire are claims, not authenticated identities
- treat a finding as a lead to check, the same as every other signature in
this tool. This feature does not detect DHCPv6 servers.

## Passive advertised-service discovery

Enriches your device inventory with services devices *advertise about
themselves* over mDNS/DNS-SD (Bonjour) and SSDP/UPnP - "this device speaks
printing (IPP)", "this device advertises AirPlay", "this is a UPnP
MediaRenderer". **These are device-advertised claims, not verified
capabilities, authenticated identities, or proof a service is actually
reachable** - treat them the same skeptical way as a vendor OUI or a
self-reported hostname.

Strictly passive, same as every other discovery mechanism in this project:
LAN Fence never sends an mDNS query, an SSDP `M-SEARCH` request, an HTTP
request, or any other discovery traffic, and it never fetches an SSDP
`LOCATION` URL. It only parses mDNS/SSDP traffic that's already flowing on
the network and reaching the existing passive capture.

```yaml
discovery:
  mdns: false   # opt-in - off by default
  ssdp: false   # opt-in - off by default
```

Both narrowly extend the existing passive capture filter (UDP port 5353 for
mDNS, 1900 for SSDP) and only take effect when `scan.passive` is also true -
`monitor` prints a warning if you enable one without the other, rather than
silently doing nothing. Like every other `scan.*`/`discovery.*` setting,
this is only read at `monitor` startup, so a config change needs a restart
to take effect - or pass `--mdns`/`--no-mdns`/`--ssdp`/`--no-ssdp` directly:

```text
lanfence monitor --mdns --ssdp
```

```text
$ lanfence device aa:bb:cc:dd:ee:ff

...
Advertised services (1 known)
  Printing — _ipp._tcp
    Instance: Office Printer
    Target: printer.local:631
    Source: mDNS/DNS-SD · Interface: eth0
    Last observed: 2026-01-05T08:00:00+00:00
    Advertisement expires: 2026-01-05T08:02:00+00:00
    Association: target IP matched observed device address

$ lanfence services
lanfence services --protocol mdns
lanfence services --protocol ssdp
lanfence services --unassociated       # only services that couldn't be confidently matched to a device
lanfence services --include-expired    # also show expired/withdrawn history
lanfence services --format json
```

**Attribution is deliberately conservative.** *Who transmitted an
advertisement* and *which device it's actually about* are two different
questions - an mDNS proxy, reflector, or shared responder can legitimately
advertise services on behalf of other hosts, so LAN Fence never assigns a
service to the packet's own Ethernet/IP source. Instead, it correlates the
service's *target* address (the mDNS SRV record's host, or - for SSDP,
which has no separate target concept - the packet's own source address)
against address evidence it has *directly observed* itself (ARP/IPv6 ND -
never a DHCP-reported lease claim or older imported data). If that match is
unique, the service is attributed; if it's ambiguous (more than one MAC has
ever held that address) or there's no match at all, the service is shown as
**unassociated** rather than guessing. Attribution is recomputed fresh every
time you look, so it can improve as better evidence arrives - and the
original advertisement evidence is never rewritten to reflect it.

**TTL and expiry semantics** follow each protocol's own rules: an mDNS
"goodbye" record (TTL 0) or an SSDP `ssdp:byebye` immediately withdraws that
specific advertisement (never every service the device advertises); absent
that, a service's advertised lifetime (its DNS TTL, or SSDP's
`CACHE-CONTROL: max-age`) determines when it's shown as **expired**. A
missing/invalid SSDP max-age never grants an immortal advertisement - it
falls back to a short, bounded default instead. `lanfence services` and
`lanfence device <MAC>` show only **current** advertisements by default;
`--include-expired` shows the bounded history too, each status explicitly
labeled. None of this ever fabricates a device lifecycle event, changes
presence/reachability, or fires a finding/alert - a service expiring does
not mean the device went offline, and this feature raises no new findings
in this release.

**What's retained**: for mDNS, the service type (with a friendly label for
a small set of well-known types - printing, AirPlay, remote audio, cast,
generic web service; an unrecognized type is kept with its raw name, never
guessed at), the instance name, the target host/port, and a small,
documented allowlist of TXT attributes (bounded in count and size) -
**never** a raw TXT blob or an arbitrary unknown key. For SSDP: `USN`
(its stable identity), `NT`/`ST`, `SERVER`, `LOCATION` (stored as
untrusted advertised metadata - never fetched, followed, or embedded as a
resource), and `CACHE-CONTROL`'s max-age. `SERVER`/TXT model-like
attributes are always advertised claims, labeled as such wherever shown -
never treated as verified vendor/model identity.

**Visibility limitations**: absence of an observation here is not evidence
a service doesn't exist - only that nothing advertising it has reached this
capture point yet (a quiet device, a switched/segmented network, or
discovery simply not having been enabled long enough all look the same as
"nothing to report"). Expired/withdrawn evidence is retained for a bounded
period (30 days) then opportunistically pruned - `lanfence services
--include-expired` shows what's still on file. `lanfence reset` clears all
discovery evidence along with the rest of a device's history.

## Running unattended

LAN Fence does not ship its own scheduler; use `systemd` (recommended on a
Pi) or `cron`.

**Continuous monitoring** - see [`packaging/lanfence.service`](packaging/lanfence.service)
for the full, hardened example unit (a dedicated unprivileged service
account with only `CAP_NET_RAW`, filesystem/capability sandboxing, and
step-by-step setup/migration instructions in its own comments) - a
condensed version:

```ini
[Unit]
Description=LAN Fence continuous network device monitoring
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/lanfence monitor --config /etc/lanfence/config.yaml
Restart=on-failure
User=lanfence
Group=lanfence
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
StateDirectory=lanfence
StateDirectoryMode=0700
ProtectSystem=strict
ProtectHome=true
UMask=0077
# ... see packaging/lanfence.service for the complete sandboxing set and
# the one-time `useradd`/config-ownership setup this depends on.

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp packaging/lanfence.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lanfence
```

Running as root (an earlier version's only documented option) still works
if you genuinely need it, but is no longer the recommended or example
configuration - the capability LAN Fence's scanning actually needs
(`CAP_NET_RAW`) is granted directly to this one service by systemd above,
never via `setcap` on the shared Python interpreter or the `lanfence`
script itself, which would hand that capability to anything else run with
that interpreter/script too.

**Daily report** - a cron entry (`sudo crontab -e`):

```cron
0 7 * * * /usr/local/bin/lanfence digest --verbose --since 24h --format json > /var/log/lanfence/daily.json
```

**Daily digest** (see [Digest](#digest) below) - `lanfence monitor` already
runs continuously and writes to the same database `digest` reads from; run
`digest` as a *separate*, periodic job as whichever user can read that
database and `config.yaml` (typically the same user/root that runs
`monitor`). A cron entry (`sudo crontab -e`):

```cron
0 7 * * * /usr/local/bin/lanfence digest --send --config /etc/lanfence/config.yaml
```

Or a systemd oneshot service + timer -
`/etc/systemd/system/lanfence-digest.service`:

```ini
[Unit]
Description=LAN Fence daily digest
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/lanfence digest --send --config /etc/lanfence/config.yaml
# digest only reads the database and sends alerts - no raw-socket access,
# so no capability is needed at all; the same dedicated, unprivileged
# account `lanfence.service` runs as (see packaging/lanfence.service) is
# enough, as long as it can read config.yaml and the database/allowlist.
User=lanfence
Group=lanfence
```

`/etc/systemd/system/lanfence-digest.timer`:

```ini
[Unit]
Description=Run the LAN Fence daily digest every day at 07:00

[Timer]
OnCalendar=*-*-* 07:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now lanfence-digest.timer
```

Two things to keep in mind when scheduling either way: `OnCalendar`/cron
times are in the **scheduler's local timezone**, while the digest's own
rolling window (`--since`, default `24h`) is always computed in **UTC**
ending at the moment `digest` runs - "daily at 07:00 local time" does not
mean "midnight-to-midnight UTC". And this first version does **not**
promise exactly-once delivery or automatic catch-up after downtime: if the
host is off when the timer would have fired, that run is simply skipped
(no backlog is queued), and running `digest --send` twice sends twice - it
is not idempotent.

## Configuration

All settings are optional; everything has a sensible default. Pass
`--config path/to/config.yaml` to any command.

```yaml
scan:
  interface: null              # null = auto-detect
  subnet: null                 # null = derive from the interface's own address
  scan_interval_seconds: 60    # how often `monitor` repeats an active sweep
  active_scan_timeout_seconds: 3
  passive: true                # also sniff ARP/ND traffic between sweeps
  ipv6: true                   # also discover devices via IPv6 neighbor discovery
  dhcp_snooping: true          # snoop DHCP for a self-reported hostname (needs passive: true)
  resolve_hostnames: true      # try reverse DNS for each device
  dns_timeout_seconds: 1
  passive_queue_maxsize: 2000  # cap per passive processing queue; excess is dropped (counted), never blocks capture

alerts:
  min_severity: medium         # info | medium | high - dispatch threshold
  rate_limit_seconds: 900      # per-MAC cooldown between alerts; 0 = alert every time
  global_rate_limit_max: 20            # cap on total alert dispatches per window, across every MAC/subject
  global_rate_limit_window_seconds: 60 # ...within this many seconds; 0 (either field) disables it
  syslog:
    enabled: false
    address: /dev/log
    facility: user
  email:
    enabled: false
    smtp_host: localhost
    smtp_port: 587
    use_tls: true
    username: null
    password: null
    from_addr: null
    to_addrs: []
    ca_file: null                # extra private CA bundle (PEM path), if your relay needs one
  webhook:
    enabled: false
    url: null
    timeout_seconds: 5
  slack:
    enabled: false
    webhook_url: null            # Slack app settings -> Incoming Webhooks
    timeout_seconds: 5
  discord:
    enabled: false
    webhook_url: null            # channel settings -> Integrations -> Webhooks
    timeout_seconds: 5
  teams:
    enabled: false
    webhook_url: null            # incoming webhook / Workflow URL
    timeout_seconds: 5
  ntfy:
    enabled: false
    url: null                    # e.g. https://ntfy.sh/my-lanfence-topic
    priority: null               # min | low | default | high | urgent
    timeout_seconds: 5
  twilio:
    enabled: false
    account_sid: null
    auth_token: null              # sensitive - treat this file like a credential
    from_number: null             # E.164, e.g. "+15551234567"
    to_numbers: []
    timeout_seconds: 10
    max_segments_per_day: 200     # durable daily SMS-segment budget across all recipients; 0 = unlimited

digest:
  channels: []                  # which alerts.<channel> destinations also get a digest, e.g. [email]
  send_when_empty: false

dhcp_servers:
  enabled: false                # opt-in; needs scan.passive/scan.dhcp_snooping too - see "Unexpected DHCP servers"
  approved: []                  # e.g. [{interface: eth0, server_ip: 192.168.1.1, name: Main router}]
  alert_cooldown_seconds: 3600  # per (interface, server) - don't flood findings from one noisy server

retention:
  max_evidence_rows_per_mac: 100      # retained address/name evidence rows kept per MAC; oldest pruned first
  max_dhcp_server_findings: 5000      # total DHCP-server-finding rows retained; oldest pruned first
  max_discovery_rows_per_table: 5000  # total rows per mDNS/SSDP table; oldest pruned first (on top of TTL expiry)

db_path: ~/.local/share/lanfence/lanfence.db
allowlist_file: ~/.config/lanfence/allowlist.yaml
vendor_file: null             # extra OUI table, merged with the packaged one
rogue_signatures_file: null   # extra signatures, merged with the packaged ones
```

Every channel dispatches independently and only when `enabled: true` and fully
configured; `min_severity` gates all of them at once. Twilio SMS is capped at
~480 characters per alert (a compact one-line summary, not the full
multi-line report the other channels get) since SMS is billed per segment.

`rate_limit_seconds` (default 15 minutes) is a per-MAC cooldown on top of
that: once a device has triggered a dispatch, further alerts about it are
suppressed until the cooldown elapses - unless a new finding's severity is
higher than what was last alerted, which always gets through immediately.
This only throttles the external channels above; the CLI table, JSON output,
and the database's event history are always complete, so a flapping device
(a phone's Wi-Fi cycling, a laptop sleeping/waking) doesn't spam every
channel - or run up a Twilio bill - once per scan interval. Set it to `0` to
alert every time, matching earlier versions' behavior.

**`global_rate_limit_max`/`global_rate_limit_window_seconds`** cap *total*
alert volume across every device combined, independent of the per-MAC
cooldown above - a per-MAC cooldown alone can't bound volume from many
distinct or rotating identities (e.g. randomized MAC addresses), since each
one looks "new" to it. An escalation still counts against this global cap
even though it bypasses its own per-MAC cooldown. Set `global_rate_limit_max`
to `0` to disable it.

**`twilio.max_segments_per_day`** is a durable (survives a restart) daily
budget on total SMS segments sent, counting every recipient and every
~153-character segment of each message - a cost-safety guardrail against a
flood of findings driving unbounded SMS billing, independent of the per-alert
480-character cap above. Once exhausted, remaining recipients for that
dispatch are skipped (not sent) until the next UTC calendar day. Set it to
`0` for no budget. `lanfence reset` does **not** clear this budget - it's a
billing safeguard, not device inventory.

`lanfence monitor`'s alert delivery (network I/O to each channel) runs on a
bounded background thread, so a slow or unreachable destination (e.g. a
webhook endpoint that's down) never blocks the main loop from continuing to
process new sightings and active sweeps. If delivery genuinely can't keep up,
newer alert batches are dropped (logged, not silently lost) rather than
buffering without limit - the underlying finding and its database record are
never affected by whether delivery itself succeeded.

## Exit codes (`--fail-on-findings`)

`scan` and `report` accept `--fail-on-findings` for CI/scripting use:

| Highest severity in the result | Exit code |
|---|---|
| none / info | 0 |
| medium | 10 |
| high | 20 |

## Privacy and security

- **No telemetry, no automatic external calls.** LAN Fence never phones home
  on its own. Alert destinations are ones *you* configure and enable (your
  own syslog daemon, SMTP relay, webhook, Slack/Discord/Teams webhook, ntfy
  topic, or Twilio account) - nothing is contacted unless you set
  `enabled: true` and fill in its details. The only other network access is
  two commands that exist purely to fetch something *you* asked for, only
  when you run them: `lanfence upgrade` (checks/installs from PyPI) and
  `lanfence vendor-refresh` (downloads the IEEE OUI registry). Every other
  command touches only your local network (ARP/ND) and disk.
- The bundled vendor and signature tables are static snapshots taken when
  this version was built; nothing is fetched automatically to "keep them
  fresh" - that's what `vendor-refresh` is for, on request.
- The device database and allowlist are written atomically. The database's
  containing directory is created (or, if it already exists, tightened)
  to mode `0700` and the database file itself to `0600` - regardless of
  the process umask - and the same applied to any pre-existing SQLite
  journal/WAL sidecar files; only the directory LAN Fence itself owns is
  ever touched, never a shared ancestor like `~/.local/share`. A directory
  or file unexpectedly owned by a different user, or that is actually a
  symlink, is refused with a clear error rather than silently used - the
  database file, its containing directory, and its SQLite sidecar files
  are all opened with an atomic, symlink-refusing syscall (`O_NOFOLLOW`/
  `O_EXCL`), never a separate exists-then-open check that a symlink swap
  could race between, so a database path an attacker redirected to
  another file is refused rather than followed.
- **Bounded against a hostile or flooding LAN.** `monitor`'s passive
  processing queues (`scan.passive_queue_maxsize`) are bounded and drop
  (counted, logged) rather than grow without limit under a packet flood;
  repeated identical observations in one burst are coalesced without losing
  any distinct evidence; alert delivery is bounded and backgrounded so a
  slow/unreachable destination can't stall sighting processing; a *global*
  alert-volume cap (`alerts.global_rate_limit_max`) bounds total external
  alert dispatch even from many distinct or rotating (e.g. randomized MAC)
  identities, which a per-MAC cooldown alone cannot; retained per-MAC
  evidence and DHCP-server/discovery-advertisement rows are capped
  (`retention.*`), independent of (and tighter than) time-based expiry, so a
  burst of spoofed/rotating observations can't grow the database without
  bound before any individually expire.
- **Delivery failures never log or display raw transport details.** A
  channel's server can influence what a raised exception's text contains
  (an HTTP "reason phrase", an SMTP response line) - LAN Fence never logs
  or shows that raw text. Every alert/digest/test-message failure is
  reported as the exception's class name plus a validated *numeric* code
  where the transport provides one (an HTTP status, an SMTP reply code) -
  e.g. `HTTPError (code 502)` - never a full webhook URL, credentials, a
  response body, or (for Twilio) a recipient's phone number.
- **The example systemd service runs as a dedicated, unprivileged
  account**, not root - see [`packaging/lanfence.service`](packaging/lanfence.service),
  which grants only `CAP_NET_RAW` (the one capability scanning needs,
  documented above) directly via systemd, never via `setcap` on the
  shared Python interpreter or the `lanfence` script itself, plus
  filesystem/capability/syscall sandboxing (`ProtectSystem=strict`,
  `NoNewPrivileges`, `UMask=0077`, and more).

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,scan]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for scope and pull-request guidelines,
and [DISTRIBUTING.md](DISTRIBUTING.md) for licensing notes on the optional
`scapy` (GPL-2.0) dependency.

## License

MIT - see [LICENSE](LICENSE).
