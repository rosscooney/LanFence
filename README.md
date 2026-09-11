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
(or `CAP_NET_RAW` on the interpreter). `allow`, `report` and `check` do not.

## Commands

```text
lanfence scan                  # one-time active ARP scan; table + findings
lanfence run                    # exact alias for `scan`
lanfence scan --format json    # same, machine-readable
lanfence monitor                # continuous: active sweeps + passive sniffing
lanfence allow <MAC> --name X   # trust a device; its findings become info
lanfence allow --list           # show the allowlist
lanfence allow --remove <MAC>   # untrust a device
lanfence devices                # list previously observed devices - no scan
lanfence devices --review-needed --format json
lanfence device <MAC>           # one device's details, trust state, timeline
lanfence review                 # interactively work through devices needing review
lanfence review <MAC> --trust --name "Kitchen speaker"
lanfence review <MAC> --snooze 24h
lanfence review <MAC> --investigate --notes "..."
lanfence review <MAC> --clear
lanfence report --since 24h     # summarize events/findings from the database
lanfence check                  # verify permissions, scapy, interface, storage
lanfence upgrade                # check PyPI and install a newer release, if any
lanfence upgrade --check        # only report whether an update is available
lanfence link                   # make `sudo lanfence` work (pipx/--user installs)
lanfence vendor-refresh         # pull a current copy of the IEEE OUI registry
```

`scan`/`monitor` warn (and show copy-pasteable fixes) if not run as root, since
ARP scanning needs raw-socket access. A pipx / `pip install --user` install
puts the `lanfence` launcher in `~/.local/bin`, which `sudo` does not see by
default - `sudo lanfence scan` then fails with "command not found". Run
`lanfence link` once (no `sudo` needed up front - it re-execs itself under
`sudo` and prompts for your password) to symlink the launcher onto root's
`PATH`; after that, a bare `sudo lanfence scan` / `sudo lanfence monitor`
works. `lanfence link --remove` undoes it.

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

## Device inventory and review

`scan`/`monitor` find devices; `devices`, `device`, and `review` let you work
through what's already in the database, without touching the network.

```text
lanfence devices                          # every observed device, no scan
lanfence devices --status online          # combine filters with AND
lanfence devices --untrusted --review-needed --format json
lanfence device aa:bb:cc:dd:ee:ff          # one device's details + timeline
lanfence device aa:bb:cc:dd:ee:ff --since 7d --format json
lanfence review                           # walk the review queue interactively
lanfence review <MAC> --trust --name "Kitchen speaker" --notes "..."
lanfence review <MAC> --snooze 24h
lanfence review <MAC> --investigate --notes "..."
lanfence review <MAC> --clear
```

`lanfence devices` lists every device ever observed, straight from SQLite -
it never scans. Each row's trusted/untrusted state is looked up fresh against
the *current* allowlist file, not whatever it was on that device's last scan.
`--status online|offline`, `--untrusted`, and `--review-needed` combine with
AND: `--status online --untrusted` shows only devices that are both online
and off the allowlist. **Review-needed** means untrusted, not currently
snoozed, and not already flagged investigating - trusting, an active snooze,
or an investigation flag all take it out of the queue.

`lanfence device <MAC>` shows one device in two clearly separated parts:
*current details* (IP/hostname/vendor/status/trust/review state), which
reflect only the most recent sighting, and a *lifecycle timeline* of
connect/reappear/disconnect events since `--since` (default `30d`). The
timeline is an append-only event log, not a full history of every address a
MAC has ever held - LAN Fence does not retain that. An invalid or
never-before-seen MAC exits non-zero with a clear error.

`lanfence review` is how you act on the queue. With no MAC, it walks devices
needing review one at a time, in a stable MAC order fixed at the start of the
session, and offers:

- **[t]rust** - prompts for a friendly name and optional notes, then adds the
  device to the same allowlist `lanfence allow` writes to. LAN Fence never
  trusts a device on its own; a human always makes this call.
- **[s]nooze** - suppresses *external* alert dispatch (Slack/Discord/Teams/
  Twilio/webhook/etc.) for this MAC for a bounded duration (default `24h`).
  Findings keep being recorded and still show up in `scan`/`report`/`devices`
  output and JSON - snoozing hides notifications, not the device.
- **[i]nvestigate** - records an investigation flag and optional notes
  without trusting the device or suppressing its alerts.
- **s[k]ip** - no changes; the device stays in the queue for next time.
- **[q]uit** - stops the session immediately; every decision made so far is
  already persisted.

It requires a real terminal and exits with a helpful error instead of
hanging if stdin isn't interactive (e.g. in a script or cron job) - use the
noninteractive form there instead, passing exactly one of `--trust`,
`--snooze`, `--investigate`, or `--clear` alongside a MAC. `--clear` removes
a snooze/investigation flag and returns the device to "pending"; it does
**not** remove allowlist membership - `lanfence allow --remove <MAC>` is
still what untrusts a device.

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

## Running unattended

LAN Fence does not ship its own scheduler; use `systemd` (recommended on a
Pi) or `cron`.

**Continuous monitoring** - `/etc/systemd/system/lanfence.service`:

```ini
[Unit]
Description=LAN Fence continuous monitoring
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/lanfence monitor --config /etc/lanfence/config.yaml
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now lanfence
```

**Daily report** - a cron entry (`sudo crontab -e`):

```cron
0 7 * * * /usr/local/bin/lanfence report --since 24h --format json > /var/log/lanfence/daily.json
```

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

alerts:
  min_severity: medium         # info | medium | high - dispatch threshold
  rate_limit_seconds: 900      # per-MAC cooldown between alerts; 0 = alert every time
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
- The device database and allowlist are written atomically and are
  owner-readable only where the platform supports it.

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
