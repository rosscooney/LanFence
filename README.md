# LAN Fence

**LAN Fence is an open-source defensive network device monitor for Linux**
(developed and tested on Raspberry Pi OS / Debian, and reasonably portable to
other Debian/Ubuntu systems).

- Home page: <https://lanfence.com>
- Source & downloads: <https://github.com/rosscooney/lanfence>
  ([releases](https://github.com/rosscooney/lanfence/releases))
- Package: [`lanfence` on PyPI](https://pypi.org/project/lanfence/)

LAN Fence runs on a small Linux box (a Raspberry Pi is the common case) sitting
on your network. It continuously scans for connected devices via ARP,
maintains an allowlist of devices you already trust, and alerts in
plain language when something unknown joins - a rogue device, unauthorized
hardware, or a supply-chain implant on your LAN.

LAN Fence **only observes**. It sends nothing beyond a standard ARP "who-has"
request (the same thing every device on your LAN does routinely) and never
touches, blocks, deauthenticates or spoofs anything.

> ⚠️ LAN Fence **cannot prove a device is malicious, or that a MAC address is
> genuine.** MAC vendor prefixes and hostnames are trivially spoofed by anyone
> deliberately trying to blend in. A finding is a lead worth checking by hand,
> not a verdict - use it as one input to your own judgement.

## How it works

1. **Active scanning** - LAN Fence periodically ARP-sweeps your subnet
   (`lanfence scan` for one sweep, or on an interval inside `lanfence
   monitor`), collecting every MAC/IP that answers.
2. **Passive monitoring** - between active sweeps, `lanfence monitor` also
   listens for ARP traffic on the wire, so a device that joins mid-interval is
   caught sooner rather than waiting for the next sweep.
3. Every sighting is folded into a persistent **SQLite database** keyed by MAC
   address, which tracks each device's lifecycle: `new_device` the first time
   it's ever seen, `reappeared` if it had gone offline and came back, and
   `disconnected` when an active sweep no longer sees it.
4. Each device is **fingerprinted**: an offline OUI → vendor lookup, a set of
   built-in rogue-device signatures (see below), and a check of whether its
   MAC is locally administered (randomized/spoofed rather than
   vendor-assigned).
5. Each device is checked against your **allowlist**
   (`lanfence allow <mac>`). A brand-new or reappearing device not on the
   allowlist produces a plain-language **finding** with a severity
   (`high`/`medium`/`info`), a rationale, and a recommendation; an allowlisted
   device is downgraded to `info` so your own hardware stops shouting every
   time it reconnects.
6. Findings can be dispatched to **syslog, email, or a webhook**, and
   everything is available as a CLI table or JSON for automation.

## Built-in rogue-device signatures

Heuristics, not proof - a match is a lead to check by hand:

| Signal | Category | Why it matters |
|---|---|---|
| Vendor: Espressif | `esp32_esp8266` | ESP32/ESP8266 - the chipset behind most cheap DIY hidden cameras, rogue APs, and ESP32-based Wi-Fi implants (as well as plenty of legitimate IoT). |
| Vendor: Raspberry Pi | `raspberry_pi` | Legitimate everywhere, but also the common hardware basis for rogue network-tap / implant projects (P4wnP1, home-built taps). |
| Vendor: ASIX Electronics | `usb_ethernet_gadget` | USB-Ethernet chipset used both by ordinary dongles and by BadUSB tools (Bash Bunny, LAN Turtle, O.MG cable) presenting as a network adapter. |
| Hostname contains `pwnagotchi` | `pwnagotchi` | Pwnagotchi's distinctive default hostname. |
| Hostname contains `bashbunny` / `lanturtle` / `pineapple` / `omg-cable` | Hak5/O.MG tooling | Default hostnames of common commercial implant/pentest hardware. |
| Hostname contains `flipper` | `flipper_zero` | Flipper Zero (via its Wi-Fi dev board). |
| Locally administered MAC | `locally_administered_mac` | No vendor OUI - common for privacy MAC-randomization on phones/laptops, but also for spoofed or gadget hardware. |

Extend or override these with your own `rogue_signatures_file:` (same YAML
shape as `lanfence/data/rogue_signatures.yaml`) and `vendor_file:` (same
tab-separated shape as `lanfence/data/oui_vendors.txt`) in config.

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
lanfence scan --format json    # same, machine-readable
lanfence monitor                # continuous: active sweeps + passive sniffing
lanfence allow <MAC> --name X   # trust a device; its findings become info
lanfence allow --list           # show the allowlist
lanfence allow --remove <MAC>   # untrust a device
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
  passive: true                # also sniff ARP traffic between sweeps
  resolve_hostnames: true      # try reverse DNS for each device
  dns_timeout_seconds: 1

alerts:
  min_severity: medium         # info | medium | high - dispatch threshold
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

db_path: ~/.local/share/lanfence/lanfence.db
allowlist_file: ~/.config/lanfence/allowlist.yaml
vendor_file: null             # extra OUI table, merged with the packaged one
rogue_signatures_file: null   # extra signatures, merged with the packaged ones
```

## Exit codes (`--fail-on-findings`)

`scan` and `report` accept `--fail-on-findings` for CI/scripting use:

| Highest severity in the result | Exit code |
|---|---|
| none / info | 0 |
| medium | 10 |
| high | 20 |

## Privacy and security

- **No telemetry, no automatic external calls.** LAN Fence never phones home
  on its own. Alert destinations are ones *you* configure (your own syslog
  daemon, SMTP relay, or webhook URL), and the only other network access is
  two commands that exist purely to fetch something *you* asked for, only
  when you run them: `lanfence upgrade` (checks/installs from PyPI) and
  `lanfence vendor-refresh` (downloads the IEEE OUI registry). Every other
  command touches only your local network (ARP) and disk.
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
