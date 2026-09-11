# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in LAN Fence, please
report it privately. **Do not open a public GitHub issue for security
vulnerabilities.**

Preferred options:

1. **GitHub private vulnerability reporting** — use the "Report a vulnerability"
   button under the repository's *Security* tab (GitHub → Security → Advisories).
2. **Email** — `contributors@lanfence.com`

Please include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected version(s) or commit hash,
- any suggested remediation.

## What to expect

- Acknowledgement of your report as soon as reasonably possible.
- An assessment of the issue and, where accepted, a fix or mitigation.
- Credit in the release notes if you would like it.

## Scope

LAN Fence is a defensive network monitor that only observes ARP traffic,
records what it sees, and reports. Relevant reports include, for example:

- a device-supplied value (hostname, vendor string) that isn't sanitised
  before reaching the terminal, the JSON report, or the SQLite database -
  e.g. terminal escape-sequence or command injection via a crafted DHCP
  hostname or ARP reply,
- a path where LAN Fence sends, spoofs, injects, or modifies network traffic
  beyond a standard ARP "who-has" request - it is observation-only and should
  never act as an attacker against devices it discovers,
- unsafe handling of the device database, allowlist file, or JSON reports
  (e.g. a way to corrupt them, or a symlink/permissions issue that exposes
  their contents to another local user),
- a way for an alert destination you did *not* configure (syslog, email,
  webhook) to receive data, or for LAN Fence to make any other network call
  you did not configure - it has no telemetry and should never phone home,
- privilege-escalation issues in `lanfence link`'s `sudo` self-elevation.

LAN Fence does not attempt to prove that a device is authorized or that a MAC
address is genuine - vendor OUIs and hostnames are trivially spoofed. "LAN
Fence failed to flag a spoofed or unusual device" is not by itself a
vulnerability, though improvements to fingerprinting/detection coverage are
very welcome as normal issues or pull requests.
