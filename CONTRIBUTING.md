# Contributing to LAN Fence

Thanks for your interest in improving LAN Fence. Contributions are welcome via
pull requests at <https://github.com/rosscooney/lanfence>.

## Licensing of contributions

- LAN Fence is distributed under the [MIT License](LICENSE).
- Contributions submitted to the project are expected to be distributed under
  the MIT License as part of LAN Fence.
- Contributors retain copyright in their own contributions unless separately
  agreed in writing.
- By submitting a pull request, you confirm that you have the right to submit
  the code under the MIT License, and that you are licensing your contribution
  under the MIT License.

There is **no** Contributor Licence Agreement or copyright assignment to sign.

## What not to submit

- Proprietary or confidential code.
- Code copied from third-party projects under licences incompatible with MIT
  distribution (for example GPL/AGPL/SSPL source code copied into LAN Fence).
- Significant new dependencies whose licences are incompatible with the
  project's MIT distribution model. If a change adds a new runtime dependency,
  note its licence in the pull request description.
- Hand edits to `lanfence/data/oui_vendors.txt`. It's a generated snapshot of
  the IEEE's public MA-L OUI registry (see the comment at the top of that
  file) - regenerate it wholesale with
  `lanfence.vendor.parse_ieee_oui_csv`/`format_vendor_table` against a fresh
  `https://standards-oui.ieee.org/oui/oui.csv` rather than editing entries by
  hand, and mention the fetch date in the PR description.

## Scope and non-goals

LAN Fence is an **observation-only, defensive** tool. It scans, records and
reports; it never sends anything beyond a standard ARP request, never joins,
deauthenticates, spoofs, blocks, or otherwise touches another device on the
network. Please do not propose features that add active exploitation, packet
injection/deauth, DHCP/ARP spoofing, network blocking or throttling, or any
other offensive capability against devices LAN Fence discovers - such pull
requests will be closed.

LAN Fence cannot prove a device is malicious or that a MAC address is genuine
- vendor OUIs and hostnames are trivially spoofed. It surfaces evidence and
heuristics for a human to judge. Keep documentation and finding wording
consistent with that (a "finding" is a lead, not a verdict).

## Development setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,scan]"
pytest
```

Active/passive scanning itself needs root (or `CAP_NET_RAW`) and a real
network interface, so most of the test suite exercises the scanning code with
the network layer mocked - `lanfence/scanner.py` is intentionally the one
thin module that talks to raw sockets.

## Before opening a pull request

- Add or update tests for behaviour changes.
- Run the test suite: `pytest`.
- Keep changes focused; describe the motivation in the PR description.
- Add the source-file header to any **new** original source files:

  ```python
  # Copyright (c) 2026-present Stable State Consulting Ltd
  # SPDX-License-Identifier: MIT
  ```

## Reporting bugs and security issues

- Normal bugs: open a GitHub issue.
- Security vulnerabilities: please follow [SECURITY.md](SECURITY.md) and do
  not open a public issue.
