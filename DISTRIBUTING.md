<!--
Copyright (c) 2026-present Stable State Consulting Ltd
SPDX-License-Identifier: MIT
-->

# Distributing LAN Fence

LAN Fence is MIT-licensed. The distribution model is deliberately
**low-friction**: this project ships **only its own MIT code**, plus a
generated snapshot of the IEEE's public MA-L OUI registry and a handful of
rogue-device fingerprint signatures (both plain-text/YAML data files, not
compiled artifacts), and never redistributes a prebuilt operating-system
image. Users install onto their own stock Raspberry Pi OS / Debian, so the
GPL/LGPL parts of the OS come straight from Raspberry Pi Ltd and Debian -
this project is not in that supply chain.

> Not legal advice. If you redistribute at scale, have a solicitor review your
> final artifact and its notices.

## Supported ways to install

### 1. pipx (recommended)

```bash
pipx install "lanfence[scan]"
```

Isolated from system Python, and puts the `lanfence` launcher on your `PATH`.
Already installed without the `scan` extra? `pipx inject lanfence scapy` adds
it in place.

### 2. pip / venv (any Debian/Ubuntu/RPi OS host)

```bash
python3 -m venv ~/.venvs/lanfence
~/.venvs/lanfence/bin/pip install 'lanfence[scan]'
```

`scapy` (its own licence, GPL-2.0 - see below) is an optional extra
(`lanfence[scan]`) because it is only needed for the actual ARP scanning code
path; everything else (config, allowlist, database, reporting) has no GPL
dependency.

## A note on `scapy`

`scapy` is licensed GPL-2.0-only. LAN Fence's own code is MIT and calls scapy
as an ordinary, unmodified, independently-installed library dependency (an
`import`, not vendored source) - this is the same relationship any Python tool
has with a GPL library it depends on via PyPI. If your organisation's
licence policy treats "depends on a GPL library at runtime" differently from
"redistributes GPL source", get your own legal read before shipping a
downstream product built on LAN Fence; LAN Fence's own source and the code it
directly redistributes (`lanfence/data/*`) remain MIT regardless.

## Publishing checklist (maintainers)

See [RELEASING.md](RELEASING.md) for the full step-by-step. In short:

- [ ] `python -m build` → `twine check dist/*` passes
- [ ] `pip install dist/*.whl` in a clean venv; `lanfence --version` works
- [ ] `CHANGELOG.md` has a dated section for this version
- [ ] tag `vX.Y.Z`; publish to PyPI as `lanfence`
- [ ] `LICENSE`, `CONTRIBUTING.md`, `CHANGELOG.md`, `DISTRIBUTING.md`,
      `SECURITY.md` present in the sdist (`LICENSE` via `license-files` in
      `pyproject.toml`; the rest via [`MANIFEST.in`](MANIFEST.in)) - check
      with `tar tzf dist/*.tar.gz`
