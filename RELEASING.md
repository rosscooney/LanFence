<!--
Copyright (c) 2026-present Stable State Consulting Ltd
SPDX-License-Identifier: MIT
-->

# Releasing LAN Fence to PyPI

Publishing is automated. Creating a **GitHub Release** runs
`.github/workflows/python-publish.yml`, which builds the package and uploads
it to [PyPI](https://pypi.org/project/lanfence/) via trusted publishing (OIDC
- no API token or password is stored anywhere).

One-time setup (do this before the first release):

- A PyPI *trusted publisher* for project `lanfence`, owner `rosscooney`, repo
  `lanfence`, workflow `python-publish.yml`, environment `pypi`.
- A GitHub Actions environment named `pypi`.

> The commands below use `origin` as the remote name (the default for a fresh
> `git clone`). Run `git remote -v` to check.

## Step by step

### 1. Make your code changes and commit them

```bash
git checkout -b my-change
# ... edit code ...
pytest                      # must pass
git add -A
git commit -m "Describe the change"
git push -u origin my-change
```

Open a pull request, get it reviewed, and merge it to `main`.

### 2. Bump the version

Every release needs a new version number. Edit the `version` field in
[`pyproject.toml`](pyproject.toml):

```toml
[project]
version = "0.2.0"        # was 0.1.0
```

Use [semantic versioning](https://semver.org/): patch (`0.1.1`) for fixes,
minor (`0.2.0`) for new features, major (`1.0.0`) for breaking changes.

`pyproject.toml` is the only place to change it. `lanfence.__version__` is
kept in sync by hand in `lanfence/__init__.py` - update both together.

Also move the changes you are releasing from `## [Unreleased]` into a new
`## [0.2.0] - <date>` section in [`CHANGELOG.md`](CHANGELOG.md), and add the
matching `[0.2.0]: …/compare/v0.1.0...v0.2.0` link at the bottom. The GitHub
release notes are the same content.

```bash
git checkout main && git pull
git checkout -b release-0.2.0
git commit -am "Bump version to 0.2.0, update changelog"
git push -u origin release-0.2.0
# open PR, merge to main
```

### 3. Sanity-check the build locally (optional but recommended)

```bash
git checkout main && git pull
python -m pip install build twine
python -m build
python -m twine check dist/*
rm -rf dist build            # don't commit these; they're gitignored
```

### 4. Tag and release

```bash
git checkout main && git pull

# annotated tag matching the pyproject version, prefixed with "v"
git tag -a v0.2.0 -m "LAN Fence 0.2.0"
git push origin v0.2.0

# create the GitHub Release -> triggers the publish workflow
gh release create v0.2.0 --title "v0.2.0" --notes "What changed in this release."
```

No `gh`? Do the release by hand at
`https://github.com/rosscooney/lanfence/releases/new?tag=v0.2.0` - set the
title, write the notes, click **Publish release**.

### 5. Watch it publish

```bash
gh run watch --exit-status "$(gh run list --workflow python-publish.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Or open the **Actions** tab on GitHub. When it's green:

```bash
pipx install "lanfence==0.2.0"     # or: pip install --upgrade lanfence
lanfence --version
```

## If the publish fails

- **`non-existent or private` / trusted publishing error** - the PyPI trusted
  publisher or the GitHub `pypi` environment is misconfigured. Fix it at
  <https://pypi.org/manage/project/lanfence/settings/publishing/> and in the
  repo's *Settings → Environments*, then re-run the failed workflow.
- **`File already exists`** - that version was already uploaded. PyPI does not
  allow re-uploading a version. Bump to the next version and release again.
- **Build failed** - reproduce locally with `python -m build` and fix
  `pyproject.toml` / packaging.

A failed release can be retried: delete the GitHub Release and its tag
(`git push origin :refs/tags/v0.2.0` and delete it on GitHub), fix the
problem, then repeat from step 4.
