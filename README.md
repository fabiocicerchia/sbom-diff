# sbom-diff

> Diff two SBOMs and explain dependency changes in plain language.

[![CI](https://github.com/fabiocicerchia/sbom-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/fabiocicerchia/sbom-diff/actions/workflows/ci.yml)
[![code-quality](https://github.com/fabiocicerchia/sbom-diff/actions/workflows/code-quality.yml/badge.svg)](https://github.com/fabiocicerchia/sbom-diff/actions/workflows/code-quality.yml)
[![security](https://github.com/fabiocicerchia/sbom-diff/actions/workflows/security.yml/badge.svg)](https://github.com/fabiocicerchia/sbom-diff/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fabiocicerchia/sbom-diff/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fabiocicerchia/sbom-diff)
[![CI carbon](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/fabiocicerchia/sbom-diff/gh-pages/badge.json)](.github/workflows/carbon-badge.yml)
[![Release](https://img.shields.io/github/v/release/fabiocicerchia/sbom-diff)](https://github.com/fabiocicerchia/sbom-diff/releases)

Diffs two SBOMs (**CycloneDX or SPDX JSON**) and explains the dependency
changes **in plain language**: major-version jumps first, license changes
flagged, new/removed dependencies grouped — markdown you can paste straight
into a PR description.

Then it does the part the diff stops at. `--review` scores every added and
updated component against ten signals — new advisories, an install script that
was not there before, a maintainer set that changed hands, a release published
yesterday — and ranks them into **read this / glance / routine**, with the
scoring rule printed in the report so a reviewer can disagree with it.

> [!NOTE]
> **This is not another diff.**
> [`cyclonedx-cli diff`](https://github.com/CycloneDX/cyclonedx-cli) is the
> CycloneDX format's own diff, and
> [`sbomdiff`](https://pypi.org/project/sbomdiff/) covers CycloneDX and SPDX
> on PyPI. Both tell you *what changed*, accurately, and this tool does not
> compete with them on that. What it adds is *which of the changes a human
> should actually read* — and that judgement needs both sides of the diff
> normalized the same way, in both formats, with no external binary, which is
> why the mechanical diff here stays first-party and stdlib-only rather than
> shelling out to one of them.

```console
$ sbom-diff old.json new.json
# SBOM diff

5 dependency change(s): 1 added, 1 removed, 3 updated (1 major)

## ⚠ Major version jumps (review breaking changes)
- **openssl**: 3.0.1 → 4.0.0

## ⚠ License changes
- **openssl**: Apache-2.0 → GPL-3.0
...
```

## Features

- Reads CycloneDX **and** SPDX JSON, no config.
- Groups changes by severity: major jumps first, then license changes,
  then minor/patch and added/removed.
- Separates **direct from transitive** additions — the count nobody sees in a
  pull request diff and everybody cares about once it is shown to them.
- Flags **downgrades**, which read as ordinary changes otherwise (2.0.0 →
  1.9.0 is classified "major" like any upgrade).
- Rename-aware: matches on purl identity, so a package that changes its
  reported name is one rename, not an add plus a remove.
- Diffs embedded VEX vulnerability data when the SBOM carries it.
- Markdown for PRs (`--json` for machines, carrying both counts and the
  rendered report).
- **Ranks what to read** (`--review`): ten signals, a visible scoring rule,
  and a tier per component — see [What to review](#what-to-review) below.
- CI gates, all opt-in: `--fail-on {any,major,license}`, `--max-added`,
  `--max-added-transitive`, `--fail-on-downgrade`, `--fail-on-license-change`,
  `--deny-licenses`, `--fail-on-tier`.
- Zero runtime dependencies (stdlib only).

## What to review

A dependency bump PR is ninety version changes and three that matter. `--review`
is the layer that says which three:

```console
$ sbom-diff base.json head.json --review
...
## What to review (91 scored)

Added and updated components, scored from 10 signal(s): 2 read this, 5 glance, 84 routine.

### ⚠ Read this (2)

- **build-helper** 1.0.0 → 2.0.0 · npm · score 10
  - postinstall added — this runs on `install`, read it — [look](https://www.npmjs.com/package/build-helper/v/2.0.0)
  - the people who can publish it changed: +mallory — [look](https://www.npmjs.com/package/build-helper/v/2.0.0)
- **vulny** 1.0.0 → 1.1.0 · npm · score 5
  - OSV reports 1 advisory(ies) new to this version: GHSA-1234-5678-9abc (high) — [look](https://osv.dev/vulnerability/GHSA-1234-5678-9abc)

### Glance (5)
...
```

Every entry carries the specific thing to look at and a link to it, and the
report ends with a folded **How this was ranked** block containing the whole
rule — the tier thresholds, the points per signal, and every signal that was
*not* run, with the reason. A ranking a reviewer cannot audit is one they will
either obey blindly or ignore entirely.

### The signals

Each one is independent, each one has its own source, and each one can be
turned off with `--disable-signal <id>` (repeatable, comma separated).
`sbom-diff --list-signals` prints this table without running anything.

| Signal | Points | What fires it | Source |
| --- | ---: | --- | --- |
| `advisories` | 5 | an advisory affects the new version and did not affect the old one | [OSV API](https://osv.dev) |
| `install-scripts` | 5 | `preinstall`/`install`/`postinstall` added or changed | npm registry — other ecosystems: *not checkable* |
| `provenance` | 4 | the old version shipped published provenance and the new one does not | npm registry (`dist.attestations`) — others: *not checkable* |
| `maintainers` | 3 | the set of people who can publish the package changed | npm registry, PyPI JSON API — others: *not checkable* |
| `major-skip` | 3 | more than one major version jumped at once | the two SBOMs |
| `new-package` | 2 | the package is not in the base SBOM at all | the two SBOMs |
| `young-package` | 2 | the release is younger than `--young-days` (default 14) | npm registry, PyPI JSON API — others: *not checkable* |
| `license` | 2 | the license changed under an existing dependency | the two SBOMs |
| `scorecard` | 2 | the OpenSSF Scorecard of the source project fell by more than `--scorecard-drop` | [deps.dev](https://deps.dev) |
| `fanout` | 1 | the transitive count grew by more than `--fanout-threshold` (default 5) | the two SBOMs' dependency graphs |

Tiers: **Read this** at 5 points or more, **Glance** at 2–4, **Routine** below
that. A signal that nobody can answer for an ecosystem — npm lifecycle scripts
have no equivalent on `deb`, and PyPI does not say whether a package runs code
at install time — is reported as **not checkable**, never as clean.

### Offline, caching, and being a good citizen

```sh
sbom-diff base.json head.json --review --offline     # SBOMs only; lists every skipped signal
sbom-diff base.json head.json --review --no-cache    # do not read or write the cache
sbom-diff base.json head.json --review --fail-on-tier read   # CI gate on the tier
```

- `--offline` scores from the two files alone and names every signal it
  skipped and why. Nothing is sent.
- Every response is cached on disk (`$XDG_CACHE_HOME/sbom-diff`, override with
  `--cache-dir`, expire with `--cache-ttl`, default 24h), so re-running on the
  same PR costs nothing. **The cache is the tool's only state** — delete it
  freely.
- Requests are spaced per host, `Retry-After` is obeyed, 429/5xx are retried
  twice and then given up on, and one run stops after `--max-requests`
  (default 300) — which the report says out loud, because a signal that ran
  out of budget is not a signal that passed.

> [!NOTE]
> Direct-vs-transitive is read from the SBOM's dependency graph
> (CycloneDX `dependencies`, SPDX `relationships`). A document without one
> reports every component as transitive — claiming a dependency is direct
> without evidence would be worse than not saying. Bear that in mind before
> gating on `--max-added-transitive`.

## Install

```sh
pipx install git+https://github.com/fabiocicerchia/sbom-diff
```

Or from a checkout:

```sh
pipx install .
```

## Usage

```sh
syft -o cyclonedx-json myapp:1.0 > old.json
syft -o cyclonedx-json myapp:1.1 > new.json

sbom-diff old.json new.json                # human/markdown
sbom-diff old.json new.json --json         # machine-readable
sbom-diff old.json new.json --fail-on license   # CI gate: any | major | license

# Threshold gates, all opt-in and combinable
sbom-diff old.json new.json --max-added-transitive 5 --fail-on-downgrade
sbom-diff old.json new.json --deny-licenses 'AGPL-3.0,GPL-3.0'

# The judgement layer: score what changed and gate on the tier
sbom-diff old.json new.json --review
sbom-diff old.json new.json --review --fail-on-tier read
sbom-diff old.json new.json --review --disable-signal scorecard,fanout
sbom-diff --list-signals
```

### As a GitHub Action

Point it at a directory and it generates both SBOMs itself — the base side is
the half a `run:` step cannot get on its own, and it is the half that makes the
numbers mean anything.

```yaml
- uses: fabiocicerchia/sbom-diff@v1
  with:
    scan-path: .
    max-added-transitive: 10
    fail-on-downgrade: 'true'
```

See [`examples/github-action/`](examples/github-action/) for the full input and
output list.

Pairs with `fabiocicerchia/security-scanner-toolbox` (syft included) for a
scan-and-diff release step. See [`examples/basic/`](examples/basic/) for a
runnable pair of SBOMs.

## Verifying the image

Every published image is signed with [cosign][cosign], keyless: the identity in
the signature is the workflow that published it, not a key anybody holds.

```sh
cosign verify ghcr.io/fabiocicerchia/sbom-diff:latest \
  --certificate-identity-regexp \
    'https://github.com/fabiocicerchia/sbom-diff/.github/workflows/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`no signatures found` means the tag predates signing, not that verification was
set up wrongly — a wrong identity or issuer says so explicitly. Re-run the
publish workflow for that tag to sign it.

[cosign]: https://docs.sigstore.dev/

## Documentation

Full docs live in [`docs/`](docs/). Runnable examples live in
[`examples/`](examples/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please don't open a
public issue.

## Support

Need help implementing this? [Get in touch](https://fabiocicerchia.it/contact).

## License

[Apache-2.0](LICENSE) © 2026 Fabio Cicerchia.
