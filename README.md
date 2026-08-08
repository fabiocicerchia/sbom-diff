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
- CI gates, all opt-in: `--fail-on {any,major,license}`, `--max-added`,
  `--max-added-transitive`, `--fail-on-downgrade`, `--fail-on-license-change`,
  `--deny-licenses`.
- Zero runtime dependencies (stdlib only).

> [!NOTE]
> Direct-vs-transitive is read from the SBOM's dependency graph
> (CycloneDX `dependencies`, SPDX `relationships`). A document without one
> reports every component as transitive — claiming a dependency is direct
> without evidence would be worse than not saying. Bear that in mind before
> gating on `--max-added-transitive`.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/fabiocicerchia/sbom-diff/main/install.sh | bash
```

Or with pipx directly:

```sh
pipx install .        # from a checkout
# or: pip install sbom-diff
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
