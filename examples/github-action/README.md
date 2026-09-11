# GitHub Action Example

What it shows: a composite action (`action.yml` at the repo root) that answers
the question a dependency bump never shows you — *what did this PR actually do
to the dependency tree?* A one-line `package.json` change is one line in the
diff and can be forty packages in the tree.

It generates an SBOM at base and at head, diffs them, and posts the Markdown
report as a PR comment (editing the same comment on re-runs instead of piling
up new ones).

## Run

The short version. Nothing to pre-generate — point it at a directory:

```yaml
# .github/workflows/sbom-diff.yml
on: pull_request

jobs:
  sbom-diff:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: fabiocicerchia/sbom-diff@v1
        with:
          scan-path: .
```

## Bring your own SBOMs

If you already generate SBOMs, hand both sides over and generation is skipped:

```yaml
      - uses: fabiocicerchia/sbom-diff@v1
        with:
          base-sbom: sbom-before.json
          head-sbom: sbom-after.json
          fail-on: major
```

## Gating

Every threshold is opt-in — a dependency review that fails by default is a
dependency review that gets disabled by default.

```yaml
      - uses: fabiocicerchia/sbom-diff@v1
        with:
          max-added: 25
          max-added-transitive: 10
          fail-on-downgrade: 'true'
          fail-on-license-change: 'true'
          deny-licenses: |
            AGPL-3.0
            GPL-3.0
```

`max-added-transitive` needs an SBOM carrying a dependency graph (CycloneDX
`dependencies` / SPDX `relationships`). Without one every component reports as
transitive, and the gate will fire on any addition at all.

## Inputs

| Input                     | Default                      | What it does                                              |
| ------------------------- | ---------------------------- | --------------------------------------------------------- |
| `scan-path`               | `.`                          | Path to scan. Ignored when both SBOMs are supplied.       |
| `base-ref`                | PR base, then default branch | Ref to diff against.                                      |
| `base-sbom` / `head-sbom` | —                            | Pre-generated SBOMs. Skips generation.                    |
| `syft-version`            | `v1.18.1`                    | Pinned syft used when generating.                         |
| `title`                   | `SBOM diff`                  | Heading for the comment and job summary.                  |
| `github-token`            | `github.token`               | Omit to write only the job summary.                       |
| `pr-number`               | from the event               | PR to comment on.                                         |
| `skip-unchanged`          | `true`                       | No comment when nothing changed.                          |
| `fail-on`                 | —                            | `any` / `major` / `license`.                              |
| `max-added`               | —                            | Fail over N added components.                             |
| `max-added-transitive`    | —                            | Fail over N added *transitive* components.                |
| `fail-on-downgrade`       | `false`                      | Fail when a component moves to a lower version.           |
| `fail-on-license-change`  | `false`                      | Fail when an existing component changes license.          |
| `deny-licenses`           | —                            | Comma/newline separated IDs barred from added components. |
| `review`                  | `false`                      | Score and rank added/updated components in the comment.   |
| `review-offline`          | `false`                      | Score the review from the SBOMs alone, no network.        |
| `disable-signals`         | —                            | Comma separated signal ids to leave out of the review.    |
| `fail-on-tier`            | —                            | Fail on `read` / `glance` / `routine` and louder.         |

## Ranking what to read

`review: 'true'` adds the judgement layer to the comment: every added and
updated component scored against ten signals — new advisories, an install
script that was not there before, a maintainer set that changed hands, a
release published yesterday — sorted into **read this / glance / routine**,
with the scoring rule folded into the comment so a reviewer can disagree with
it.

```yaml
      - uses: fabiocicerchia/sbom-diff@v1
        with:
          review: 'true'
          fail-on-tier: read          # block the PR on the loudest tier only
          disable-signals: scorecard  # ...and ignore this one entirely
```

It talks to the npm and PyPI registries, OSV and deps.dev, so the job needs
egress; `review-offline: 'true'` scores from the two SBOMs alone and says in
the comment which signals it skipped.

## Outputs

`summary`, `added`, `added-transitive`, `removed`, `changed`,
`license-changed`, `read-this`, `glance`, and `markdown` (JSON-encoded — a raw
multi-line body is not a legal step output). The two tier counts are `0` when
`review` is off.

```yaml
      - uses: fabiocicerchia/sbom-diff@v1
        id: sbom
      - run: echo "${{ steps.sbom.outputs.added-transitive }} transitive additions"
```

## Forks

A fork PR's token cannot write to the base repo, so the comment is skipped —
the job summary is always written regardless, which is why it is there.
