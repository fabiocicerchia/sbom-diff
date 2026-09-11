# Getting Started

## Prerequisites

- Python 3.10+
- Two SBOMs in CycloneDX or SPDX JSON (e.g. produced by
  [syft](https://github.com/anchore/syft)).

## Install

```sh
pipx install .        # from a checkout
# or: pip install sbom-diff
```

## Run

```sh
syft -o cyclonedx-json myapp:1.0 > old.json
syft -o cyclonedx-json myapp:1.1 > new.json

sbom-diff old.json new.json                    # human/markdown
sbom-diff old.json new.json --json             # machine-readable
sbom-diff old.json new.json --fail-on license  # CI gate: any | major | license

# Threshold gates, all opt-in and combinable
sbom-diff old.json new.json --max-added 25 --max-added-transitive 10
sbom-diff old.json new.json --fail-on-downgrade --fail-on-license-change
sbom-diff old.json new.json --deny-licenses 'AGPL-3.0,GPL-3.0'
```

See [`../examples/basic/`](../examples/basic/) for a runnable pair of SBOMs.

## Ranking what to read

The diff says what changed; `--review` says which of it to read first. It
scores every added and updated component against ten independent signals and
sorts them into **read this / glance / routine**, printing the scoring rule in
the report so you can disagree with it.

```sh
sbom-diff old.json new.json --review                      # score and rank
sbom-diff old.json new.json --review --offline            # SBOMs only, no network
sbom-diff old.json new.json --review --fail-on-tier read  # CI gate on the tier
sbom-diff --list-signals                                  # every signal, its points, its source
```

The signals that need somebody else's API — OSV for advisories, the npm and
PyPI registries for install scripts, maintainers and publish dates, deps.dev
for OpenSSF Scorecard — are cached under `$XDG_CACHE_HOME/sbom-diff` for a day
(`--cache-dir`, `--cache-ttl`, `--no-cache`), spaced out per host, and capped
at `--max-requests` per run. A signal that could not be answered for an
ecosystem is reported as *not checkable*, never as clean.

Turn any of them off — the report rescores without it and says it was
disabled:

```sh
sbom-diff old.json new.json --review --disable-signal scorecard,fanout
```

See [`../examples/review/`](../examples/review/) for a runnable pair that
trips several signals offline.

## Other CI systems

The composite action is GitHub-specific; the CLI is not. It is stdlib-only
Python 3.10+, takes two SBOM files, prints markdown, and exits `1` when an
opt-in gate trips (an unusable input gets its own code, not `1`) — which is
all a gate needs anywhere:

```sh
syft -q -o cyclonedx-json=head.json dir:.
git worktree add /tmp/base "$BASE_REF"      # the half a one-off scan can't get
syft -q -o cyclonedx-json=base.json dir:/tmp/base
docker run --rm -v "$PWD:/work" -w /work ghcr.io/fabiocicerchia/sbom-diff:1.0.1 \
  base.json head.json --fail-on major --max-added-transitive 10
```

The image's entrypoint is the CLI, so the SBOMs are just arguments. Every
example in `examples/ci-platforms/` pulls it rather than installing from
source; `pipx install` remains the right answer on a workstation.

Drop-in files for GitLab CI, CircleCI, Travis, Azure DevOps, AWS CodePipeline,
Devtron, Northflank, Spacelift, Jenkins, Bitbucket Pipelines, Google Cloud
Build, Tekton, Argo Workflows, Harness, Buildkite and Drone/Woodpecker are in
[`examples/ci-platforms/`](https://github.com/fabiocicerchia/sbom-diff/blob/main/examples/ci-platforms/README.md) — including
which variable names the base ref on each platform, which is the fiddly part.
