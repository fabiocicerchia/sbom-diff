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

## Other CI systems

The composite action is GitHub-specific; the CLI is not. It is stdlib-only
Python 3.10+, takes two SBOM files, prints markdown, and exits `1` when an
opt-in gate trips — which is all a gate needs anywhere:

```sh
pip install "git+https://github.com/fabiocicerchia/sbom-diff@v1.0.1"
syft -q -o cyclonedx-json=head.json dir:.
git worktree add /tmp/base "$BASE_REF"      # the half a one-off scan can't get
syft -q -o cyclonedx-json=base.json dir:/tmp/base
sbom-diff base.json head.json --fail-on major --max-added-transitive 10
```

There is also an image whose entrypoint is the CLI,
`ghcr.io/fabiocicerchia/sbom-diff:1.0.1`, for platforms that would rather run a
container than install anything.

Drop-in files for GitLab CI, CircleCI, Travis, Azure DevOps, AWS CodePipeline,
Devtron, Northflank, Spacelift, Jenkins, Bitbucket Pipelines, Google Cloud
Build, Tekton, Argo Workflows, Harness, Buildkite and Drone/Woodpecker are in
[`examples/ci-platforms/`](../examples/ci-platforms/README.md) — including
which variable names the base ref on each platform, which is the fiddly part.
