# GitHub Action Example

What it shows: a composite action (`action.yml` at the repo root) that runs
`sbom-diff` on two SBOMs and posts the Markdown report as a PR comment
(editing the same comment on re-runs instead of piling up new ones).

## Run

```yaml
# .github/workflows/sbom-diff.yml
on: pull_request

jobs:
  sbom-diff:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: fabiocicerchia/sbom-diff@v1
        with:
          old-sbom: sbom-before.json
          new-sbom: sbom-after.json
          fail-on: major
```
