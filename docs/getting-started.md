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
