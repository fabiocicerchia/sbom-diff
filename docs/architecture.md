# Architecture

sbom-diff is a single module (`sbom_diff.py`) with no runtime dependencies. It
reads two SBOM files and prints a plain-language diff.

## Overview

```text
old.json ─┐
          ├─▶ parse ─▶ compare ─▶ classify ─▶ render ─▶ markdown / JSON
new.json ─┘
```

## Components

- **parse** — `_load_cyclonedx` and `_load_spdx`, one per format, normalize
  into `{key: {name, version, type, ecosystem, licenses, purl, direct}}`;
  `load_vulnerabilities` does the same for embedded CycloneDX VEX data.
  `read_sbom` wraps both and turns an unusable file into an exit code.
- **compare** — `diff` and `diff_vulnerabilities`: set operations on the match
  keys — added, removed, changed, renamed, and vulnerability state changes.
- **classify** — `classify_jumps` buckets version changes into major / minor /
  patch / other; `is_downgrade` marks the ones that went backwards.
- **gate** — `policy_failures` turns a `Counts` into reasons to fail; empty
  means pass. `fail_on_verdict` covers `--fail-on`.
- **render** — one `_render_*` per section plus `summarize` for the headline,
  emitting markdown (default) or JSON (`--json`, carrying the counts and the
  rendered markdown together so a caller needing both runs the diff once).

## Data flow

Components are matched by PURL identity (`pkg:type/namespace/name`, ignoring
the `@version` and any qualifiers) when a `purl` is present, falling back to
the SBOM `name` field otherwise. This makes matching rename-aware: the same
purl across a name change is reported as a rename, not add+remove.

A component catalogued twice collapses to one entry, keeping the higher
version — two copies coexisting in a tree is not a version change.

`--fail-on {any,major,license}` and the threshold gates (`--max-added`,
`--max-added-transitive`, `--fail-on-downgrade`, `--fail-on-license-change`,
`--deny-licenses`) turn the diff into a CI gate by controlling the exit code.
Only `0` and `1` are gate outcomes; an unusable input exits with its own
sysexits code (65/66/74/77) so a broken SBOM is not read as a dependency
problem. The full table is in
[`examples/ci-platforms/README.md`](../examples/ci-platforms/README.md).

## Decisions

- **PURL-based matching** with a name fallback — rename-aware without
  requiring every SBOM to carry a purl.
- **Direct vs transitive from the document's own graph** — CycloneDX
  `dependencies`, SPDX `relationships` (which producers write in either
  direction, so both are read). Without a graph every component reports as
  transitive: claiming a dependency is direct without evidence is worse than
  not saying.
- **`compare_versions` separate from `semver_jump`** — one says how big a
  change is, the other which direction it went. A downgrade classifies as
  "major" like any other and reads as an upgrade unless it is labelled.
- **Every gate opt-in** — a dependency review that fails by default is a
  dependency review that gets disabled by default.
- **stdlib only** — keep the tool trivial to install and audit.
