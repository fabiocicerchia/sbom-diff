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

- **parse** — normalize CycloneDX or SPDX JSON into `{key: {name, version,
  type, licenses, purl}}`, plus `{id: {state, severity}}` for any embedded
  CycloneDX vulnerabilities/VEX data.
- **compare** — set operations on the match keys: added, removed, changed,
  renamed; same for vulnerability IDs (added/removed/state-changed).
- **classify** — bucket version changes into major / minor / patch / other and
  flag license changes.
- **render** — emit markdown (default) or JSON (`--json`).

## Data flow

Components are matched by PURL identity (`pkg:type/namespace/name`, ignoring
the `@version` and any qualifiers) when a `purl` is present, falling back to
the SBOM `name` field otherwise. This makes matching rename-aware: the same
purl across a name change is reported as a rename, not add+remove.
`--fail-on {any,major,license}` turns the diff into a CI gate by controlling
the exit code.

## Decisions

- **PURL-based matching** with a name fallback — rename-aware without
  requiring every SBOM to carry a purl.
- **stdlib only** — keep the tool trivial to install and audit.
