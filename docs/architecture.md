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

- **parse** — normalize CycloneDX or SPDX JSON into `{name: {version, type,
  licenses}}`.
- **compare** — set operations on component names: added, removed, changed.
- **classify** — bucket version changes into major / minor / patch / other and
  flag license changes.
- **render** — emit markdown (default) or JSON (`--json`).

## Data flow

Components are matched by name. `--fail-on {any,major,license}` turns the diff
into a CI gate by controlling the exit code.

## Decisions

- **Name-based matching** for now; PURL-based (rename-aware) matching is on the
  roadmap.
- **stdlib only** — keep the tool trivial to install and audit.
