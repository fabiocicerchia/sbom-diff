# Architecture

sbom-diff has no runtime dependencies. It reads two SBOM files and prints a
plain-language diff, and — with `--review` — asks npm, PyPI, OSV and deps.dev
what they know about what changed. `sbom_diff.py` is the entry point and does
nothing but call into `sbom_diff_lib`, a package of one-job modules.

## Overview

```text
old.json ─┐
          ├─▶ parse ─▶ compare ─▶ classify ─▶ render ─▶ markdown / JSON
new.json ─┘                          │                     ▲
                                     ▼                     │
                            review (opt-in) ─▶ signals ─▶ score ─▶ tier
                                                  │
                            npm · PyPI · OSV · deps.dev (cached on disk)
```

Two layers, and the second one is the point. The first is the mechanical diff
— what changed. The second, behind `--review`, is the judgement layer: which
of the changes a human should read, and why.

## Modules

One module per job, under `sbom_diff_lib/`:

- **`purl.py`** — the PURL identity two SBOMs are matched on, and the
  ecosystem name a purl type maps to.
- **`versions.py`** — version arithmetic: `semver_jump` says how big a change
  is, `compare_versions` / `is_downgrade` say which direction it went.
- **`normalize.py`** — `load_cyclonedx` and `load_spdx`, one per format,
  normalize into `{key: {name, version, type, ecosystem, licenses, purl,
  direct}}`.
- **`load.py`** — reading a file off disk: format detection,
  `load_vulnerabilities` for embedded CycloneDX VEX data, and `read_sbom`,
  which turns an unusable file into an exit code.
- **`compare.py`** — `diff` and `diff_vulnerabilities`: set operations on the
  match keys — added, removed, changed, renamed, and vulnerability state
  changes — plus `counts`, which produces the `Counts` record.
- **`policy.py`** — the gates. `policy_failures` turns a `Counts` into reasons
  to fail; empty means pass. `fail_on_verdict` covers `--fail-on`.
- **`render.py`** — `classify_jumps` buckets version changes into major /
  minor / patch / other, one `_render_*` per section, `summarize` for the
  headline, and `json_payload` for `--json` (which carries the counts and the
  rendered markdown together so a caller needing both runs the diff once).
- **`exits.py`** — the exit-code table and `SbomError`, which carries a code.
- **`cli.py`** — the argument parser and `main`.

The judgement layer, each module still one job:

- **`cache.py`** — the on-disk response cache: one JSON file per request,
  with a TTL. Every failure is a miss, because a cache that raises is worse
  than no cache.
- **`fetch.py`** — `Fetcher`: cached, rate-limit-polite JSON lookups that
  never raise for a network condition. The network sits behind a `Transport`,
  which is what lets the tests run on recorded responses.
- **`registries.py`** — npm and PyPI: install scripts, maintainers, publish
  time, provenance, as `VersionFacts` whose every field is either a fact or a
  `None` with a note saying why.
- **`osv.py`** — advisories for one package version, queried for *both*
  versions so the signal reports what the new one brings.
- **`depsdev.py`** — the OpenSSF Scorecard of the project deps.dev links a
  version to.
- **`graph.py`** — the dependency graph the SBOM carries, and `fanout`, how
  many packages one component drags in behind it.
- **`signals.py`** — the ten signals, each a `Subject → Outcome` function,
  plus the `SIGNALS` table that gives each one its points and its source.
- **`tiers.py`** — the bands (`read` / `glance` / `routine`) and
  `rule_markdown`, which renders the whole ranking rule into the report.
- **`review.py`** — orchestration: choose the signals, fetch only the sources
  those signals need, score, rank.
- **`render_review.py`** — the review section as markdown, the `review` object
  in `--json`, and the `--fail-on-tier` gate.

## Data flow

Components are matched by PURL identity (`pkg:type/namespace/name`, ignoring
the `@version` and any qualifiers) when a `purl` is present, falling back to
the SBOM `name` field otherwise. This makes matching rename-aware: the same
purl across a name change is reported as a rename, not add+remove.

A component catalogued twice collapses to one entry, keeping the higher
version — two copies coexisting in a tree is not a version change.

With `--review`, every added and version-changed component becomes a
`Subject`: both sides of the change plus whatever its sources answered. Each
enabled signal turns that into an `Outcome` — **hit**, **clear**, **not
applicable** (there is no previous version), or **not checkable** (nobody
could answer). The points of the signals that *hit* add up, and the first
tier that total reaches is the component's tier.

The order matters for politeness: the signals to run are chosen first, and
only the sources those signals need are ever fetched. Turning off every npm
signal means npm is never contacted; `--offline` means nothing is.

`--fail-on {any,major,license}` and the threshold gates (`--max-added`,
`--max-added-transitive`, `--fail-on-downgrade`, `--fail-on-license-change`,
`--deny-licenses`) turn the diff into a CI gate by controlling the exit code.
Only `0` and `1` are gate outcomes; an unusable input exits with its own
sysexits code (65/66/74/77) so a broken SBOM is not read as a dependency
problem. The full table is in
[`examples/ci-platforms/README.md`](https://github.com/fabiocicerchia/sbom-diff/blob/main/examples/ci-platforms/README.md).

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
- **The mechanical diff stays first-party** — `cyclonedx-cli diff` and
  `sbomdiff` already do that job well, and delegating to one of them was
  considered and rejected: `cyclonedx-cli` is a .NET binary that would have to
  be present, and it speaks CycloneDX only, while the judgement layer needs
  both formats normalized identically on both sides. The diff here is a few
  set operations; the dependency is the expensive part.
- **A signal's absence is never its success** — "not checkable" is a distinct
  outcome, printed next to the ones that were checked. npm lifecycle scripts
  have no equivalent on `deb`; PyPI does not say whether a package runs code
  at install time. Reporting either as clean would be a lie by omission.
- **The ranking rule is printed, not hidden** — the tier thresholds, the
  points per signal, and every signal that did not run travel in the report
  itself. A reviewer who disagrees can turn one signal off and rescore.
- **Every signal is independent** — its own source, its own `--disable-signal`
  id, and its own line in the output. Nothing is a composite score nobody can
  take apart.
- **The cache is the only state** — no server, no account, no database. Delete
  the directory and the next run is merely slower.
