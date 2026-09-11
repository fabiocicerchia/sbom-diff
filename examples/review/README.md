# Review Example

What it shows: the layer on top of the diff. Two CycloneDX SBOMs for the same
app, where four things changed and a reviewer has time for two of them.

- `chalk` jumped **three majors at once** (2.4.2 → 5.3.0).
- `internal-toolkit` **changed licence** (MIT → Apache-2.0) *and* its
  **fan-out grew** from one package to seven.
- `left-pad` is **new to the tree**.
- `lodash` moved a patch version and nothing else happened — routine.

## Run

Scored from the two files alone, no network:

```sh
sbom-diff old.json new.json --review --offline
```

```text
## What to review (4 scored)

Added and updated components, scored from the SBOMs alone (offline): 0 read this, 3 glance, 1 routine.

### Glance (3)

- **chalk** 2.4.2 → 5.3.0 · npm · score 3
  - jumped 3 majors at once (2.x → 5.x) — 2 release(s) of breaking changes went unread
- **internal-toolkit** 1.0.0 → 1.1.0 · npm · score 3
  - MIT → Apache-2.0
  - pulls in 7 package(s), 6 more than before
- **left-pad** 1.3.0 (new) · npm · score 2
  - not in the base SBOM at all — nobody has reviewed it before

### Routine (1)

- lodash 4.17.20 → 4.17.21 · score 0 · no signal fired
```

The report ends with a folded **How this was ranked** block: the tier
thresholds, the points each signal is worth, and — because this run was
offline — the six signals that were *not* run and why.

## With the network

Drop `--offline` and the six remaining signals join in: OSV advisories for
each new version, npm install scripts, the maintainer set, npm provenance, how
old the release is, and the project's OpenSSF Scorecard from deps.dev.

```sh
sbom-diff old.json new.json --review
```

Responses are cached under `$XDG_CACHE_HOME/sbom-diff`, so the second run of
the same pull request sends nothing.

> [!NOTE]
> `internal-toolkit` is a made-up package and no registry has heard of it —
> its network signals come back *not checkable*, which is exactly what that
> looks like in the report. `chalk`, `lodash` and `left-pad` are real.

## As a gate

```sh
sbom-diff old.json new.json --review --fail-on-tier read
```

Exit `1` when anything lands in that tier or a louder one; here nothing does,
so it exits `0`. Disagree with the ranking? Turn a signal off and rescore:

```sh
sbom-diff old.json new.json --review --offline --disable-signal fanout
```
