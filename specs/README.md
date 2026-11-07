# Specifications of sbom-diff

What this code does, one atomic Gherkin scenario per behaviour, read from the code by code-atlas.
Tags: `@verified` a test asserts it · `@inferred` read from the code only · `@gap` an entry point no test covers · `@human` written or amended by a person, never rewritten.

## Change Detection
Working out exactly what changed between the old and new SBOM.

- **Added and removed dependencies**: [Spotting added, removed and updated dependencies](change-detection/added-removed/added-removed-dependencies.feature) (2)
- **Change totals**: [Headline change totals](change-detection/change-totals/change-totals.feature) (2)
- **License changes**: [Flagging license changes](change-detection/license-changes/license-change-detection.feature) (1)
- **Rename detection**: [Reporting renamed packages](change-detection/renames/rename-detection.feature) (2)
- **Version changes**: [Sizing and directing version changes](change-detection/version-changes/version-change-size-and-direction.feature) (5)
- **Vulnerability state changes**: [Showing vulnerability state changes](change-detection/vulnerability-changes/vulnerability-state-changes.feature) (1)

## CI Gating
Turning a dependency diff into a pass or fail result a pipeline can act on.

- **Change thresholds**: [Gating a change on how much it adds or downgrades](ci-gating/change-thresholds/change-threshold-gates.feature) (4)
- **Exit codes**: [Reporting the outcome of a run through its exit code](ci-gating/exit-codes/exit-codes.feature) (3), [Gating a pipeline on the diff](ci-gating/exit-codes/gating-a-pipeline.feature) (4)
- **Fail-on rules**: [Failing CI on a chosen class of change](ci-gating/fail-on-rules/fail-on-rules.feature) (2), [Failing a build on review tier](ci-gating/fail-on-rules/fail-on-tier.feature) (2)
- **License policy**: [Gating a change on licenses](ci-gating/license-policy/license-policy-gates.feature) (2)

## Command Line
How users run sbom-diff and control its behaviour.

- **Run flow**: [Running a diff from the command line](command-line/run-flow/running-a-diff.feature) (5)

## Build, Packaging and Integrations
Building, installing, containerising and wiring sbom-diff into CI platforms.

- **CI platform examples**: [Gating a Devtron deployment on the SBOM diff](developer-tooling/ci-platform-examples/devtron-sbom-gate.feature) (3)
- **Container image**: [Running sbom-diff from the container image](developer-tooling/container-image/container-image.feature) (2)

## Diff Report
Presenting the dependency changes as plain-language output for people and machines.

- **JSON output**: [Consuming the diff as JSON](diff-report/json-output/json-diff-output.feature) (3)
- **Markdown report**: [Reading the dependency change report](diff-report/markdown-report/markdown-diff-report.feature) (7)
- **Summary headline**: [Summarising a dependency update in one line](diff-report/summary-headline/summary-headline.feature) (2)

## Package Intelligence
Gathering outside facts about packages from public registries and security databases.

- **Network access**: [Looking up packages over the network politely](package-intelligence/network-access/network-lookups.feature) (5)
- **Project health scorecard**: [Looking up a package's project health scorecard](package-intelligence/project-health/project-health-scorecard.feature) (4)
- **npm and PyPI facts**: [Reading npm and PyPI facts about a package version](package-intelligence/registry-facts/registry-version-facts.feature) (8)
- **Response cache**: [Reusing package lookups between runs](package-intelligence/response-cache/lookup-response-cache.feature) (2)
- **Security advisories**: [Looking up known advisories for a package version](package-intelligence/security-advisories/osv-advisory-lookup.feature) (6)

## Risk Review
The opt-in judgement layer that decides which changes a human should actually read, and why.

- **Review orchestration**: [Deciding what gets reviewed and in what order](risk-review/review-orchestration/review-orchestration.feature) (4)
- **Review report**: [Reading the ranked review](risk-review/review-report/review-report.feature) (7)
- **Risk signals**: [Asking risk questions of every changed package](risk-review/risk-signals/risk-signals.feature) (7)
- **Scoring and tiers**: [Ranking reviewed packages into tiers](risk-review/scoring-tiers/review-tiers.feature) (4)
- **Signal selection**: [Choosing which risk signals run](risk-review/signal-selection/risk-signal-selection.feature) (3)

## SBOM Ingestion
Reading CycloneDX and SPDX documents into one consistent picture of the components they list.

- **Dependency graph**: [Counting what a dependency pulls in](sbom-ingestion/dependency-graph/dependency-fan-out.feature) (5), [Telling direct from transitive dependencies](sbom-ingestion/dependency-graph/direct-vs-transitive.feature) (2)
- **Embedded vulnerability data**: [Reading embedded vulnerability statements](sbom-ingestion/embedded-vulnerabilities/embedded-vex-reading.feature) (2)
- **File loading and format detection**: [Loading an SBOM file and recognising its format](sbom-ingestion/format-detection/sbom-file-loading.feature) (4)
- **Component normalization**: [Reading components the same way from CycloneDX and SPDX](sbom-ingestion/normalization/component-normalization.feature) (5)
- **Package identity**: [Matching packages across SBOMs](sbom-ingestion/package-identity/package-identity.feature) (6)
