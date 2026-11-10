@domain:ci-gating @area:fail-on-rules @from:sbom-diff-lib/render-review
Feature: Failing a build on review tier
  Lets a CI operator block a merge when any changed package scores at or above a chosen review tier.

  Background:
    Given the operator diffs two SBOMs with a tier gate

  @id:ci-gating.fail-on-rules.004 @rule:ci-gating.fail-on-rules.tier-failure-names-five @inferred @source:sbom_diff_lib/render_review.py#tier_failures
  Scenario: A tier gate failure names the first five components and counts the rest
    Given 8 scored components are at or above the "Read this" tier
    When the operator runs the diff with "--fail-on-tier read"
    Then the failure message starts "8 component(s) at or above “Read this”:"
    And it names 5 components with their tier and score
    And it ends " and 3 more"
