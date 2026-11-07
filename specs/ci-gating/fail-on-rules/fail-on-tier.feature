@domain:ci-gating @area:fail-on-rules @from:sbom-diff-lib/render-review
Feature: Failing a build on review tier
  Lets a CI operator block a merge when any changed package scores at or above a chosen review tier.

  Background:
    Given the operator diffs two SBOMs with a tier gate

  @id:ci-gating.fail-on-rules.003 @rule:ci-gating.fail-on-rules.tier-threshold @verified @source:sbom_diff_lib/render_review.py#tier_failures @test:tests/test_review.py#test_fail_on_tier_is_the_gate
  Scenario Outline: The tier gate fails the run only when a component reaches the chosen tier
    Given the loudest scored component is left-pad, in the "<landed>" tier with score 3
    When the operator runs the diff with "--fail-on-tier <gate>"
    Then the exit code is <exit>
    And <message>

    Examples:
      | landed | gate   | exit | message                                                                       |
      | Glance | glance | 1    | stderr says "1 component(s) at or above “Glance”: left-pad (glance, score 3)" |
      | Glance | read   | 0    | no tier failure is reported                                                   |

  @id:ci-gating.fail-on-rules.004 @rule:ci-gating.fail-on-rules.tier-failure-names-five @inferred @source:sbom_diff_lib/render_review.py#tier_failures
  Scenario: A tier gate failure names the first five components and counts the rest
    Given 8 scored components are at or above the "Read this" tier
    When the operator runs the diff with "--fail-on-tier read"
    Then the failure message starts "8 component(s) at or above “Read this”:"
    And it names 5 components with their tier and score
    And it ends " and 3 more"
