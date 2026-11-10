@domain:risk-review @area:scoring-tiers @from:sbom-diff-lib/tiers
Feature: Ranking reviewed packages into tiers
  Gives the reviewer of a dependency change a small, published, arithmetic rule that sorts every added or updated package into Read this, Glance or Routine, so they know where to spend attention and can audit the ranking.

  Background:
    Given the operator runs sbom-diff with the review enabled on an old and a new SBOM

  @id:risk-review.scoring-tiers.001 @rule:risk-review.tiers.score-picks-tier @verified @source:sbom_diff_lib/tiers.py#tier_for @test:tests/test_review.py#test_score_adds_up_and_picks_the_tier @test:tests/test_review.py#test_json_carries_the_findings_and_the_rule
  Scenario Outline: A package's total score decides its tier
    Given a changed package whose firing signals add up to <score> points
    When the operator runs the review
    Then the package is listed under the "<tier>" tier
    And its tier id in the JSON output is "<tier_id>"

    Examples:
      | score | tier      | tier_id |
      | 0     | Routine   | routine |
      | 1     | Routine   | routine |
      | 2     | Glance    | glance  |
      | 4     | Glance    | glance  |
      | 5     | Read this | read    |
      | 9     | Read this | read    |

  @id:risk-review.scoring-tiers.002 @rule:risk-review.tiers.rule-published-in-report @verified @source:sbom_diff_lib/tiers.py#rule_markdown @test:tests/test_review.py#test_the_ranking_rule_is_in_the_report
  Scenario: The report publishes the ranking rule it used
    Given the license signal is enabled and worth 2 points
    When the operator runs the review
    Then the report has a "How this was ranked" section
    And it shows the tier bands "Read this | 5 or more", "Glance | 2-4" and "Routine | under 2"
    And it lists each signal that ran with its points and source, such as "`license` — License changed | 2"
    And it tells the reader that "--disable-signal maintainers" drops a signal and rescores without it

  @id:risk-review.scoring-tiers.004 @rule:ci-gating.fail-on-tier.at-or-above @verified @source:sbom_diff_lib/tiers.py#meets @test:tests/test_review.py#test_fail_on_tier_is_the_gate
  Scenario Outline: A tier gate fails on any package at or above the chosen tier
    Given the only changed package scores 3 points and lands in Glance
    When the operator runs the diff offline with "--fail-on-tier <threshold>"
    Then the command exits with code <exit_code>
    And <message>

    Examples:
      | threshold | exit_code | message                                               |
      | routine   | 1         | stderr reports "1 component(s) at or above “Routine”" |
      | glance    | 1         | stderr reports "1 component(s) at or above “Glance”"  |
      | read      | 0         | no tier failure is reported                           |
