@domain:risk-review @area:review-orchestration @from:sbom-diff-lib/review
Feature: Deciding what gets reviewed and in what order
  Lets a reviewer approving a dependency update see every added or rebuilt package judged and ranked worst first, without the tool contacting sources nobody asked about.

  Background:
    Given a base SBOM and a target SBOM have been diffed
    And the operator has asked for the risk review

  @id:risk-review.review-orchestration.001 @rule:risk.review.only-new-builds-are-judged @verified @source:sbom_diff_lib/review.py#_subjects @test:tests/test_review.py#test_new_package_fires_only_for_something_that_was_not_there @questionable
  Scenario Outline: Only packages that arrive or change version are judged
    Given a package <change> between the base and the target SBOM
    When the operator runs the review
    Then the package <judged> in the review findings

    Examples:
      | change                                        | judged          |
      | is added                                      | appears         |
      | moves to another version                      | appears         |
      | is renamed and moves to another version       | appears         |
      | is renamed but keeps its version              | does not appear |
      | is removed                                    | does not appear |
      | changes only its license, keeping its version | does not appear |

  @id:risk-review.review-orchestration.003 @rule:risk.review.findings-ranked-worst-first @inferred @source:sbom_diff_lib/review.py#review
  Scenario: Findings are listed loudest tier first, then highest score, then by name
    Given package "zeta" lands in "Read this" with 7 points
    And package "Alpha" lands in "Glance" with 3 points
    And package "beta" lands in "Glance" with 3 points
    And package "gamma" lands in "Glance" with 4 points
    When the operator runs the review
    Then the findings are listed in the order "zeta", "gamma", "Alpha", "beta"
    And running the review again on the same diff lists them in the same order

  @id:risk-review.review-orchestration.004 @rule:risk.review.only-needed-sources-contacted @verified @source:sbom_diff_lib/review.py#Plan @test:tests/test_review.py#test_install_script_added_is_reported_with_somewhere_to_read_it @test:tests/test_review.py#test_json_carries_the_findings_and_the_rule
  Scenario: A lookup source is never contacted when every signal that reads it is turned off
    Given the added npm package "build-helper" 2.0.0
    And the advisories and scorecard signals are disabled
    When the operator runs the review
    Then only the npm registry is asked about "build-helper"
    And no request goes to OSV or deps.dev
    And the review reports 1 request made
