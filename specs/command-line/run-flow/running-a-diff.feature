@domain:command-line @area:run-flow @from:sbom-diff-lib/cli
Feature: Running a diff from the command line
  Lets an operator compare two SBOMs in one command and get the same report as markdown or JSON, with the review added when asked for.

  Background:
    Given two readable SBOM files, an old one and a new one

  @id:command-line.run-flow.001 @rule:cli.run.both-sboms-required @inferred @source:sbom_diff_lib/cli.py#main
  Scenario: A diff needs both the old and the new SBOM
    Given the operator names only the old SBOM
    When the operator runs sbom-diff
    Then the run stops with a usage error saying "the old and new SBOM paths are both required"
    And the exit code is 2
    And no report is printed

  @id:command-line.run-flow.003 @rule:cli.run.review-only-when-asked @verified @source:sbom_diff_lib/cli.py#main @test:tests/test_review.py#test_a_diff_without_the_review_flag_is_unchanged @test:tests/test_review.py#test_offline_scores_from_the_sboms_and_says_what_it_skipped @test:tests/test_review.py#test_a_tier_gate_implies_the_review
  Scenario Outline: The review appears only when the operator asks for it or sets a tier gate
    Given the new SBOM updates a component by a major version
    When the operator runs sbom-diff with <flags>
    Then the report <presence> a "What to review" section

    Examples:
      | flags                         | presence         |
      | no extra flags                | does not contain |
      | --review --offline            | contains         |
      | --offline --fail-on-tier read | contains         |

  @id:command-line.run-flow.004 @rule:cli.signals.list-without-sboms @verified @source:sbom_diff_lib/cli.py#signal_listing @test:tests/test_review.py#test_list_signals_prints_the_rule_without_running_anything
  Scenario: Listing the signals needs no SBOMs and shows the whole ranking rule
    Given no SBOM files are named
    When the operator runs sbom-diff --list-signals
    Then every signal is printed with its id, its points and its source
    And every tier is printed with its minimum score, such as "Read this  score >= 5"
    And the exit code is 0
