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

  @id:command-line.run-flow.002 @rule:cli.run.json-carries-the-printed-report @verified @source:sbom_diff_lib/cli.py#_print_report @test:tests/test_e2e.py#test_basic_example_trips_the_major_gate_and_json_matches_stdout @test:tests/test_sbom_diff.py#test_json_output_carries_counts_and_markdown
  Scenario: JSON output carries exactly the markdown report the plain run prints
    Given the new SBOM adds one component
    When the operator runs sbom-diff with --json
    Then stdout is a JSON document
    And its markdown field is the same report a run without --json prints, starting with "# SBOM diff"
    And its summary appears inside that markdown
    And its counts show 1 added component

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

  @id:command-line.run-flow.005 @rule:cli.signals.unknown-signal-refused @verified @source:sbom_diff_lib/cli.py#main @test:tests/test_review.py#test_unknown_signal_is_a_usage_error
  Scenario: Disabling a signal that does not exist is refused as a usage error
    Given the operator asks for the review
    When the operator runs sbom-diff with --disable-signal nonsense
    Then the run stops with an error naming "unknown signal(s): nonsense"
    And the exit code is 2
