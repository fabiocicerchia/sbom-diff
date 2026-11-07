@domain:risk-review @area:signal-selection @from:sbom-diff-lib/signals
Feature: Choosing which risk signals run
  Lets an operator switch off signals they do not trust and run the review offline, and always tells them which questions went unasked and why.

  Background:
    Given the operator runs sbom-diff with the review turned on over a base SBOM and a new SBOM

  @id:risk-review.signal-selection.001 @rule:risk.selection.disabled-signal-reported @verified @source:sbom_diff_lib/signals.py#select @test:tests/test_review.py#test_a_disabled_signal_does_not_score
  Scenario: A disabled signal does not run and the report says it was disabled
    Given the operator disables the license and fanout signals
    When the operator runs the review
    Then no license change is scored in the review
    And the review lists "`license` — disabled on the command line" among the signals not run

  @id:risk-review.signal-selection.002 @rule:risk.selection.offline-skips-network-signals @verified @source:sbom_diff_lib/signals.py#select @test:tests/test_review.py#test_offline_scores_from_the_sboms_and_says_what_it_skipped
  Scenario Outline: Offline, only the signals the two SBOMs can answer run, and the rest are listed with what they needed
    Given the operator runs in offline mode
    When the operator runs the review
    Then the <signal> signal <outcome>

    Examples:
      | signal          | outcome                                                                                 |
      | advisories      | is listed as "offline: needs OSV API"                                                   |
      | install-scripts | is listed as "offline: needs npm registry (other ecosystems: not checkable)"            |
      | provenance      | is listed as "offline: needs npm registry (other ecosystems: not checkable)"            |
      | maintainers     | is listed as "offline: needs npm and PyPI registries (other ecosystems: not checkable)" |
      | young-package   | is listed as "offline: needs npm and PyPI registries (other ecosystems: not checkable)" |
      | scorecard       | is listed as "offline: needs deps.dev"                                                  |
      | major-skip      | runs                                                                                    |
      | new-package     | runs                                                                                    |
      | license         | runs                                                                                    |
      | fanout          | runs                                                                                    |

  @id:risk-review.signal-selection.003 @rule:risk.selection.unknown-signal-refused @verified @source:sbom_diff_lib/signals.py#select @test:tests/test_review.py#test_unknown_signal_is_a_usage_error
  Scenario: Disabling a signal that does not exist is refused, naming the known ones
    Given the operator disables a signal called nonsense
    When the operator runs the review
    Then the run stops with "unknown signal(s): nonsense" followed by the list of known signal ids
    And the exit code is 2
