@domain:ci-gating @area:change-thresholds @from:sbom-diff-lib/policy
Feature: Gating a change on how much it adds or downgrades
  Lets a CI operator fail a pull request when it adds too many components, too many transitive components, or downgrades a dependency, and see on stderr why it failed.

  Background:
    Given the operator compares an old SBOM with a new SBOM using sbom-diff in CI

  @id:ci-gating.change-thresholds.001 @rule:ci-gating.change-thresholds.opt-in-only @verified @source:sbom_diff_lib/policy.py#policy_failures @test:tests/test_sbom_diff.py#test_policy_thresholds_are_opt_in @test:tests/test_sbom_diff.py#test_downgrade_detection
  Scenario: With no gates chosen, a run passes whatever changed
    Given the new SBOM adds 5 components, 3 of them transitive
    And it downgrades 1 component and changes the license of 1 component
    When the operator runs sbom-diff without any gate option
    Then the exit code is 0
    And no gate failure reason is printed on stderr

  @id:ci-gating.change-thresholds.002 @rule:ci-gating.change-thresholds.added-count-limit @inferred @source:sbom_diff_lib/policy.py#_threshold_failures
  Scenario Outline: A change that adds more components than the limit fails the run
    Given the new SBOM adds <added> components, <transitive> of them transitive
    When the operator runs sbom-diff with <option> <limit>
    Then the exit code is <exit>
    And stderr shows <reason>

    Examples:
      | added | transitive | option                 | limit | exit | reason                                                          |
      | 5     | 3          | --max-added            | 4     | 1    | "sbom-diff: 5 components added, over the limit of 4"            |
      | 4     | 3          | --max-added            | 4     | 0    | no reason                                                       |
      | 5     | 3          | --max-added-transitive | 2     | 1    | "sbom-diff: 3 transitive components added, over the limit of 2" |
      | 5     | 3          | --max-added-transitive | 3     | 0    | no reason                                                       |

  @id:ci-gating.change-thresholds.003 @rule:ci-gating.change-thresholds.downgrade-gate @verified @source:sbom_diff_lib/policy.py#_threshold_failures @test:tests/test_sbom_diff.py#test_downgrade_detection
  Scenario: A dependency moving to a lower version fails the run when downgrades are gated
    Given component x goes from version 2.0.0 to 1.9.0
    When the operator runs sbom-diff with --fail-on-downgrade
    Then the exit code is 1
    And stderr shows "sbom-diff: 1 component(s) downgraded — usually a lockfile conflict resolved the wrong way"

  @id:ci-gating.change-thresholds.004 @rule:ci-gating.change-thresholds.all-reasons-reported @verified @source:sbom_diff_lib/policy.py#policy_failures @test:tests/test_sbom_diff.py#test_policy_thresholds_are_opt_in
  Scenario: Every gate that trips is reported, not just the first
    Given the new SBOM adds 5 components, 3 of them transitive, downgrades 1 and relicenses 1
    When the operator runs sbom-diff with --max-added 4 --max-added-transitive 2 --fail-on-downgrade --fail-on-license-change
    Then the exit code is 1
    And stderr shows 4 reasons, one per tripped gate, in the order: added, transitive, downgrade, licence change
