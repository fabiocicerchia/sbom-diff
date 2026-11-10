@domain:ci-gating @area:license-policy @from:sbom-diff-lib/policy
Feature: Gating a change on licenses
  Lets a compliance-minded operator fail CI when a dependency changes license or when the change brings in a license they have banned.

  Background:
    Given the operator compares an old SBOM with a new SBOM using sbom-diff in CI

  @id:ci-gating.license-policy.001 @rule:ci-gating.license-policy.license-change-gate @verified @source:sbom_diff_lib/policy.py#_threshold_failures @test:tests/test_docs_commands.py#test_every_documented_command_runs_on_the_review_example
  Scenario: An existing dependency changing license fails the run when license changes are gated
    Given component internal-toolkit changes its declared license between the two SBOMs
    When the operator runs sbom-diff with --fail-on-license-change
    Then the exit code is 1
    And stderr shows "sbom-diff: 1 licence change(s)"

  @id:ci-gating.license-policy.002 @rule:ci-gating.license-policy.denied-license-introduced @verified @source:sbom_diff_lib/policy.py#_denied_license_hits @test:tests/test_sbom_diff.py#test_deny_licenses_matches_added_and_newly_changed @questionable
  Scenario Outline: A denied license that the change introduces fails the run, whatever its letter case
    Given component a is added with license GPL-3.0
    And component b changes license from MIT to AGPL-3.0
    When the operator runs sbom-diff with --deny-licenses <denied>
    Then the exit code is <exit>
    And stderr shows <reason>

    Examples:
      | denied           | exit | reason                                                    |
      | gpl-3.0          | 1    | "sbom-diff: denied licence(s): a (GPL-3.0)"               |
      | AGPL-3.0,GPL-3.0 | 1    | "sbom-diff: denied licence(s): a (GPL-3.0), b (AGPL-3.0)" |
      | MIT              | 0    | no reason                                                 |
