@domain:ci-gating @area:exit-codes @from:sbom-diff-lib/cli
Feature: Gating a pipeline on the diff
  Lets a CI operator fail a build on chosen kinds of change while telling a tripped gate apart from an unusable input.

  Background:
    Given two SBOMs where one component moves from version 2.0.0 down to 1.9.0

  @id:ci-gating.exit-codes.002 @rule:cli.gates.fail-on-exits-without-reason @verified @source:sbom_diff_lib/cli.py#_exit_code @test:tests/test_e2e.py#test_basic_example_trips_the_major_gate_and_json_matches_stdout @questionable
  Scenario: A tripped --fail-on gate fails the run without saying why
    Given the new SBOM updates a component by a major version
    When the operator runs sbom-diff with --fail-on major
    Then the full markdown report is printed on stdout
    And the exit code is 1
    And no line names --fail-on as the reason on stderr

  @id:ci-gating.exit-codes.003 @rule:cli.gates.denied-license-list-format @inferred @source:sbom_diff_lib/cli.py#policy_from_args
  Scenario Outline: Denied licenses can be given comma or newline separated
    Given the new SBOM adds a component licensed GPL-3.0
    When the operator runs sbom-diff with --deny-licenses "<list>"
    Then stderr names the denied licence on a line starting "sbom-diff: denied licence(s):"
    And the exit code is 1

    Examples:
      | list         |
      | MIT,GPL-3.0  |
      | MIT\nGPL-3.0 |
      |  GPL-3.0 ,   |
