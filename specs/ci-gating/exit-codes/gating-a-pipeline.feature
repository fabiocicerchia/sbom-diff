@domain:ci-gating @area:exit-codes @from:sbom-diff-lib/cli
Feature: Gating a pipeline on the diff
  Lets a CI operator fail a build on chosen kinds of change while telling a tripped gate apart from an unusable input.

  Background:
    Given two SBOMs where one component moves from version 2.0.0 down to 1.9.0

  @id:ci-gating.exit-codes.001 @rule:cli.gates.opt-in-and-reported @verified @source:sbom_diff_lib/cli.py#_exit_code @test:tests/test_sbom_diff.py#test_downgrade_detection @test:tests/test_e2e.py#test_basic_example_prints_the_report_and_passes
  Scenario Outline: Gates are opt-in, and a tripped gate keeps the report and names its reason
    When the operator runs sbom-diff with <gate>
    Then the full markdown report is printed on stdout
    And <stderr>
    And the exit code is <code>

    Examples:
      | gate                | stderr                                                                | code |
      | no gate flags       | nothing is printed on stderr                                          | 0    |
      | --fail-on-downgrade | each failed gate is printed on stderr as a line starting "sbom-diff:" | 1    |

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

  @id:ci-gating.exit-codes.004 @rule:cli.exit.unusable-input-by-kind @verified @source:sbom_diff_lib/cli.py#main @test:tests/test_sbom_diff.py#test_unusable_input_exits_by_kind_not_as_a_gate @test:tests/test_e2e.py#test_missing_sbom_exits_with_a_message_not_a_traceback
  Scenario Outline: An unusable SBOM exits with a code for its kind, never the gate code
    Given the old SBOM is <problem>
    When the operator runs sbom-diff
    Then nothing is printed on stdout
    And stderr carries one line starting "sbom-diff:" that ends with <message>
    And the exit code is <code>

    Examples:
      | problem                            | message                                          | code |
      | a path that does not exist         | "absent.json: no such file"                      | 66   |
      | a file that is not JSON            | a mention of "not valid JSON"                    | 65   |
      | JSON that is not CycloneDX or SPDX | "not a recognizable CycloneDX or SPDX JSON SBOM" | 65   |
      | a directory                        | a read error                                     | 74   |
