@domain:ci-gating @area:exit-codes @from:sbom-diff-lib/exits
Feature: Reporting the outcome of a run through its exit code
  Gives CI operators distinct exit codes, so a pipeline can tell a passing diff from a tripped gate and from an SBOM that could not be used at all.

  Background:
    Given a valid CycloneDX SBOM "new.json"

  @id:ci-gating.exit-codes.005 @rule:ci.exit-codes.unusable-input-exits-by-kind @verified @source:sbom_diff_lib/load.py#read_sbom @test:tests/test_sbom_diff.py#test_unusable_input_exits_by_kind_not_as_a_gate @test:tests/test_sbom_diff.py#test_deeply_nested_json_is_an_input_error_not_a_recursion_crash @test:tests/test_e2e.py#test_missing_sbom_exits_with_a_message_not_a_traceback
  Scenario Outline: An unusable SBOM ends the run with an exit code that names the kind of problem
    Given the old SBOM "<old>" is <problem>
    When the operator diffs "<old>" against "new.json"
    Then the run exits with code <code>
    And stderr shows one line starting "sbom-diff: " and ending "<message>"
    And no report is printed on stdout
    And no traceback is shown

    Examples:
      | old         | problem                                 | code | message                                        |
      | absent.json | not on disk                             | 66   | absent.json: no such file                      |
      | locked.json | not readable by the operator            | 77   | locked.json: permission denied                 |
      | sbom-dir    | a directory, not a file                 | 74   | sbom-dir: Is a directory                       |
      | page.json   | an HTML page, not JSON                  | 65   | page.json: not valid JSON: <parser detail>     |
      | other.json  | JSON that is neither CycloneDX nor SPDX | 65   | not a recognizable CycloneDX or SPDX JSON SBOM |
      | deep.json   | 10,000 levels of nested brackets        | 65   | deep.json: nested too deeply to parse          |

  @id:ci-gating.exit-codes.006 @rule:ci.exit-codes.clean-run-exits-zero @verified @source:sbom_diff_lib/cli.py#_exit_code @test:tests/test_e2e.py#test_basic_example_prints_the_report_and_passes
  Scenario: A diff that trips no gate exits with code 0
    Given the old SBOM "old.json" is a valid SBOM
    And no configured gate is tripped by the changes
    When the operator diffs "old.json" against "new.json"
    Then the report is printed on stdout
    And stderr is empty
    And the run exits with code 0
