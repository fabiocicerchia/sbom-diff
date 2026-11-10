@domain:ci-gating @area:fail-on-rules @from:sbom-diff-lib/policy
Feature: Failing CI on a chosen class of change
  Lets an operator make any change, any major version jump, or any license change fail the pipeline with one option.

  Background:
    Given the operator compares an old SBOM with a new SBOM using sbom-diff in CI

  @id:ci-gating.fail-on-rules.001 @rule:ci-gating.fail-on-rules.class-of-change @verified @source:sbom_diff_lib/policy.py#fail_on_verdict @test:tests/test_sbom_diff.py#test_fail_on_major @test:tests/test_e2e.py#test_basic_example_trips_the_major_gate_and_json_matches_stdout @test:tests/test_docs_commands.py#test_every_documented_command_runs_on_the_review_example
  Scenario Outline: The chosen class of change fails the run only when it is present
    Given <diff>
    When the operator runs sbom-diff with --fail-on <choice>
    Then the exit code is <exit>

    Examples:
      | diff                                 | choice  | exit |
      | openssl goes from 1.1.1 to 3.0.0     | major   | 1    |
      | only libfoo goes from 1.2.0 to 1.2.1 | major   | 0    |
      | the two SBOMs are identical          | any     | 0    |
      | one component is added               | any     | 1    |
      | internal-toolkit changes license     | license | 1    |
      | no component changes license         | license | 0    |
