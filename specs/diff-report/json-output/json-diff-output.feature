@domain:diff-report @area:json-output @from:sbom-diff-lib/render
Feature: Consuming the diff as JSON
  Lets CI pipelines and other tools read the counts, the rendered report and every change from a single run.

  Background:
    Given an old SBOM and a new SBOM of the same application

  @id:diff-report.json-output.001 @rule:diff-report.json.carries-summary-markdown-counts @verified @source:sbom_diff_lib/render.py#json_payload @test:tests/test_sbom_diff.py#test_json_output_carries_counts_and_markdown @test:tests/test_e2e.py#test_basic_example_trips_the_major_gate_and_json_matches_stdout
  Scenario: JSON output carries the headline, the same markdown report as plain output, and the counts
    Given the new SBOM adds one dependency
    When the operator compares the two SBOMs asking for JSON output
    Then "counts.added" is 1
    And "markdown" starts with "# SBOM diff" and contains "summary"
    And "markdown" is identical to the report printed without JSON output

  @id:diff-report.json-output.002 @rule:diff-report.json.changes-as-old-new-pairs @inferred @source:sbom_diff_lib/render.py#json_payload
  Scenario: JSON output lists every change, with updates, renames and license changes as old and new records
    Given the SBOMs differ by an addition, a removal, an update, a rename and a license change
    When the operator compares the two SBOMs asking for JSON output
    Then "added" and "removed" hold the component records keyed by package
    And "changed", "renamed" and "license_changes" hold, per package, an "old" and a "new" component record

  @id:diff-report.json-output.003 @rule:diff-report.json.vulnerabilities-always-present @inferred @source:sbom_diff_lib/render.py#json_payload
  Scenario: JSON output always has the vulnerability changes, empty when the SBOMs carry no vulnerability data
    Given neither SBOM carries vulnerability statements
    When the operator compares the two SBOMs asking for JSON output
    Then "vulnerabilities" has "added", "removed" and "changed", each empty
    And when vulnerability data is present, each "changed" entry has an "old" and a "new" state
