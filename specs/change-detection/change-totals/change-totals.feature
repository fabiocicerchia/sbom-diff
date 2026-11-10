@domain:change-detection @area:change-totals @from:sbom-diff-lib/compare
Feature: Headline change totals
  Gives reviewers and CI gates one set of numbers for a change: how many packages were added (direct vs transitive), removed, updated, relicensed and downgraded.

  Background:
    Given an old SBOM and a new SBOM of the same application

  @id:change-detection.change-totals.001 @rule:change-detection.change-totals.counts-contract @verified @source:sbom_diff_lib/compare.py#counts @test:tests/test_sbom_diff.py#test_counts_split_added_by_depth_and_spot_downgrades @test:tests/test_sbom_diff.py#test_json_output_carries_counts_and_markdown
  Scenario: The totals report added, direct, transitive, removed, changed, relicensed and downgraded packages
    Given the old SBOM lists openssl 3.0.1 under Apache-2.0 and left-pad 1.0.0
    And the new SBOM lists openssl 4.0.0 under GPL-3.0 and requests 2.31.0
    And the new SBOM has no dependency graph
    When the operator compares the two SBOMs with --json
    Then the "counts" object holds, in this order, added 1, added_direct 0, added_transitive 1, removed 1, changed 1, license_changed 1, downgrades 0

  @id:change-detection.change-totals.002 @rule:change-detection.change-totals.downgrade-counted @verified @source:sbom_diff_lib/compare.py#downgrade_count @test:tests/test_sbom_diff.py#test_downgrade_detection
  Scenario: A package moving to a lower version is counted as a downgrade
    Given the old SBOM lists x 2.0.0
    And the new SBOM lists x 1.9.0
    When the operator compares the old SBOM with the new SBOM
    Then the downgrades count is 1
    And the headline includes ", 1 downgraded"
    And x is listed as "**x**: 2.0.0 → 1.9.0 *(downgrade)*" under the major version jumps
