@domain:change-detection @area:license-changes @from:sbom-diff-lib/compare
Feature: Flagging license changes
  Tells a reviewer or compliance owner when a dependency they already ship changes the license it is declared under.

  Background:
    Given an old SBOM and a new SBOM of the same application

  @id:change-detection.license-changes.001 @rule:change-detection.license-changes.declared-license-differs @verified @source:sbom_diff_lib/compare.py#diff @test:tests/test_sbom_diff.py#test_diff_finds_all_change_kinds @test:tests/test_sbom_diff.py#test_counts_split_added_by_depth_and_spot_downgrades
  Scenario Outline: A package whose declared license differs between the SBOMs is flagged, including a license that appears or disappears
    Given the old SBOM declares openssl under <old_license>
    And the new SBOM declares openssl under <new_license>
    When the operator compares the old SBOM with the new SBOM
    Then the report shows "## ⚠ License changes" with "**openssl**: <shown>"
    And the license_changed count is 1

    Examples:
      | old_license | new_license | shown                |
      | Apache-2.0  | GPL-3.0     | Apache-2.0 → GPL-3.0 |
      | MIT         | no license  | MIT → (none)         |
      | no license  | MIT         | (none) → MIT         |
