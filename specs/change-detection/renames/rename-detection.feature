@domain:change-detection @area:renames @from:sbom-diff-lib/compare
Feature: Reporting renamed packages
  Keeps a scanner relabelling a package from showing up as a scary add-plus-remove, so reviewers only see real dependency churn.

  Background:
    Given an old SBOM and a new SBOM of the same application

  @id:change-detection.renames.001 @rule:change-detection.renames.same-identity-new-name-is-rename @verified @source:sbom_diff_lib/compare.py#diff @test:tests/test_sbom_diff.py#test_purl_matching_is_rename_aware
  Scenario: A package whose name changed but whose Package URL did not is reported as a rename
    Given the old SBOM lists python-requests 2.31.0 with Package URL pkg:pypi/requests@2.31.0
    And the new SBOM lists requests 2.31.0 with Package URL pkg:pypi/requests@2.31.0
    When the operator compares the old SBOM with the new SBOM
    Then the report shows "## Renamed (1)" with "**python-requests** → **requests**"
    And nothing is listed as added, removed or updated
    And the headline ends with ", 1 renamed"

  @id:change-detection.renames.002 @rule:change-detection.renames.renamed-version-change-not-an-update @inferred @source:sbom_diff_lib/compare.py#diff @questionable
  Scenario: A renamed package that also changed version is shown only as a rename, not as an update
    Given the old SBOM lists python-requests 3.0.0 with Package URL pkg:pypi/requests@3.0.0
    And the new SBOM lists requests 2.0.0 with Package URL pkg:pypi/requests@2.0.0
    When the operator compares the old SBOM with the new SBOM
    Then the Renamed section shows "**python-requests** → **requests** (3.0.0 → 2.0.0)"
    And the package is not listed under the major version jumps and is not marked as a downgrade
    And the headline reports 0 updated and no downgrade
    And the counts in --json report changed 0 and downgrades 0
