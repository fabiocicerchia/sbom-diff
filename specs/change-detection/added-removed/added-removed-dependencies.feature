@domain:change-detection @area:added-removed @from:sbom-diff-lib/compare
Feature: Spotting added, removed and updated dependencies
  Lets a reviewer see which packages a change brings in, drops or moves to another version, matched by package identity rather than by line-by-line text.

  Background:
    Given an old SBOM and a new SBOM of the same application

  @id:change-detection.added-removed.001 @rule:change-detection.added-removed.by-package-identity @verified @source:sbom_diff_lib/compare.py#diff @test:tests/test_sbom_diff.py#test_diff_finds_all_change_kinds
  Scenario: A package only in the new SBOM is added, one only in the old SBOM is removed
    Given the old SBOM lists openssl 3.0.1 and left-pad 1.0.0
    And the new SBOM lists openssl 4.0.0 and requests 2.31.0
    And the new SBOM has no dependency graph
    When the operator compares the old SBOM with the new SBOM
    Then the report lists requests 2.31.0 under "New dependencies (1, 1 transitive)"
    And the report lists left-pad 1.0.0 under "Removed dependencies (1)"
    And openssl is reported as a version change from 3.0.1 to 4.0.0, not as one added and one removed package
