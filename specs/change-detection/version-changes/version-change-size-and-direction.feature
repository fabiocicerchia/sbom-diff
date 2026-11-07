@domain:change-detection @area:version-changes @from:sbom-diff-lib/versions
Feature: Sizing and directing version changes
  Tells a reviewer how big each dependency version change is and whether it went backwards, so breaking upgrades and accidental downgrades stand out in the report.

  Background:
    Given the old and new SBOMs both list the same package under the same name

  @id:change-detection.version-changes.001 @rule:change-detection.version-changes.size-classified @verified @source:sbom_diff_lib/versions.py#semver_jump @test:tests/test_sbom_diff.py#test_semver_classification @test:tests/test_render.py#test_explain_buckets_smaller_jumps_below_major_in_decreasing_size @test:tests/test_render.py#test_explain_renders_every_section_most_alarming_first
  Scenario Outline: A version change is reported under its size: major, minor, patch or other
    Given the package is at version <old> in the old SBOM
    And the package is at version <new> in the new SBOM
    When the operator diffs the two SBOMs
    Then the report lists the package as "<old> → <new>" under the "<section>" heading

    Examples:
      | old    | new    | section                                         |
      | 1.2.3  | 2.0.0  | ⚠ Major version jumps (review breaking changes) |
      | 1.0.0  | 1.1.0  | Minor updates                                   |
      | v1.2.3 | v1.2.4 | Patch updates                                   |
      | 1.2    | 1.2.1  | Patch updates                                   |
      | abc    | def    | Other version changes                           |

  @id:change-detection.version-changes.002 @rule:change-detection.version-changes.downgrade-flagged @verified @source:sbom_diff_lib/versions.py#is_downgrade @test:tests/test_render.py#test_explain_renders_every_section_most_alarming_first @test:tests/test_sbom_diff.py#test_compare_versions_orders_and_handles_prereleases @test:tests/test_sbom_diff.py#test_downgrade_detection
  Scenario Outline: A change to a lower version is labelled as a downgrade
    Given the package is at version <old> in the old SBOM
    And the package is at version <new> in the new SBOM
    When the operator diffs the two SBOMs
    Then the package's line in the report <flag> carry the "(downgrade)" label

    Examples:
      | old        | new          | flag     |
      | 2.0.0      | 1.9.0        | does     |
      | 1.0.0      | 1.0.0-rc1    | does     |
      | 1.0.0-beta | 1.0.0-alpha  | does     |
      | 1.2.3      | 2.0.0        | does not |
      | 1.0.0-rc1  | 1.0.0        | does not |
      | v1.0.0     | 1.0.0        | does not |
      | 1.0.0      | 1.0.0+abc123 | does not |

  @id:change-detection.version-changes.003 @rule:change-detection.version-changes.non-plain-versions-unsized @inferred @source:sbom_diff_lib/versions.py#semver_jump @questionable
  Scenario Outline: A version change involving a pre-release, build tag or fourth segment is reported as an other change, even when the major number moved
    Given the package is at version <old> in the old SBOM
    And the package is at version <new> in the new SBOM
    When the operator diffs the two SBOMs
    Then the report lists the package as "<old> → <new>" under "Other version changes"
    And the package is not listed under the major version jumps heading

    Examples:
      | old       | new          |
      | 1.0.0-rc1 | 2.0.0        |
      | 1.9.0     | 2.0.0-beta   |
      | 1.0.0     | 1.0.0+abc123 |
      | 1.2.3.4   | 1.2.3.5      |

  @id:change-detection.version-changes.004 @rule:change-detection.version-changes.prerelease-numbers-compared-as-text @inferred @source:sbom_diff_lib/versions.py#_compare_prerelease @questionable
  Scenario Outline: Numbered pre-releases are ordered as text, so moving from rc9 to rc10 is labelled a downgrade
    Given the package is at version <old> in the old SBOM
    And the package is at version <new> in the new SBOM
    When the operator diffs the two SBOMs
    Then the package's line in the report <flag> carry the "(downgrade)" label

    Examples:
      | old           | new            | flag     |
      | 1.0.0-rc9     | 1.0.0-rc10     | does     |
      | 1.0.0-alpha.2 | 1.0.0-alpha.10 | does     |
      | 1.0.0-rc10    | 1.0.0-rc9      | does not |

  @id:change-detection.version-changes.005 @rule:change-detection.version-changes.unknown-version-gaining-value-is-downgrade @inferred @source:sbom_diff_lib/versions.py#_compare_core @questionable
  Scenario: A package whose version goes from unknown to a stated version is labelled a downgrade
    Given the package has no version in the old SBOM
    And the package is at version 1.0.0 in the new SBOM
    When the operator diffs the two SBOMs
    Then the report lists the package as "? → 1.0.0 *(downgrade)*" under "Other version changes"
    And the headline counts the package as 1 downgraded
