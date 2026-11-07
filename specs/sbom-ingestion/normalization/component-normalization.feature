@domain:sbom-ingestion @area:normalization @from:sbom-diff-lib/normalize
Feature: Reading components the same way from CycloneDX and SPDX
  Gives operators one consistent view of each dependency (name, version, licenses, direct or not) whichever SBOM format their scanner writes, so the diff reports real changes rather than format noise.

  Background:
    Given the operator has an old SBOM and a new SBOM of the same project

  @id:sbom-ingestion.normalization.001 @rule:sbom.normalization.duplicates-keep-higher-version @verified @source:sbom_diff_lib/normalize.py#_insert @test:tests/test_sbom_diff.py#test_duplicate_component_keeps_the_higher_version
  Scenario: Two copies of one package in a single SBOM count as one, at the higher version
    Given the old SBOM lists package "dup" (pkg:npm/dup) at 2.0.0
    And the new SBOM lists package "dup" (pkg:npm/dup) at both 1.0.0 and 2.0.0
    And in the new SBOM only the 1.0.0 copy is listed as a direct dependency of the project
    When the operator diffs the old SBOM against the new SBOM
    Then the report shows no version change for "dup"
    And "dup" is treated as a direct dependency at version 2.0.0

  @id:sbom-ingestion.normalization.002 @rule:sbom.normalization.project-not-own-dependency @verified @source:sbom_diff_lib/normalize.py#load_cyclonedx @test:tests/test_sbom_diff.py#test_root_component_is_not_its_own_dependency @test:tests/test_sbom_diff.py#test_spdx_direct_from_relationships_both_directions @questionable
  Scenario Outline: The scanned project is never listed as one of its own dependencies
    Given the <format> SBOM describes the project "my-app"
    And it also catalogues "my-app" as a package <how>, alongside the dependency "dep"
    When the operator diffs the old SBOM against the new SBOM
    Then "dep" is the only dependency read from that SBOM
    And "my-app" never appears as an added, removed or changed dependency

    Examples:
      | format    | how                                                |
      | CycloneDX | under a different reference from the project's own |
      | CycloneDX | under the same reference as the project's own      |
      | SPDX      | as the package the document describes              |

  @id:sbom-ingestion.normalization.003 @rule:sbom.normalization.license-forms-read @inferred @source:sbom_diff_lib/normalize.py#_cyclonedx_licenses
  Scenario Outline: Licenses are read from every form the SBOM may state them in
    Given the old SBOM lists "openssl" 3.0.1 with no license
    And the new SBOM lists "openssl" 3.0.1 with its license stated as <stated>
    When the operator diffs the old SBOM against the new SBOM
    Then the report shows the license of "openssl" changing from none to <shown>

    Examples:
      | stated                                                   | shown             |
      | a CycloneDX SPDX id "Apache-2.0"                         | Apache-2.0        |
      | a CycloneDX license name "Acme Commercial"               | Acme Commercial   |
      | a CycloneDX expression "MIT OR Apache-2.0"               | MIT OR Apache-2.0 |
      | an SPDX concluded license "MIT"                          | MIT               |
      | an SPDX declared license "MIT" with no concluded license | MIT               |

  @id:sbom-ingestion.normalization.004 @rule:sbom.normalization.spdx-no-assertion-is-no-license @inferred @source:sbom_diff_lib/normalize.py#_spdx_component @questionable
  Scenario Outline: An SPDX "NOASSERTION" or "NONE" license means no license, even when a declared license exists
    Given the old SBOM lists "zlib" 1.3 with no license
    And the new SBOM is SPDX and lists "zlib" 1.3 with concluded license <concluded> and declared license "Zlib"
    When the operator diffs the old SBOM against the new SBOM
    Then the report shows no license change for "zlib"
    And "zlib" carries no license, so a denied-license policy cannot match it

    Examples:
      | concluded   |
      | NOASSERTION |
      | NONE        |

  @id:sbom-ingestion.normalization.005 @rule:sbom.normalization.missing-fields-shown-as-question-mark @inferred @source:sbom_diff_lib/normalize.py#load_cyclonedx
  Scenario: A component missing its name or version is shown with "?" instead of being dropped
    Given the new SBOM lists a package with purl "pkg:pypi/requests@2.31.0" and no version field
    And the old SBOM does not list it
    When the operator diffs the old SBOM against the new SBOM
    Then the report lists it as added with version "?"
