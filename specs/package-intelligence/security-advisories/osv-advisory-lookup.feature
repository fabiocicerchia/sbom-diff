@domain:package-intelligence @area:security-advisories @from:sbom-diff-lib/osv
Feature: Looking up known advisories for a package version
  Gives the reviewer of a dependency change the known OSV advisories for a package version, with a stated reason whenever none could be looked up, so a new vulnerability is not missed and a missing check is not mistaken for a clean one.

  Background:
    Given the operator runs sbom-diff with the review and the advisories signal enabled

  @id:package-intelligence.security-advisories.001 @rule:package-intelligence.advisories.unsupported-ecosystem-not-queried @verified @source:sbom_diff_lib/osv.py#advisories @test:tests/test_review.py#test_osv_is_not_queried_for_ecosystems_it_does_not_index
  Scenario Outline: Packages from ecosystems OSV is not asked about are reported as not checkable
    Given the head SBOM updates a package from the <ecosystem> ecosystem
    When the operator reviews the change
    Then the advisories signal for that package is not checkable
    And its detail reads "OSV is not queried for <ecosystem> packages"
    And no request is sent to OSV for that package

    Examples:
      | ecosystem |
      | deb       |
      | rpm       |
      | apk       |
      | unknown   |

  @id:package-intelligence.security-advisories.002 @rule:package-intelligence.advisories.osv-ecosystem-naming @inferred @source:sbom_diff_lib/osv.py#advisories
  Scenario Outline: Packages are looked up in OSV under the ecosystem name OSV uses
    Given the head SBOM updates the package "<name>" version "<version>" whose purl type is <purl_ecosystem>
    When the operator reviews the change
    Then OSV is asked about "<name>" version "<version>" in the "<osv_ecosystem>" ecosystem

    Examples:
      | purl_ecosystem | osv_ecosystem | name            | version |
      | npm            | npm           | left-pad        | 1.3.0   |
      | PyPI           | PyPI          | requests        | 2.31.0  |
      | Cargo          | crates.io     | serde           | 1.0.200 |
      | Composer       | Packagist     | monolog/monolog | 3.5.0   |
      | hex            | Hex           | plug            | 1.15.0  |
      | pub            | Pub           | http            | 1.2.0   |
      | conan          | ConanCenter   | zlib            | 1.3.1   |

  @id:package-intelligence.security-advisories.003 @rule:package-intelligence.advisories.both-versions-queried @verified @source:sbom_diff_lib/review.py#_advisories @test:tests/test_review.py#test_advisories_new_to_the_version_are_the_ones_reported
  Scenario: Advisories are looked up for both the old and the new version of an updated package
    Given the base SBOM has "vulny" at version "1.0.0"
    And the head SBOM has "vulny" at version "1.1.0"
    When the operator reviews the change
    Then OSV is asked about "vulny" 1.0.0 and about "vulny" 1.1.0
    And two requests are sent to OSV for that package

  @id:package-intelligence.security-advisories.004 @rule:package-intelligence.advisories.advisory-identity-severity-link @verified @source:sbom_diff_lib/osv.py#_advisory @test:tests/test_review.py#test_advisories_new_to_the_version_are_the_ones_reported @questionable
  Scenario: A reported advisory shows its id, its severity in lower case and a link to its OSV page
    Given OSV lists advisory "GHSA-1234-5678-9abc" with severity "HIGH" for "vulny" 1.1.0 and not for 1.0.0
    When the operator reviews the update of "vulny" from 1.0.0 to 1.1.0
    Then the advisories signal names "GHSA-1234-5678-9abc (high)"
    And the finding links to "https://osv.dev/vulnerability/GHSA-1234-5678-9abc"

  @id:package-intelligence.security-advisories.005 @rule:package-intelligence.advisories.lookup-failure-stated @inferred @source:sbom_diff_lib/osv.py#advisories
  Scenario Outline: When OSV cannot be asked or answers unusably, the reason is reported rather than a clean result
    Given the OSV lookup for the updated package fails because <cause>
    When the operator reviews the change
    Then the advisories signal for that package is not checkable
    And its detail reads "OSV: <reason>"
    And the run still finishes and prints the review

    Examples:
      | cause                                                | reason                             |
      | the request budget is spent                          | request budget of 50 spent         |
      | OSV answered with something other than a JSON object | the response was not a JSON object |

  @id:package-intelligence.security-advisories.006 @rule:package-intelligence.advisories.ordered-by-id @inferred @source:sbom_diff_lib/osv.py#advisories @questionable
  Scenario: Advisories for a version are listed in id order
    Given OSV lists advisories "PYSEC-2024-1", "GHSA-bbbb-0000-0000" and "CVE-2024-0001" for the new version only
    When the operator reviews the update
    Then the advisories signal lists "CVE-2024-0001", then "GHSA-bbbb-0000-0000", then "PYSEC-2024-1"
    And the finding links to the OSV page of "CVE-2024-0001"
