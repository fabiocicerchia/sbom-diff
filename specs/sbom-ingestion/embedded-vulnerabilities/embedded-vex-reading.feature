@domain:sbom-ingestion @area:embedded-vulnerabilities @from:sbom-diff-lib/load
Feature: Reading embedded vulnerability statements
  Lets a security reviewer see vulnerability state changes between builds from the VEX data a CycloneDX SBOM already carries, without any network lookup.

  Background:
    Given the operator runs sbom-diff with an old SBOM and a new SBOM

  @id:sbom-ingestion.embedded-vulnerabilities.001 @rule:sbom-ingestion.embedded-vulnerabilities.state-and-severity @verified @source:sbom_diff_lib/load.py#load_vulnerabilities @test:tests/test_sbom_diff.py#test_load_vulnerabilities
  Scenario Outline: Each embedded vulnerability is read with its analysis state and first stated severity
    Given the SBOM carries vulnerability "CVE-2023-1111" with <analysis> and <ratings>
    When the operator compares the two SBOMs
    Then CVE-2023-1111 is taken as having state <state> and severity <severity>

    Examples:
      | analysis                      | ratings                                           | state        | severity |
      | analysis state "affected"     | one rating with severity "high"                   | affected     | high     |
      | no analysis                   | one rating with severity "high"                   | unknown      | high     |
      | analysis state "not_affected" | a rating without severity, then one with "medium" | not_affected | medium   |
      | analysis state "affected"     | no ratings                                        | affected     | none     |

  @id:sbom-ingestion.embedded-vulnerabilities.002 @rule:sbom-ingestion.embedded-vulnerabilities.absent-means-none @verified @source:sbom_diff_lib/load.py#load_vulnerabilities @test:tests/test_sbom_diff.py#test_load_vulnerabilities_absent
  Scenario Outline: An SBOM without vulnerability statements contributes no vulnerabilities
    Given the SBOM is <kind> with no "vulnerabilities" entries
    When the operator compares the two SBOMs
    Then that SBOM contributes no vulnerabilities to the comparison
    And the run continues without an error

    Examples:
      | kind                                          |
      | a CycloneDX SBOM not augmented with VEX data  |
      | an SPDX SBOM                                  |
      | a CycloneDX SBOM with "vulnerabilities": null |
