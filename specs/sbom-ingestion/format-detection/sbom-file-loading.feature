@domain:sbom-ingestion @area:format-detection @from:sbom-diff-lib/load
Feature: Loading an SBOM file and recognising its format
  Lets an operator or CI pipeline hand sbom-diff any CycloneDX or SPDX JSON file and get either a diff or one clear line saying why the file is unusable, with an exit code that cannot be mistaken for a gate failure.

  Background:
    Given the operator runs sbom-diff with an old SBOM and a new SBOM

  @id:sbom-ingestion.format-detection.001 @rule:sbom-ingestion.format-detection.cyclonedx-recognised @verified @source:sbom_diff_lib/load.py#load_components @test:tests/test_sbom_diff.py#test_null_components_is_an_empty_scan_only_inside_a_real_cyclonedx_doc
  Scenario Outline: A CycloneDX document is recognised by its format marker or its component list
    Given the old SBOM is <document>
    When the operator compares it with a valid new SBOM
    Then the old SBOM is read as CycloneDX
    And it contributes <components> to the comparison

    Examples:
      | document                                                        | components                    |
      | a document with "bomFormat": "CycloneDX" and a component list   | the listed components         |
      | a document with a component list and no "bomFormat"             | the listed components         |
      | a document with "bomFormat": "CycloneDX" and "components": null | no components (an empty scan) |

  @id:sbom-ingestion.format-detection.002 @rule:sbom-ingestion.format-detection.spdx-recognised @inferred @source:sbom_diff_lib/load.py#load_components
  Scenario: An SPDX document is recognised by its SPDX version field
    Given the old SBOM is a JSON document carrying "spdxVersion" and no component list
    When the operator compares it with a valid new SBOM
    Then the old SBOM is read as SPDX
    And its packages take part in the comparison

  @id:sbom-ingestion.format-detection.003 @rule:sbom-ingestion.format-detection.non-sbom-json-refused @verified @source:sbom_diff_lib/load.py#load_components @test:tests/test_sbom_diff.py#test_unrecognized_format @test:tests/test_sbom_diff.py#test_null_components_is_an_empty_scan_only_inside_a_real_cyclonedx_doc @test:tests/test_sbom_diff.py#test_unusable_input_exits_by_kind_not_as_a_gate
  Scenario Outline: JSON that is not a CycloneDX or SPDX SBOM is refused rather than read as empty
    Given the old SBOM file contains <content>
    When the operator compares it with a valid new SBOM
    Then no report is printed
    And the error output reads "sbom-diff: <path>: not a recognizable CycloneDX or SPDX JSON SBOM"
    And the exit code is 65

    Examples:
      | content                                                           |
      | {"hello": "world"}                                                |
      | {"components": null} with no format marker (a truncated fragment) |
      | a bare JSON array                                                 |
      | a bare JSON string                                                |
