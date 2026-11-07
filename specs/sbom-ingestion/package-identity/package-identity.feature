@domain:sbom-ingestion @area:package-identity @from:sbom-diff-lib/purl
Feature: Matching packages across SBOMs
  Lets a reviewer trust that the same package in the old and new SBOM is recognised as one package, under the ecosystem name they know, even when scanners spell it differently.

  Background:
    Given two SBOMs of the same project, an older and a newer one

  @id:sbom-ingestion.package-identity.001 @rule:sbom.package-identity.purl-matches-ignoring-version @verified @source:sbom_diff_lib/purl.py#purl_identity @test:tests/test_sbom_diff.py#test_purl_matching_is_rename_aware @test:tests/test_sbom_diff.py#test_purl_identity
  Scenario Outline: Components with the same Package URL are the same package whatever their version, qualifiers or display name
    Given the old SBOM lists a component named "<old_name>" with Package URL "<old_purl>"
    And the new SBOM lists a component named "<new_name>" with Package URL "<new_purl>"
    When the operator diffs the two SBOMs
    Then the two components are matched as one package
    And the package is not reported as added or as removed

    Examples:
      | old_name        | old_purl                                    | new_name | new_purl                                |
      | python-requests | pkg:pypi/requests@2.31.0                    | requests | pkg:pypi/requests@2.31.0                |
      | requests        | pkg:pypi/requests@2.31.0                    | requests | pkg:pypi/requests@2.32.3?extra=socks    |
      | guava           | pkg:maven/com.google.guava/guava@32.0.0#jar | guava    | pkg:maven/com.google.guava/guava@33.0.0 |

  @id:sbom-ingestion.package-identity.002 @rule:sbom.package-identity.name-fallback-without-purl @verified @source:sbom_diff_lib/normalize.py#load_cyclonedx @test:tests/test_sbom_diff.py#test_diff_finds_all_change_kinds
  Scenario: Components without a Package URL are matched by name
    Given the old SBOM lists "openssl" 3.0.1 with no Package URL
    And the new SBOM lists "openssl" 4.0.0 with no Package URL
    When the operator diffs the two SBOMs
    Then "openssl" is reported as changed from 3.0.1 to 4.0.0
    And "openssl" is not reported as added or as removed

  @id:sbom-ingestion.package-identity.003 @rule:sbom.package-identity.scoped-npm-purls-distinct @inferred @source:sbom_diff_lib/purl.py#purl_identity @questionable
  Scenario: Scoped npm packages written with a plain @ in their Package URL are all treated as one package
    Given the new SBOM lists "@babel/core" 7.0.0 with Package URL "pkg:npm/@babel/core@7.0.0"
    And the new SBOM lists "@types/node" 20.1.0 with Package URL "pkg:npm/@types/node@20.1.0"
    And the old SBOM lists neither package
    When the operator diffs the two SBOMs
    Then only "@types/node" 20.1.0, the higher version, is reported as added
    And "@babel/core" does not appear anywhere in the report

  @id:sbom-ingestion.package-identity.004 @rule:sbom.package-identity.purl-match-is-exact-text @inferred @source:sbom_diff_lib/purl.py#purl_identity @questionable
  Scenario Outline: Package URLs that differ only in letter case or in how the scope @ is encoded are treated as different packages
    Given the old SBOM lists "requests" with Package URL "<old_purl>"
    And the new SBOM lists "requests" with Package URL "<new_purl>"
    When the operator diffs the two SBOMs
    Then the two components are not matched as one package

    Examples:
      | old_purl                 | new_purl                 |
      | pkg:PyPI/requests@2.31.0 | pkg:pypi/requests@2.31.0 |
      | pkg:pypi/Requests@2.31.0 | pkg:pypi/requests@2.31.0 |

  @id:sbom-ingestion.package-identity.005 @rule:sbom.package-identity.ecosystem-from-purl-type @verified @source:sbom_diff_lib/purl.py#ecosystem @test:tests/test_sbom_diff.py#test_ecosystem_from_purl
  Scenario Outline: Each package is labelled with the ecosystem name people recognise, and unrecognised types are kept as written
    Given the new SBOM adds a component with Package URL "<purl>"
    When the operator diffs the two SBOMs with review enabled
    Then the package's ecosystem in the JSON review is "<ecosystem>"
    And, when the package lands in the "Read this" or "Glance" tier, its markdown review heading <heading>

    Examples:
      | purl                               | ecosystem      | heading                  |
      | pkg:pypi/requests@2.31.0           | PyPI           | shows "· PyPI"           |
      | pkg:npm/%40scope/pkg@1.0.0         | npm            | shows "· npm"            |
      | pkg:GOLANG/golang.org/x/net@0.17.0 | Go             | shows "· Go"             |
      | pkg:github/actions/checkout@v4     | GitHub Actions | shows "· GitHub Actions" |
      | pkg:conan/zlib@1.3                 | conan          | shows "· conan"          |
      | (none)                             | unknown        | shows no ecosystem       |

  @id:sbom-ingestion.package-identity.006 @rule:sbom.package-identity.registry-name-from-purl @inferred @source:sbom_diff_lib/purl.py#purl_name
  Scenario Outline: Packages are looked up in their registry under the name their Package URL carries, with the scope included however it is encoded
    Given the new SBOM adds a component named "<sbom_name>" with Package URL "<purl>"
    When the operator diffs the two SBOMs with review enabled
    Then the review looks the package up under the name "<registry_name>"

    Examples:
      | sbom_name       | purl                                 | registry_name |
      | core            | pkg:npm/%40babel/core@7.24.0         | @babel/core   |
      | core            | pkg:npm/@babel/core@7.24.0           | @babel/core   |
      | python-requests | pkg:pypi/requests@2.31.0?extra=socks | requests      |
      | left-pad        | (none)                               | left-pad      |
