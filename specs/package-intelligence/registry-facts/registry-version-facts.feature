@domain:package-intelligence @area:registry-facts @from:sbom-diff-lib/registries
Feature: Reading npm and PyPI facts about a package version
  Gives reviewers the install scripts, maintainers, publish time and provenance of each changed npm or PyPI package version, and says plainly why any fact could not be checked instead of treating it as clean.

  Background:
    Given the operator runs sbom-diff with the risk review enabled and network lookups allowed

  @id:package-intelligence.registry-facts.001 @rule:package-intelligence.registry-facts.unsupported-ecosystem-not-checkable @verified @source:sbom_diff_lib/registries.py#version_facts @test:tests/test_review.py#test_install_scripts_are_not_checkable_outside_npm
  Scenario Outline: Packages outside npm and PyPI are reported as not checkable, naming their ecosystem
    Given a changed package from the <ecosystem> ecosystem
    When the operator reviews the diff
    Then install scripts, maintainers, publish time and provenance are each reported as not checkable
    And the reason reads "no registry this tool reads exposes it for <ecosystem>"
    And no registry is contacted for that package

    Examples:
      | ecosystem |
      | deb       |
      | Maven     |
      | Go        |

  @id:package-intelligence.registry-facts.002 @rule:package-intelligence.registry-facts.npm-install-scripts @verified @source:sbom_diff_lib/registries.py#_npm_facts @test:tests/test_review.py#test_install_script_added_is_reported_with_somewhere_to_read_it
  Scenario: Only npm scripts that run on install are reported as install scripts
    Given an npm package version whose published scripts include "postinstall" and "test"
    When the operator reviews the diff
    Then the version is reported with the "postinstall" script and its command
    And the "test" script is not reported
    And only scripts named preinstall, install or postinstall are ever reported

  @id:package-intelligence.registry-facts.003 @rule:package-intelligence.registry-facts.pypi-install-code-never-clean @inferred @source:sbom_diff_lib/registries.py#_pypi_facts
  Scenario: A PyPI package is never reported as free of install scripts or as lacking provenance
    Given a changed PyPI package version
    When the operator reviews the diff
    Then install scripts are reported as not checkable: "PyPI does not expose whether a package runs code at install time"
    And provenance is reported as not checkable: "PyPI attestations are not exposed by the JSON API"

  @id:package-intelligence.registry-facts.004 @rule:package-intelligence.registry-facts.maintainer-set @verified @source:sbom_diff_lib/registries.py#_npm_maintainers @test:tests/test_review.py#test_npm_maintainer_change_names_who_arrived @test:tests/test_review.py#test_pypi_maintainer_change_is_checkable_too @questionable
  Scenario Outline: The maintainers of a version come from its registry, by name or email
    Given a changed <registry> package version
    When the operator reviews the diff
    Then its maintainers are taken from <source>
    And each maintainer is identified by <identity>
    And a version listing no maintainers has maintainers reported as not checkable: "<note>"

    Examples:
      | registry | source                                                                                     | identity                                          | note                                       |
      | npm      | the version's own maintainer list, or the package's current list when the version has none | name, or email when the name is missing           | npm listed no maintainers for this version |
      | PyPI     | the maintainer, maintainer email, author and author email fields                           | every one of those values, names and emails alike | PyPI listed no maintainer or author        |

  @id:package-intelligence.registry-facts.005 @rule:package-intelligence.registry-facts.npm-provenance @verified @source:sbom_diff_lib/registries.py#_npm_facts @test:tests/test_review.py#test_provenance_present_before_and_absent_now
  Scenario Outline: An npm version without a published attestation is reported as having no provenance
    Given an npm package version whose registry record <attestation>
    When the operator reviews the diff
    Then the version's provenance is reported as <provenance>

    Examples:
      | attestation             | provenance |
      | carries attestations    | present    |
      | carries no attestations | absent     |

  @id:package-intelligence.registry-facts.006 @rule:package-intelligence.registry-facts.publish-time @verified @source:sbom_diff_lib/registries.py#_parse_time @test:tests/test_review.py#test_a_release_younger_than_the_floor_is_flagged @questionable
  Scenario Outline: A version's publish time is its registry release time, read as UTC when no zone is given
    Given a changed <registry> package version
    When the operator reviews the diff
    Then its publish time is <publish_time>
    And a timestamp without a time zone is read as UTC
    And a version with no usable timestamp has its publish time reported as not checkable

    Examples:
      | registry | publish_time                                       |
      | npm      | the time npm records for that version              |
      | PyPI     | the earliest upload time among the version's files |

  @id:package-intelligence.registry-facts.007 @rule:package-intelligence.registry-facts.lookup-failure-not-checkable @verified @source:sbom_diff_lib/registries.py#_npm_facts @test:tests/test_review.py#test_a_registry_404_is_an_answer_not_a_crash
  Scenario Outline: When the registry cannot describe a version, every fact is not checkable with the registry's reason
    Given a changed <registry> package version that <failure>
    When the operator reviews the diff
    Then install scripts, maintainers, publish time and provenance are each reported as not checkable
    And the reason starts with "<prefix>" and says what went wrong
    And the run carries on to the next package

    Examples:
      | registry | failure                                    | prefix               |
      | npm      | the registry answers 404 for               | npm:                 |
      | PyPI     | the registry cannot be reached for         | PyPI:                |
      | npm      | is missing from the package's version list | npm has no record of |

  @id:package-intelligence.registry-facts.008 @rule:package-intelligence.registry-facts.package-page-link @verified @source:sbom_diff_lib/registries.py#package_link @test:tests/test_review.py#test_install_script_added_is_reported_with_somewhere_to_read_it
  Scenario Outline: Each reviewed npm or PyPI package links to its page for that exact version
    Given a changed <registry> package "<name>" at version "<version>"
    When the operator reviews the diff
    Then the finding links to "<link>"
    And a package from any other ecosystem gets no link

    Examples:
      | registry | name         | version | link                                               |
      | npm      | build-helper | 2.0.0   | https://www.npmjs.com/package/build-helper/v/2.0.0 |
      | PyPI     | requests     | 2.32.0  | https://pypi.org/project/requests/2.32.0/          |
