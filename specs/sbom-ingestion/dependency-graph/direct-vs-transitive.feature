@domain:sbom-ingestion @area:dependency-graph @from:sbom-diff-lib/normalize
Feature: Telling direct from transitive dependencies
  Lets operators and CI gates see which added dependencies the project chose itself and which were pulled in, using the dependency relationships the SBOM carries.

  Background:
    Given the old SBOM lists no dependencies
    And the new SBOM describes the project "my-app" and lists dependencies "a" and "b"

  @id:sbom-ingestion.dependency-graph.006 @rule:sbom.dependency-graph.direct-from-relationships @verified @source:sbom_diff_lib/normalize.py#_spdx_direct_refs @test:tests/test_sbom_diff.py#test_direct_vs_transitive_from_dependency_graph @test:tests/test_sbom_diff.py#test_spdx_direct_from_relationships_both_directions
  Scenario Outline: A dependency the project itself depends on counts as direct; the rest count as transitive
    Given the new SBOM is <format> and records that <relationship>
    And nothing records "my-app" depending on "b"
    When the operator diffs the old SBOM against the new SBOM
    Then the report counts 2 added dependencies: 1 direct and 1 transitive
    And "a" is the direct one

    Examples:
      | format    | relationship                            |
      | CycloneDX | my-app depends on a, and a depends on b |
      | SPDX      | my-app DEPENDS_ON a                     |
      | SPDX      | a is a DEPENDENCY_OF my-app             |

  @id:sbom-ingestion.dependency-graph.007 @rule:sbom.dependency-graph.no-graph-means-transitive @verified @source:sbom_diff_lib/normalize.py#_cyclonedx_direct_refs @test:tests/test_sbom_diff.py#test_no_dependency_graph_means_everything_is_transitive
  Scenario: Without dependency relationships every dependency counts as transitive
    Given the new SBOM carries no dependency relationships, or does not say which package is the project
    When the operator diffs the old SBOM against the new SBOM
    Then the report counts 2 added dependencies: 0 direct and 2 transitive
