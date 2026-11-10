@domain:sbom-ingestion @area:dependency-graph @from:sbom-diff-lib/graph
Feature: Counting what a dependency pulls in
  Reviewers deciding whether an upgraded or new dependency is worth reading need to know how many packages it drags in behind it, as recorded in each SBOM's own dependency graph.

  Background:
    Given the operator runs a review of an old and a new SBOM with the fan-out signal enabled

  @id:sbom-ingestion.dependency-graph.001 @rule:sbom.dependency-graph.fan-out-counts-everything-reached @verified @source:sbom_diff_lib/graph.py#fanout @test:tests/test_review.py#test_fanout_growth_comes_from_the_dependency_graph
  Scenario Outline: A dependency's fan-out counts every distinct package it reaches, directly or through others
    Given the old SBOM's dependency graph shows "hub" 1.0.0 depending on 2 packages
    And the new SBOM's dependency graph shows "hub" 1.1.0 depending on <direct> packages, which in turn depend on <indirect> more distinct packages
    And the fan-out threshold is 5
    When the operator reviews the two SBOMs
    Then the fan-out signal for "hub" reports "<detail>"

    Examples:
      | direct | indirect | detail                                    |
      | 9      | 0        | pulls in 9 package(s), 7 more than before |
      | 3      | 5        | pulls in 8 package(s), 6 more than before |

  @id:sbom-ingestion.dependency-graph.002 @rule:sbom.dependency-graph.cycles-and-self-counted-once @inferred @source:sbom_diff_lib/graph.py#fanout
  Scenario: A dependency cycle is counted once and a package never counts itself
    Given the new SBOM records "alpha" depending on "beta", "beta" depending on "gamma", and "gamma" depending back on "alpha" and on "beta"
    When the operator reviews the two SBOMs
    Then the review completes
    And the fan-out signal for "alpha" reports it pulls in 2 package(s)

  @id:sbom-ingestion.dependency-graph.003 @rule:sbom.dependency-graph.spdx-relationships-either-direction @inferred @source:sbom_diff_lib/graph.py#_spdx_edge
  Scenario Outline: SPDX dependency relationships count whichever direction they are written in
    Given the new SPDX SBOM records that "web" has "lib" as a dependency using a <relationship> relationship
    When the operator reviews the two SBOMs
    Then the fan-out signal for "web" reports it pulls in 1 package(s)

    Examples:
      | relationship              |
      | "web" DEPENDS_ON "lib"    |
      | "lib" DEPENDENCY_OF "web" |

  @id:sbom-ingestion.dependency-graph.005 @rule:sbom.dependency-graph.package-absent-from-graph-not-checkable @inferred @source:sbom_diff_lib/graph.py#fanout @questionable
  Scenario Outline: A package the graph lists no dependencies for is reported as not checkable
    Given the new SBOM carries a dependency graph
    And that graph records nothing that "leftpad" depends on, as <how>
    When the operator reviews the two SBOMs
    Then the fan-out signal for "leftpad" is not checkable
    And its detail reads "the new SBOM has no dependency graph for it"

    Examples:
      | how                                                          |
      | an SPDX package with no DEPENDS_ON relationship of its own   |
      | a CycloneDX component with no entry in the dependencies list |
