@domain:package-intelligence @area:project-health @from:sbom-diff-lib/depsdev
Feature: Looking up a package's project health scorecard
  Gives reviewers the OpenSSF Scorecard of the source project behind each package version, so a fall in project health, or a move to a different repository, shows up in the review.

  Background:
    Given the operator runs a review with the scorecard signal enabled and network lookups allowed

  @id:package-intelligence.project-health.001 @rule:package-intelligence.project-health.score-of-linked-source-project @verified @source:sbom_diff_lib/depsdev.py#scorecard @test:tests/test_review.py#test_scorecard_drop_names_the_project_it_moved_to
  Scenario: A package version's Scorecard is the score of the source project deps.dev links it to
    Given deps.dev links npm package "slipping" 1.0.0 to project "github.com/old/slipping" with an OpenSSF Scorecard of 8.1
    And deps.dev links "slipping" 1.1.0 to project "github.com/new/slipping" with an OpenSSF Scorecard of 3.2
    And the new SBOM updates "slipping" from 1.0.0 to 1.1.0
    When the operator reviews the changes
    Then the finding for "slipping" reports "OpenSSF Scorecard 8.1 → 3.2"
    And the finding names "github.com/new/slipping" as the project the source moved to
    And the finding links to "https://scorecard.dev/viewer/?uri=github.com/new/slipping"

  @id:package-intelligence.project-health.002 @rule:package-intelligence.project-health.unindexed-ecosystem-not-checkable @inferred @source:sbom_diff_lib/depsdev.py#scorecard
  Scenario Outline: A package from an ecosystem deps.dev does not index gets no Scorecard and the reason is stated
    Given the new SBOM updates a package from the "<ecosystem>" ecosystem
    When the operator reviews the changes
    Then the scorecard check for that package is reported as not checkable
    And the reason reads "deps.dev does not index <ecosystem> packages"
    And deps.dev is not asked about that package

    Examples:
      | ecosystem |
      | deb       |
      | hex       |
      | pub       |

  @id:package-intelligence.project-health.003 @rule:package-intelligence.project-health.missing-score-reason @inferred @source:sbom_diff_lib/depsdev.py#scorecard
  Scenario Outline: When no Scorecard can be found, the review says why instead of guessing a score
    Given the new SBOM updates npm package "left-pad" from 1.0.0 to 1.1.0
    And for "left-pad" 1.1.0, <situation>
    When the operator reviews the changes
    Then the scorecard check for "left-pad" is reported as not checkable
    And the reason reads "<reason>"

    Examples:
      | situation                                   | reason                                           |
      | deps.dev links the version to no repository | deps.dev links this version to no source project |
      | the linked project has no Scorecard score   | the project has no Scorecard result              |
      | the deps.dev lookup fails                   | deps.dev: <the lookup failure>                   |

  @id:package-intelligence.project-health.004 @rule:package-intelligence.project-health.prefers-source-repository @inferred @source:sbom_diff_lib/depsdev.py#_source_project
  Scenario: The project used for the Scorecard is the version's source repository when deps.dev lists several
    Given deps.dev relates npm package "widget" 2.0.0 to "github.com/acme/widget-docs" first and to its source repository "github.com/acme/widget" second
    When the operator reviews the update of "widget" to 2.0.0
    Then the Scorecard reported for "widget" 2.0.0 is that of "github.com/acme/widget"
    And the scorecard link points at "github.com/acme/widget"
