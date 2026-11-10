@domain:diff-report @area:summary-headline @from:sbom-diff-lib/render
Feature: Summarising a dependency update in one line
  Gives reviewers and CI logs a one-line count of what changed before the detail.

  Background:
    Given an old SBOM and a new SBOM of the same application

  @id:diff-report.summary-headline.001 @rule:diff-report.summary.headline-counts @verified @source:sbom_diff_lib/render.py#summarize @test:tests/test_render.py#test_explain_renders_every_section_most_alarming_first @test:tests/test_render.py#test_explain_with_no_changes_is_a_headline_and_an_empty_body
  Scenario Outline: The headline counts additions, removals and updates, and mentions downgrades, renames and transitive splits only when present
    Given between the SBOMs there are <added> additions (<transitive> transitive), <removed> removals, <updated> updates (<major> major), <downgraded> downgrades and <renamed> renames
    When the reviewer compares the two SBOMs
    Then the report headline reads "<headline>"

    Examples:
      | added | transitive | removed | updated | major | downgraded | renamed | headline                                                                                                          |
      | 0     | 0          | 0       | 0       | 0     | 0          | 0       | 0 dependency change(s): 0 added, 0 removed, 0 updated (0 major)                                                   |
      | 2     | 1          | 1       | 2       | 2     | 1          | 1       | 5 dependency change(s): 2 added (1 direct, 1 transitive), 1 removed, 2 updated (2 major), 1 downgraded, 1 renamed |

  @id:diff-report.summary-headline.002 @rule:diff-report.summary.total-excludes-renames-and-vulns @inferred @source:sbom_diff_lib/render.py#summarize @questionable
  Scenario: The headline total leaves out renames and vulnerability changes
    Given the only differences between the SBOMs are one package rename at the same version and one newly reported vulnerability
    When the reviewer compares the two SBOMs
    Then the headline reads "0 dependency change(s): 0 added, 0 removed, 0 updated (0 major), 1 renamed"
    And the headline does not mention the vulnerability
