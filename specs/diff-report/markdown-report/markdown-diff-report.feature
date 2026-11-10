@domain:diff-report @area:markdown-report @from:sbom-diff-lib/render
Feature: Reading the dependency change report
  Lets a reviewer of a dependency update see every kind of change in one markdown report, with the most alarming changes first, so risky changes are not missed.

  Background:
    Given an old SBOM and a new SBOM of the same application

  @id:diff-report.markdown-report.001 @rule:diff-report.markdown.sections-most-alarming-first @verified @source:sbom_diff_lib/render.py#explain @test:tests/test_render.py#test_explain_renders_every_section_most_alarming_first @test:tests/test_render.py#test_explain_buckets_smaller_jumps_below_major_in_decreasing_size @test:tests/test_e2e.py#test_basic_example_prints_the_report_and_passes
  Scenario: Report sections run from most to least alarming
    Given the two SBOMs differ by a rename, a major jump, a minor, a patch and a non-semver version change, an addition, a removal, a license change and a vulnerability change
    When the reviewer compares the two SBOMs
    Then the sections appear in this order: "Renamed", "⚠ Major version jumps (review breaking changes)", "Minor updates", "Patch updates", "Other version changes", "New dependencies", "Removed dependencies", "⚠ License changes", "Vulnerability changes (VEX)"
    And major-jump package names are bold and calmer buckets are plain
    And within each section packages are listed alphabetically by name

  @id:diff-report.markdown-report.003 @rule:diff-report.markdown.transitive-additions-marked @verified @source:sbom_diff_lib/render.py#_render_added @test:tests/test_render.py#test_explain_renders_every_section_most_alarming_first @questionable
  Scenario: New transitive dependencies are marked and counted in the section heading
    Given the new SBOM adds direct dependency "requests 2.31.0" and transitive dependency "idna 3.6"
    When the reviewer compares the two SBOMs
    Then the section heading reads "New dependencies (2, 1 transitive)"
    And "idna 3.6" is marked "_(transitive)_"
    And "requests 2.31.0" has no marker

  @id:diff-report.markdown-report.004 @rule:diff-report.markdown.license-change-old-to-new @verified @source:sbom_diff_lib/render.py#_render_license_changes @test:tests/test_render.py#test_explain_renders_every_section_most_alarming_first
  Scenario Outline: A license change shows the old and new licenses, or "(none)" when a side declares none
    Given package "<package>" declares <old> in the old SBOM and <new> in the new SBOM
    When the reviewer compares the two SBOMs
    Then the license changes section lists "**<package>**: <shown_old> → <shown_new>"

    Examples:
      | package | old                | new     | shown_old       | shown_new |
      | openssl | Apache-2.0         | GPL-3.0 | Apache-2.0      | GPL-3.0   |
      | libfoo  | no license         | MIT     | (none)          | MIT       |
      | libbar  | MIT and Apache-2.0 | MIT     | Apache-2.0, MIT | MIT       |

  @id:diff-report.markdown-report.005 @rule:diff-report.markdown.vulnerability-delta @verified @source:sbom_diff_lib/render.py#_render_vulnerabilities @test:tests/test_render.py#test_explain_renders_every_section_most_alarming_first
  Scenario: Vulnerability changes list what was newly reported, what is no longer reported and what changed state
    Given the new SBOM newly reports CVE-1 as affected with high severity
    And it no longer reports CVE-2, which was exploitable
    And CVE-3 moved from in_triage to not_affected
    When the reviewer compares the two SBOMs
    Then the "Vulnerability changes (VEX)" section lists "⚠ **CVE-1** newly reported (affected, high)"
    And then "✅ **CVE-2** no longer reported (was: exploitable)"
    And then "🔄 **CVE-3**: in_triage → not_affected"

  @id:diff-report.markdown-report.007 @rule:diff-report.markdown.no-change-no-sections @verified @source:sbom_diff_lib/render.py#explain @test:tests/test_render.py#test_explain_with_no_changes_is_a_headline_and_an_empty_body
  Scenario: Identical SBOMs give a headline and no sections
    Given the old and new SBOMs list the same components, licenses and vulnerabilities
    When the reviewer compares the two SBOMs
    Then the headline reads "0 dependency change(s): 0 added, 0 removed, 0 updated (0 major)"
    And no section follows the headline
