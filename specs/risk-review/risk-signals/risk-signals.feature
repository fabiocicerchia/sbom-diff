@domain:risk-review @area:risk-signals @from:sbom-diff-lib/signals
Feature: Asking risk questions of every changed package
  Gives the reviewer of a dependency update a short, explained verdict per package on the supply-chain questions that matter, so they know what to read before merging.

  Background:
    Given the reviewer runs sbom-diff with the review turned on over a base SBOM and a new SBOM

  @id:risk-review.risk-signals.001 @rule:risk.signals.hit-explains-what-to-look-at @verified @source:sbom_diff_lib/signals.py#SIGNALS @test:tests/test_review.py#test_new_package_fires_only_for_something_that_was_not_there @test:tests/test_review.py#test_major_skip_counts_the_releases_that_went_unread @test:tests/test_review.py#test_license_change_is_read_from_the_sboms @test:tests/test_review.py#test_install_script_added_is_reported_with_somewhere_to_read_it @test:tests/test_review.py#test_npm_maintainer_change_names_who_arrived @test:tests/test_review.py#test_pypi_maintainer_change_is_checkable_too @test:tests/test_review.py#test_provenance_present_before_and_absent_now @test:tests/test_review.py#test_a_release_younger_than_the_floor_is_flagged @test:tests/test_review.py#test_fanout_growth_comes_from_the_dependency_graph @test:tests/test_review.py#test_scorecard_drop_names_the_project_it_moved_to
  Scenario Outline: Each risk signal that fires says what happened in plain words
    Given the package <package> changed between the two SBOMs: <change>
    When the reviewer reviews the change
    Then the <signal> signal reports a hit for <package>
    And its detail reads "<detail>"

    Examples:
      | package       | change                                                                                             | signal          | detail                                                                                                                  |
      | brand-new     | it is not in the base SBOM at all                                                                  | new-package     | not in the base SBOM at all — nobody has reviewed it before                                                             |
      | leap          | it went from 1.2.0 to 4.0.0                                                                        | major-skip      | jumped 3 majors at once (1.x → 4.x) — 2 release(s) of breaking changes went unread                                      |
      | relicensed    | its license went from MIT to GPL-3.0                                                               | license         | MIT → GPL-3.0                                                                                                           |
      | build-helper  | the npm registry shows a postinstall script the previous version did not have                      | install-scripts | postinstall added — this runs on `install`, read it                                                                     |
      | left-pad-ish  | the npm registry lists mallory as a new maintainer                                                 | maintainers     | the people who can publish it changed: +mallory                                                                         |
      | signed-lib    | the previous version shipped with published provenance and the new one does not                    | provenance      | 1.0.0 shipped with published provenance and 1.1.0 does not — nothing now ties the published artifact to a build         |
      | fresh-release | the new version was published 3 days ago on 2024-06-10                                             | young-package   | published 3 day(s) ago (2024-06-10) — younger than the 14-day floor, so a bad release has had little time to be noticed |
      | hub           | it now pulls in 9 packages where it pulled in 2                                                    | fanout          | pulls in 9 package(s), 7 more than before                                                                               |
      | slipping      | its OpenSSF Scorecard fell from 8.1 to 3.2 and its source project moved to github.com/new/slipping | scorecard       | OpenSSF Scorecard 8.1 → 3.2, and the source project moved to github.com/new/slipping                                    |

  @id:risk-review.risk-signals.002 @rule:risk.signals.advisories-new-to-version-only @verified @source:sbom_diff_lib/signals.py#new_advisories @test:tests/test_review.py#test_advisories_new_to_the_version_are_the_ones_reported @test:tests/test_review.py#test_an_advisory_the_old_version_already_had_is_not_news
  Scenario Outline: Only advisories the previous version did not already have count as new
    Given OSV reports <new_count> advisories against the new version of a package
    And <already> of them were already reported against the previous version
    When the reviewer reviews the change
    Then the advisories signal reports <status>
    And its detail reads "<detail>"

    Examples:
      | new_count | already | status | detail                                                                        |
      | 1         | 1       | clear  | OSV reports 1 advisory(ies), all of them already on 1.0.0                     |
      | 1         | 0       | a hit  | OSV reports 1 advisory(ies) new to this version: GHSA-1234-5678-9abc (high)   |
      | 5         | 0       | a hit  | OSV reports 5 advisory(ies) new to this version: <first three ids> and 2 more |
      | 0         | 0       | clear  | OSV reports no advisories                                                     |

  @id:risk-review.risk-signals.003 @rule:risk.signals.thresholds-are-strict-and-configurable @verified @source:sbom_diff_lib/signals.py#Options @test:tests/test_review.py#test_the_young_floor_is_configurable @test:tests/test_review.py#test_fanout_below_the_threshold_is_clear @test:tests/test_review.py#test_a_release_younger_than_the_floor_is_flagged @test:tests/test_review.py#test_fanout_growth_comes_from_the_dependency_graph
  Scenario Outline: Age, fan-out and scorecard signals fire only past their threshold
    Given the <threshold> is set to <limit>
    And a changed package measures <measured>
    When the reviewer reviews the change
    Then the <signal> signal reports <status>

    Examples:
      | threshold           | limit                 | measured                                  | signal        | status |
      | young-package floor | 14 days (the default) | published 3 days ago                      | young-package | a hit  |
      | young-package floor | 14 days (the default) | published 14 days ago                     | young-package | clear  |
      | young-package floor | 1 day                 | published 3 days ago                      | young-package | clear  |
      | fan-out threshold   | 5 (the default)       | 7 more packages pulled in than before     | fanout        | a hit  |
      | fan-out threshold   | 5 (the default)       | 5 more packages pulled in than before     | fanout        | clear  |
      | fan-out threshold   | 10                    | 7 more packages pulled in than before     | fanout        | clear  |
      | fan-out threshold   | 5 (the default)       | a brand-new package pulling in 6 packages | fanout        | a hit  |
      | scorecard drop      | 1.0 (the default)     | a Scorecard fall of 4.9                   | scorecard     | a hit  |
      | scorecard drop      | 1.0 (the default)     | a Scorecard fall of exactly 1.0           | scorecard     | clear  |

  @id:risk-review.risk-signals.004 @rule:risk.signals.weights @verified @source:sbom_diff_lib/signals.py#SIGNALS @test:tests/test_review.py#test_the_ranking_rule_is_in_the_report @test:tests/test_review.py#test_score_adds_up_and_picks_the_tier
  Scenario Outline: Each signal is worth a fixed number of points
    Given the <signal> signal fires for a package
    When the reviewer reviews the change
    Then that hit adds <points> points to the package's score
    And the ranking table in the report lists <signal> as "<title>" worth <points>

    Examples:
      | signal          | title                            | points |
      | advisories      | New advisories                   | 5      |
      | install-scripts | Install scripts added or changed | 5      |
      | provenance      | Provenance or attestation lost   | 4      |
      | maintainers     | Maintainer set changed           | 3      |
      | major-skip      | More than one major skipped      | 3      |
      | new-package     | Package is new to the tree       | 2      |
      | young-package   | Release younger than the floor   | 2      |
      | license         | License changed                  | 2      |
      | scorecard       | OpenSSF Scorecard dropped        | 2      |
      | fanout          | Dependency fan-out grew          | 1      |

  @id:risk-review.risk-signals.005 @rule:risk.signals.new-package-not-applicable @inferred @source:sbom_diff_lib/signals.py#_no_previous
  Scenario Outline: Questions that compare versions do not apply to a package that is new to the tree
    Given a package is in the new SBOM but not in the base SBOM
    When the reviewer reviews the change
    Then the <signal> signal reports not applicable with "no previous version to compare against"
    And that signal adds no points

    Examples:
      | signal      |
      | major-skip  |
      | maintainers |
      | license     |
      | provenance  |
      | scorecard   |

  @id:risk-review.risk-signals.006 @rule:risk.signals.unanswerable-is-not-checkable @verified @source:sbom_diff_lib/signals.py#NOT_CHECKABLE @test:tests/test_review.py#test_install_scripts_are_not_checkable_outside_npm @test:tests/test_review.py#test_osv_is_not_queried_for_ecosystems_it_does_not_index @test:tests/test_review.py#test_a_registry_404_is_an_answer_not_a_crash @test:tests/test_review.py#test_unreadable_facts_are_never_mistaken_for_clean
  Scenario Outline: A question nobody could answer is reported as not checkable with the reason, never as clear
    Given <situation>
    When the reviewer reviews the change
    Then the <signal> signal reports not checkable
    And its detail gives the reason: <reason>
    And that signal adds no points

    Examples:
      | situation                                                        | signal          | reason                                              |
      | a Debian package changed, which the npm registry does not cover  | install-scripts | the registry's note naming deb                      |
      | a Debian package changed, which OSV does not index               | advisories      | OSV was not queried for deb                         |
      | the npm registry has no record of the new version                | maintainers     | no record of this package version                   |
      | a package went from release-2023 to release-2024                 | major-skip      | release-2023 → release-2024 is not a numbered major |
      | the new SBOM carries no dependency graph for the package         | fanout          | the new SBOM has no dependency graph for it         |
      | the base SBOM carries no dependency graph for an updated package | fanout          | the base SBOM has no dependency graph for it        |
      | deps.dev was not asked                                           | scorecard       | deps.dev was not asked                              |

  @id:risk-review.risk-signals.007 @rule:risk.signals.install-scripts-unverified-previous @inferred @source:sbom_diff_lib/signals.py#install_scripts @questionable
  Scenario: Install scripts count as added when the previous version's scripts could not be checked
    Given an npm package was updated and its new version declares a postinstall script
    And the registry could not say which scripts the previous version had
    When the reviewer reviews the change
    Then the install-scripts signal reports a hit
    And its detail reads "postinstall added — this runs on `install`, read it (the previous version could not be checked)"
