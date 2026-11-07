@domain:risk-review @area:review-report @from:sbom-diff-lib/render-review
Feature: Reading the ranked review
  Gives a pull-request reviewer a ranked, auditable list of the added and updated packages worth looking at, in markdown for people and JSON for tools.

  Background:
    Given the operator diffs two SBOMs with the review turned on

  @id:risk-review.review-report.001 @rule:risk-review.review-report.grouped-by-tier @verified @source:sbom_diff_lib/render_review.py#render_review @test:tests/test_review.py#test_offline_scores_from_the_sboms_and_says_what_it_skipped
  Scenario: Scored components are grouped under their tier, loudest first, under a counting headline
    Given the review scored 3 components: 1 in "Read this", 1 in "Glance" and 1 in "Routine"
    When the operator reads the report
    Then a section "What to review (3 scored)" follows the diff
    And its headline reads "Added and updated components, scored from <n> signal(s): 1 read this, 1 glance, 1 routine."
    And the tiers appear in the order "⚠ Read this", "Glance", "Routine", each with its count
    And a tier with no components is left out

  @id:risk-review.review-report.002 @rule:risk-review.review-report.detail-by-tier @inferred @source:sbom_diff_lib/render_review.py#_render_finding
  Scenario Outline: Components worth a look show what fired and where to look; routine ones get one line
    Given <package> moved <movement> and landed in the "<tier>" tier
    And the signals that fired on it were <fired>
    When the operator reads the review section
    Then its entry reads <entry>

    Examples:
      | package      | movement              | tier      | fired                             | entry                                                                                                            |
      | build-helper | from nothing to 2.0.0 | Read this | install-scripts, with an npm link | bold "build-helper 2.0.0 (new) · npm · score 5" then a sub-line with the signal's detail and " — [look](<link>)" |
      | left-pad     | 1.0.0 → 3.0.0         | Glance    | major-skip                        | bold "left-pad 1.0.0 → 3.0.0 · score 3" then a sub-line with the signal's detail                                 |
      | tiny-util    | 1.2.0 → 1.2.1         | Routine   | none                              | the single line "tiny-util 1.2.0 → 1.2.1 · score 0 · no signal fired"                                            |

  @id:risk-review.review-report.003 @rule:risk-review.review-report.unchecked-signals-shown @inferred @source:sbom_diff_lib/render_review.py#_render_finding @questionable
  Scenario: Signals that could not be checked are named under the component, not reported clean
    Given a component in the "Read this" or "Glance" tier could not be checked by the advisories signal because the advisory source did not answer
    When the operator reads its entry
    Then a line "not checkable: `advisories` (<reason>)" appears under it

  @id:risk-review.review-report.004 @rule:risk-review.review-report.ranking-rule-published @verified @source:sbom_diff_lib/render_review.py#_rule_block @test:tests/test_review.py#test_the_ranking_rule_is_in_the_report @test:tests/test_review.py#test_offline_scores_from_the_sboms_and_says_what_it_skipped @test:tests/test_review.py#test_a_disabled_signal_does_not_score
  Scenario Outline: The report publishes how it ranked and what that cost
    Given the review ran <mode>
    When the operator opens "How this was ranked"
    Then it shows the tier table, every signal with its points and source, and the signals not run with their reason
    And it suggests "--disable-signal maintainers" to drop a signal
    And it ends with "<cost>"

    Examples:
      | mode                                                | cost                                              |
      | offline                                             | Nothing was fetched: this run was offline.        |
      | online, making 4 lookups with 2 answered from cache | 4 request(s) made, 2 answer(s) served from cache. |

  @id:risk-review.review-report.005 @rule:risk-review.review-report.budget-spent-warning @inferred @source:sbom_diff_lib/render_review.py#render_review
  Scenario: A run that ran out of its request budget warns that later signals are unchecked, not clean
    Given the request budget was spent before every component was checked
    When the operator reads the review section
    Then a warning under the headline says the signals below are marked not checkable, not clean
    And it advises raising "--max-requests" or re-running with a warm cache

  @id:risk-review.review-report.006 @rule:risk-review.review-report.silent-when-nothing-scored @inferred @source:sbom_diff_lib/render_review.py#render_review @questionable
  Scenario: When no component was scored the report has no review section at all
    Given the diff has no added or updated components to score
    When the operator reads the report
    Then there is no "What to review" section
    And there is no "How this was ranked" block

  @id:risk-review.review-report.007 @rule:risk-review.review-report.json-review-contract @verified @source:sbom_diff_lib/render_review.py#review_payload @test:tests/test_review.py#test_json_carries_the_findings_and_the_rule
  Scenario: The JSON output carries the review as a stable object
    Given the operator asked for JSON output
    When the operator reads the "review" object
    Then it has keys offline, thresholds, tiers, signals, skipped_signals, findings, requests, cache_hits and budget_spent
    And each tier has id, label, min_score and count
    And each finding has key, name, ecosystem, old_version, new_version, purl, link, score, tier and signals
    And each finding's signals list every signal asked, with signal, status, detail and link
