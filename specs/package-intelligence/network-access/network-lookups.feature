@domain:package-intelligence @area:network-access @from:sbom-diff-lib/fetch
Feature: Looking up packages over the network politely
  Operators running a review in CI need the lookups to npm, PyPI, OSV and deps.dev to stay within a bounded, polite load, respect offline mode, and turn every network problem into a stated reason instead of a crash.

  Background:
    Given the operator runs sbom-diff with --review on two SBOMs that differ

  @id:package-intelligence.network-access.001 @rule:package-intelligence.network-access.request-budget-per-run @verified @source:sbom_diff_lib/fetch.py#Fetcher @test:tests/test_review.py#test_the_request_budget_stops_the_run_and_says_so
  Scenario Outline: A run stops asking once its request budget is spent, and says so
    Given the run allows at most <limit> requests to package sources
    And the review needs more lookups than that
    When the operator runs the review
    Then the lookups past the budget are not sent
    And each such signal is shown as not checkable with the source's name followed by the reason "request budget of <limit> spent"
    And the review section warns that the request budget was spent before every component was checked and suggests raising --max-requests

    Examples:
      | limit |
      | 300   |
      | 1     |

  @id:package-intelligence.network-access.002 @rule:package-intelligence.network-access.unlimited-budget @inferred @source:sbom_diff_lib/fetch.py#Fetcher
  Scenario: A request budget of zero means no limit
    Given the operator passes --max-requests 0
    And the review needs 500 lookups
    When the operator runs the review
    Then every lookup is sent
    And no signal is marked not checkable because the request budget was spent
    And the review section shows no budget warning

  @id:package-intelligence.network-access.003 @rule:package-intelligence.network-access.offline-sends-nothing @verified @source:sbom_diff_lib/fetch.py#Fetcher @test:tests/test_review.py#test_offline_never_reaches_the_transport @test:tests/test_integration.py#test_a_response_is_written_to_disk_and_answers_a_later_offline_run
  Scenario: Offline mode sends nothing and skips every signal that needs a package source
    Given the operator runs with --offline
    And an earlier run saved the npm answer for left-pad
    When the operator runs the review
    Then no request leaves the machine
    And every signal that needs npm, PyPI, OSV or deps.dev is skipped with the reason "offline: needs" and its source
    And the saved left-pad answer is not used

  @id:package-intelligence.network-access.004 @rule:package-intelligence.network-access.failures-stated-not-crashed @verified @source:sbom_diff_lib/fetch.py#RawResponse @test:tests/test_review.py#test_a_registry_404_is_an_answer_not_a_crash
  Scenario Outline: A lookup that brings back no data says why, and the run carries on
    Given a package source answers a lookup with <answer>
    When the operator runs the review
    Then the run does not crash
    And the affected signal is shown as not checkable with the source's name followed by the reason "<reason>"

    Examples:
      | answer                                           | reason                             |
      | 404 Not Found                                    | no record of this package version  |
      | 429 Too Many Requests, still after the retries   | rate limited                       |
      | a connection failure or a 10-second timeout      | the request did not complete       |
      | 503 Service Unavailable, still after the retries | the source answered 503            |
      | 200 with a body that is not a JSON object        | the response was not a JSON object |

  @id:package-intelligence.network-access.005 @rule:package-intelligence.network-access.honour-retry-after @verified @source:sbom_diff_lib/fetch.py#Fetcher @test:tests/test_review.py#test_a_rate_limited_source_is_retried_after_the_delay_it_asked_for
  Scenario Outline: A source that asks for a short pause is asked again; one that asks for a long pause is given up on
    Given a package source rate-limits a lookup and asks to retry after <wait> seconds, then answers normally
    When the operator runs the review
    Then the lookup outcome is <outcome>

    Examples:
      | wait | outcome                                      |
      | 1.5  | answered after waiting 1.5 seconds           |
      | 300  | not checkable with the reason "rate limited" |
