@domain:package-intelligence @area:response-cache @from:sbom-diff-lib/cache
Feature: Reusing package lookups between runs
  Lets an operator re-run a review on the same pull request without asking npm, PyPI, OSV or deps.dev again, controlling where answers are kept, how long they stay fresh, and switching it off, without the saved answers ever being able to break a run.

  Background:
    Given two SBOMs whose changes include packages the review looks up online
    And the operator runs sbom-diff with --review

  @id:package-intelligence.response-cache.001 @rule:package-intelligence.response-cache.never-breaks-a-run @verified @source:sbom_diff_lib/cache.py#Cache @test:tests/test_integration.py#test_a_corrupt_entry_is_a_miss_not_a_crash @test:tests/test_integration.py#test_an_unwritable_cache_directory_still_answers
  Scenario Outline: A damaged or unusable answer store never fails the review
    Given <problem>
    When the operator runs the review with --cache-dir pointing at that location
    Then the review completes and its lookups are answered by the package sources
    And nothing is reported as an error because of the stored answers

    Examples:
      | problem                                                    |
      | a stored answer was cut off half-way by an interrupted run |
      | the --cache-dir path is an existing file, not a directory  |
      | the --cache-dir directory cannot be written to             |

  @id:package-intelligence.response-cache.002 @rule:package-intelligence.response-cache.default-location @inferred @source:sbom_diff_lib/cache.py#default_cache_dir
  Scenario Outline: Answers are kept under the user's cache directory unless another is chosen
    Given XDG_CACHE_HOME is <xdg>
    When the operator runs the review <with>
    Then the answers are kept under <location>

    Examples:
      | xdg                 | with                                  | location                      |
      | /home/ci/.xdg-cache | without --cache-dir                   | /home/ci/.xdg-cache/sbom-diff |
      | unset               | without --cache-dir                   | ~/.cache/sbom-diff            |
      | unset               | with --cache-dir /tmp/sbom-diff-cache | /tmp/sbom-diff-cache          |
