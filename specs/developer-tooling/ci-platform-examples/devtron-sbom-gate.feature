@domain:developer-tooling @area:ci-platform-examples @from:examples/ci-platforms
Feature: Gating a Devtron deployment on the SBOM diff
  Gives Devtron operators a ready-made task that compares the image about to deploy with the one running and fails the stage when the dependency change is too risky.

  Background:
    Given the operator has added the sbom-diff example as a Shell task on a Devtron stage
    And the node running the task has Docker

  @id:developer-tooling.ci-platform-examples.001 @rule:ci-examples.devtron.required-settings-refused-when-missing @inferred @source:examples/ci-platforms/devtron-task.sh#IMAGE_REPO
  Scenario Outline: The Devtron task refuses to run without an image repository and candidate tag
    Given the task is configured without <missing_setting>
    When the Devtron stage runs the task
    Then the task stops with the message "<message>"
    And no image is scanned
    And the stage fails

    Examples:
      | missing_setting | message                    |
      | IMAGE_REPO      | set the image repository   |
      | CANDIDATE_TAG   | set the tag being deployed |

  @id:developer-tooling.ci-platform-examples.002 @rule:ci-examples.devtron.compares-candidate-against-deployed-tag @inferred @source:examples/ci-platforms/devtron-task.sh#DEPLOYED_TAG
  Scenario Outline: The candidate image is compared against the deployed image, which defaults to the production tag
    Given IMAGE_REPO is "registry.example.com/shop"
    And CANDIDATE_TAG is "v2.4.0"
    And DEPLOYED_TAG is <deployed_setting>
    When the Devtron stage runs the task
    Then the old SBOM is taken from "registry.example.com/shop:<baseline_tag>"
    And the new SBOM is taken from "registry.example.com/shop:v2.4.0"
    And both SBOMs are CycloneDX JSON

    Examples:
      | deployed_setting | baseline_tag |
      | not set          | production   |
      | "v2.3.1"         | v2.3.1       |

  @id:developer-tooling.ci-platform-examples.003 @rule:ci-examples.devtron.stage-fails-on-risky-change @inferred @source:examples/ci-platforms/devtron-task.sh#SBOM_DIFF_IMAGE
  Scenario Outline: The Devtron stage fails on a major version jump, more than ten new transitive dependencies, or a license change
    Given the candidate image differs from the deployed image by <change>
    When the Devtron stage runs the task
    Then the task exits non-zero
    And the stage <outcome>

    Examples:
      | change                                                      | outcome |
      | a dependency moving from 1.x to 2.x                         | fails   |
      | 11 newly added transitive dependencies                      | fails   |
      | an existing dependency changing license from MIT to GPL-3.0 | fails   |
