@domain:developer-tooling @area:container-image @from:sbom-diff/dockerfile
Feature: Running sbom-diff from the container image
  Lets operators run the SBOM diff anywhere Docker runs, without installing Python, by passing SBOM files to the image as if it were the command itself.

  Background:
    Given the sbom-diff container image has been built

  @id:developer-tooling.container-image.001 @rule:container.image.runs-sbom-diff-with-given-arguments @inferred @source:Dockerfile#ENTRYPOINT
  Scenario: The image behaves as the sbom-diff command with the arguments given to it
    Given the operator's current directory holds old.json and new.json SBOMs
    And that directory is mounted into the container as its working directory
    When the operator runs the image with the arguments old.json new.json
    Then sbom-diff compares old.json against new.json
    And the diff report is printed to the operator's terminal
    And the container exits with sbom-diff's own exit code

  @id:developer-tooling.container-image.002 @rule:container.image.runs-as-unprivileged-user @inferred @source:Dockerfile#USER
  Scenario: The tool inside the image runs as an unprivileged user, not root
    Given the operator mounts a directory of SBOMs into the container
    When the operator runs the image
    Then sbom-diff runs as the user "app" with uid 10001, not root
    And it can read only mounted SBOM files that uid 10001 has permission to read
    And files it writes to a mounted directory are owned by uid 10001
