#!/bin/sh
# Devtron — SBOM diff between the running image and the one about to deploy.
#
# Paste into a task of type "Execute custom script" / Shell on the
# Pre-Deployment stage (App -> Workflow -> Pre-Deployment stage -> Add task),
# or on Post-Build if you want it at CI time instead. A non-zero exit fails the
# stage, so a release that pulls in a major bump or a denied license never
# deploys.
#
# Declare IMAGE_REPO / CANDIDATE_TAG / DEPLOYED_TAG as Input Variables on the
# task — Devtron already knows the image it built, so wire the candidate tag to
# it rather than restating it here.
set -eu

IMAGE_REPO="${IMAGE_REPO:?set the image repository}"
CANDIDATE_TAG="${CANDIDATE_TAG:?set the tag being deployed}"
DEPLOYED_TAG="${DEPLOYED_TAG:-production}"
SYFT_VERSION="${SYFT_VERSION:-v1.18.1}"

pip install --no-cache-dir --quiet "git+https://github.com/fabiocicerchia/sbom-diff@v1.0.1"
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b /usr/local/bin "$SYFT_VERSION"

syft -q -o cyclonedx-json "registry:$IMAGE_REPO:$DEPLOYED_TAG" > /tmp/base.json
syft -q -o cyclonedx-json "registry:$IMAGE_REPO:$CANDIDATE_TAG" > /tmp/head.json

# Every gate is opt-in — drop the flags to report without ever failing.
sbom-diff /tmp/base.json /tmp/head.json \
  --fail-on major \
  --max-added-transitive 10 \
  --fail-on-license-change
