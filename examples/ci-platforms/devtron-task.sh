# shellcheck shell=sh
# Devtron — SBOM diff between the running image and the one about to deploy.
#
# Not a standalone script: it is the body of a Devtron task, and Devtron
# supplies the interpreter — hence the shellcheck directive instead of a
# shebang.
#
# The neater setup is two tasks of type "Container image", which need no script
# at all because both images already have the right entrypoint:
#
#   1. anchore/syft:v1.18.1                       -> args: -q -o cyclonedx-json=/work/base.json <repo>:<deployed>
#   2. anchore/syft:v1.18.1                       -> args: -q -o cyclonedx-json=/work/head.json <repo>:<candidate>
#   3. ghcr.io/fabiocicerchia/sbom-diff:1.0.1     -> args: /work/base.json /work/head.json --fail-on major
#
# This script is the Shell-task equivalent, for a node that has Docker but no
# per-task image. Put it on Pre-Deployment to gate the release, or Post-Build
# to gate at CI time; a non-zero exit fails the stage.
set -eu

IMAGE_REPO="${IMAGE_REPO:?set the image repository}"
CANDIDATE_TAG="${CANDIDATE_TAG:?set the tag being deployed}"
DEPLOYED_TAG="${DEPLOYED_TAG:-production}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.18.1}"
SBOM_DIFF_IMAGE="${SBOM_DIFF_IMAGE:-ghcr.io/fabiocicerchia/sbom-diff:1.0.1}"
WORK="${WORK:-/tmp/sbom}"

mkdir -p "$WORK"

docker run --rm -v "$WORK:/work" "$SYFT_IMAGE" \
  -q -o cyclonedx-json=/work/base.json "$IMAGE_REPO:$DEPLOYED_TAG"
docker run --rm -v "$WORK:/work" "$SYFT_IMAGE" \
  -q -o cyclonedx-json=/work/head.json "$IMAGE_REPO:$CANDIDATE_TAG"

# Every gate is opt-in — drop the flags to report without ever failing.
docker run --rm -v "$WORK:/work" "$SBOM_DIFF_IMAGE" \
  /work/base.json /work/head.json \
  --fail-on major \
  --max-added-transitive 10 \
  --fail-on-license-change
