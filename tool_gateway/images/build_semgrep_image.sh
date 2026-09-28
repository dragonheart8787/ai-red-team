#!/usr/bin/env bash
# Build the image the Semgrep tool runs in (D43).
#
# A real Dockerfile, not a docker-import scratch tree -- see
# semgrep.Dockerfile's header for why. This script adds the same habit D35
# established: verify the image can actually do its job, cap-dropped and
# read-only, before CI (or a developer) finds out three steps later.
set -euo pipefail

IMAGE="${IMAGE:-cyberorch/semgrep:local}"
BASE="${BASE:-python:3.12-slim}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.178.0}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v docker >/dev/null 2>&1 || {
    echo "error: docker is required to build $IMAGE" >&2
    exit 1
}

docker build \
    --build-arg "BASE=$BASE" \
    --build-arg "SEMGREP_VERSION=$SEMGREP_VERSION" \
    -t "$IMAGE" -f "$here/semgrep.Dockerfile" "$here"

docker run --rm --entrypoint /bin/cat "$IMAGE" /etc/cyberorch/semgrep-manifest.txt \
    | grep -q "semgrep_version=${SEMGREP_VERSION}" || {
    echo "error: $IMAGE manifest does not record semgrep_version=${SEMGREP_VERSION}" >&2
    exit 1
}

# The check that matters: can the tool actually run, as a non-root,
# cap-dropped, read-only, network-less container -- exactly how the sandbox
# runs it (tool_gateway/sandbox.py). --version needs no source tree and no
# ruleset, so this catches an image that cannot start at all without needing
# a real scan target.
#
# --disable-version-check is not optional here, and this is exactly why
# tool_gateway/adapters/semgrep.py always includes it in the built command
# rather than making it a constraint someone could omit: confirmed
# empirically while building this image, semgrep's own version-check HTTP
# call does not fail fast under --network none -- the process hangs past
# any timeout this script or the sandbox's own kill-after-max-duration would
# reasonably use, rather than getting a quick connection-refused. Metrics
# and the version check are the only two network calls semgrep's own CLI
# makes on its own initiative, independent of --config; both are always
# disabled.
selfcheck="$(timeout 15 docker run --rm --network none \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --read-only --tmpfs /home/semgrep:rw,mode=1777 --tmpfs /tmp:rw,mode=1777 \
    "$IMAGE" --version --disable-version-check --metrics=off 2>&1)" || true
echo "--- self-check output ---"
echo "$selfcheck"
echo "$selfcheck" | grep -q "$SEMGREP_VERSION" || {
    echo "error: $IMAGE cannot run semgrep --version as a non-root, cap-dropped, read-only, network-less container" >&2
    exit 1
}

echo "built $IMAGE (semgrep ${SEMGREP_VERSION})"
