#!/usr/bin/env bash
# Build the image ad.collect (bloodhound-python) runs in (D42/D45).
#
# This image never existed before D45 -- D42 shipped ad_collector.py
# "buildable and testable against fixture output, no live/production path
# until the Vault lands" (its own module docstring), and even after D44's
# Vault landed, nothing had ever built the container bloodhound-python
# would actually run in. This script closes that gap the same way D43's
# build_semgrep_image.sh closes the equivalent one for Semgrep.
set -euo pipefail

IMAGE="${IMAGE:-cyberorch/bloodhound:local}"
BASE="${BASE:-python:3.12-slim}"
BLOODHOUND_VERSION="${BLOODHOUND_VERSION:-1.9.0}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v docker >/dev/null 2>&1 || {
    echo "error: docker is required to build $IMAGE" >&2
    exit 1
}

docker build \
    --build-arg "BASE=$BASE" \
    --build-arg "BLOODHOUND_VERSION=$BLOODHOUND_VERSION" \
    -t "$IMAGE" -f "$here/bloodhound.Dockerfile" "$here"

docker run --rm --entrypoint /bin/cat "$IMAGE" /etc/cyberorch/bloodhound-manifest.txt \
    | grep -q "bloodhound_version=${BLOODHOUND_VERSION}" || {
    echo "error: $IMAGE manifest does not record bloodhound_version=${BLOODHOUND_VERSION}" >&2
    exit 1
}

# The check that matters: can the tool actually run, as a non-root,
# cap-dropped, read-only container -- exactly how the sandbox runs it
# (tool_gateway/sandbox.py). --help needs no network and no real domain, so
# this catches an image that cannot start at all without needing a live LDAP
# target. Unlike Semgrep, ad.collect genuinely needs network egress at run
# time (an LDAP bind is the entire point) -- --network none here is only
# because --help itself makes no network call, not a claim about the tool's
# real requirements.
selfcheck="$(timeout 15 docker run --rm --network none \
    --cap-drop ALL --security-opt no-new-privileges:true --read-only \
    "$IMAGE" bloodhound-python --help 2>&1)" || true
echo "--- self-check output ---"
echo "$selfcheck"
echo "$selfcheck" | grep -qi "collectionmethod" || {
    echo "error: $IMAGE cannot run bloodhound-python --help as a non-root, cap-dropped, read-only container" >&2
    exit 1
}

echo "built $IMAGE (bloodhound-python ${BLOODHOUND_VERSION})"
