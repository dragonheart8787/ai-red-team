#!/usr/bin/env bash
# Build the image the Playwright browser tool runs in (§8.3, D36).
#
# Unlike the other three images this one is a real Dockerfile, not a
# docker-import scratch tree -- see browser.Dockerfile's header for why Chromium
# forces that choice. What this script adds around `docker build` is the part
# the other builds also have: a verification that runs the tool the way the
# sandbox will run it, so a broken image fails here and not in CI three steps
# later. D35 added that habit (run the check as a non-root, cap-dropped,
# read-only container); this is the deliverable that needs it most, because the
# attack surface it introduces is the largest so far.
set -euo pipefail

IMAGE="${IMAGE:-cyberorch/browser:local}"
BASE="${BASE:-ubuntu:24.04}"
PLAYWRIGHT_VERSION="${PLAYWRIGHT_VERSION:-1.56.0}"
CHROMIUM_REVISION="${CHROMIUM_REVISION:-1194}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

command -v docker >/dev/null 2>&1 || {
    echo "error: docker is required to build $IMAGE" >&2
    exit 1
}

# The build context is a temp dir holding only the Dockerfile and the runner
# copied out of the repository -- not the whole repo, and not a heredoc copy of
# the runner. The runner that runs is the one under review.
ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
cp "$here/browser.Dockerfile" "$ctx/Dockerfile"
cp "$repo/tool_gateway/browser_runner.py" "$ctx/browser_runner.py"

docker build \
    --build-arg "BASE=$BASE" \
    --build-arg "PLAYWRIGHT_VERSION=$PLAYWRIGHT_VERSION" \
    --build-arg "CHROMIUM_REVISION=$CHROMIUM_REVISION" \
    -t "$IMAGE" "$ctx"

# The manifest has to exist and name the browser revision we pinned; an image
# that installed a different browser than we recorded is not the image we think
# we shipped.
docker run --rm --entrypoint /bin/cat "$IMAGE" /etc/cyberorch/browser-manifest.txt \
    | grep -q "chromium_revision=${CHROMIUM_REVISION}" || {
    echo "error: $IMAGE manifest does not record chromium_revision=${CHROMIUM_REVISION}" >&2
    exit 1
}

# The check the run-time-only version could not make: launch the browser the
# way the sandbox will -- the image's own non-root user, every capability
# dropped, read-only root with tmpfs for the paths Chromium must write. If the
# browser cannot start under exactly these restrictions, the tool would fail at
# dispatch with traffic already arriving; catch it here.
#
# The writable set is a whole tmpfs HOME plus /tmp, not just ~/.cache: a fresh
# Chromium writes a profile, config, crash dumps and font caches across several
# dirs under $HOME, and Playwright's driver writes a temp profile under /tmp.
# The rest of the root stays read-only, which is the point. These same mounts
# are what the sandbox gives the browser at run time (stage 3).
#
# The output is captured and printed whatever happens, then the gate runs on
# it: a browser that failed to launch prints *why* (the D31/D35 lesson -- a
# check that hides the container's own error reports the wrong thing).
selfcheck="$(docker run --rm --network none \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --read-only --tmpfs /tmp:rw,mode=1777 --tmpfs /home/browser:rw,mode=1777 \
    "$IMAGE" --self-check 2>&1)" || true
echo "--- self-check output ---"
echo "$selfcheck"
echo "$selfcheck" | grep -q '"self_check": true' || {
    echo "error: $IMAGE cannot launch the browser as a non-root, cap-dropped, read-only container" >&2
    exit 1
}

echo "built $IMAGE (playwright ${PLAYWRIGHT_VERSION}, chromium ${CHROMIUM_REVISION})"
