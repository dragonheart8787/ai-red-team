#!/usr/bin/env bash
# Build the image the Gitleaks tool runs in (D55) -- the registry-less scratch route.
#
# Why not a Dockerfile, like semgrep and bloodhound. Gitleaks is one static Go
# binary plus the ``git`` it shells out to for history, which is exactly the
# shape build_nmap_image.sh already handles: copy the binaries and every shared
# library ``ldd`` reports, ``docker import``. A Dockerfile would need
# ``apt-get install git`` (or a base image that has it), and the development
# container's egress policy denies the distro mirrors (the proxy answers 403/405
# for deb.debian.org and its CDN), so a Dockerfile could not be *built and run*
# here -- and a CI-only image is an image nobody verified. ``docker import`` of
# host binaries builds anywhere the host has git, including the CI runner.
#
# The gitleaks binary itself is not taken from the host: it is downloaded from
# the project's release page at the pinned version and checked against a sha256
# pinned in THIS FILE, so a moved tag or a tampered mirror fails the build
# instead of changing what runs. Override GITLEAKS_TARBALL to build offline from
# a copy of that same file (the checksum is still enforced).
#
# What is inside, and what is not: gitleaks, git, git's libraries, a passwd entry
# for uid 10001, and /etc/gitconfig. No shell, no package manager, no curl, no
# distro. The container is also given no network route at run time
# (dispatch_code_scan's NO_EGRESS_ALLOWLIST), so the binary's breadth is not
# reachable in any way that matters -- the one thing it could try on its own
# initiative, a version/telemetry call, it does not make (gitleaks has none; the
# command still passes --no-banner so nothing decorative is emitted).
#
# /etc/gitconfig marks /repo as safe: the fetched bare repository is owned by
# the control-plane user and the container runs as uid 10001, and git refuses
# ("detected dubious ownership") a repository owned by another uid. Gitleaks
# reports that as an empty scan rather than an error, which is the silent
# "found nothing" failure this whole tool exists to avoid -- see the ADR.
set -euo pipefail

IMAGE="${IMAGE:-cyberorch/gitleaks:local}"
# Keep equal to GITLEAKS_VERSION in tool_gateway/adapters/gitleaks.py; a test
# reads both and fails if they drift.
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
# sha256 of gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz, from the release's own
# gitleaks_${GITLEAKS_VERSION}_checksums.txt. Bumping the version without this
# fails the build; that is the point.
GITLEAKS_SHA256="${GITLEAKS_SHA256:-551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb}"
GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: $1 not found on the host." >&2
        exit 1
    }
}
need docker
need git
need sha256sum
need tar

tarball="${GITLEAKS_TARBALL:-}"
if [ -z "$tarball" ]; then
    need curl
    tarball="$STAGE/gitleaks.tar.gz.download"
    curl -fsSL -o "$tarball" "$GITLEAKS_URL"
fi
echo "${GITLEAKS_SHA256}  ${tarball}" | sha256sum -c - >/dev/null || {
    echo "error: $tarball does not match the pinned sha256 for gitleaks ${GITLEAKS_VERSION}" >&2
    exit 1
}

tree="$STAGE/tree"
mkdir -p "$tree"/{usr/bin,lib64,etc,tmp,home/gitleaks,etc/cyberorch}
tar -xzf "$tarball" -C "$STAGE" gitleaks
cp "$STAGE/gitleaks" "$tree/usr/bin/gitleaks"
chmod 0755 "$tree/usr/bin/gitleaks"

copy_with_libs() {
    local binary="$1"
    cp "$binary" "$tree/usr/bin/"
    ldd "$binary" 2>/dev/null | awk '{print $3}' | grep -E '^/' | while read -r lib; do
        mkdir -p "$tree$(dirname "$lib")"
        cp -n "$lib" "$tree$lib" 2>/dev/null || true
    done || true
}
copy_with_libs "$(command -v git)"
cp /lib64/ld-linux-x86-64.so.2 "$tree/lib64/" 2>/dev/null || true

# uid 10001 owns nothing (same reasoning as semgrep.Dockerfile). HOME is a tmpfs
# at run time (the adapter's TMPFS), not something baked in.
printf 'root:x:0:0:root:/:/bin/sh\ngitleaks:x:10001:10001:gitleaks:/home/gitleaks:/bin/false\n' \
    > "$tree/etc/passwd"
printf 'gitleaks:x:10001:\n' > "$tree/etc/group"
printf 'hosts: files\n' > "$tree/etc/nsswitch.conf"
printf '[safe]\n\tdirectory = /repo\n' > "$tree/etc/gitconfig"

{ echo "gitleaks_version=${GITLEAKS_VERSION}"
  echo "gitleaks_sha256=${GITLEAKS_SHA256}"
  echo "git_version=$(git --version)"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$tree/etc/cyberorch/gitleaks-manifest.txt"

# No ENTRYPOINT: like the nmap image, the command the adapter builds carries the
# binary itself. (semgrep's image sets an ENTRYPOINT and its command repeats the
# binary as well, which works only because semgrep ignores an extra path it
# cannot classify. Gitleaks would take a repeated "gitleaks" as a subcommand.)
tar -C "$tree" -c . | docker import \
    --change 'USER 10001:10001' \
    --change 'ENV HOME=/home/gitleaks' \
    - "$IMAGE" >/dev/null

# The binary inside the image reports the version the pin says (a manifest file
# would need a `cat` the image deliberately lacks).
docker run --rm "$IMAGE" /usr/bin/gitleaks version 2>&1 | grep -q "^${GITLEAKS_VERSION}$" || {
    echo "error: $IMAGE does not report gitleaks ${GITLEAKS_VERSION}" >&2
    exit 1
}

# The check that matters: can the tool run, and can it READ A REPOSITORY, exactly
# as the sandbox runs it (non-root, cap-dropped, read-only root, no-new-privileges,
# no network) -- not merely print its version. `gitleaks version` passing while
# `gitleaks git` scans nothing (git missing, dubious ownership) is the failure this
# tool cannot afford, so the self-check builds a repository owned by ANOTHER uid,
# with a known secret in a commit that is no longer in the tree, and requires the
# finding. Output is printed before it is gated on (D36).
check="$STAGE/check"
mkdir -p "$check/work"
git -C "$check/work" init -q -b main
git -C "$check/work" config user.email selfcheck@example.invalid
git -C "$check/work" config user.name selfcheck
# Assembled from two pieces so this script is not itself a finding for a scanner.
printf 'token = %s%s\n' 'ghp_' 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6' > "$check/work/c.env"
git -C "$check/work" add c.env
git -C "$check/work" commit -q -m one
git -C "$check/work" rm -q c.env
git -C "$check/work" commit -q -m two
git clone -q --bare "file://$check/work" "$check/repo.git"
printf '[extend]\nuseDefault = true\n' > "$check/config.toml"
chmod -R a+rX "$check"

selfcheck="$(timeout 60 docker run --rm --network none \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --read-only --tmpfs /home/gitleaks:rw,mode=1777 --tmpfs /tmp:rw,mode=1777 \
    -v "$check/repo.git:/repo:ro" -v "$check/config.toml:/rules/gitleaks.toml:ro" \
    "$IMAGE" /usr/bin/gitleaks git /repo --config /rules/gitleaks.toml \
    --redact=100 --exit-code 0 --no-banner --no-color -f json -r - 2>&1)" || true
echo "--- self-check output ---"
echo "$selfcheck"
echo "$selfcheck" | grep -q '"RuleID": "github-pat"' || {
    echo "error: $IMAGE cannot find a history-only secret as a non-root, cap-dropped, read-only, network-less container" >&2
    exit 1
}

echo "built $IMAGE (gitleaks ${GITLEAKS_VERSION})"
