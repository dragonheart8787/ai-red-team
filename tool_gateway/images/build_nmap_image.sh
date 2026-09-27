#!/usr/bin/env bash
# Build the Nmap sandbox image without a registry.
#
# The tool image is assembled from the host's own nmap installation and
# imported directly, rather than pulled. Two reasons: environments that run
# this (including CI and the development container) may have no route to a
# registry, and a sandbox image whose contents are pinned to what the operator
# installed is easier to reason about than a tag that can move underneath you.
#
# The result is a scratch image containing nmap, ncat, curl, their shared
# libraries and nmap's data files. No shell beyond /bin/sh, no package manager,
# no network tooling the tool could use to reconfigure its own namespace.
#
# curl is here for D31's web.get adapter. It is a general HTTP client and the
# adapter is what makes it a narrow one: the command built in
# tool_gateway/adapters/http_get.py pins --request GET, --proto =http and
# --no-location, so the binary's breadth is not reachable from a capability.
set -euo pipefail

IMAGE="${IMAGE:-cyberorch/nmap:local}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: $1 not found on the host. Install nmap and ncat first." >&2
        exit 1
    }
}
need nmap
need ncat
need curl

mkdir -p "$STAGE"/{bin,usr/bin,usr/share,lib64,etc}

copy_with_libs() {
    local binary="$1"
    cp "$binary" "$STAGE/usr/bin/"
    ldd "$binary" 2>/dev/null | awk '{print $3}' | grep -E '^/' | while read -r lib; do
        mkdir -p "$STAGE$(dirname "$lib")"
        cp -n "$lib" "$STAGE$lib" 2>/dev/null || true
    done
}

copy_with_libs "$(command -v nmap)"
copy_with_libs "$(command -v ncat)"
copy_with_libs "$(command -v curl)"
copy_with_libs "$(command -v sleep)"
cp -r /usr/share/nmap "$STAGE/usr/share/"
cp /lib64/ld-linux-x86-64.so.2 "$STAGE/lib64/" 2>/dev/null || true

# Minimal /etc. No resolv.conf is written on purpose: §8.3 binds egress to an
# explicit CIDR allowlist rather than to resolved hostnames, so the sandbox has
# no business resolving names in the first place.
printf 'root:x:0:0:root:/:/bin/sh\n' > "$STAGE/etc/passwd"
printf 'hosts: files\n' > "$STAGE/etc/nsswitch.conf"

tar -C "$STAGE" -c . | docker import - "$IMAGE" >/dev/null
echo "built $IMAGE"
