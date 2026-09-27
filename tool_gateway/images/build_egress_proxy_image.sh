#!/usr/bin/env bash
# Build the image the policy-aware egress proxy runs in (§8.3, D34).
#
# Same staging technique as the web target, through the same shared library, so
# the two cannot drift. What differs is what goes in beside the interpreter:
# one file, tool_gateway/egress_proxy.py, copied out of the repository rather
# than reimplemented in a heredoc. That matters more than it sounds -- a copy
# of the proxy living in a build script would be a second implementation of the
# authorization check, and the tests would be exercising the wrong one.
#
# The image carries no credential and no database client. The in-container
# proxy checks host, port, method and the within-run request ceiling; the
# capability's persistent budget is spent by the control plane before the run
# starts. Keeping credentials off the sandbox network is worth more than having
# one shared counter.
set -euo pipefail

IMAGE="${IMAGE:-cyberorch/egress-proxy:local}"
PY="${PY:-$(command -v python3)}"
PYVER="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
PYLIB="$("$PY" -c 'import sysconfig;print(sysconfig.get_paths()["stdlib"])')"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

[ -x "$PY" ] || { echo "error: python3 not found on the host" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=tool_gateway/images/_python_scratch.sh
. "$here/_python_scratch.sh"

source_module="$repo/tool_gateway/egress_proxy.py"
[ -f "$source_module" ] || {
    echo "error: $source_module is missing" >&2
    exit 1
}

mkdir -p "$STAGE"/{usr/bin,usr/lib,lib64,etc,opt}
scratch_stage_python
scratch_verify_stage

# The module is copied, not rewritten. Its imports are stdlib only -- checked
# here rather than assumed, because a third-party import would fail at proxy
# start with the container's traffic already flowing at it.
cp "$source_module" "$STAGE/opt/egress_proxy.py"
"$PY" - "$source_module" <<'PYEOF'
import ast
import sys
from pathlib import Path

STDLIB = set(sys.stdlib_module_names)
tree = ast.parse(Path(sys.argv[1]).read_text())
foreign = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        foreign |= {a.name.split(".")[0] for a in node.names}
    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        foreign.add(node.module.split(".")[0])
foreign -= STDLIB | {"__future__"}
if foreign:
    print(f"error: egress_proxy.py imports non-stdlib modules: {sorted(foreign)}",
          file=sys.stderr)
    print("The proxy image stages the stdlib only; a third-party import would "
          "fail at proxy start with traffic already arriving.", file=sys.stderr)
    raise SystemExit(1)
PYEOF

tar -C "$STAGE" -c . \
  | docker import \
      --change 'WORKDIR /opt' \
      --change 'ENTRYPOINT ["/usr/bin/python3", "-u", "/opt/egress_proxy.py"]' \
      - "$IMAGE" >/dev/null

# Asked of the image itself, with no network. `http.server` is what the proxy
# listens with and `urllib.request` is what it forwards with; an image that can
# do one and not the other would accept a connection and then fail the request.
scratch_verify_image "$IMAGE" http.server urllib.request

# The proxy module itself has to import, not just its dependencies. Run with
# --help so the check exercises the real entry point and still exits.
docker run --rm --network none --entrypoint /usr/bin/python3 "$IMAGE" \
    /opt/egress_proxy.py --help >/dev/null || {
    echo "error: $IMAGE cannot start the proxy module" >&2
    exit 1
}

# And again the way the sandbox actually runs it: as a non-root uid, every
# capability dropped, read-only root (D35). The check above runs as root with
# default capabilities, which can read anything; the proxy never runs like
# that. 65534 is deliberately not the build user, so it passes only if the
# staged tree is readable by "other" -- whatever uid the control plane turns
# out to be.
docker run --rm --network none --user 65534:65534 --cap-drop ALL \
    --security-opt no-new-privileges:true --read-only \
    --entrypoint /usr/bin/python3 "$IMAGE" /opt/egress_proxy.py --help >/dev/null || {
    echo "error: $IMAGE cannot start the proxy module as a non-root, cap-dropped uid" >&2
    exit 1
}

echo "built $IMAGE (python $PYVER)"
