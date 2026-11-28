#!/usr/bin/env bash
# S8's laboratory (plan item 164): one target container on the network the control plane derives
# from the cidr scope object 10.82.0.0/24 (numbered change D69-NC-2).
#
#   bash scripts/shadow_lab/start_lab.sh
#
# Pulls nothing: an image that is not on this machine ends the script with a non-zero exit. The
# network is made by ``DockerSandbox.ensure_network(["10.82.0.0/24"])``, as
# ``scripts/live_run/start_d40_hosts.sh`` makes its own, so it is the same internal network a
# dispatch under that scope object joins. The target is ``python:3.12-slim`` at the fixed address
# 10.82.0.10, running Python's minimal HTTP server on 8080 over an empty directory (no banner of its
# own beyond the server's); the lure 10.82.0.71 has no container. Everything this script starts
# carries the label cyberorch.shadow_lab=s8, which ``stop_lab.sh`` removes by.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$REPO/.venv/bin/python}"
SCOPE="10.82.0.0/24"
TARGET_IP="10.82.0.10"
LABEL="cyberorch.shadow_lab=s8"
NAME="shadow-lab-target"
TARGET_IMAGE="python:3.12-slim"
SCANNER_IMAGE="cyberorch/nmap:local"

for image in "$SCANNER_IMAGE" "$TARGET_IMAGE"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "start_lab: the image $image is not on this machine; nothing is pulled" >&2
        exit 3
    fi
done

NETWORK="$(cd "$REPO" && PYTHONPATH="$REPO" "$PYTHON" - "$SCOPE" <<'PY'
import sys
from tool_gateway.sandbox import DockerSandbox
sandbox = DockerSandbox()
sandbox.ensure_network([sys.argv[1]])
print(sandbox.network_name([sys.argv[1]]))
PY
)"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --pull never --name "$NAME" --network "$NETWORK" --ip "$TARGET_IP" \
    --label "$LABEL" "$TARGET_IMAGE" \
    python -m http.server 8080 --bind 0.0.0.0 --directory /srv >/dev/null

echo "network: $NETWORK"
echo "target: $NAME at $(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$NAME")"
