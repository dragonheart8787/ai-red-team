#!/usr/bin/env bash
# Start N disposable live-target containers on the allowlist network at fixed addresses (D68).
#
# For the P1 shadow runs at scale: a planner with one host and one network has little to
# decompose. These hosts are spread over the four /26 sub-networks of 10.79.0.0/24 (addresses
# .10 .20 / .70 .80 / .130 .140 / .200 .210 and so on), so a sub-network task has hosts inside it.
# The image is the one build_target_image.sh makes (real Redis, SMTP and HTTP daemons).
set -euo pipefail

COUNT="${1:-8}"
IMAGE="${IMAGE:-cyberorch/live-target:local}"
ALLOWLIST="${ALLOWLIST:-10.79.0.0/24}"
ADDRESSES=(10 20 70 80 130 140 200 210 30 90 150 220)

NETWORK="$(python3 - "$ALLOWLIST" <<'PY'
import sys
from tool_gateway.sandbox import DockerSandbox
sandbox = DockerSandbox()
sandbox.ensure_network([sys.argv[1]])
print(sandbox.network_name([sys.argv[1]]))
PY
)"

for i in $(seq 1 "$COUNT"); do
    name="d40-host-$i"
    last="${ADDRESSES[$((i - 1))]}"
    ip="${ALLOWLIST%.*.*}.0.$last"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --network "$NETWORK" --ip "$ip" \
        --label cyberorch.live_run=d40 "$IMAGE" >/dev/null
    echo "$name up at $ip"
done
sleep 3
