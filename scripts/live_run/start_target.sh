#!/usr/bin/env bash
# Start the disposable D11 target on the sandbox's allowlist network.
#
# The network is the one DockerSandbox provisions for the allowlist CIDR
# (internal=True, no default gateway), so the target is inside the same
# confinement the scanner is — which is what makes the authorization question
# unambiguous: the operator owns both ends and nothing routes off the range.
set -euo pipefail

NAME="${NAME:-d11-target}"
IMAGE="${IMAGE:-cyberorch/live-target:local}"
ALLOWLIST="${ALLOWLIST:-10.79.0.0/24}"

NETWORK="$(python3 - "$ALLOWLIST" <<'PY'
import sys
from tool_gateway.sandbox import DockerSandbox
print(DockerSandbox().network_name([sys.argv[1]]))
PY
)"

docker network inspect "$NETWORK" >/dev/null 2>&1 || python3 - "$ALLOWLIST" <<'PY'
import sys
from tool_gateway.sandbox import DockerSandbox
DockerSandbox().ensure_network([sys.argv[1]])
PY

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --network "$NETWORK" \
    --label cyberorch.live_run=d11 "$IMAGE" >/dev/null

for _ in $(seq 1 20); do
    ip="$(docker inspect "$NAME" \
        --format "{{ (index .NetworkSettings.Networks \"$NETWORK\").IPAddress }}")"
    [ -n "$ip" ] && break
    sleep 0.5
done
sleep 3
echo "$NAME up on $NETWORK at $ip"
