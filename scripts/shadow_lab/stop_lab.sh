#!/usr/bin/env bash
# Remove S8's laboratory (plan item 164): every container labelled cyberorch.shadow_lab=s8, then the
# network of the scope object 10.82.0.0/24 (``DockerSandbox.remove_network``), and list what is left.
#
#   bash scripts/shadow_lab/stop_lab.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$REPO/.venv/bin/python}"
SCOPE="10.82.0.0/24"
LABEL="cyberorch.shadow_lab=s8"

ids="$(docker ps -aq --filter "label=$LABEL")"
if [ -n "$ids" ]; then
    # shellcheck disable=SC2086 -- one id per word
    docker rm -f $ids >/dev/null
fi

(cd "$REPO" && PYTHONPATH="$REPO" "$PYTHON" - "$SCOPE" <<'PY'
import sys
from tool_gateway.sandbox import DockerSandbox
DockerSandbox().remove_network([sys.argv[1]])
PY
)

echo "networks left:"
docker network ls --format '{{.Name}}'
echo "containers left:"
docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}'
