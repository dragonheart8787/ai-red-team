#!/usr/bin/env bash
# One worker of the larger P1 shadow run (D68): repeated d40 runs, each a fresh engagement, in
# the "sub-networks" scenario -- four /26 ranges and nine hosts in scope, no /24 scope object,
# web.get only, a scripted Reviewer, no browser image, the Supervisor shown no raw evidence.
#   usage: d40_scale_worker.sh WORKER_ID TARGET_RUNS CEILING
# The role models are the harness defaults (opus) unless CYBERORCH_WORKER_MODEL and
# CYBERORCH_SUPERVISOR_MODEL are set in the environment; OUT and STARTED_DIR select a stratum.
# Workers share a target: each looks at how many runs' records exist before starting another.
# While the account's reported usage is at or above CEILING the worker waits (it never spends
# past it, and it never stops early because of it).
set -uo pipefail
cd "$(dirname "$0")/../.."
export PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=.
WORKER="$1"; TARGET="$2"; CEILING="${3:-0.60}"
OUT="${OUT:-docs/D68_S7_BASELINE/p1_scale}"
STARTED="${STARTED_DIR:-/tmp/claude-0/s5}"
mkdir -p "$OUT"
HOSTS=d40-host-1,d40-host-2,d40-host-3,d40-host-4,d40-host-5,d40-host-6,d40-host-7,d40-host-8
SUBNETS=10.79.0.0/26,10.79.0.64/26,10.79.0.128/26,10.79.0.192/26
usage() {
  python scripts/plan_fit_route_diagnostic.py --items matched-000 --model sonnet \
      --out "/tmp/claude-0/s5/rl_$WORKER.json" >/dev/null 2>&1
  python - "$WORKER" <<'PY'
import json, sys
try:
    u = json.load(open(f"/tmp/claude-0/s5/rl_{sys.argv[1]}.json"))[0]["rate_limit"]["utilization"]
    print(u.get("five_hour", 1), u.get("seven_day", 1))
except Exception:
    print(1, 1)
PY
}
n=0
while true; do
  done_runs=$(ls "$OUT"/run_*.json 2>/dev/null | wc -l)
  started=$(ls $STARTED/scale_started_* 2>/dev/null | wc -l)
  [ "$started" -ge "$TARGET" ] && break
  read five seven < <(usage)
  if python -c "import sys; sys.exit(0 if float('$five') < $CEILING and float('$seven') < $CEILING else 1)"; then
    started=$(ls $STARTED/scale_started_* 2>/dev/null | wc -l)
    [ "$started" -ge "$TARGET" ] && break
    n=$((started + 1)); touch "$STARTED/scale_started_$n"
    echo "$(date +%T) worker $WORKER run $n: five_hour=$five seven_day=$seven"
    python scripts/live_run/d40_three_role.py --rounds 3 --skip-injection --allow-missing-browser \
      --no-parent-range --web-actions get --fake-reviewer --max-evidence-shown 0 \
      --max-observation-chars 20000 --extra-containers "$HOSTS" --subnets "$SUBNETS" \
      --out "$OUT/run_$n.json" > "/tmp/claude-0/s5/scale_run_$n.log" 2>&1
    echo "$(date +%T) worker $WORKER run $n exit $?"
  else
    echo "$(date +%T) worker $WORKER waiting: five_hour=$five seven_day=$seven (ceiling $CEILING)"
    sleep 600
  fi
done
echo "WORKER $WORKER DONE"
