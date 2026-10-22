#!/usr/bin/env python
"""Does the enablement check fire? (D68 S8a) -- the cases it exists for, produced for real.

A check that has only ever passed has shown nothing. This makes, in the database it runs against,
each state the checks of ``scripts/s8_enablement_check.py`` are for, runs the script as a process,
and requires the verdict each state should get:

====================================================  =========================================
state                                                 expected
====================================================  =========================================
P1 on, a task-bearing proposal decided and recorded   exit 0
P1 on, the stored ``plan_fit`` of that proposal gone   exit 1, "the comparison is not running"
an engagement made before the layer was published     exit 1, "not true in the effective policy"
(a baseline is frozen into an engagement when it is
made, D54: publishing later does not reach it)
Q1 on with no validator configured (``fake``)         exit 1, "no validator is configured" and
                                                      "doing nothing"
Q1 on, backend a real name, no decision with an       exit 1, "doing nothing"
answer (the validator never called)
====================================================  =========================================

Exit status 0 only if every state got its verdict. The engagement it makes is its own and is
withdrawn, and the layers it publishes are retired, at the end (rows stay, as the soak's do).

    PYTHONPATH=. python -m scripts.soak.negative_controls [--out controls.json]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from scripts.soak import lib

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_check(switch: str, eid: str, **env: str) -> tuple[int, str]:
    environment = {k: v for k, v in os.environ.items() if k != "CYBERORCH_PLANFIT_BACKEND"}
    environment.update(env, PYTHONPATH=str(REPO_ROOT))
    done = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "s8_enablement_check.py"),
         "--switch", switch, "--engagement", eid],
        capture_output=True, text=True, env=environment, timeout=120, cwd=REPO_ROOT)
    return done.returncode, done.stdout + done.stderr


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    lib.load_env()
    from sqlalchemy import text

    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from control_plane.api.function_api import propose_action
    from tests import scheduler_support as sup
    from tests.helpers import (
        EngagementManager,
        committing_scope,
        deactivate_global_layer,
        ensure_test_baseline,
        make_engagement,
        publish_global_layer,
    )
    from tests.task_support import task_for

    stamp = time.strftime("%m%d%H%M%S", time.gmtime())
    eid = f"ENG-CTL-{stamp}"
    layers: list[int] = []
    retire_baseline = ensure_test_baseline()
    if retire_baseline:
        layers.append(retire_baseline)
    # made BEFORE the layer is published: the baseline is frozen into an engagement at its creation
    # (D54), so this one never gets the switch -- "published somewhere that does not reach it"
    early = f"ENG-CTL-{stamp}-EARLY"
    make_engagement(early, actor="soak-controls")
    layers.append(publish_global_layer(
        layer="baseline_global", version=int(time.time()) % 2_000_000_000,
        document={"task_relation_enforce": True, "goal_fit_enforce": True},
        actor="soak-controls"))
    make_engagement(eid, actor="soak-controls")
    sup.publish_engagement_policy(eid)
    scope_id = sup.register_scope(EngagementManager(eid), type="cidr", value="10.66.250.0/24")
    sup.enroll(eid, by="soak-controls")

    results: list[dict] = []

    def expect(name: str, got: tuple[int, str], code: int, *needles: str) -> None:
        ok = got[0] == code and all(n in got[1] for n in needles)
        results.append({"state": name, "ok": ok, "exit": got[0], "expected_exit": code,
                        "needles": list(needles), "output": got[1][-700:]})
        print(f"{'OK  ' if ok else 'FAIL'} {name}: exit {got[0]} (wanted {code})", flush=True)

    try:
        proposal = sup.proposal_for(scope_id, host="10.66.250.11", ports="8080")
        proposal = dataclasses.replace(proposal, task_id=task_for(eid, proposal))
        outcome = propose_action(
            engagement_id=eid, proposal=proposal,
            reviewer=HonestFakeReviewer(sensitive_hint=("pii",)), policy=sup.effective_policy(eid),
            agent_id="soak-controls")
        print(f"a proposal decided {outcome.decision}", flush=True)

        expect("P1 on, a task-bearing proposal decided and recorded",
               run_check("p1", eid), 0, "OK: every condition holds")

        # Q1 with no validator: the switch is on (the layer says so), the backend is the default
        expect("Q1 on with no validator configured",
               run_check("q1", eid), 1, "no validator is configured", "doing nothing")
        # a real backend *name* with nothing behind it: nothing in the process passed a validator,
        # so the decisions record `not_assessed/disabled` and the check must see no answer
        expect("Q1 on, a backend named, no answer ever recorded",
               run_check("q1", eid, CYBERORCH_PLANFIT_BACKEND="claude_code"), 1, "doing nothing")

        with committing_scope(eid) as conn:
            conn.execute(text(
                "UPDATE action_proposals SET reviewer_hints = reviewer_hints - 'plan_fit' "
                "WHERE engagement_id = :e"), {"e": eid})
        expect("P1 on, the stored plan_fit is gone",
               run_check("p1", eid), 1, "the comparison is not running")

        expect("an engagement made before the layer was published: the switch does not reach it",
               run_check("p1", early), 1, "not true in the effective policy")
    finally:
        sup.withdraw(eid)
        for layer in layers:
            deactivate_global_layer(layer, actor="soak-controls")

    failed = [r for r in results if not r["ok"]]
    if args.out:
        args.out.write_text(json.dumps({"engagement": eid, "controls": results}, indent=1))
    for r in failed:
        print(f"--- {r['state']}\n{r['output']}", file=sys.stderr)
    print(f"{len(results) - len(failed)} of {len(results)} controls behaved as expected")
    return 1 if failed or len(results) < 5 else 0


if __name__ == "__main__":
    raise SystemExit(main())
