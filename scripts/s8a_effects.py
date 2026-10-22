#!/usr/bin/env python
"""Required checks 3 and 4 of D68 plan 8.1, executed (S8a): what enabling P1 does to waiting
approvals, and whether it can be rolled back.

    PYTHONPATH=. python scripts/s8a_effects.py [--out effects.json]

Against the database in ``.env``, in an engagement of its own, with a global **emergency overlay**
as the enabling layer (an overlay, because a *baseline* is frozen into each engagement when it is
made, D54, and so reaches only engagements made after it -- a baseline's retirement is no rollback
for the others; this script also shows that, with a second engagement). It prints, in order:

1. the approvals waiting, and the policy version each was decided under (the announcement of
   DP-10: what the enabling will void);
2. the same after the overlay is published: how many are now decided under another version, and
   what happens to one of them when it is approved and dispatched;
3. the decisions with the switch on: a task-bearing proposal is unchanged, a task-less one asks
   for a person (``proposal_without_task``);
4. the rollback: the overlay retired, the task-less proposal is ``ALLOW`` again, and the switch
   reads false in the engagement; plus a baseline-published switch retired the same way, to show
   which engagements it does and does not return.

The layers it publishes are retired at the end; the rows stay. Exit 1 if a step does not give what
it should.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.soak import lib  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    lib.load_env()
    from sqlalchemy import text

    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from control_plane.api.approved_dispatch import dispatch_approved
    from control_plane.api.function_api import propose_action
    from control_plane.capability.broker import current_policy_version
    from scripts.soak import checks
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
    from tests.test_approved_dispatch import approve
    from tests.test_pipeline_stages import FakeSandbox

    stamp = time.strftime("%m%d%H%M%S", time.gmtime())
    eid = f"ENG-S8A-{stamp}"
    cidr = "10.66.251.0/24"
    out: dict = {"engagement": eid}
    problems: list[str] = []
    layers: list[int] = []
    base = ensure_test_baseline()
    if base:
        layers.append(base)

    def say(label: str, value) -> None:
        out[label] = value
        print(f"{label}: {value}", flush=True)

    def expect(label: str, ok: bool, detail="") -> None:
        print(f"{'OK  ' if ok else 'FAIL'} {label} {detail}", flush=True)
        out.setdefault("expectations", []).append({"label": label, "ok": ok, "detail": str(detail)})
        if not ok:
            problems.append(label)

    make_engagement(eid, actor="s8a")
    sup.publish_engagement_policy(eid)
    scope_id = sup.register_scope(EngagementManager(eid), type="cidr", value=cidr)
    sup.enroll(eid, by="s8a")
    world = {"engagement_id": eid, "scope_id": scope_id}

    def version() -> int:
        with committing_scope(eid) as conn:
            return int(current_policy_version(conn, eid))

    def decide(host: str, *, task: bool, human: bool = False):
        proposal = sup.proposal_for(scope_id, host=host, ports="8080")
        if task:
            proposal = dataclasses.replace(proposal, task_id=task_for(eid, proposal))
        return propose_action(
            engagement_id=eid, proposal=proposal,
            reviewer=HonestFakeReviewer(sensitive_hint=("pii",)) if human else HonestFakeReviewer(),
            policy=sup.effective_policy(eid), agent_id="s8a", sandbox=FakeSandbox(),
            network_allowlist=[cidr])

    try:
        # -- 1. before: the approvals waiting
        waiting = [decide(f"10.66.251.{n}", task=True, human=True) for n in (21, 22)]
        before = version()
        say("1. waiting approvals", [(w.proposal_id, w.decision) for w in waiting])
        say("1. policy version they were decided under", before)
        expect("two approvals are waiting", all(w.decision == "HUMAN_APPROVAL" for w in waiting))

        # -- 2. enable: an emergency overlay carrying the switch
        overlay = publish_global_layer(
            layer="emergency_overlay", version=int(time.time()) % 2_000_000_000,
            document={"task_relation_enforce": True}, actor="s8a")
        layers.append(overlay)
        after = version()
        say("2. policy version after the overlay", after)
        expect("the enabling bumped the policy version", after != before, f"{before} -> {after}")
        expect("the switch reads true in the engagement",
               checks.p1_switches([eid])[eid] is True)
        approve(world, waiting[0].proposal_id)
        done = dispatch_approved(
            engagement_id=eid, proposal_id=waiting[0].proposal_id, policy=sup.effective_policy(eid),
            sandbox=FakeSandbox(), network_allowlist=[cidr])
        say("2. a waiting approval, approved and dispatched after the enabling",
            {"executed": done.executed, "failure": done.failure,
             "deny_reasons": list(done.deny_reasons)})
        with committing_scope(eid) as conn:
            versions = conn.execute(text(
                "SELECT proposal_id, decided_policy_version, pipeline_stage FROM action_proposals "
                "WHERE proposal_id = ANY(:p)"), {"p": [w.proposal_id for w in waiting]}).all()
        say("2. waiting proposals: decided-under version and stage",
            [tuple(v) for v in versions])
        voided = sum(1 for v in versions if v[1] is not None and int(v[1]) != after)
        say("2. approvals decided under another version than the current", voided)

        # -- 3. the decisions with the switch on
        with_task = decide("10.66.251.31", task=True)
        without = decide("10.66.251.32", task=False)
        say("3. task-bearing proposal", (with_task.decision, list(with_task.approval_reasons)))
        say("3. task-less proposal", (without.decision, list(without.approval_reasons)))
        expect("a task-bearing proposal is allowed", with_task.decision == "ALLOW")
        expect("a task-less proposal asks for a person under its own name",
               without.decision == "HUMAN_APPROVAL"
               and "proposal_without_task" in without.approval_reasons)

        # -- 4. rollback: retire the overlay
        deactivate_global_layer(overlay, actor="s8a")
        layers.remove(overlay)
        expect("rollback: the switch reads false again", checks.p1_switches([eid])[eid] is False)
        again = decide("10.66.251.33", task=False)
        say("4. task-less proposal after the rollback",
            (again.decision, list(again.approval_reasons)))
        expect("rollback: the task-less proposal is allowed again", again.decision == "ALLOW")

        # -- 4b. the same by a baseline: which engagements it returns
        baseline = publish_global_layer(
            layer="baseline_global", version=int(time.time()) % 2_000_000_000 + 1,
            document={"task_relation_enforce": True}, actor="s8a")
        layers.append(baseline)
        made_after = f"ENG-S8A-{stamp}-B"
        make_engagement(made_after, actor="s8a")
        deactivate_global_layer(baseline, actor="s8a")
        layers.remove(baseline)
        made_later = f"ENG-S8A-{stamp}-C"
        make_engagement(made_later, actor="s8a")
        state = checks.p1_switches([eid, made_after, made_later])
        say("4b. after a baseline carrying the switch was published and then retired",
            {"made before it": state[eid], "made while it was active": state[made_after],
             "made after it was retired": state[made_later]})
        expect("a baseline's retirement returns only the engagements made after it",
               state[eid] is False and state[made_after] is True and state[made_later] is False,
               "(the one made while it was active keeps the switch: D54 freezes the baseline)")
    finally:
        sup.withdraw(eid)
        for layer in layers:
            deactivate_global_layer(layer, actor="s8a")

    if args.out:
        args.out.write_text(json.dumps(out, indent=1, default=str))
    print(f"{len(problems)} step(s) did not give what they should" if problems else "all steps ok")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
