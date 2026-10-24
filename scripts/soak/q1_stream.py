#!/usr/bin/env python
"""Real proposals for the goal-fit validator across action classes (D68 S8b).

The soak's own workload is ``network.scan`` only. Q1 will judge every action class, and the
baseline's one anomaly (``code.secrets`` failing 65%, which turned out to be Active-Directory
wording and not the action; ``docs/D68_S7_CODE_SECRETS_FAILURE.md``) cannot be checked against
traffic of one action. This sends proposals of every class through the real ``propose_action`` with
the real validator, so that the failure rate of each class and of each goal *wording* is counted
on the pipeline's own path.

* One engagement of its own, outside the soak's world (its proposals are not in the soak's
  invariants and it is not enrolled in the scheduler: nothing is dispatched, no sandbox is passed).
* Each proposal names a task made for it whose goal is an ordinary sentence for the action
  (the wording of ``tests/plan_fit_corpus.SCENARIOS``, so numbers can be set beside S7's).
* ``natural`` cells: the goal's wording matches the action. ``crossed`` cells (about 10% of the
  stream): an Active-Directory goal on a ``code.secrets`` task and a secrets-scan goal on an
  ``ad.collect`` task -- the S7 probe's cells -- tagged apart so that they cannot contaminate the
  natural rate.
* Weights favour ``code.secrets`` (4) and ``ad.collect`` (2); the other six classes 1 each.
* Waits for the goal-fit switch to be in the engagement's effective policy (the soak's conductor
  publishes it) and fails loudly if it does not appear. Stops at the deadline or ``--max-calls``.

    PYTHONPATH=. python -m scripts.soak.q1_stream --hours 4 --per-hour 100 --out q1_stream.jsonl
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from pathlib import Path

from scripts.soak import lib

ZONES = ("corp", "eu", "us", "lab", "ops", "dmz")
CIDR = "10.66.252.0/24"
ACTIONS = ("network.scan", "network.recon", "web.get", "web.render", "code.scan", "code.secrets",
           "ad.collect")
WEIGHTS = {"code.secrets": 4, "ad.collect": 2}
CROSSED_SHARE = 0.10
WAIT_FOR_SWITCH_S = 900


def build_plan(rng: random.Random):
    """One stream item: (cell, scenario name, action, goal, target) -- no database, no model."""
    from tests.plan_fit_corpus import _ROLES_PLAIN, _ROLES_SENSITIVE, SCENARIOS

    by_name = {s[0]: s for s in SCENARIOS}
    cell, goal_from = "natural", None
    if rng.random() < CROSSED_SHARE:
        # the S7 probe's cells: the wording of one of the two classes on the task of the other
        cell = "crossed"
        name, goal_from = rng.choice(
            (("code-secrets", "ad-collect"), ("ad-collect", "code-secrets")))
    else:
        names = [s[0] for s in SCENARIOS]
        name = rng.choices(names, [WEIGHTS.get(by_name[n][1], 1) for n in names])[0]
        goal_from = name
    _, action, kind, templates = by_name[name]
    host = None
    if kind == "ip":
        target = ("ip", f"10.66.252.{rng.randint(2, 250)}")
    elif kind == "cidr":
        target = ("cidr", CIDR)
    else:
        host = f"{rng.choice(_ROLES_PLAIN + _ROLES_SENSITIVE)}{rng.randint(1, 19):02d}." \
               f"{rng.choice(ZONES)}.example"
        target = ("fqdn", host)
    shown = target[1]
    goal = by_name[goal_from][3][rng.randrange(3)].format(t=shown)
    return {"cell": cell, "scenario": name, "goal_wording": goal_from, "action": action,
            "goal": goal, "target_type": target[0], "target_value": target[1]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hours", type=float, required=True)
    parser.add_argument("--per-hour", type=float, default=100.0)
    parser.add_argument("--max-calls", type=int, default=1000)
    parser.add_argument("--seed", default="s8b")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    lib.load_env()
    backend = os.environ.get("CYBERORCH_PLANFIT_BACKEND", "").strip().lower()
    if not backend or backend == "fake":
        print("no validator is configured (CYBERORCH_PLANFIT_BACKEND): refusing to send a stream "
              "that would record nothing", file=sys.stderr)
        return 2

    from agents.base_agent import ProposedAction
    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from agents.llm.selection import build_plan_fit_validator
    from control_plane.api.function_api import propose_action
    from scripts.soak import checks
    from tests import scheduler_support as sup
    from tests.helpers import EngagementManager, ensure_test_baseline, make_engagement
    from tests.task_support import task_for

    stamp = time.strftime("%m%d%H%M%S", time.gmtime())
    eid = f"ENG-SOAK-Q1-{stamp}"
    ensure_test_baseline()           # the conductor's setup makes one too; whichever is first
    make_engagement(eid, actor="soak-q1-stream")
    sup.publish_engagement_policy(eid, actions=ACTIONS)
    manager = EngagementManager(eid)
    scopes = {"cidr": sup.register_scope(manager, type="cidr", value=CIDR, actions=ACTIONS)}
    for zone in ZONES:
        scopes[zone] = sup.register_scope(manager, type="fqdn", value=f"{zone}.example",
                                          actions=ACTIONS)
    validator = build_plan_fit_validator()
    deadline = time.monotonic() + 3600.0 * args.hours
    gap = 3600.0 / args.per_hour
    rng = random.Random(args.seed)
    journal = lib.Journal(args.out)
    journal.write("start", engagement=eid, backend=backend, hours=args.hours,
                  per_hour=args.per_hour)

    waited = time.monotonic()
    while not checks.q1_switches([eid])[eid]:
        if time.monotonic() - waited > WAIT_FOR_SWITCH_S:
            journal.write("fatal", reason="goal_fit_enforce never appeared in the effective policy")
            print("goal_fit_enforce never appeared in the engagement's effective policy",
                  file=sys.stderr)
            return 3
        time.sleep(5)
    journal.write("switch_seen", after_s=round(time.monotonic() - waited, 1))

    sent = 0
    while time.monotonic() < deadline and sent < args.max_calls:
        item = build_plan(rng)
        scope_id = scopes["cidr"] if item["target_type"] != "fqdn" else scopes[
            item["target_value"].rsplit(".", 2)[-2]]
        proposal = ProposedAction(
            action=item["action"],
            target={"logical_identity": {"type": item["target_type"],
                                         "value": item["target_value"]}},
            authorization={"source": "engagement_scope", "scope_object_id": scope_id},
            discovery={"source": "explicit_scope"})
        started = time.monotonic()
        calls_before = len(getattr(validator, "calls", ()))
        try:
            import dataclasses

            proposal = dataclasses.replace(
                proposal, task_id=task_for(eid, proposal, goal=item["goal"]))
            outcome = propose_action(
                engagement_id=eid, proposal=proposal, reviewer=HonestFakeReviewer(),
                policy=sup.effective_policy(eid), agent_id="soak-q1-stream",
                plan_fit_validator=validator, network_allowlist=[CIDR])
            # why a call failed is kept in the validator's own call record (operations), not in the
            # audit; this stream is single-threaded, so the new record is this proposal's
            calls = getattr(validator, "calls", [])
            call = calls[-1] if len(calls) > calls_before else None
            journal.write("proposal", **item, proposal_id=outcome.proposal_id,
                          decision=outcome.decision, reasons=list(outcome.approval_reasons),
                          failure=outcome.failure, seconds=round(time.monotonic() - started, 2),
                          validator_called=call is not None,
                          validator_seconds=round(call.latency_seconds, 2) if call else None,
                          validator_failure=(str(call.failure)[:400] if call and call.failed
                                             else None))
        except Exception as exc:  # noqa: BLE001 - recorded, and counted as an error, never dropped
            journal.write("error", **item, type=type(exc).__name__, message=str(exc)[:300])
        sent += 1
        time.sleep(max(0.0, rng.uniform(0.5, 1.5) * gap - (time.monotonic() - started)))
    journal.write("end", sent=sent, engagement=eid)
    print(f"sent {sent} proposals in {eid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
