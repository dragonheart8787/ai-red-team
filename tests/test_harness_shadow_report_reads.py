"""D69 shadow runner plan, stage S5 (design 11.11): the existing shadow report reads the harness's
engagements without a change to it.

An engagement is made the way H7 makes one (``tests/test_harness_h7_528.py``): evidence from one
real ``propose_action`` ALLOW with a fake container that prints a hand-written stdout; then one
round of the real loop (``run_loop``) and the real adapter (``LoopAdapter``), whose Worker is a
``BaseWorker`` that builds every proposal with ``BaseWorker._to_proposal``, sent to the real
``propose_action`` and the real OPA, with fake sandboxes. The round's three proposals are H7's cases
1M (ALLOW), 1L (the lure: HUMAN_APPROVAL) and 3D (DENY). A second engagement, made the same way with
one ALLOW, exists so that a reading of the report's total across engagements differs from a reading
of the one engagement.

The report is not changed: ``scripts/plan_fit_report.collect`` is called as it is, and
``scripts/plan_fit_report.py --json`` is run as a process with its existing arguments. Its numbers
are compared with ``action_proposals``. The stdout is a fixture, not a real nmap run. No model, no
container, no real traffic. The expectations were written and hashed before the first run (plan
item 135) and are not changed by its result.
"""

from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
from pathlib import Path

from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from agents.llm.worker_base import BaseWorker
from harness.bounds import Bounds, RunCounters
from harness.exit_codes import StopReason
from harness.loop import run_loop
from harness.loop_adapter import LoopAdapter
from harness.signals import SignalFlag
from scripts import plan_fit_report
from tests.test_harness_h5c1_support import WINDOW, FakeSandbox
from tests.test_harness_h5c2_support import allowed
from tests.test_harness_h7_528 import (
    RANGE,
    STDOUT,
    _Enrolled,
    _payload,
    _read,
    _scope,
    _seed,
    _Supervisor,
    _task,
)

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "scripts" / "plan_fit_report.py"
ACTION = "network.scan"
TIMEOUT = 120

# BEGIN PREREGISTERED EXPECTATIONS -- written before the first run; not to be changed after it
# (plan item 135; a change after a result would be a change made because of the result)
#
# The harness's own proposals in engagement A (agent_id of the loop's Worker), by decision: at
# least these many of each, so that the engagement holds all three decisions.
HARNESS_AT_LEAST = {"ALLOW": 1, "HUMAN_APPROVAL": 1, "DENY": 1}
# For engagement A, read three ways -- the table (action_proposals under A's own scope), the
# unmodified collect(), and the unmodified script's --json output under "engagements" -> A:
#   E1  the report's "proposals" equals the table's count of A's proposals;
#   E2  the report's "without_plan_fit" is 0 (design 11.11: every proposal the harness made carries
#       the stored plan_fit), whatever the decision;
#   E3  the report's "decisions" (decision -> count) equals the table's count by decision of A's
#       decided proposals, and its "decided" equals the table's count of decided proposals;
#   E4  collect() and --json agree with each other on E1-E3.
WITHOUT_PLAN_FIT = 0
# END PREREGISTERED EXPECTATIONS


class _Worker(BaseWorker):
    """As H7's Worker: the payload (target and action) is the script's, the ``discovery`` block is
    ``_discovery_provenance``'s, and only ``propose`` is defined. The payload is chosen by the
    task's scope object and target, since two of the round's tasks share one scope object."""

    agent_id = "s5-report-worker"
    model = "scripted-worker"

    def __init__(self, payloads):
        super().__init__()
        self._payloads = payloads

    def propose(self, *, task, candidates, observations=(), task_id=None):
        payload = self._payloads[(task.scope_object_id, task.target["logical_identity"]["value"])]
        return self._to_proposal(
            payload, candidates=candidates, task_id=task_id, observations=observations)


def _one_round(engagement_ids, tasks, payloads):
    adapter = LoopAdapter(
        enrolment=_Enrolled(*engagement_ids), supervisor=_Supervisor(tasks),
        worker=_Worker(payloads), reviewer=HonestFakeReviewer(), sandbox=FakeSandbox(),
        objective="find the live hosts", window_limit=WINDOW)
    result = run_loop(adapter, Bounds(1, 100, 5), RunCounters(), adapter.refusals,
                      window_limit=WINDOW, stop_event=SignalFlag(), once=False)
    assert result.reason is StopReason.CAP_REACHED, result      # one round, no fault, no refusal


def _table(engagement_id):
    """The engagement's proposals as ``action_proposals`` holds them, under its own scope."""
    rows = _read(engagement_id, "SELECT agent_id, decision FROM action_proposals")
    decided = [r for r in rows if r["decision"] is not None]
    return {"proposals": len(rows), "decided": len(decided),
            "decisions": dict(collections.Counter(r["decision"] for r in decided)),
            "harness": dict(collections.Counter(
                r["decision"] for r in rows if r["agent_id"] == _Worker.agent_id))}


def _report_json(*engagement_ids):
    args = [part for eid in engagement_ids for part in ("--engagement", eid)]
    done = subprocess.run(
        [sys.executable, "-B", str(REPORT), *args, "--json"], cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=TIMEOUT)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_the_existing_report_reads_an_engagement_the_harness_made(
        engagement_id, registry, engagement_factory):
    other_id, other_registry = engagement_factory()
    scope_a = _scope(registry, type="cidr", value=RANGE)
    scope_b = _scope(other_registry, type="cidr", value=RANGE)
    allow, lure, deny = ("ip", "10.82.0.5"), ("ip", "10.82.0.77"), ("fqdn", "dc99.lure.example")
    with allowed(engagement_id, ACTION), allowed(other_id, ACTION):
        _seed(engagement_id, scope_a, ACTION, STDOUT[1], "ping")
        _seed(other_id, scope_b, ACTION, STDOUT["B"], "ping")
        _one_round(
            [engagement_id, other_id],
            {engagement_id: [_task(scope_a, ACTION, t) for t in (allow, lure, deny)],
             other_id: [_task(scope_b, ACTION, allow)]},
            {**{(scope_a, t[1]): _payload(scope_a, ACTION, t) for t in (allow, lure, deny)},
             (scope_b, allow[1]): _payload(scope_b, ACTION, allow)})

    table = _table(engagement_id)
    collected = plan_fit_report.collect(engagement_id)
    report = _report_json(engagement_id, other_id)
    from_json = report["engagements"][engagement_id]
    print("OBSERVED table", table)
    print("OBSERVED collect", {k: collected[k] for k in
                               ("proposals", "decided", "decisions", "with_plan_fit",
                                "without_plan_fit")})
    print("OBSERVED json", {k: from_json[k] for k in
                            ("proposals", "decided", "decisions", "with_plan_fit",
                             "without_plan_fit")})
    print("OBSERVED json total", {k: report["total"][k] for k in ("proposals", "decisions")})

    # the engagement holds all three decisions, made by the harness's own Worker
    for decision, least in HARNESS_AT_LEAST.items():
        assert table["harness"].get(decision, 0) >= least, (decision, table)
    for reading in (collected, from_json):
        assert reading["proposals"] == table["proposals"]                          # E1
        assert reading["without_plan_fit"] == WITHOUT_PLAN_FIT                     # E2
        assert reading["decisions"] == table["decisions"]                          # E3
        assert reading["decided"] == table["decided"]                              # E3
    for key in ("proposals", "without_plan_fit", "decisions", "decided"):           # E4
        assert collected[key] == from_json[key], key
