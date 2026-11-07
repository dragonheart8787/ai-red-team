"""D69 H3: the evidence window and the builder against the real tables.

The rows here are produced the way production produces them wherever that is possible: a
proposal through ``propose_action``, an ALLOW decision, and a dispatch whose container is a
fake sandbox returning hand-written stdout. The real adapter derives the view, the real
pipeline writes ``tool_runs`` and ``evidence``, and the harness reads them back through
``read_evidence_window`` under an ``engagement_scope`` connection.

Two cases cannot be produced that way and are **constructed** with INSERTs, each marked where
it happens:

* an evidence row with no run (``run_id IS NULL``). The pipeline always writes the run first.
* a run whose ``scan_type`` differs from the one the proposal asked for. Preflight P4: the
  capability's constraints are derived from the proposal's stored target in one place
  (``execution_constraints``), both on the ALLOW path and after a human approval, and
  ``tool_runs.normalized_params`` is ``NmapPlan.as_params()`` of those same constraints -- so
  through the pipeline the two always agree. The divergence is exactly the case the rule about
  reading the *run* exists for, so it is constructed on top of a real ping proposal.

The cross-engagement case is a regression guard on row-level security, not a property H3
added, and it carries no mutation of its own; it is here because a window that leaked another
engagement's evidence would hand a Worker identities from an engagement nobody authorized.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import text

from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.state.db import engagement_scope
from harness.observations import (
    observation_from_evidence,
    observed_identities,
    read_evidence_window,
)
from tests import scheduler_support as sup
from tests.helpers import committing_scope
from tests.task_support import attach_task
from tool_gateway.adapters import nmap
from tool_gateway.sandbox import SandboxResult

HOST = "10.83.0.5"
OTHER_HOST = "10.83.0.9"

PING_STDOUT = f"""Nmap scan report for {HOST}
Host is up (0.00042s latency).
Nmap done: 1 IP address (1 host up) scanned in 1.11 seconds
"""
OTHER_PING_STDOUT = f"""Nmap scan report for {OTHER_HOST}
Host is up (0.00031s latency).
Nmap done: 1 IP address (1 host up) scanned in 1.09 seconds
"""


def _policy():
    """network.scan ALLOWed in the baseline, built in memory: no layer is published."""
    return merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


class StdoutSandbox:
    """Stands in for the container, returning stdout the test chose."""

    def __init__(self, stdout: str):
        self.stdout = stdout
        self.calls = 0

    def run(self, **kwargs):
        self.calls += 1
        return SandboxResult(
            0, self.stdout, "", False, 0.5, tuple(kwargs["network_allowlist"]), "fake",
        )


def scan(engagement_id: str, registry, *, host: str, scan_type: str, stdout: str):
    """One real dispatch of ``network.scan`` against ``host``, with a fake container."""
    scope_id = sup.register_scope(registry, type="ip", value=host)
    proposal = attach_task(
        engagement_id,
        sup.proposal_for(scope_id, host=host, scan_type=scan_type),
    )
    outcome = propose_action(
        engagement_id=engagement_id, proposal=proposal, reviewer=HonestFakeReviewer(),
        policy=_policy(), agent_id="worker-h3", sandbox=StdoutSandbox(stdout),
        idempotency_key=f"h3-{uuid.uuid4().hex[:10]}",
    )
    assert outcome.decision == "ALLOW", outcome
    assert outcome.run_id and outcome.evidence_id, outcome
    return outcome


def window(engagement_id: str, *, limit: int = 20):
    with engagement_scope(engagement_id) as conn:
        return read_evidence_window(conn, limit=limit)


def one(engagement_id: str, evidence_id: str):
    """The window row for one evidence id."""
    rows = [r for r in window(engagement_id) if r.evidence_id == evidence_id]
    assert len(rows) == 1, rows
    return rows[0]


def construct_run_and_evidence(
    engagement_id: str, *, stdout: str, scan_type: str | None, target: str,
    proposal_id: str | None = None, with_run: bool = True,
) -> str:
    """**Constructed rows**, not produced by the pipeline. Returns the evidence id."""
    evidence_id = f"EV-H3-{uuid.uuid4().hex[:10]}"
    run_id = f"RUN-H3-{uuid.uuid4().hex[:10]}" if with_run else None
    with committing_scope(engagement_id) as conn:
        if with_run:
            conn.execute(
                text("""
                    INSERT INTO tool_runs (run_id, engagement_id, proposal_id, tool,
                        tool_version, normalized_target, normalized_params,
                        execution_fingerprint, status)
                    VALUES (:run, :eng, :pid, 'nmap', 'constructed', :target,
                        CAST(:params AS JSONB), :fp, 'succeeded')
                """),
                {"run": run_id, "eng": engagement_id, "pid": proposal_id, "target": target,
                 "params": json.dumps({"target": target, "ports": None,
                                       "scan_type": scan_type}),
                 "fp": f"fp-{run_id}"},
            )
        conn.execute(
            text("""
                INSERT INTO evidence (evidence_id, engagement_id, run_id, type,
                    raw_artifact_path, raw_sha256, raw_collected_at, derived_view,
                    tool, tool_version)
                VALUES (:ev, :eng, :run, 'tool_output', '/dev/null', :sha, now(),
                    CAST(:view AS JSONB), 'nmap', 'constructed')
            """),
            {"ev": evidence_id, "eng": engagement_id, "run": run_id,
             "sha": f"{uuid.uuid4().hex}{uuid.uuid4().hex}",
             "view": json.dumps(nmap.derive_view(stdout, ""))},
        )
    return evidence_id


# -- (b) the real rows -------------------------------------------------------------------

def test_b_a_ping_run_puts_its_responder_into_observed_identities(engagement_id, registry):
    outcome = scan(engagement_id, registry, host=HOST, scan_type="ping", stdout=PING_STDOUT)
    row = one(engagement_id, outcome.evidence_id)

    assert row.scan_type == "ping"
    assert row.run_id == outcome.run_id
    assert observed_identities(row) == (HOST,)
    observation = observation_from_evidence(row)
    assert observation.observed_identities == (HOST,)
    assert observation.evidence_id == outcome.evidence_id
    assert json.loads(observation.content)["hosts"] == [HOST]


@pytest.mark.parametrize("scan_type", ["connect", "version"])
def test_b_a_connect_or_version_run_observes_nothing_from_the_same_output(
    engagement_id, registry, scan_type,
):
    """The control for the whole rule: identical stdout, different scan type."""
    ping = scan(engagement_id, registry, host=HOST, scan_type="ping", stdout=PING_STDOUT)
    other = scan(engagement_id, registry, host=HOST, scan_type=scan_type, stdout=PING_STDOUT)

    ping_row, other_row = one(engagement_id, ping.evidence_id), one(
        engagement_id, other.evidence_id)
    assert ping_row.derived_view["hosts"] == other_row.derived_view["hosts"] == [HOST]
    assert other_row.scan_type == scan_type
    assert observed_identities(ping_row) == (HOST,)
    assert observed_identities(other_row) == ()


def test_b_an_evidence_row_with_no_run_observes_nothing(engagement_id):
    evidence_id = construct_run_and_evidence(
        engagement_id, stdout=PING_STDOUT, scan_type=None, target=HOST, with_run=False,
    )
    row = one(engagement_id, evidence_id)

    assert row.run_id is None
    assert row.scan_type is None
    assert row.derived_view["hosts"] == [HOST]
    assert observed_identities(row) == ()


def test_b_a_run_whose_scan_type_differs_from_the_request_observes_nothing(
    engagement_id, registry,
):
    requested = scan(engagement_id, registry, host=HOST, scan_type="ping",
                     stdout=PING_STDOUT)
    with committing_scope(engagement_id) as conn:
        asked = conn.execute(
            text("SELECT target->>'scan_type' AS scan_type FROM action_proposals "
                 "WHERE proposal_id = :p"),
            {"p": requested.proposal_id},
        ).scalar_one()
    assert asked == "ping"                       # what the proposal asked for

    evidence_id = construct_run_and_evidence(      # constructed: the pipeline cannot diverge
        engagement_id, stdout=PING_STDOUT, scan_type="connect", target=HOST,
        proposal_id=requested.proposal_id,
    )
    row = one(engagement_id, evidence_id)

    assert row.scan_type == "connect"            # what was actually run
    assert row.derived_view["hosts"] == [HOST]
    assert observed_identities(row) == ()


def test_b_another_engagements_evidence_is_not_in_the_window(
    engagement_id, registry, engagement_factory,
):
    mine = scan(engagement_id, registry, host=HOST, scan_type="ping", stdout=PING_STDOUT)
    other_id, other_registry = engagement_factory()
    theirs = scan(other_id, other_registry, host=OTHER_HOST, scan_type="ping",
                  stdout=OTHER_PING_STDOUT)

    seen = [r.evidence_id for r in window(engagement_id)]
    assert mine.evidence_id in seen
    assert theirs.evidence_id not in seen
    assert observed_identities(one(engagement_id, mine.evidence_id)) == (HOST,)


def test_b_the_window_is_newest_first_and_the_limit_bounds_it(engagement_id, registry):
    first = scan(engagement_id, registry, host=HOST, scan_type="ping", stdout=PING_STDOUT)
    second = scan(engagement_id, registry, host=OTHER_HOST, scan_type="ping",
                  stdout=OTHER_PING_STDOUT)
    third = scan(engagement_id, registry, host=HOST, scan_type="connect",
                 stdout=PING_STDOUT)

    rows = window(engagement_id, limit=20)
    order = [r.evidence_id for r in rows]
    # the whole engagement's window, not one target's: all three rows are in it
    assert {first.evidence_id, second.evidence_id, third.evidence_id} <= set(order)
    assert {HOST, OTHER_HOST} <= {r.requested_target for r in rows}
    assert order.index(third.evidence_id) < order.index(second.evidence_id)
    assert order.index(second.evidence_id) < order.index(first.evidence_id)

    assert [r.evidence_id for r in window(engagement_id, limit=1)] == [third.evidence_id]
    assert len(window(engagement_id, limit=2)) == 2
