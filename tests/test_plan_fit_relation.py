"""P1, the shadow stage (D68 S2): the relation between a proposal and the task it names.

Two layers. The comparison is a pure function and is tested as a table. Then the real entry point:
``propose_action`` computes the relation, stores it beside the decision, writes one audit event --
and **changes no decision**, which is what "shadow" means and is tested as a property, not assumed.
"""

from __future__ import annotations

import itertools
import uuid

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction, ProposedTask
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api import function_api
from control_plane.api.function_api import _task_identity, create_task, propose_action
from control_plane.plan_fit import relation as r
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.state.db import engagement_scope
from tests.task_support import task_for

# ---------------------------------------------------------------------------------------------
# the comparison, as a table (no database)
# ---------------------------------------------------------------------------------------------

SCAN = "network.scan"


def row(*, status="queued", action=SCAN, canonical="ip:10.88.0.5", identity="auto"):
    if identity == "auto":
        identity = f"{action}\x1f{canonical}" if canonical else None
    return {"status": status, "action": action, "canonical_target": canonical,
            "identity_key": identity}


def cmp(task, *, action=SCAN, canonical="ip:10.88.0.5", identity="auto"):
    if identity == "auto":
        identity = f"{action}\x1f{canonical}" if canonical else None
    return r.compare(task_id="TASK-x", task=task, action=action,
                     canonical_target=canonical, identity_key=identity)


@pytest.mark.parametrize("task,kwargs,value,sub", [
    (None, {}, r.TASK_NOT_LIVE, r.TASK_NOT_FOUND),
    (row(status="completed"), {}, r.TASK_NOT_LIVE, r.TASK_STATUS_NOT_LIVE),
    (row(status="failed"), {}, r.TASK_NOT_LIVE, r.TASK_STATUS_NOT_LIVE),
    (row(status="cancelled"), {}, r.TASK_NOT_LIVE, r.TASK_STATUS_NOT_LIVE),
    (row(), {}, r.MATCHES_TASK, None),
    (row(status="claimed"), {}, r.MATCHES_TASK, None),
    (row(status="running"), {}, r.MATCHES_TASK, None),
    (row(identity=None), {}, r.DIFFERS_FROM_TASK, r.TASK_TARGET_NOT_CANONICAL),
    (row(), {"identity": None, "canonical": None}, r.DIFFERS_FROM_TASK,
     r.PROPOSAL_TARGET_NOT_CANONICAL),
    (row(), {"canonical": "ip:10.88.0.6"}, r.DIFFERS_FROM_TASK, r.DIFFERENT_TARGET),
    (row(), {"action": "network.recon"}, r.DIFFERS_FROM_TASK, r.DIFFERENT_ACTION),
    (row(), {"action": "network.recon", "canonical": "ip:10.88.0.6"}, r.DIFFERS_FROM_TASK,
     r.DIFFERENT_ACTION_AND_TARGET),
    # a task on a network, a proposal for one host inside it: still "differs", with its own cause
    (row(canonical="cidr:10.88.0.0/24"), {"canonical": "ip:10.88.0.5"}, r.DIFFERS_FROM_TASK,
     r.INSIDE_TASK_TARGET),
    (row(canonical="cidr:10.88.0.0/24"), {"canonical": "cidr:10.88.0.0/25"}, r.DIFFERS_FROM_TASK,
     r.INSIDE_TASK_TARGET),
    # ... but not a host outside it, a wider network, or the same network under another action
    (row(canonical="cidr:10.88.0.0/24"), {"canonical": "ip:10.99.0.5"}, r.DIFFERS_FROM_TASK,
     r.DIFFERENT_TARGET),
    (row(canonical="cidr:10.88.0.0/24"), {"canonical": "cidr:10.88.0.0/16"}, r.DIFFERS_FROM_TASK,
     r.DIFFERENT_TARGET),
    (row(canonical="cidr:10.88.0.0/24"),
     {"canonical": "ip:10.88.0.5", "action": "network.recon"}, r.DIFFERS_FROM_TASK,
     r.DIFFERENT_ACTION_AND_TARGET),
    (row(canonical="fqdn:a.example"), {"canonical": "ip:10.88.0.5"}, r.DIFFERS_FROM_TASK,
     r.DIFFERENT_TARGET),
])
def test_the_comparison_table(task, kwargs, value, sub):
    got = cmp(task, **kwargs)
    assert (got.value, got.sub_cause) == (value, sub)


def test_a_dead_task_is_not_live_even_when_the_identity_is_the_same():
    """Liveness is judged before identity: a finished task does not vouch for a new proposal."""
    assert cmp(row(status="completed")).value == r.TASK_NOT_LIVE


def test_every_value_the_comparison_can_give_is_in_the_vocabulary():
    """The dataclass refuses a value or sub-cause outside the vocabulary, so a grid of inputs that
    builds at all stayed inside it; and every vocabulary entry is reached by the grid."""
    seen = set()
    statuses = ("queued", "completed")
    canon = (None, "ip:10.88.0.5", "ip:10.88.0.6", "cidr:10.88.0.0/24")
    for status, t_canon, p_canon, p_action in itertools.product(
            statuses, canon, canon, (SCAN, "network.recon")):
        task = row(status=status, canonical=t_canon)
        got = cmp(task, action=p_action, canonical=p_canon)
        seen.add((got.value, got.sub_cause))
    seen.add((cmp(None).value, cmp(None).sub_cause))
    seen.add((r.NO_TASK, r.TASK_ID_ABSENT))
    expected = {(v, s) for v, subs in r.SUB_CAUSES.items() for s in subs}
    assert seen == expected


def test_a_value_outside_the_vocabulary_cannot_be_built():
    with pytest.raises(ValueError):
        r.TaskRelation("probably_fine")
    with pytest.raises(ValueError):
        r.TaskRelation(r.MATCHES_TASK, r.DIFFERENT_TARGET)
    with pytest.raises(ValueError):
        r.TaskRelation(r.DIFFERS_FROM_TASK, None)


def test_live_means_what_the_overlap_warning_means():
    assert r.LIVE_STATUSES == function_api._LIVE_TASK_STATUSES


def test_the_stored_form_is_small_and_carries_the_version():
    got = r.TaskRelation(r.DIFFERS_FROM_TASK, r.DIFFERENT_TARGET, "TASK-1", "queued")
    assert got.as_hint() == {"version": "plan_fit_v1", "task_relation": "differs_from_task",
                             "sub_cause": "different_target"}
    assert got.audit_payload() == {**got.as_hint(), "task_id": "TASK-1", "task_status": "queued"}


# ---------------------------------------------------------------------------------------------
# through propose_action (the real database)
# ---------------------------------------------------------------------------------------------

CIDR = "10.88.0.0/24"
HOST = "10.88.0.5"


class _NoSandbox:
    def run(self, **kwargs):
        from tool_gateway.sandbox import SandboxUnavailable

        raise SandboxUnavailable("dispatch is not what these tests measure")


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", actions={SCAN: ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _scope(registry, engagement_id):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR, allowed_actions=[SCAN])
    return scope_id


def _proposal(scope_id, *, host=HOST, task_id=None, action=SCAN):
    return ProposedAction(
        action=action, target={"logical_identity": {"type": "ip", "value": host}},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"}, task_id=task_id,
    )


def _propose(engagement_id, proposal, *, reviewer=None, key=None):
    return propose_action(
        engagement_id=engagement_id, proposal=proposal, reviewer=reviewer or HonestFakeReviewer(),
        policy=_policy(), agent_id="worker-1", sandbox=_NoSandbox(), network_allowlist=[CIDR],
        idempotency_key=key,
    )


def _hints(engagement_id, proposal_id):
    with engagement_scope(engagement_id) as conn:
        return conn.execute(
            text("SELECT reviewer_hints FROM action_proposals WHERE proposal_id = :p"),
            {"p": proposal_id}).scalar_one()


def _plan(engagement_id, proposal_id):
    """The stored ``plan_fit`` of a decision; its absence is a failed assertion, not a KeyError."""
    hints = _hints(engagement_id, proposal_id)
    assert "plan_fit" in hints, f"no plan_fit stored with the decision: {hints}"
    return hints["plan_fit"]


def _events(engagement_id, proposal_id, event_type="plan_fit.assessed"):
    with engagement_scope(engagement_id) as conn:
        return [dict(x) for x in conn.execute(
            text("SELECT payload FROM audit_log WHERE subject_id = :p AND event_type = :e "
                 "ORDER BY audit_id"), {"p": proposal_id, "e": event_type}).mappings()]


def _task(engagement_id, scope_id, *, host=HOST, action=SCAN, target_type="ip", value=None):
    task = ProposedTask(
        goal="scan the host", action=action, scope_object_id=scope_id,
        target={"logical_identity": {"type": target_type, "value": value or host}})
    with engagement_scope(engagement_id) as conn:
        return create_task(conn, engagement_id=engagement_id, task=task, created_by="supervisor")


def _set_status(engagement_id, task_id, status):
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE tasks SET status = :s WHERE task_id = :t"),
                     {"s": status, "t": task_id})


def test_no_task_is_recorded_stored_and_audited_once(engagement_id, registry):
    scope = _scope(registry, engagement_id)
    outcome = _propose(engagement_id, _proposal(scope))
    plan = _plan(engagement_id, outcome.proposal_id)
    assert plan == {"version": "plan_fit_v1", "task_relation": "no_task",
                    "sub_cause": "task_id_absent"}
    payloads = [e["payload"] for e in _events(engagement_id, outcome.proposal_id)]
    assert len(payloads) == 1 and payloads[0]["task_relation"] == "no_task"


def test_a_matching_task_is_matches_task(engagement_id, registry):
    scope = _scope(registry, engagement_id)
    task_id = _task(engagement_id, scope)
    outcome = _propose(engagement_id, _proposal(scope, task_id=task_id))
    plan = _plan(engagement_id, outcome.proposal_id)
    assert (plan["task_relation"], plan["sub_cause"]) == ("matches_task", None)
    event = _events(engagement_id, outcome.proposal_id)[0]["payload"]
    assert (event["task_id"], event["task_status"]) == (task_id, "queued")


def test_a_task_for_another_host_differs(engagement_id, registry):
    scope = _scope(registry, engagement_id)
    task_id = _task(engagement_id, scope, host="10.88.0.9")
    outcome = _propose(engagement_id, _proposal(scope, task_id=task_id))
    plan = _plan(engagement_id, outcome.proposal_id)
    assert (plan["task_relation"], plan["sub_cause"]) == ("differs_from_task", "different_target")


def test_a_task_on_the_network_and_a_proposal_for_one_host_inside_it(engagement_id, registry):
    """The case the shadow exists to count (DP-13): its own sub-cause, judged as nothing."""
    scope = _scope(registry, engagement_id)
    task_id = _task(engagement_id, scope, target_type="cidr", value=CIDR)
    outcome = _propose(engagement_id, _proposal(scope, task_id=task_id))
    plan = _plan(engagement_id, outcome.proposal_id)
    assert (plan["task_relation"], plan["sub_cause"]) == (
        "differs_from_task", "same_action_target_inside_task_target")


def test_a_completed_task_is_not_live(engagement_id, registry):
    scope = _scope(registry, engagement_id)
    task_id = _task(engagement_id, scope)
    _set_status(engagement_id, task_id, "completed")
    outcome = _propose(engagement_id, _proposal(scope, task_id=task_id))
    plan = _plan(engagement_id, outcome.proposal_id)
    assert (plan["task_relation"], plan["sub_cause"]) == ("task_not_live", "task_status_not_live")
    assert _events(engagement_id, outcome.proposal_id)[0]["payload"]["task_status"] == "completed"


def test_another_engagements_task_is_not_found(engagement_id, registry, engagement_factory):
    """The foreign key on ``tasks(task_id)`` is global, so a proposal can name another engagement's
    task; row-level security hides it, and it reads as not found. (That the insert is accepted is an
    existing quirk, recorded in ACCEPTANCE 5.118 and not changed here.)"""
    scope = _scope(registry, engagement_id)
    other_id, other_registry = engagement_factory()
    other_scope = _scope(other_registry, other_id)
    foreign = _task(other_id, other_scope)
    outcome = _propose(engagement_id, _proposal(scope, task_id=foreign))
    plan = _plan(engagement_id, outcome.proposal_id)
    assert (plan["task_relation"], plan["sub_cause"]) == ("task_not_live", "task_not_found")


def test_a_retried_request_is_one_event_and_one_stored_value(engagement_id, registry):
    scope = _scope(registry, engagement_id)
    task_id = _task(engagement_id, scope)
    proposal, key = _proposal(scope, task_id=task_id), f"key-{uuid.uuid4().hex[:8]}"
    first = _propose(engagement_id, proposal, key=key)
    second = _propose(engagement_id, proposal, key=key)
    assert second.proposal_id == first.proposal_id
    assert len(_events(engagement_id, first.proposal_id)) == 1


def test_the_signal_changes_no_decision_whatever_the_relation(engagement_id, registry):
    """Shadow: the same proposal, with no task, a matching task, a differing one and a dead one,
    is decided identically -- decision, reasons and the reviewer's part of the stored hints."""
    scope = _scope(registry, engagement_id)
    matching = _task(engagement_id, scope)
    differing = _task(engagement_id, scope, host="10.88.0.9")
    dead = _task(engagement_id, scope)
    _set_status(engagement_id, dead, "failed")
    outcomes = {}
    for label, task_id in (("none", None), ("matching", matching), ("differing", differing),
                           ("dead", dead)):
        for reviewer_label, reviewer in (("honest", HonestFakeReviewer()),
                                         ("worried", HonestFakeReviewer(sensitive_hint=("pii",)))):
            out = _propose(engagement_id, _proposal(scope, task_id=task_id), reviewer=reviewer)
            hints = dict(_hints(engagement_id, out.proposal_id))
            hints.pop("plan_fit")
            outcomes[(label, reviewer_label)] = (out.decision, out.deny_reasons,
                                                 out.approval_reasons, hints)
    for reviewer_label in ("honest", "worried"):
        assert len({repr(outcomes[(label, reviewer_label)])
                    for label in ("none", "matching", "differing", "dead")}) == 1
    assert outcomes[("none", "worried")][0] == "HUMAN_APPROVAL"
    assert outcomes[("none", "honest")][0] == "ALLOW"


def test_a_denied_proposal_is_assessed_too(engagement_id, registry):
    """A DENY is a decision like any other: the relation is recorded for it, so the shadow counts
    what the pipeline refused as well as what it let through."""
    _scope(registry, engagement_id)
    out = _propose(engagement_id, _proposal("SCOPE-none"))
    assert out.decision == "DENY"
    assert _plan(engagement_id, out.proposal_id)["task_relation"] == "no_task"


def test_task_for_builds_a_task_the_comparison_matches(engagement_id, registry):
    """The fixture helper of S1 and the comparison of S2 agree: its task is ``matches_task``."""
    scope = _scope(registry, engagement_id)
    proposal = _proposal(scope)
    task_id = task_for(engagement_id, proposal)
    canonical, key = _task_identity(proposal.action, proposal.target)
    with engagement_scope(engagement_id) as conn:
        got = r.assess_task_relation(conn, task_id=task_id, action=proposal.action,
                                     canonical_target=canonical, identity_key=key)
    assert got.value == "matches_task"


# ---------------------------------------------------------------------------------------------
# DP-12: nothing else in the database depends on the shape of reviewer_hints
# ---------------------------------------------------------------------------------------------

def test_nothing_in_the_database_depends_on_the_shape_of_reviewer_hints(engagement_id):
    """The condition under which the signal is stored as a key inside the existing column
    (DP-12) instead of in a new one: no trigger, check constraint, index, view, policy or function
    reads or validates ``action_proposals.reviewer_hints``. If one is ever added, this fails and the
    decision is taken again."""
    with engagement_scope(engagement_id) as conn:
        def rows(sql):
            return [tuple(x) for x in conn.execute(text(sql)).all()]

        assert rows("SELECT tgname FROM pg_trigger WHERE tgrelid = 'action_proposals'::regclass "
                    "AND NOT tgisinternal") == []
        assert [c for c in rows(
            "SELECT conname FROM pg_constraint WHERE conrelid = 'action_proposals'::regclass "
            "AND pg_get_constraintdef(oid) ILIKE '%reviewer_hints%'")] == []
        assert rows("SELECT indexname FROM pg_indexes WHERE tablename = 'action_proposals' "
                    "AND indexdef ILIKE '%reviewer_hints%'") == []
        assert rows("SELECT viewname FROM pg_views WHERE definition ILIKE '%reviewer_hints%'") == []
        assert rows("SELECT proname FROM pg_proc WHERE prosrc ILIKE '%reviewer_hints%'") == []
        assert rows("SELECT policyname FROM pg_policies WHERE tablename = 'action_proposals' AND "
                    "(coalesce(qual, '') || coalesce(with_check, '')) ILIKE '%reviewer_hints%'"
                    ) == []
