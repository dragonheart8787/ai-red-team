"""The web console — D29's two verification requirements.

1. **Approving through the console is the same act as approving through the
   CLI.** Not "similar": the same underlying call, producing the same §4.7 row
   and the same audit record, because both front ends call ``grant_approval``.
   The test asserts that by driving two equivalent engagements — one through the
   HTTP endpoint, one through the D24 function ``scripts/approvals.py`` calls —
   and comparing what each left behind.

2. **The console's read role cannot write anything.** ``ui_reader`` is asserted
   against the database rather than against the application: SELECT works,
   every write is refused, and the engagement boundary still holds. A test that
   only checked the handlers never call a write would prove the handlers as
   written today, not the boundary.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.approvals import grant_approval, list_pending_approvals
from control_plane.api.function_api import propose_action
from control_plane.audit.query import events_for_subject
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.state.db import engagement_scope, ui_reader_scope
from control_plane.web.app import app

CIDR = "10.79.0.0/24"
HOST = "10.79.0.2"


@pytest.fixture
def client():
    return TestClient(app)


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global",
                    data_deny=frozenset({"PII", "customer_database"}),
                    actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _escalate(engagement_id, registry):
    """One HUMAN_APPROVAL proposal waiting, the D24 way (a sensitive-data hint)."""
    scope_id = f"SCOPE-{engagement_id[-10:]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.recon", "network.scan"])
    proposal = ProposedAction(
        action="network.scan",
        # Deliberately not the defaults ("8080"/"connect"): with those, a
        # console showing the request and a console showing a fallback are
        # indistinguishable, which is how D30's defect went unseen here.
        target={"logical_identity": {"type": "ip", "value": HOST},
                "ports": "443", "scan_type": "version"},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
    )
    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(sensitive_hint=("pii",)),
            policy=_policy(), agent_id="worker-1",
        )
    assert outcome.decision == "HUMAN_APPROVAL"
    return scope_id, outcome.proposal_id


@pytest.fixture
def escalated(engagement_id, registry):
    return (engagement_id, *_escalate(engagement_id, registry))


def _approval_row(engagement_id, proposal_id):
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT action_class, resource, constraints, approved_by, "
                 "approved_scope, revoked FROM approvals WHERE proposal_id = :p"),
            {"p": proposal_id},
        ).mappings().one_or_none()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Requirement 1 — the console and the CLI are one act
# ---------------------------------------------------------------------------

def test_approving_through_the_console_matches_approving_through_the_cli(
    client, escalated, engagement_factory
):
    """Same §4.7 row, same audit trail, from two front ends over one function.

    The console approves one engagement over HTTP; the second engagement is
    approved by calling ``grant_approval`` directly, which is exactly what
    ``scripts/approvals.py`` does. Everything that is not an identifier or a
    timestamp must match — if the console had grown its own approval logic, this
    is where the two would diverge.
    """
    eid_web, _, pid_web = escalated
    eid_cli, registry_cli = engagement_factory()
    _, pid_cli = _escalate(eid_cli, registry_cli)

    r = client.post(
        f"/api/engagements/{eid_web}/approvals/{pid_web}/approve",
        json={"approver": "operator-x", "approved_scope": "this_task",
              "valid_for_seconds": 3600},
    )
    assert r.status_code == 200, r.text

    with engagement_scope(eid_cli) as conn:
        grant_approval(
            conn, engagement_id=eid_cli, proposal_id=pid_cli,
            approver="operator-x", approved_scope="this_task",
            valid_for_seconds=3600,
        )

    web_row, cli_row = _approval_row(eid_web, pid_web), _approval_row(eid_cli, pid_cli)
    assert web_row is not None and cli_row is not None
    assert web_row == cli_row, "the console wrote a different §4.7 object than the CLI"

    def audit_shape(eid, pid):
        with engagement_scope(eid) as conn:
            events = events_for_subject(conn, subject_id=pid)
        return [
            (e.event_type, e.actor, e.decision,
             sorted(k for k in e.payload if k not in ("approval_id",)))
            for e in events
        ]

    assert audit_shape(eid_web, pid_web) == audit_shape(eid_cli, pid_cli), (
        "the console's audit trail differs in shape from the CLI's"
    )


def test_the_console_approval_leaves_the_queue_and_issues_a_capability(
    client, escalated
):
    """The visible outcome: gone from the queue, capability minted by the broker."""
    eid, _, pid = escalated
    assert client.get(f"/api/engagements/{eid}/approvals").json()

    body = client.post(
        f"/api/engagements/{eid}/approvals/{pid}/approve",
        json={"approver": "operator-x", "approved_scope": "this_proposal_only"},
    ).json()

    assert body["issued"] is True
    assert body["capability_id"]
    assert body["approved_scope"] == "this_proposal_only"
    assert client.get(f"/api/engagements/{eid}/approvals").json() == []


def test_denying_through_the_console_mints_nothing(client, escalated):
    eid, _, pid = escalated
    r = client.post(f"/api/engagements/{eid}/approvals/{pid}/deny",
                    json={"denier": "operator-x", "reason": "out of window"})
    assert r.status_code == 200
    assert _approval_row(eid, pid) is None
    with engagement_scope(eid) as conn:
        kinds = {e.event_type for e in events_for_subject(conn, subject_id=pid)}
    assert "approval.denied" in kinds
    assert "capability.issued" not in kinds


# ---------------------------------------------------------------------------
# Constraints 1–3 — the console adds no decision of its own
# ---------------------------------------------------------------------------

def test_the_preview_matches_what_the_grant_actually_writes(client, escalated):
    """D29 constraint 3: the operator consents to the object that gets stored.

    Preview and grant share one derivation (``approval_fields``). If they were
    two implementations, a preview could show constraints the grant did not
    write, and the operator's consent would be to something that never happened.
    """
    eid, _, pid = escalated
    preview = client.get(
        f"/api/engagements/{eid}/approvals/{pid}/preview?valid_for_seconds=3600"
    ).json()

    assert preview["approved_scope_options"] == [
        "this_proposal_only", "this_task", "this_resource",
    ], "§4.7's scopes must be offered individually, never as one approve-all"
    assert preview["authorization_still_holds"] is True

    client.post(f"/api/engagements/{eid}/approvals/{pid}/approve",
                json={"approver": "operator-x", "approved_scope": "this_task",
                      "valid_for_seconds": 3600})
    stored = _approval_row(eid, pid)
    assert stored["action_class"] == preview["action_class"]
    assert stored["resource"] == preview["resource"]
    assert stored["constraints"] == preview["constraints"]

    # Agreement alone is not enough: a shared derivation makes preview and
    # stored agree even when both are wrong, which mutation testing confirmed
    # by pointing the shared function at invented constraints and watching this
    # test stay green. So anchor on what the proposal actually said.
    assert preview["action_class"] == "network.scan"
    assert preview["resource"] == f"ip:{HOST}"

    # This assertion is where D29 found the defect D30 then fixed. It used to
    # read {"ports": None, "scan_type": None}: the console faithfully displayed
    # a §4.7 record that described nothing, because `_persist_proposal` had
    # dropped the proposal's execution parameters and `grant_approval` — holding
    # only the stored row — recorded the resulting absence while issuing a
    # capability built from defaults.
    #
    # Now the console shows what the proposal asked for and what the capability
    # will carry, because they are one derivation (D30).
    assert preview["constraints"] == {"ports": "443", "scan_type": "version"}


def test_the_console_refuses_a_scope_outside_section_4_7(client, escalated):
    """There is no approve-everything, and inventing one is a 422."""
    eid, _, pid = escalated
    r = client.post(f"/api/engagements/{eid}/approvals/{pid}/approve",
                    json={"approver": "operator-x", "approved_scope": "everything"})
    assert r.status_code == 422
    assert _approval_row(eid, pid) is None


def test_the_console_cannot_approve_what_opa_never_escalated(
    client, engagement_id, registry
):
    """D29 constraint 2: OPA decides who needs a human, not this UI.

    A DENY proposal is not an escalation, and the console has no route that
    turns one into an approvable item — the refusal comes from ``grant_approval``
    itself, which the console does not get to second-guess.
    """
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": HOST}},
        authorization={"source": "engagement_scope", "scope_object_id": "MISSING"},
        discovery={"source": "explicit_scope"},
    )
    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="worker-1",
        )
    assert outcome.decision == "DENY"

    r = client.post(
        f"/api/engagements/{engagement_id}/approvals/{outcome.proposal_id}/approve",
        json={"approver": "operator-x", "approved_scope": "this_task"},
    )
    assert r.status_code == 409
    assert "not awaiting a human" in r.json()["detail"]


def test_the_console_exposes_no_route_that_drives_an_agent(client):
    """D29 constraint 1, asserted on the route table rather than by reading it.

    The console may read and may approve or deny. It must expose nothing that
    creates a task, submits a proposal, or invokes a tool, and no endpoint that
    takes free text destined for a model. Written mechanically because "we did
    not add one" is a statement about today.
    """
    paths = {
        (r.path, method)
        for r in app.routes
        for method in getattr(r, "methods", set())
        if method not in ("HEAD", "OPTIONS")
    }
    writes = {p for p, m in paths if m in ("POST", "PUT", "PATCH", "DELETE")}
    assert writes == {
        "/api/engagements/{engagement_id}/approvals/{proposal_id}/approve",
        "/api/engagements/{engagement_id}/approvals/{proposal_id}/deny",
    }, f"unexpected write route(s): {writes}"

    forbidden = ("task", "propose", "proposal", "dispatch", "scan", "tool",
                 "prompt", "chat", "message", "command")
    for path in writes:
        segment = path.rsplit("/", 1)[-1]
        assert not any(f in segment for f in forbidden), path


# ---------------------------------------------------------------------------
# Requirement 2 / constraint 4 — the read role's boundary, asserted on the DB
# ---------------------------------------------------------------------------

def test_the_console_never_renders_a_granted_approvals_constraints(
    client, escalated
):
    """Pins the reason historical NULL constraints cannot mislead anyone (D30).

    Rows written before D30 carry ``constraints`` of NULL, meaning *unknown
    scope* rather than *no constraints were imposed*, and they are deliberately
    left that way (``ACCEPTANCE_MVP1_AGENTS.md`` §5). That decision rests on a
    fact about this console: it has no surface that shows a granted approval's
    constraints, so a NULL is never rendered as a blank that reads like "nothing
    was restricted".

    Asserted rather than described, because the fact is what makes the decision
    safe and a sentence in a document does not fail when it stops being true —
    which is lesson 1 in that same section. If a granted-approvals view is added
    later, this goes red and the NULL handling has to be decided on purpose.
    """
    eid, _, pid = escalated
    client.post(f"/api/engagements/{eid}/approvals/{pid}/approve",
                json={"approver": "operator-x", "approved_scope": "this_task"})

    # The approval now exists and carries constraints in the database.
    with engagement_scope(eid) as conn:
        stored = conn.execute(
            text("SELECT constraints FROM approvals WHERE proposal_id = :p"),
            {"p": pid},
        ).scalar()
    assert stored, "the approval should have been written"

    # No read endpoint surfaces it. The queue is pending-only and now empty; the
    # preview refuses a decided proposal; the task history carries the
    # approval.granted event, whose payload has no constraints.
    assert client.get(f"/api/engagements/{eid}/approvals").json() == []
    assert client.get(
        f"/api/engagements/{eid}/approvals/{pid}/preview"
    ).status_code == 409

    with engagement_scope(eid) as conn:
        task_id = conn.execute(
            text("SELECT task_id FROM action_proposals WHERE proposal_id = :p"),
            {"p": pid},
        ).scalar()
    if task_id:
        history = client.get(
            f"/api/engagements/{eid}/tasks/{task_id}/history"
        ).json()
        assert "constraints" not in json.dumps(history), (
            "the task history now exposes approval constraints; NULL rows from "
            "before D30 would render here and must be handled explicitly"
        )

    overview = client.get(f"/api/engagements/{eid}/overview").json()
    assert "constraints" not in json.dumps(overview)


def test_ui_reader_can_read_the_dashboard_tables(escalated):
    eid, _, _ = escalated
    with ui_reader_scope(eid) as conn:
        assert list_pending_approvals(conn, engagement_id=eid)
        assert conn.execute(text("SELECT count(*) FROM findings")).scalar() is not None


@pytest.mark.parametrize("statement", [
    "INSERT INTO findings (finding_id, engagement_id, claim, state, "
    "evidence_strength, evidence_ids, affects, attack_path_ids, "
    "verification_conflict) VALUES ('F-X', :eid, 'x', 'candidate', 'E1', "
    "'{}', '{}'::jsonb, '{}', false)",
    "UPDATE tasks SET status = 'completed'",
    "DELETE FROM action_proposals",
    "INSERT INTO approvals (approval_id, engagement_id, action_class, "
    "constraints, valid_until, approved_by, approved_scope) VALUES "
    "('A-X', :eid, 'network.scan', '{}'::jsonb, now(), 'x', 'this_task')",
    "INSERT INTO audit_log (engagement_id, scope, actor, event_type, reasons, "
    "payload) VALUES (:eid, 'engagement', 'x', 'x', '{}', '{}'::jsonb)",
])
def test_ui_reader_cannot_write_anything(escalated, statement):
    """Including ``audit_log``, and that one is the point.

    ``cyberorch_app`` holds INSERT on ``audit_log`` because it has to record
    decisions. The console's *reads* have no such need, so the role that serves
    them cannot forge an audit record either — the trail can only be written by
    the path that actually decides something.
    """
    eid, _, _ = escalated
    with pytest.raises(ProgrammingError, match="permission denied"):
        with ui_reader_scope(eid) as conn:
            conn.execute(text(statement), {"eid": eid})


def test_ui_reader_cannot_reach_tables_the_dashboard_does_not_show(escalated):
    """The grant is the list of what the console displays, not "read everything".

    ``credentials`` is the sharpest case: it is engagement data the console has
    no reason to render, so the read role cannot see it at all.
    """
    eid, _, _ = escalated
    for table in ("credentials", "metadata_registry", "provenance_edges"):
        with pytest.raises(ProgrammingError, match="permission denied"):
            with ui_reader_scope(eid) as conn:
                conn.execute(text(f"SELECT count(*) FROM {table}"))


def test_the_read_endpoints_actually_use_the_read_only_role(client, escalated,
                                                            monkeypatch):
    """The role boundary is only worth anything if the handlers go through it.

    The tests above prove ``ui_reader`` cannot write. This proves the console's
    read endpoints are the thing using it — otherwise a handler could quietly
    switch to ``engagement_scope`` and every assertion above would stay green
    while the browser-facing reads regained INSERT. Same shape as D25's
    shared-predicate check: patch the seam and require the behaviour to change.
    """
    import control_plane.web.app as web

    eid, _, pid = escalated
    calls: list[str] = []
    real = web.ui_reader_scope

    def spy(engagement_id):
        calls.append(engagement_id)
        return real(engagement_id)

    monkeypatch.setattr(web, "ui_reader_scope", spy)

    for path in ("/overview", "/findings", "/approvals",
                 f"/approvals/{pid}/preview"):
        assert client.get(f"/api/engagements/{eid}{path}").status_code == 200
    assert calls == [eid] * 4, "a read endpoint bypassed the read-only role"

    # And the name must still be bound to the read-only role. Checking only
    # that the handlers call something named ui_reader_scope would pass if it
    # were rebound to the write role -- mutation testing found exactly that,
    # so the database is asked who it thinks is connected.
    with web.ui_reader_scope(eid) as conn:
        assert conn.execute(text("SELECT current_user")).scalar() == "ui_reader"

    # And the writes deliberately do not: they need the D24 path.
    calls.clear()
    assert client.post(
        f"/api/engagements/{eid}/approvals/{pid}/deny",
        json={"denier": "operator-x"},
    ).status_code == 200
    assert calls == [], "a write endpoint ran on the read-only role"


def test_the_console_cannot_read_another_engagement(client, escalated,
                                                    engagement_factory):
    """I4 through the console: naming another engagement returns *its* nothing.

    RLS decides what the connection can see, and the id in the URL only names
    the scope to pin. There is no cross-engagement view (D29 constraint 4), so
    asking for one yields an empty engagement rather than someone else's data.
    """
    eid_a, _, _ = escalated
    eid_b, registry_b = engagement_factory()
    _, pid_b = _escalate(eid_b, registry_b)

    assert client.get(f"/api/engagements/{eid_b}/approvals").json() != []
    # Engagement A's console, asked for B's proposal, sees nothing of B's.
    seen = client.get(f"/api/engagements/{eid_a}/approvals").json()
    assert all(p["proposal_id"] != pid_b for p in seen)

    r = client.get(f"/api/engagements/{eid_a}/approvals/{pid_b}/preview")
    assert r.status_code == 409
    assert "not found in this engagement" in r.json()["detail"]
