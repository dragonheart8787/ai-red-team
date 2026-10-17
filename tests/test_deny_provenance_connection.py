"""A denial recorded on an autocommit connection has no provenance, and says so (ACCEPTANCE 5.110).

``deny_approval`` records the provenance of the finished proposal inside a savepoint, so that a
failure there cannot take the denial with it. A savepoint needs a transaction; on an autocommit
connection (the one ``tests.helpers.committing_scope`` opens, and so the soak's approver) Postgres
refuses it, the product catches it, logs "provenance for denied ... was not recorded" and goes on.
These two tests pin both halves: the transactional path records provenance; the autocommit path
closes the proposal, records the denial, writes no provenance, logs, and does not raise.
"""

from __future__ import annotations

import logging

from sqlalchemy import text

from control_plane.api.approvals import deny_approval
from control_plane.orchestrator import stages
from control_plane.state.db import engagement_scope as transactional_scope
from tests.helpers import committing_scope
from tests.test_approvals import escalated  # noqa: F401  (the fixture)


def _edges(conn, proposal_id) -> int:
    return conn.execute(
        text("SELECT count(*) FROM provenance_edges WHERE from_id = :p OR to_id = :p"),
        {"p": proposal_id}).scalar_one()


def test_a_denial_on_a_transactional_connection_records_the_provenance(escalated, caplog):  # noqa: F811
    engagement_id, _, proposal_id = escalated
    with caplog.at_level(logging.ERROR):
        with transactional_scope(engagement_id) as conn:
            deny_approval(conn, engagement_id=engagement_id, proposal_id=proposal_id,
                          denier="alice", reason="x")
    assert "was not recorded" not in caplog.text
    with committing_scope(engagement_id) as conn:
        assert stages.stage_of(conn, proposal_id) == ("closed", "approval_denied")
        assert _edges(conn, proposal_id) > 0


def test_a_denial_on_an_autocommit_connection_closes_the_proposal_without_provenance_and_logs(
        escalated, caplog):  # noqa: F811
    engagement_id, _, proposal_id = escalated
    raised = None
    with caplog.at_level(logging.ERROR):
        with committing_scope(engagement_id) as conn:
            try:
                deny_approval(conn, engagement_id=engagement_id, proposal_id=proposal_id,
                              denier="alice", reason="x")
            except Exception as exc:  # noqa: BLE001 -- the point is that nothing escapes
                raised = exc
    assert raised is None, repr(raised)
    assert f"provenance for denied {proposal_id} was not recorded" in caplog.text
    with committing_scope(engagement_id) as conn:
        assert stages.stage_of(conn, proposal_id) == ("closed", "approval_denied")
        assert _edges(conn, proposal_id) == 0
