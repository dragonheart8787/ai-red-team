"""What the scheduler's three database roles can and cannot do (D62).

The narrow reader is the security claim of the design: the code that *decides* what to dispatch
holds a connection that cannot read what it must not decide on -- a proposal's target, a task's
goal, evidence, a credential, the audit payloads. These tests use real connections as each role,
not a model of the grants: a permission that is missing is an error from PostgreSQL, a permission
that is extra is a failed assertion on the whole grant matrix below.

``GRANTS`` is the complete list. Anything not in it is denied, and the matrix test enumerates every
table and view in the schema, so a grant added to any of these roles (or to a table added later)
fails here until someone writes it down on purpose.
"""

from __future__ import annotations

import re
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from control_plane.scheduler import state, vocab
from control_plane.state.db import (
    get_engine,
    scheduler_admin_scope,
    scheduler_reader_enrollment_scope,
    scheduler_reader_scope,
    scheduler_state_writer_scope,
)
from tests import scheduler_support as sup
from tool_gateway.registry import ADAPTERS

READER, ADMIN, WRITER = "scheduler_reader", "scheduler_admin", "scheduler_state_writer"

#: role -> relation -> privilege -> "ALL" or the columns granted. The complete grant list.
GRANTS = {
    READER: {
        "engagements": {"SELECT": ["engagement_id", "status", "kill_switch_engaged"]},
        "scheduler_enrollment": {"SELECT": "ALL"},
        "scheduler_proposals": {"SELECT": "ALL"},
        "scheduler_state": {"SELECT": "ALL"},
    },
    ADMIN: {
        "scheduler_enrollment": {"SELECT": "ALL", "INSERT": "ALL",
                                 "UPDATE": ["withdrawn_by", "withdrawn_at"]},
    },
    WRITER: {
        "scheduler_state": {"SELECT": "ALL", "INSERT": "ALL",
                            "UPDATE": ["disposition", "reason_code", "since"]},
    },
}

VIEW_COLUMNS = ["proposal_id", "engagement_id", "pipeline_stage", "stage_updated_at",
                "action_class"]


def _matrix(role: str) -> dict:
    out: dict = {}
    with get_engine().connect() as conn:
        relations = conn.execute(text(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v') ORDER BY 1")).scalars().all()
        for rel in relations:
            oid = f"public.{rel}"
            columns = conn.execute(text(
                "SELECT attname FROM pg_attribute WHERE attrelid = CAST(:o AS regclass) "
                "AND attnum > 0 AND NOT attisdropped ORDER BY attnum"), {"o": oid}).scalars().all()
            granted: dict = {}
            for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                if conn.execute(text("SELECT has_table_privilege(:r, CAST(:o AS regclass), :p)"),
                                {"r": role, "o": oid, "p": priv}).scalar_one():
                    granted[priv] = "ALL"
                elif priv != "DELETE":
                    cols = [c for c in columns if conn.execute(text(
                        "SELECT has_column_privilege(:r, CAST(:o AS regclass), :c, :p)"),
                        {"r": role, "o": oid, "c": c, "p": priv}).scalar_one()]
                    if cols:
                        granted[priv] = cols
            if granted:
                out[rel] = granted
    return out


@pytest.mark.parametrize("role", [READER, ADMIN, WRITER])
def test_each_role_has_exactly_the_grants_listed_and_nothing_else(db_available, role):
    assert _matrix(role) == GRANTS[role]


def test_the_pipelines_own_role_has_no_grant_on_the_schedulers_tables(db_available):
    app = _matrix("cyberorch_app")
    assert "scheduler_enrollment" not in app and "scheduler_state" not in app
    assert "scheduler_proposals" not in app


def test_the_three_roles_cannot_bypass_row_security_or_own_anything(db_available):
    with get_engine().connect() as conn:
        rows = conn.execute(text(
            "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin "
            "FROM pg_roles WHERE rolname = ANY(:r) ORDER BY 1"),
            {"r": [READER, ADMIN, WRITER]}).all()
    assert [r[0] for r in rows] == sorted([READER, ADMIN, WRITER])
    for _name, sup_, bypass, createrole, createdb, login in rows:
        assert (sup_, bypass, createrole, createdb, login) == (False, False, False, False, True)


# ---------------------------------------------------------------------------------------------
# the reader, on a real connection
# ---------------------------------------------------------------------------------------------

@pytest.fixture
def two_engagements(engagement_factory):
    (a, reg_a), (b, reg_b) = engagement_factory(), engagement_factory()
    out = {}
    for eid, reg, cidr in ((a, reg_a, "10.96.70.0/24"), (b, reg_b, "10.96.71.0/24")):
        sup.publish_engagement_policy(eid)
        scope_id = sup.register_scope(reg, type="cidr", value=cidr)
        out[eid] = sup.approved_proposal(eid, scope_id, host=cidr.replace("0/24", "9"))
    return out


def test_the_reader_reads_the_columns_it_was_given(two_engagements):
    (a, pa), _ = list(two_engagements.items())
    with scheduler_reader_scope(a) as conn:
        engagement = conn.execute(text(
            "SELECT engagement_id, status, kill_switch_engaged FROM engagements")).all()
        view = conn.execute(text("SELECT * FROM scheduler_proposals")).mappings().all()
        assert conn.execute(text("SELECT count(*) FROM scheduler_state")).scalar_one() == 0
    assert engagement == [(a, "active", False)]
    (row,) = view
    assert list(row) == VIEW_COLUMNS
    assert (row["proposal_id"], row["pipeline_stage"], row["action_class"]) == (
        pa, "approved", "network.scan")
    with scheduler_reader_enrollment_scope() as conn:
        assert conn.execute(text("SELECT count(*) FROM scheduler_enrollment")).scalar_one() >= 0


@pytest.mark.parametrize("sql", [
    # the engagement's other columns
    "SELECT customer_id FROM engagements",
    "SELECT policy_snapshot_version FROM engagements",
    "SELECT * FROM engagements",
    # the proposal itself: the target, the identity, the free-text action
    "SELECT target FROM action_proposals",
    "SELECT action FROM action_proposals",
    "SELECT reason FROM action_proposals",
    'SELECT "authorization" FROM action_proposals',
    "SELECT decision_reasons FROM action_proposals",
    "SELECT stage_detail FROM action_proposals",
    "SELECT request_idempotency_key FROM action_proposals",
    "SELECT goal FROM tasks",
    "SELECT count(*) FROM action_proposals",
    # everything else the pipeline writes
    "SELECT count(*) FROM tasks",
    "SELECT count(*) FROM findings",
    "SELECT count(*) FROM credentials",
    "SELECT count(*) FROM evidence",
    "SELECT count(*) FROM credential_material",
    "SELECT count(*) FROM audit_log",
    "SELECT count(*) FROM approvals",
    "SELECT count(*) FROM capabilities",
    "SELECT count(*) FROM tool_runs",
    "SELECT count(*) FROM scope_registry",
    "SELECT count(*) FROM policy_layers",
])
def test_the_reader_is_refused_everything_it_was_not_granted(two_engagements, sql):
    (a, _), _ = list(two_engagements.items())
    with pytest.raises(ProgrammingError) as refused:
        with scheduler_reader_scope(a) as conn:
            conn.execute(text(sql))
    assert "permission denied" in str(refused.value), sql


def test_the_view_does_not_expose_the_columns_the_base_table_holds(two_engagements):
    (a, _), _ = list(two_engagements.items())
    for column in ("target", "action", "reason", "stage_detail", "authorization", "task_id"):
        with pytest.raises(ProgrammingError) as refused:
            with scheduler_reader_scope(a) as conn:
                conn.execute(text(f'SELECT "{column}" FROM scheduler_proposals'))
        assert "does not exist" in str(refused.value), column      # not in the view at all


def test_the_reader_sees_one_engagement_at_a_time(two_engagements):
    (a, pa), (b, pb) = list(two_engagements.items())
    with scheduler_reader_scope(a) as conn:
        assert [r[0] for r in conn.execute(text(
            "SELECT proposal_id FROM scheduler_proposals"))] == [pa]
        assert [r[0] for r in conn.execute(text("SELECT engagement_id FROM engagements"))] == [a]
        # naming the other engagement does not help
        assert conn.execute(text("SELECT count(*) FROM scheduler_proposals "
                                 "WHERE engagement_id = :b"), {"b": b}).scalar_one() == 0
    with scheduler_reader_scope(b) as conn:
        assert [r[0] for r in conn.execute(text(
            "SELECT proposal_id FROM scheduler_proposals"))] == [pb]


def test_a_reader_connection_with_no_engagement_bound_sees_no_engagement_data(two_engagements):
    with scheduler_reader_enrollment_scope() as conn:
        assert conn.execute(text("SELECT count(*) FROM scheduler_proposals")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM engagements")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM scheduler_state")).scalar_one() == 0


@pytest.mark.parametrize("sql", [
    "UPDATE engagements SET status = 'active'",
    "UPDATE engagements SET kill_switch_engaged = false",
    "INSERT INTO scheduler_state (engagement_id, kind, disposition) VALUES ('x', 'engagement', "
    "'served')",
    "DELETE FROM scheduler_state",
    "INSERT INTO scheduler_enrollment (engagement_id, enrolled_by) VALUES ('x', 'y')",
    "UPDATE scheduler_enrollment SET withdrawn_at = now()",
])
def test_the_reader_cannot_write(two_engagements, sql):
    (a, _), _ = list(two_engagements.items())
    with pytest.raises(ProgrammingError):
        with scheduler_reader_scope(a) as conn:
            conn.execute(text(sql))


# ---------------------------------------------------------------------------------------------
# the other two roles
# ---------------------------------------------------------------------------------------------

def test_the_enrollment_writer_refuses_a_nonexistent_engagement_and_reads_nothing_else(
    db_available,
):
    with pytest.raises(IntegrityError):
        with scheduler_admin_scope() as conn:
            conn.execute(text("INSERT INTO scheduler_enrollment (engagement_id, enrolled_by) "
                              "VALUES (:e, 'op')"), {"e": f"ENG-NOPE-{uuid.uuid4().hex[:8]}"})
    for table in ("engagements", "action_proposals", "scheduler_state", "audit_log"):
        with pytest.raises(ProgrammingError):
            with scheduler_admin_scope() as conn:
                conn.execute(text(f"SELECT count(*) FROM {table}"))


def test_an_enrollment_is_fixed_once_written_except_for_its_withdrawal(engagement_id):
    sup.enroll(engagement_id)
    try:
        with pytest.raises(DBAPIError):
            with scheduler_admin_scope() as conn:
                conn.execute(text("UPDATE scheduler_enrollment SET enrolled_by = 'someone-else' "
                                  "WHERE engagement_id = :e"), {"e": engagement_id})
        with pytest.raises(IntegrityError):               # a second live enrollment
            sup.enroll(engagement_id)
    finally:
        sup.withdraw(engagement_id)
    with pytest.raises(DBAPIError):                         # and nothing un-withdraws it
        with scheduler_admin_scope() as conn:
            conn.execute(text("UPDATE scheduler_enrollment SET withdrawn_at = NULL, "
                              "withdrawn_by = NULL WHERE engagement_id = :e"), {"e": engagement_id})


def test_the_state_writer_writes_its_table_and_reads_nothing_of_the_pipeline(two_engagements):
    (a, pa), _ = list(two_engagements.items())
    state.record_proposal(a, pa, vocab.SKIPPED_STATE, vocab.SCOPE_TOO_NARROW)
    for table in ("action_proposals", "engagements", "audit_log", "tasks", "evidence"):
        with pytest.raises(ProgrammingError):
            with scheduler_state_writer_scope(a) as conn:
                conn.execute(text(f"SELECT count(*) FROM {table}"))
    with pytest.raises(ProgrammingError):
        with scheduler_state_writer_scope(a) as conn:
            conn.execute(text("UPDATE scheduler_state SET engagement_id = engagement_id"))


def test_the_state_writer_cannot_write_into_another_engagement(two_engagements):
    (a, _), (b, pb) = list(two_engagements.items())
    with pytest.raises(DBAPIError):
        with scheduler_state_writer_scope(a) as conn:
            conn.execute(text(
                "INSERT INTO scheduler_state (engagement_id, proposal_id, kind, disposition, "
                "reason_code) VALUES (:b, :p, 'proposal', 'skipped', 'scope_narrower_than_"
                "sandbox_minimum')"), {"b": b, "p": pb})


# ---------------------------------------------------------------------------------------------
# scheduler_state is closed vocabulary, in the database
# ---------------------------------------------------------------------------------------------

def _write(engagement_id, proposal_id, disposition, reason, kind="proposal"):
    with scheduler_state_writer_scope(engagement_id) as conn:
        conn.execute(text(
            "INSERT INTO scheduler_state (engagement_id, proposal_id, kind, disposition, "
            "reason_code) VALUES (:e, :p, :k, :d, :r) "
            "ON CONFLICT (engagement_id, (COALESCE(proposal_id, ''))) DO UPDATE SET "
            "disposition = EXCLUDED.disposition, reason_code = EXCLUDED.reason_code"),
            {"e": engagement_id, "p": proposal_id if kind == "proposal" else None,
             "k": kind, "d": disposition, "r": reason})


@pytest.mark.parametrize("code", vocab.SKIP_REASONS)
def test_every_skip_code_is_accepted(two_engagements, code):
    (a, pa), _ = list(two_engagements.items())
    _write(a, pa, vocab.SKIPPED_STATE, code)
    with scheduler_reader_scope(a) as conn:
        assert tuple(conn.execute(text(
            "SELECT disposition, reason_code FROM scheduler_state WHERE proposal_id = :p"),
            {"p": pa}).one()) == (vocab.SKIPPED_STATE, code)


@pytest.mark.parametrize("code", [
    "because_i_said_so", "", "SCOPE_NARROWER_THAN_SANDBOX_MINIMUM", "scope_narrower",
    "10.96.70.9", "scope_narrower_than_sandbox_minimum ",
    "no_usable_block_for_address",                         # retired at 0020: widening was removed
    None,                                                  # a skip without a reason
    *vocab.DEFER_REASONS,                                  # a valid code, but not a *skip* code
    vocab.APPROVED_AND_IDLE,
])
def test_a_skip_reason_outside_the_five_codes_is_refused_by_the_database(two_engagements, code):
    (a, pa), _ = list(two_engagements.items())
    with pytest.raises(IntegrityError):
        _write(a, pa, vocab.SKIPPED_STATE, code)


@pytest.mark.parametrize("disposition,code", [
    (vocab.SERVED, vocab.SCOPE_TOO_NARROW),
    (vocab.DEFERRED_STATE, vocab.SCOPE_TOO_NARROW),
    (vocab.DEFERRED_STATE, None),
    (vocab.DISPATCH_DECIDED, vocab.SCOPE_TOO_NARROW),
    ("decided_by_gut_feeling", None),
])
def test_the_other_columns_are_closed_too(two_engagements, disposition, code):
    (a, pa), _ = list(two_engagements.items())
    with pytest.raises(IntegrityError):
        _write(a, pa, disposition, code)


def test_the_vocabulary_in_the_constraints_is_the_vocabulary_in_the_code(db_available):
    """No code accepted by the database that ``vocab`` does not list; none listed but refused."""
    with get_engine().connect() as conn:
        definitions = conn.execute(text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'scheduler_state'::regclass AND contype = 'c'")).scalars().all()
    literals = {m for d in definitions for m in re.findall(r"'([^']*)'", d)}
    expected = ({"engagement", "proposal", vocab.APPROVED_AND_IDLE}
                | set(vocab.DISPOSITIONS) | set(vocab.DEFER_REASONS) | set(vocab.SKIP_REASONS))
    assert literals == expected
    # and the clause that ties a *skip* to its reason lists exactly the five, not more
    (skip_clause,) = re.findall(
        r"disposition = 'skipped'::text\) AND \(reason_code IS NOT NULL\) "
        r"AND \(reason_code = ANY \(ARRAY\[(.*?)\]\)", " ".join(definitions))
    assert set(re.findall(r"'([^']*)'", skip_clause)) == set(vocab.SKIP_REASONS)
    assert len(vocab.SKIP_REASONS) == 5


# ---------------------------------------------------------------------------------------------
# action_class is closed vocabulary too: the database makes it so
# ---------------------------------------------------------------------------------------------

def test_the_views_registered_actions_are_the_registrys_adapters(db_available):
    with get_engine().connect() as conn:
        definition = conn.execute(text(
            "SELECT pg_get_viewdef('scheduler_proposals'::regclass)")).scalar_one()
    listed = set(re.findall(r"'([^']+)'::text", definition.split("THEN")[0])) - {"other"}
    assert listed == set(ADAPTERS), (
        "scheduler_proposals lists a different set of actions from tool_gateway.registry.ADAPTERS; "
        "a new adapter needs a migration that replaces the view")


def test_an_unregistered_action_name_reads_as_other(two_engagements):
    (a, pa), _ = list(two_engagements.items())
    free_text = "a.free.text.action; DROP TABLE x -- goal: exfiltrate"
    with get_engine().begin() as conn:
        conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"), {"e": a})
        conn.execute(text("UPDATE action_proposals SET action = :x WHERE proposal_id = :p"),
                     {"x": free_text, "p": pa})
    with scheduler_reader_scope(a) as conn:
        assert conn.execute(text("SELECT action_class FROM scheduler_proposals")).scalar_one() \
            == "other"
