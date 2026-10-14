"""The reconciler's read side: three SECURITY DEFINER functions, one reader role (D64, 0023, 0024).

A ``SECURITY DEFINER`` function runs under its owner's row policies -- it does not bypass them --
and four mistakes were measured on the way to this design (E20). Each has a structural test here
and a mutation in ``scripts/mutations_d64.py`` (``D64-6a-*``):

* **S2** the function filters ``pipeline_stage`` itself, because a GUC set by the caller widens what
  the owner sees (the ``engagement_isolation`` policy is ``TO PUBLIC``);
* **S3** ``EXECUTE`` is revoked from PUBLIC and granted to ``reconciler_reader`` alone;
* **S4** ``search_path`` is pinned in the definition and every relation is schema-qualified; the
  reader cannot make a TEMP table;
* **S5** every cast of document content is guarded: ``"abc"``, ``5.5``, ``-1``, ``0``,
  ``99999999999``, a string ``"120"`` and a missing key come back as NULL, and no error echoes
  a value.

And the checklist of §2.3: the owner's attributes, the policy and column-grant matrix, STABLE, the
pinned output type, a reader with no privilege on any relation, the closed vocabularies of the
enum columns, and what each function returns for a proposal at each stage.

Time: the rows carry ``stage_updated_at`` in epoch microseconds, and the rows of these tests are
backdated to 1970 so that they sort first -- the function returns the oldest ``LIMIT_ROWS`` rows of
the whole database, and a long-lived development database holds thousands of other stuck rows.
"""

from __future__ import annotations

import importlib.util
import os
import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from control_plane.orchestrator import stages
from control_plane.state.db import (
    RECONCILER_FN_OWNER_ROLE,
    RECONCILER_READER_ROLE,
    engagement_scope,
    get_engine,
    reconciler_reader_scope,
    scheduler_reader_enrollment_scope,
    ui_reader_scope,
)
from tests import scheduler_support as sup
from tests.reconciler_support import _approval, _capability, _proposal, _run

REPO = Path(__file__).resolve().parents[1]
MIGRATION = REPO / "db" / "migrations" / "versions" / "0023_reconciler_reader.py"

spec = importlib.util.spec_from_file_location("m0023", MIGRATION)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

spec25 = importlib.util.spec_from_file_location(
    "m0025", REPO / "db" / "migrations" / "versions" / "0025_tool_run_refusal_code.py")
M25 = importlib.util.module_from_spec(spec25)
spec25.loader.exec_module(M25)

spec26 = importlib.util.spec_from_file_location(
    "m0026", REPO / "db" / "migrations" / "versions" / "0026_reconciler_has_decision.py")
M26 = importlib.util.module_from_spec(spec26)
spec26.loader.exec_module(M26)

OWNER, READER = RECONCILER_FN_OWNER_ROLE, RECONCILER_READER_ROLE
CONFLICTS = "reconciler_network_conflicts"             # which networks blocked refused runs (0025)
STUCK = "reconciler_stuck_proposals"
AFTER = "reconciler_stuck_proposals_after"             # the next page (migration 0024)
RUNS = "reconciler_run_states"
FUNCTIONS = {f"{STUCK}()": STUCK, f"{AFTER}(bigint, text)": AFTER, f"{RUNS}(text[])": RUNS,
             f"{CONFLICTS}(integer)": CONFLICTS}

#: The columns of ``reconciler_stuck_proposals()``, in order, with their types. The complete list.
STUCK_COLUMNS = [
    ("engagement_id", "text"), ("proposal_id", "text"), ("pipeline_stage", "text"),
    ("stage_updated_us", "bigint"), ("db_now_us", "bigint"), ("engagement_status", "text"),
    ("kill_switch_engaged", "boolean"), ("enrolled", "boolean"), ("capability_id", "text"),
    ("max_duration_s", "integer"), ("lease_expires_us", "bigint"),
    ("capability_revoked", "boolean"),
    ("approval_id", "text"), ("approval_valid_until_us", "bigint"), ("approval_revoked", "boolean"),
    ("run_id", "text"), ("run_status", "text"), ("has_decision", "boolean"),    # 0026
]
RUN_COLUMNS = [("run_id", "text"), ("status", "text")]
SCALAR_TYPES = {"text", "bigint", "integer", "boolean"}
def _stuck(conn=None) -> dict[str, dict]:
    """The function's rows by proposal id. A database error is a failed expectation: the call must
    answer, whatever the data."""
    sql = text(f"SELECT * FROM {STUCK}()")
    try:
        if conn is None:
            with reconciler_reader_scope() as c:
                rows = c.execute(sql).mappings().all()
        else:
            rows = conn.execute(sql).mappings().all()
    except DBAPIError as exc:
        pytest.fail(f"the call did not answer: {str(exc.orig)[:100]}")
    return {r["proposal_id"]: dict(r) for r in rows}


def _catalog(sql: str, **params):
    with get_engine().connect() as conn:
        return conn.execute(text(sql), params).all()


# ---------------------------------------------------------------------------------------------
# the owner and the reader: who they are, what they own, what they can reach
# ---------------------------------------------------------------------------------------------

def test_the_owner_is_a_role_nobody_can_log_in_as_and_that_cannot_bypass_row_security(db_available):
    (row,) = _catalog("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, "
                      "rolcanlogin FROM pg_roles WHERE rolname = :r", r=OWNER)
    assert tuple(row) == (False, False, False, False, False, False), row


def test_the_reader_is_an_ordinary_login_role(db_available):
    (row,) = _catalog("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, "
                      "rolcanlogin FROM pg_roles WHERE rolname = :r", r=READER)
    assert tuple(row) == (False, False, False, False, False, True), row


def test_the_owner_owns_nothing_but_the_reconciler_functions(db_available):
    owned = {
        "relations": _catalog("SELECT relname FROM pg_class WHERE relowner = CAST(:r AS regrole)",
                              r=OWNER),
        "schemas": _catalog("SELECT nspname FROM pg_namespace WHERE nspowner = CAST(:r AS regrole)",
                            r=OWNER),
        "types": _catalog("SELECT typname FROM pg_type WHERE typowner = CAST(:r AS regrole) "
                          "AND typtype <> 'c' AND typname NOT LIKE '\\_%'", r=OWNER),
        "functions": sorted(r[0] for r in _catalog(
            "SELECT proname FROM pg_proc WHERE proowner = CAST(:r AS regrole)", r=OWNER)),
    }
    assert owned["relations"] == [] and owned["schemas"] == [] and owned["types"] == [], owned
    assert owned["functions"] == sorted([STUCK, AFTER, RUNS, CONFLICTS])


def test_only_the_migration_role_is_a_member_of_the_owner_without_inheriting_it(db_available):
    """WITH INHERIT FALSE is load-bearing: a policy TO the owner applies to every role holding the
    owner's privileges, and migration_owner owns the tables and the scheduler's view."""
    members = {r[0]: (r[1], r[2]) for r in _catalog(
        "SELECT m.rolname, am.inherit_option, am.set_option FROM pg_auth_members am "
        "JOIN pg_roles m ON m.oid = am.member WHERE am.roleid = CAST(:r AS regrole)", r=OWNER)}
    assert members == {"migration_owner": (False, True)}, members
    assert _catalog("SELECT 1 FROM pg_auth_members WHERE member = CAST(:r AS regrole)", r=READER) \
        == []


def test_the_table_owner_and_the_schedulers_view_are_not_widened_by_the_owner_s_policies(
        db_available, engagement_id):
    _proposal(engagement_id, "dispatching")
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        with engine.begin() as conn:
            visible = conn.execute(text("SELECT count(*) FROM action_proposals")).scalar_one()
    finally:
        engine.dispose()
    assert visible == 0, f"the table owner, bound by FORCE ROW LEVEL SECURITY, sees {visible} rows"
    with scheduler_reader_enrollment_scope() as conn:
        seen = conn.execute(text("SELECT count(*) FROM scheduler_proposals")).scalar_one()
    assert seen == 0, f"scheduler_reader sees {seen} proposals of engagements it did not name"


def test_the_reader_cannot_become_the_owner(db_available):
    with pytest.raises(DBAPIError):
        with reconciler_reader_scope() as conn:
            conn.execute(text(f"SET ROLE {OWNER}"))


def test_the_reader_has_no_privilege_on_any_table_view_or_sequence(db_available):
    leaked = []
    with get_engine().connect() as conn:
        for rel, kind in conn.execute(text(
                "SELECT c.oid::regclass::text, c.relkind::text FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v', 'm', 'p', 'S')")).all():
            privs = ("USAGE", "SELECT", "UPDATE") if kind == "S" else \
                ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
            fn = "has_sequence_privilege" if kind == "S" else "has_table_privilege"
            for priv in privs:
                if conn.execute(text(f"SELECT {fn}(:r, CAST(:o AS regclass), :p)"),
                                {"r": READER, "o": rel, "p": priv}).scalar_one():
                    leaked.append((rel, priv))
            if kind != "S":
                cols = conn.execute(text(
                    "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = CAST(:o AS regclass) "
                    "AND a.attnum > 0 AND NOT a.attisdropped "
                    "AND has_column_privilege(:r, a.attrelid, a.attnum, 'SELECT')"),
                    {"o": rel, "r": READER}).scalars().all()
                leaked.extend((rel, f"column {c}") for c in cols)
    assert leaked == [], leaked


@pytest.mark.parametrize("table", ["action_proposals", "capabilities", "approvals", "engagements",
                                   "tool_runs", "scheduler_enrollment", "audit_log",
                                   "credential_material"])
def test_a_direct_select_as_the_reader_is_permission_denied(db_available, table):
    with pytest.raises(ProgrammingError, match="permission denied"):
        with reconciler_reader_scope() as conn:
            conn.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))


def test_the_reader_has_no_create_on_the_schema_and_no_temp_on_the_database(db_available):
    (create, temp, owner_create) = _catalog(
        "SELECT has_schema_privilege(:r, 'public', 'CREATE'), "
        "has_database_privilege(:r, current_database(), 'TEMPORARY'), "
        "has_schema_privilege(:o, 'public', 'CREATE')", r=READER, o=OWNER)[0]
    assert (create, temp, owner_create) == (False, False, False)
    with pytest.raises(ProgrammingError, match="permission denied"):
        with reconciler_reader_scope() as conn:
            conn.execute(text("CREATE TEMP TABLE action_proposals (proposal_id text)"))


# ---------------------------------------------------------------------------------------------
# the owner's policies and column grants: exactly what the functions read
# ---------------------------------------------------------------------------------------------

def test_the_owner_has_column_select_on_exactly_the_listed_columns_and_nothing_else(db_available):
    found: dict[str, set[str]] = {}
    with get_engine().connect() as conn:
        for rel in conn.execute(text(
                "SELECT c.oid::regclass::text FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v', 'm', 'p')")
        ).scalars().all():
            for priv in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                assert not conn.execute(text(
                    "SELECT has_table_privilege(:r, CAST(:o AS regclass), :p)"),
                    {"r": OWNER, "o": rel, "p": priv}).scalar_one(), (rel, priv)
            assert not conn.execute(text(
                "SELECT has_table_privilege(:r, CAST(:o AS regclass), 'SELECT')"),
                {"r": OWNER, "o": rel}).scalar_one(), f"table-wide SELECT on {rel}"
            cols = set(conn.execute(text(
                "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = CAST(:o AS regclass) "
                "AND a.attnum > 0 AND NOT a.attisdropped "
                "AND has_column_privilege(:r, a.attrelid, a.attnum, 'SELECT')"),
                {"o": rel, "r": OWNER}).scalars().all())
            if cols:
                found[rel] = cols
            for col in cols:
                assert not conn.execute(text(
                    "SELECT has_column_privilege(:r, CAST(:o AS regclass), :c, 'UPDATE')"),
                    {"r": OWNER, "o": rel, "c": col}).scalar_one(), (rel, col)
    expected = {t: set(c) for t, c in M.OWNER_COLUMNS.items()}
    expected["tool_runs"] |= set(M25.NEW_OWNER_COLUMNS)              # 0025: the conflicts read
    for table, columns in M26.NEW_OWNER_COLUMNS.items():             # 0026: has_decision
        expected[table] |= set(columns)
    assert found == expected


def test_the_owner_has_one_select_only_policy_on_each_of_the_six_tables(db_available):
    rows = _catalog("SELECT tablename, policyname, cmd, roles::text FROM pg_policies "
                    "WHERE roles::text LIKE :r ORDER BY 1", r=f"%{OWNER}%")
    assert {r[0] for r in rows} == set(M.OWNER_COLUMNS), rows
    assert all(r[1] == M.POLICY and r[2] == "SELECT" and r[3] == f"{{{OWNER}}}" for r in rows), rows
    assert len(rows) == len(M.OWNER_COLUMNS)


def test_the_owner_sees_no_recorded_proposal_without_a_guc_and_no_row_of_a_table_that_is_not_listed(
        db_available, engagement_id):
    recorded = _proposal(engagement_id, "recorded")
    stuck = _proposal(engagement_id, "dispatching")
    # migration_owner may SET ROLE to the owner (membership); the runtime role may not.
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        with engine.begin() as conn:
            conn.execute(text(f"SET LOCAL ROLE {OWNER}"))
            ids = set(conn.execute(
                text("SELECT proposal_id FROM action_proposals")).scalars().all())
    finally:
        engine.dispose()
    assert recorded not in ids
    assert stuck in ids


# ---------------------------------------------------------------------------------------------
# the functions' definitions: S2, S3, S4 and the checklist items that are catalog facts
# ---------------------------------------------------------------------------------------------

def _proc(signature: str):
    (row,) = _catalog(
        "SELECT p.prosecdef, p.provolatile, pg_get_userbyid(p.proowner), p.proconfig, p.prosrc, "
        "pg_get_function_result(p.oid), p.proretset, p.proisstrict FROM pg_proc p "
        "WHERE p.oid = CAST(:s AS regprocedure)", s=f"public.{signature}")
    return row


@pytest.mark.parametrize("signature", list(FUNCTIONS))
def test_s_the_function_is_security_definer_stable_and_owned_by_the_owner(db_available, signature):
    definer, volatility, owner, _config, _src, _result, returns_set, strict = _proc(signature)
    assert definer is True
    assert volatility == "s"                       # STABLE: it reads and writes nothing
    assert owner == OWNER
    assert returns_set is True
    assert strict is False       # a NULL argument is refused, not answered with nothing


@pytest.mark.parametrize("signature", list(FUNCTIONS))
def test_s4_the_search_path_is_pinned_in_the_definition(db_available, signature):
    config = _proc(signature)[3]
    assert config == ["search_path=pg_catalog, public, pg_temp"], config


@pytest.mark.parametrize("signature", list(FUNCTIONS))
def test_s4_every_relation_in_the_body_is_schema_qualified(db_available, signature):
    src = _proc(signature)[4]
    # `extract(epoch FROM p.col)` and `FROM now()` are not relations: `.` or `(` follows them.
    ctes = set(re.findall(r"(?:\bWITH|,)\s*([a-z_][a-z_0-9]*)\s+AS\s*\(", src))   # not relations
    unqualified = [name for name in re.findall(
        r"\b(?:FROM|JOIN)\s+(?!public\.|LATERAL\b|\()([a-z_][a-z_0-9]*)\b(?![.(])", src)
        if name not in ctes]
    assert unqualified == [], unqualified
    assert "public." in src


@pytest.mark.parametrize("signature", list(FUNCTIONS))
def test_s3_execute_is_granted_to_the_reader_and_the_owner_alone(db_available, signature):
    grants = _catalog(
        "SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, "
        "a.privilege_type FROM pg_proc p, aclexplode(p.proacl) a "
        "WHERE p.oid = CAST(:s AS regprocedure) ORDER BY 1", s=f"public.{signature}")
    assert {(g, p) for g, p in grants} == {(OWNER, "EXECUTE"), (READER, "EXECUTE")}, grants


@pytest.mark.parametrize("role", ["cyberorch_app", "ui_reader", "scheduler_reader",
                                  "global_auditor"])
def test_s3_an_unrelated_role_is_refused(db_available, role):
    for signature in FUNCTIONS:
        assert not _catalog(
            "SELECT has_function_privilege(:r, CAST(:f AS regprocedure), 'EXECUTE')",
            r=role, f=f"public.{signature}")[0][0], (role, signature)
    with pytest.raises(ProgrammingError, match="permission denied"):
        with ui_reader_scope("ENG-NONE") as conn:
            conn.execute(text(f"SELECT * FROM {STUCK}()"))


def test_s2_the_stage_filter_is_in_the_function_body(db_available):
    src = _proc(f"{STUCK}()")[4]
    match = re.search(r"WHERE\s+p\.pipeline_stage IN \(([^)]*)\)", src)
    assert match, "the stuck-proposals function has no explicit stage filter"
    assert re.findall(r"'([a-z_]+)'", match.group(1)) == list(M.STUCK_STAGES)


def test_the_stuck_stages_leave_out_the_terminal_ones_and_the_persons_stage(db_available):
    assert set(M.STUCK_STAGES) <= set(stages.STAGES)
    assert not set(M.STUCK_STAGES) & set(stages.TERMINAL)
    assert stages.AWAITING_APPROVAL not in M.STUCK_STAGES


# ---------------------------------------------------------------------------------------------
# the output: ids, closed vocabularies, integers -- pinned, column by column
# ---------------------------------------------------------------------------------------------

def _result_columns(signature: str) -> list[tuple[str, str]]:
    result = _proc(signature)[5]
    assert result.startswith("TABLE(") and result.endswith(")"), result
    return [tuple(part.strip().split(" ", 1)) for part in result[len("TABLE("):-1].split(",")]


def test_the_stuck_function_returns_exactly_the_pinned_columns_and_only_scalar_types(db_available):
    columns = _result_columns(f"{STUCK}()")
    assert columns == STUCK_COLUMNS
    assert {t for _, t in columns} <= SCALAR_TYPES


def test_the_run_function_returns_exactly_the_pinned_columns_and_only_scalar_types(db_available):
    columns = _result_columns(f"{RUNS}(text[])")
    assert columns == RUN_COLUMNS
    assert {t for _, t in columns} <= SCALAR_TYPES


def test_no_column_names_a_target_a_decision_a_reason_a_budget_or_a_tool_document(db_available):
    # (``has_decision`` says whether there is one, as a boolean -- see the next test)
    names = {n for n, _ in STUCK_COLUMNS + RUN_COLUMNS if n != "has_decision"}
    for forbidden in ("target", "decision", "reason", "budget", "tool", "params", "authorization",
                      "discovery", "payload", "credential", "allowlist"):
        assert not [n for n in names if forbidden in n], (forbidden, names)


def test_has_decision_is_a_boolean_that_says_whether_never_what(db_available, engagement_id):
    undecided = _proposal(engagement_id, "received")
    decided = _proposal(engagement_id, "decided")
    odd = _proposal(engagement_id, "received")
    with engagement_scope(engagement_id) as conn:           # a decision on a `received` row
        conn.execute(text("UPDATE action_proposals SET decision = 'DENY' WHERE proposal_id = :p"),
                     {"p": odd})
    rows = _stuck()
    assert (rows[undecided]["has_decision"], rows[decided]["has_decision"],
            rows[odd]["has_decision"]) == (False, True, True)
    page = {r["proposal_id"]: r for r in _after(0, "")}      # the next page says the same
    assert {p: page[p]["has_decision"] for p in (undecided, decided, odd) if p in page} == {
        p: rows[p]["has_decision"] for p in (undecided, decided, odd) if p in page}
    for row in rows.values():                                # and it is a boolean, not a value
        assert type(row["has_decision"]) is bool
    assert "DENY" not in repr(rows[odd]) and "ALLOW" not in repr(rows[decided])


def test_the_functions_owner_reads_the_decision_column_and_the_reader_cannot(db_available):
    with get_engine().connect() as conn:
        assert conn.execute(text(
            "SELECT has_column_privilege(:r, 'action_proposals', 'decision', 'SELECT')"),
            {"r": OWNER}).scalar_one() is True
        assert conn.execute(text(
            "SELECT has_column_privilege(:r, 'action_proposals', 'decision', 'SELECT')"),
            {"r": READER}).scalar_one() is False
        assert conn.execute(text(
            "SELECT has_column_privilege(:r, 'action_proposals', 'decision', 'UPDATE')"),
            {"r": OWNER}).scalar_one() is False


def test_the_enum_columns_hold_only_the_closed_vocabularies(db_available, engagement_id):
    for stage in M.STUCK_STAGES:
        pid = _proposal(engagement_id, stage)
        if stage in ("capability_issued", "dispatching"):
            cid = _capability(engagement_id, pid, '{"max_duration_seconds": 60}')
            if stage == "dispatching":
                _run(engagement_id, pid, cid, "running")
    rows = [r for r in _stuck().values() if r["engagement_id"] == engagement_id]
    assert {r["pipeline_stage"] for r in rows} == set(M.STUCK_STAGES)
    allowed_engagement = {"active", "paused", "completed", "killed"}
    allowed_run = {"queued", "dispatching", "running", "succeeded", "failed", "unknown_outcome"}
    assert {r["engagement_status"] for r in rows} <= allowed_engagement
    assert {r["run_status"] for r in rows if r["run_status"]} <= allowed_run
    # the database's own CHECKs are the vocabularies the tests above rely on
    checks = " ".join(r[0] for r in _catalog(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname IN "
        "('engagements_status_check', 'tool_runs_status_check')"))
    for word in allowed_engagement | allowed_run:
        assert f"'{word}'" in checks


# ---------------------------------------------------------------------------------------------
# what the function returns
# ---------------------------------------------------------------------------------------------

def test_a_proposal_at_each_stage_is_returned_only_if_it_is_stuck(db_available, engagement_id):
    made = {stage: _proposal(engagement_id, stage) for stage in stages.STAGES}
    seen = _stuck()
    returned = {s for s, p in made.items() if p in seen}
    assert returned == set(M.STUCK_STAGES), returned
    for stage in M.STUCK_STAGES:
        assert seen[made[stage]]["pipeline_stage"] == stage


def test_s2_a_guc_set_by_the_caller_does_not_widen_the_result(db_available, engagement_id):
    recorded = _proposal(engagement_id, "recorded")
    closed = _proposal(engagement_id, "closed")
    stuck = _proposal(engagement_id, "dispatching")
    with reconciler_reader_scope() as conn:
        conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                     {"e": engagement_id})
        seen = _stuck(conn)
    assert stuck in seen
    assert recorded not in seen and closed not in seen


def test_the_rows_are_the_databases_own_facts_in_integers(db_available, engagement_id):
    pid = _proposal(engagement_id, "dispatching", age_s=7)
    cid = _capability(engagement_id, pid, '{"max_duration_seconds": 120, "tool": {"k": "v"}}',
                      lease="TIMESTAMPTZ '1970-01-03 00:00:00+00'")
    rid = _run(engagement_id, pid, cid, "running")
    with reconciler_reader_scope() as conn:
        row = _stuck(conn)[pid]
        db_now = conn.execute(text(
            "SELECT (extract(epoch FROM now()) * 1000000)::bigint")).scalar_one()
    assert row["engagement_id"] == engagement_id
    assert row["stage_updated_us"] == (24 * 3600 + 7) * 1_000_000
    assert row["lease_expires_us"] == 2 * 24 * 3600 * 1_000_000
    assert abs(row["db_now_us"] - db_now) < 60 * 1_000_000   # the database's clock
    assert (row["capability_id"], row["max_duration_s"], row["capability_revoked"]) \
        == (cid, 120, False)
    assert (row["run_id"], row["run_status"]) == (rid, "running")
    assert (row["engagement_status"], row["kill_switch_engaged"], row["enrolled"]) \
        == ("active", False, False)
    assert row["approval_id"] is None and row["approval_valid_until_us"] is None


def test_a_killed_an_enrolled_engagement_and_an_expired_approval_are_visible(
        db_available, engagement_id):
    pid = _proposal(engagement_id, "approved")
    aid = _approval(engagement_id, pid, valid="TIMESTAMPTZ '1970-01-05 00:00:00+00'")
    sup.enroll(engagement_id)
    sup.kill(engagement_id)
    row = _stuck()[pid]
    assert (row["engagement_status"], row["kill_switch_engaged"], row["enrolled"]) \
        == ("killed", True, True)
    assert row["approval_id"] == aid and row["approval_valid_until_us"] == 4 * 24 * 3600 * 1_000_000
    assert row["approval_revoked"] is False
    sup.withdraw(engagement_id)
    assert _stuck()[pid]["enrolled"] is False


def test_the_latest_capability_of_a_proposal_is_the_one_returned(db_available, engagement_id):
    pid = _proposal(engagement_id, "capability_issued")
    _capability(engagement_id, pid, '{"max_duration_seconds": 11}')
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE capabilities SET issued_at = now() - interval '1 day' "
                          "WHERE proposal_id = :p"), {"p": pid})
    newest = _capability(engagement_id, pid, '{"max_duration_seconds": 22}')
    row = _stuck()[pid]
    assert (row["capability_id"], row["max_duration_s"]) == (newest, 22)


def test_a_proposal_of_another_engagement_is_never_joined_to_these_rows(
        db_available, engagement_factory):
    (e1, _), (e2, _) = engagement_factory(), engagement_factory()
    p1 = _proposal(e1, "capability_issued")
    p2 = _proposal(e2, "capability_issued")
    c1 = _capability(e1, p1, '{"max_duration_seconds": 5}')
    seen = _stuck()
    assert seen[p1]["capability_id"] == c1 and seen[p2]["capability_id"] is None


# ---------------------------------------------------------------------------------------------
# S5: a value the function cannot cast is NULL, never an error and never an echo
# ---------------------------------------------------------------------------------------------

BUDGETS = {
    "ok": ('{"max_duration_seconds": 120}', 120),
    "ok_with_a_tool_document": (
        '{"max_duration_seconds": 30, "tool": {"x": "secret-tool-doc"}}', 30),
    "string_abc": ('{"max_duration_seconds": "abc"}', None),
    "string_number": ('{"max_duration_seconds": "120"}', None),
    "float": ('{"max_duration_seconds": 5.5}', None),
    "negative": ('{"max_duration_seconds": -1}', None),
    "zero": ('{"max_duration_seconds": 0}', None),
    "huge": ('{"max_duration_seconds": 99999999999}', None),
    "null_value": ('{"max_duration_seconds": null}', None),
    "object_value": ('{"max_duration_seconds": {"a": 1}}', None),
    "array_value": ('{"max_duration_seconds": [1, 2]}', None),
    "missing_key": ('{"other": 1}', None),
    "empty": ('{}', None),
    "budget_is_a_string": ('"abc"', None),
    "budget_is_an_array": ('[1]', None),
}


def test_s5_one_unreadable_budget_neither_blinds_the_call_nor_is_echoed(
        db_available, engagement_id):
    made = {}
    for name, (budget, expected) in BUDGETS.items():
        pid = _proposal(engagement_id, "dispatching")
        _capability(engagement_id, pid, budget)
        made[name] = (pid, expected)
    seen = _stuck()                      # one unreadable budget must not blind the whole call
    for name, (pid, expected) in made.items():
        assert pid in seen, name
        assert seen[pid]["max_duration_s"] == expected, (name, seen[pid]["max_duration_s"])
    ours = [seen[pid] for pid, _ in made.values()]
    assert not any("secret-tool-doc" in repr(row) for row in ours)
    assert all(isinstance(row["max_duration_s"], (int, type(None))) for row in ours)


# ---------------------------------------------------------------------------------------------
# the run-state function: absent means orphan, so it refuses instead of answering with less
# ---------------------------------------------------------------------------------------------

def _states(ids):
    with reconciler_reader_scope() as conn:
        return {r[0]: r[1] for r in conn.execute(
            text(f"SELECT run_id, status FROM {RUNS}(CAST(:i AS text[]))"), {"i": ids})}


def test_run_states_returns_the_known_runs_and_leaves_the_unknown_ones_out(
        db_available, engagement_factory):
    (e1, _), (e2, _) = engagement_factory(), engagement_factory()
    r1 = _run(e1, _proposal(e1, "dispatching"), None, "succeeded")
    r2 = _run(e2, _proposal(e2, "dispatching"), None, "running")
    unknown = f"RUN-{uuid.uuid4().hex[:12]}"
    assert _states([r1, r2, unknown]) == {r1: "succeeded", r2: "running"}
    assert _states([]) == {}


def test_run_states_refuses_a_null_and_an_oversized_argument_with_a_fixed_text(db_available):
    oversized = [f"R{i}" for i in range(M.MAX_RUN_IDS + 1)]
    for argument, label in ((None, "NULL"), (oversized, "oversized")):
        with pytest.raises(DBAPIError) as caught:
            _states(argument)
        text_ = str(caught.value.orig)    # the server's message; SQLAlchemy's echoes the parameters
        assert "argument refused" in text_, label
        assert "R5" not in text_ and "R1999" not in text_            # no content in the message
    assert _states(oversized[:M.MAX_RUN_IDS]) == {}        # the limit itself is allowed


def test_run_states_takes_an_injection_shaped_id_as_data(db_available):
    assert _states(["x'; DROP TABLE tool_runs; --", "' OR '1'='1"]) == {}


# ---------------------------------------------------------------------------------------------
# a function the migration did not mention does not exist, and the row limit is the stated one
# ---------------------------------------------------------------------------------------------

def test_the_row_limit_and_the_order_are_in_the_definition(db_available):
    src = _proc(f"{STUCK}()")[4]
    assert re.search(rf"ORDER BY p\.stage_updated_at, p\.proposal_id\s+LIMIT {M.LIMIT_ROWS}\b", src)


def test_there_are_exactly_four_reconciler_functions(db_available):
    names = sorted(r[0] for r in _catalog(
        "SELECT proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace "
        "AND proname LIKE 'reconciler\\_%'"))
    assert names == sorted([STUCK, AFTER, RUNS, CONFLICTS])
    assert stages.ABANDONED not in M.STUCK_STAGES


# ---------------------------------------------------------------------------------------------
# the next page (migration 0024): the same rows, strictly after a keyset cursor
# ---------------------------------------------------------------------------------------------

def _after(us, pid, conn=None):
    sql = text(f"SELECT * FROM {AFTER}(:u, :i)")
    params = {"u": us, "i": pid}
    try:
        if conn is None:
            with reconciler_reader_scope() as c:
                return [dict(r) for r in c.execute(sql, params).mappings().all()]
        return [dict(r) for r in conn.execute(sql, params).mappings().all()]
    except DBAPIError as exc:
        pytest.fail(f"the call did not answer: {str(exc.orig)[:100]}")


def test_the_next_page_returns_exactly_the_columns_of_the_first(db_available):
    columns = _result_columns(f"{AFTER}(bigint, text)")
    assert columns == STUCK_COLUMNS == _result_columns(f"{STUCK}()")


def test_the_next_page_has_the_same_stage_filter_order_and_limit_as_the_first(db_available):
    src = _proc(f"{AFTER}(bigint, text)")[4]
    match = re.search(r"WHERE\s+p\.pipeline_stage IN \(([^)]*)\)", src)
    assert match and re.findall(r"'([a-z_]+)'", match.group(1)) == list(M.STUCK_STAGES)
    assert re.search(rf"ORDER BY p\.stage_updated_at, p\.proposal_id\s+LIMIT {M.LIMIT_ROWS}\b", src)


def test_the_cursor_is_strictly_after_the_row_it_names_and_before_the_next(db_available,
                                                                          engagement_id):
    ids = [_proposal(engagement_id, "dispatching", age_s=n) for n in (10, 20, 30)]
    first = _stuck()
    a, b, c = (first[p] for p in ids)
    after_a = {r["proposal_id"] for r in _after(a["stage_updated_us"], a["proposal_id"])}
    assert a["proposal_id"] not in after_a and {b["proposal_id"], c["proposal_id"]} <= after_a
    after_b = {r["proposal_id"] for r in _after(b["stage_updated_us"], b["proposal_id"])}
    assert b["proposal_id"] not in after_b and a["proposal_id"] not in after_b
    assert c["proposal_id"] in after_b
    after_c = {r["proposal_id"] for r in _after(c["stage_updated_us"], c["proposal_id"])}
    assert not {a["proposal_id"], b["proposal_id"], c["proposal_id"]} & after_c


def test_rows_with_the_same_timestamp_are_ordered_by_id_and_the_cursor_splits_them(
        db_available, engagement_id):
    same = sorted(_proposal(engagement_id, "dispatching", age_s=500) for _ in range(3))
    first = _stuck()
    us = {first[p]["stage_updated_us"] for p in same}
    assert len(us) == 1
    (us,) = us
    page = _after(us, same[0])
    ids = [r["proposal_id"] for r in page]
    assert same[0] not in ids and ids.index(same[1]) < ids.index(same[2])
    page = _after(us, same[1])
    ids = {r["proposal_id"] for r in page}
    assert same[2] in ids and same[0] not in ids and same[1] not in ids


@pytest.mark.parametrize("us, pid", [(None, "x"), (5, None), (None, None)])
def test_a_cursor_with_a_missing_half_returns_nothing(db_available, engagement_id, us, pid):
    """SQL compares rows left to right, so ROW(a, b) > ROW(x, NULL) is true whenever a > x; found by
    calling it with (5, NULL), which returned every stuck row. The function says it in a WHERE.
    (There is a stuck row to return: with none, the test would pass for any function -- found when
    the suite stopped leaving stuck rows behind and D64-P6-a stopped failing.)"""
    _proposal(engagement_id, "dispatching", age_s=100)
    assert _stuck(), "the premise: there is something for a bad cursor to return"
    assert _after(us, pid) == []


def test_the_cursor_text_is_data_and_not_sql(db_available):
    _after(0, "'; DROP TABLE action_proposals; --")       # answers (rows or none), raises nothing
    with get_engine().connect() as conn:                 # and the table is still there
        assert conn.execute(text("SELECT to_regclass('public.action_proposals')")).scalar_one()


def test_s2_the_caller_s_guc_does_not_widen_the_next_page_either(db_available, engagement_id):
    recorded = _proposal(engagement_id, "recorded")
    stuck = _proposal(engagement_id, "dispatching")
    with reconciler_reader_scope() as conn:
        conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                     {"e": engagement_id})
        seen = {r["proposal_id"] for r in _after(0, "", conn)}
    assert stuck in seen and recorded not in seen


def test_the_next_page_is_refused_to_every_role_but_the_reader(db_available):
    for role in ("cyberorch_app", "ui_reader", "scheduler_reader", "global_auditor"):
        assert not _catalog(
            "SELECT has_function_privilege(:r, "
            "'public.reconciler_stuck_proposals_after(bigint, text)'::regprocedure, 'EXECUTE')",
            r=role)[0][0], role
