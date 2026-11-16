"""D69 H5b: the table of migration 0031 as the database enforces it (T2, T3 and the guard).

T2 -- the ``purpose`` CHECK. T3 -- who may do what: asked of the catalogue with
``has_table_privilege`` and ``has_column_privilege`` for every role there is, and then shown once
with the real ``cyberorch_app`` connection. The guard trigger and the unique index are here too.
Every write is made in a transaction that is rolled back (``tests/test_harness_h5b_support.py``).
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from control_plane.state.db import get_engine
from tests.test_harness_h5b_support import TABLE, owner_transaction

INSERT_WITH_PURPOSE = (
    "INSERT INTO harness_enrolment (engagement_id, purpose, enrolled_by) VALUES (:e, :p, 'alice')")
INSERT_WITHOUT_PURPOSE = (
    "INSERT INTO harness_enrolment (engagement_id, enrolled_by) VALUES (:e, 'alice')")


def _sqlstate(exc: BaseException) -> str:
    return getattr(exc.orig, "sqlstate", "")


# -- T2: the purpose CHECK ----------------------------------------------------------------------


def test_an_insert_that_does_not_name_a_purpose_fails(engagement_id):
    with owner_transaction() as conn:
        with pytest.raises(IntegrityError) as caught, conn.begin_nested():
            conn.execute(text(INSERT_WITHOUT_PURPOSE), {"e": engagement_id})
        assert _sqlstate(caught.value) == "23502"                       # not_null_violation


def test_the_purpose_column_is_not_null_and_has_no_default(db_available):
    with owner_transaction() as conn:
        nullable, default = conn.execute(text(
            "SELECT is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'harness_enrolment' AND column_name = 'purpose'")).one()
    assert nullable == "NO"
    assert default is None


@pytest.mark.parametrize("purpose", ["other", "harness_prod", "HARNESS_LAB", "", " harness_lab"])
def test_an_insert_with_any_purpose_but_harness_lab_is_a_check_violation(engagement_id, purpose):
    with owner_transaction() as conn:
        with pytest.raises(IntegrityError) as caught, conn.begin_nested():
            conn.execute(text(INSERT_WITH_PURPOSE), {"e": engagement_id, "p": purpose})
        assert _sqlstate(caught.value) == "23514"                       # check_violation
        assert caught.value.orig.diag.constraint_name == "harness_enrolment_purpose_check"


def test_an_insert_with_purpose_harness_lab_goes_in(engagement_id):
    with owner_transaction() as conn:
        conn.execute(text(INSERT_WITH_PURPOSE), {"e": engagement_id, "p": "harness_lab"})
        assert conn.execute(text("SELECT count(*) FROM harness_enrolment "
                                 "WHERE engagement_id = :e"), {"e": engagement_id}).scalar() == 1


def test_an_empty_name_of_who_registered_is_refused(engagement_id):
    with owner_transaction() as conn:
        with pytest.raises(IntegrityError) as caught, conn.begin_nested():
            conn.execute(text("INSERT INTO harness_enrolment (engagement_id, purpose, enrolled_by)"
                              " VALUES (:e, 'harness_lab', '')"), {"e": engagement_id})
        assert _sqlstate(caught.value) == "23514"


def test_a_withdrawal_names_who_did_it_or_it_is_not_one(engagement_id):
    with owner_transaction() as conn:
        conn.execute(text(INSERT_WITH_PURPOSE), {"e": engagement_id, "p": "harness_lab"})
        with pytest.raises(IntegrityError) as caught, conn.begin_nested():
            conn.execute(text("UPDATE harness_enrolment SET withdrawn_at = now() "
                              "WHERE engagement_id = :e"), {"e": engagement_id})
        assert caught.value.orig.diag.constraint_name == "harness_enrolment_withdrawn_pair"


def test_an_engagement_that_does_not_exist_is_refused_by_a_foreign_key(db_available):
    with owner_transaction() as conn:
        with pytest.raises(IntegrityError) as caught, conn.begin_nested():
            conn.execute(text(INSERT_WITH_PURPOSE),
                         {"e": "ENG-NOBODY-MADE-THIS", "p": "harness_lab"})
        assert _sqlstate(caught.value) == "23503"                       # foreign_key_violation


# -- T3: who may do what ------------------------------------------------------------------------


def _roles(conn) -> list[str]:
    """Every role of the cluster that is not a superuser and not the table's owner."""
    return [r[0] for r in conn.execute(text(
        "SELECT rolname FROM pg_roles WHERE NOT rolsuper AND rolname !~ '^pg_' "
        "AND rolname NOT IN ('migration_owner', 'cyberorch_app') ORDER BY 1"))]


def _has(conn, role: str, kind: str, privilege: str) -> bool:
    function = {"table": "has_table_privilege", "any_column": "has_any_column_privilege"}[kind]
    return bool(conn.execute(text(f"SELECT {function}(:r, 'harness_enrolment', :p)"),
                {"r": role, "p": privilege}).scalar())


def test_there_are_the_roles_the_rule_is_about(db_available):
    with owner_transaction() as conn:
        roles = _roles(conn)
    for expected in ("scheduler_reader", "scheduler_admin", "scheduler_state_writer",
                     "reconciler_reader", "ui_reader", "registry_admin", "credential_admin",
                     "global_auditor", "global_policy_admin"):
        assert expected in roles, expected


def test_no_role_but_cyberorch_app_and_the_owner_has_any_privilege_on_the_table(db_available):
    with owner_transaction() as conn:
        granted = {}
        for role in _roles(conn):
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES",
                              "TRIGGER"):
                for kind in ("table", "any_column"):
                    # (a column has no DELETE, TRUNCATE or TRIGGER to hold)
                    if kind == "any_column" and privilege not in (
                            "SELECT", "INSERT", "UPDATE", "REFERENCES"):
                        continue
                    if _has(conn, role, kind, privilege):
                        granted.setdefault(role, []).append(f"{kind}:{privilege}")
        public = conn.execute(text(
            "SELECT count(*) FROM information_schema.role_table_grants "
            "WHERE table_name = 'harness_enrolment' AND grantee = 'PUBLIC'")).scalar()
    assert granted == {}
    assert public == 0


def test_cyberorch_app_reads_inserts_and_withdraws_and_has_no_delete(db_available):
    with owner_transaction() as conn:
        def table(privilege):
            return _has(conn, "cyberorch_app", "table", privilege)

        def column(name):
            return bool(conn.execute(text(
                "SELECT has_column_privilege('cyberorch_app', 'harness_enrolment', :c, 'UPDATE')"),
                {"c": name}).scalar())

        assert table("SELECT") and table("INSERT")
        assert not table("DELETE") and not table("UPDATE") and not table("TRUNCATE")
        assert not table("REFERENCES") and not table("TRIGGER")
        assert column("withdrawn_by") and column("withdrawn_at")
        for fixed in ("enrolment_id", "engagement_id", "purpose", "enrolled_by", "enrolled_at"):
            assert not column(fixed), fixed


def test_the_real_cyberorch_app_connection_cannot_delete_or_change_a_fixed_column(db_available):
    for statement in ("DELETE FROM harness_enrolment WHERE false",
                      "UPDATE harness_enrolment SET purpose = 'harness_lab' WHERE false",
                      "UPDATE harness_enrolment SET enrolled_by = 'x' WHERE false",
                      "TRUNCATE harness_enrolment"):
        with pytest.raises(DBAPIError) as caught, get_engine().begin() as conn:
            conn.execute(text(statement))
        assert _sqlstate(caught.value) == "42501", statement           # insufficient_privilege


def test_the_real_cyberorch_app_connection_reads_the_table_with_no_engagement_bound(db_available):
    with get_engine().begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM harness_enrolment")).scalar() >= 0


def test_row_level_security_is_on_and_forced_and_the_policies_name_cyberorch_app_alone(
        db_available):
    with get_engine().begin() as conn:
        on, forced = conn.execute(text(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'public.harness_enrolment'::regclass")).one()
        policies = conn.execute(text(
            "SELECT policyname, cmd, roles::text FROM pg_policies "
            "WHERE tablename = 'harness_enrolment' ORDER BY 1")).all()
    assert on is True and forced is True
    assert [tuple(p) for p in policies] == [
        ("runtime_insert", "INSERT", "{cyberorch_app}"),
        ("runtime_read", "SELECT", "{cyberorch_app}"),
        ("runtime_withdraw", "UPDATE", "{cyberorch_app}"),
    ]


# -- the guard trigger and the unique index ----------------------------------------------------


def _live_row(conn, engagement_id: str) -> None:
    conn.execute(text(INSERT_WITH_PURPOSE), {"e": engagement_id, "p": "harness_lab"})


@pytest.mark.parametrize("change", [
    "enrolment_id = enrolment_id + 1000000",
    "engagement_id = 'ENG-SOMEONE-ELSE'",
    "enrolled_by = 'mallory'",
    "enrolled_at = enrolled_at - interval '1 day'",
])
def test_a_written_row_changes_in_no_column_but_the_two_of_a_withdrawal(engagement_id, change):
    with owner_transaction() as conn:
        _live_row(conn, engagement_id)
        with pytest.raises(DBAPIError) as caught, conn.begin_nested():
            conn.execute(text(f"UPDATE {TABLE} SET {change} WHERE engagement_id = :e"),
                         {"e": engagement_id})
        # (the guard is a BEFORE trigger: it speaks before the foreign key is looked at)
        assert _sqlstate(caught.value) == "23000", change


def test_a_withdrawn_row_cannot_be_made_live_again_or_withdrawn_by_someone_else(engagement_id):
    with owner_transaction() as conn:
        _live_row(conn, engagement_id)
        conn.execute(text("UPDATE harness_enrolment SET withdrawn_by = 'alice', "
                          "withdrawn_at = now() WHERE engagement_id = :e"), {"e": engagement_id})
        for change in ("withdrawn_at = NULL, withdrawn_by = NULL",
                       "withdrawn_by = 'bob'", "withdrawn_at = now() + interval '1 day'"):
            with pytest.raises(DBAPIError) as caught, conn.begin_nested():
                conn.execute(text(f"UPDATE harness_enrolment SET {change} "
                                  "WHERE engagement_id = :e"), {"e": engagement_id})
            assert _sqlstate(caught.value) == "23000", change


def test_two_live_registrations_of_one_engagement_are_refused_but_a_withdrawn_one_is_history(
        engagement_id):
    with owner_transaction() as conn:
        _live_row(conn, engagement_id)
        with pytest.raises(IntegrityError) as caught, conn.begin_nested():
            _live_row(conn, engagement_id)
        assert _sqlstate(caught.value) == "23505"                       # unique_violation
        assert caught.value.orig.diag.constraint_name == "harness_enrolment_live"
        conn.execute(text("UPDATE harness_enrolment SET withdrawn_by = 'alice', "
                          "withdrawn_at = now() WHERE engagement_id = :e"), {"e": engagement_id})
        _live_row(conn, engagement_id)                                  # allowed again
        assert conn.execute(text("SELECT count(*) FROM harness_enrolment WHERE "
                                 "engagement_id = :e"), {"e": engagement_id}).scalar() == 2
