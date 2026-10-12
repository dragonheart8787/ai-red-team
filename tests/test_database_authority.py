"""Who can act as whom in the database, audited as a whole (ACCEPTANCE 5.84).

D64 step 6a found one leak by accident: ``migration_owner`` was a member of the reconciler's
function owner with the default ``INHERIT TRUE``, so every policy written
``TO reconciler_fn_owner`` also applied to the role that owns every table (and, through the view it
owns, to ``scheduler_reader``). It was found because a scheduler test happened to look. This file is
the audit that does not depend on luck: it lists **every** role membership and **every** object
that runs with its owner's privileges, in the live catalog, against an explicit allow-list. Adding
one without adding it here -- with the reason -- turns a test red.

**PostgreSQL 16 is required**, and the tests say so before anything else. Two things this repository
relies on exist only from 16 on: ``GRANT <role> TO <role> WITH INHERIT FALSE, SET TRUE`` (before 16,
membership inheritance was a property of the *member role*, ``rolinherit``, not of one grant), and
the ``inherit_option`` / ``set_option`` columns of ``pg_auth_members`` that these tests read. On 15
or earlier ``db/roles.sql`` does not even parse. CI runs ``postgres:16``.

What is audited, and what each rule protects:

* **memberships** -- the complete list is pinned, with the inherit and set option of each grant;
  no application role is a member of a built-in ``pg_*`` role; a membership statement in the
  repository without ``WITH INHERIT FALSE`` is refused (static, so it is caught before it runs).
* **role attributes** -- no role but the bootstrap superuser is SUPERUSER, BYPASSRLS, CREATEROLE,
  CREATEDB or REPLICATION. A role the repository does not know (a developer's benchmark role, say)
  must hold no privilege on any table of the schema and be in no group.
* **SECURITY DEFINER functions** -- the complete list is pinned: owner, pinned ``search_path`` (with
  ``pg_temp`` last, so a temporary object cannot shadow a catalog or schema object), who may
  EXECUTE (a default ACL is allowed only for a trigger function, which cannot be called), and that
  the owner can neither bypass row security nor log in unless it is the table owner.
* **views** -- a view runs with its *owner's* privileges unless it is ``security_invoker``; the
  complete list is pinned (one view), with its owner and grantees.
* **the rest of the surface** -- no default ACLs, no event triggers, no foreign servers or
  publications, ``PUBLIC`` has no CREATE on the schema and no TEMP/CREATE on the database.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.state.db import get_engine

REPO = Path(__file__).resolve().parents[1]

#: The roles this repository creates (db/roles.sql), and the one bootstrap superuser.
REPO_ROLES = {
    "migration_owner", "cyberorch_app", "registry_admin", "global_auditor", "ui_reader",
    "global_policy_admin", "credential_admin", "scheduler_reader", "scheduler_admin",
    "scheduler_state_writer", "reconciler_reader", "reconciler_fn_owner",
}
BOOTSTRAP = "postgres"

#: Every role membership between two non-built-in roles: (member, group) -> (inherit, set, admin).
#: ``migration_owner`` may SET ROLE to the reconciler's function owner so that a migration can hand
#: the functions over, and it must NOT inherit that role's privileges (see db/roles.sql).
EXPECTED_MEMBERSHIPS = {
    ("migration_owner", "reconciler_fn_owner"): (False, True, False),
}

#: Every SECURITY DEFINER function, by signature. ``execute`` is the exact set of roles that may
#: call it; ``None`` means the default ACL (PUBLIC) is accepted, only for a trigger function.
EXPECTED_DEFINERS = {
    "policy_layers_stamp()": {
        "owner": "migration_owner", "returns": "trigger", "execute": None,
        "search_path": ["public", "pg_temp"],
        "why": "stamps policy_change_seq on a policy layer; a trigger function cannot be called",
    },
    "policy_freeze_point()": {
        "owner": "migration_owner", "returns": "bigint",
        "execute": {"migration_owner", "registry_admin"},
        "search_path": ["public", "pg_temp"],
        "why": "reads the next value of a sequence the runtime role has no privilege on (5.20)",
    },
    "reconciler_stuck_proposals()": {
        "owner": "reconciler_fn_owner", "returns": "record",
        "execute": {"reconciler_fn_owner", "reconciler_reader"},
        "search_path": ["pg_catalog", "public", "pg_temp"],
        "why": "the reconciler's cross-engagement read (5.80)",
    },
    "reconciler_stuck_proposals_after(p_after_us bigint, p_after_id text)": {
        "owner": "reconciler_fn_owner", "returns": "record",
        "execute": {"reconciler_fn_owner", "reconciler_reader"},
        "search_path": ["pg_catalog", "public", "pg_temp"],
        "why": "the next page of the reconciler's cross-engagement read (5.88)",
    },
    "reconciler_run_states(p_run_ids text[])": {
        "owner": "reconciler_fn_owner", "returns": "record",
        "execute": {"reconciler_fn_owner", "reconciler_reader"},
        "search_path": ["pg_catalog", "public", "pg_temp"],
        "why": "the reconciler's run-status read (5.80)",
    },
}

#: Every view (a view reads with its owner's privileges unless it is security_invoker).
EXPECTED_VIEWS = {
    "scheduler_proposals": {
        "owner": "migration_owner", "options": ["security_barrier=true"],
        "grantees": {"migration_owner", "scheduler_reader"},
    },
}

#: Migration files that may contain a SECURITY DEFINER function. A new one must be added here, which
#: is the moment a person looks at it.
DEFINER_MIGRATIONS = {"0015_baseline_freeze.py", "0023_reconciler_reader.py",
                      "0024_reconciler_paging.py"}

#: Privilege keywords: ``GRANT <one of these> ...`` is an object grant, not a role membership.
PRIVILEGES = {
    "select", "insert", "update", "delete", "truncate", "references", "trigger", "execute", "usage",
    "create", "connect", "temporary", "temp", "all", "set", "alter", "maintain",
}


def _rows(sql: str, **params):
    with get_engine().connect() as conn:
        return conn.execute(text(sql), params).all()


# ---------------------------------------------------------------------------------------------
# PostgreSQL 16
# ---------------------------------------------------------------------------------------------

def test_postgres_is_16_or_newer(db_available):
    (num,) = _rows("SELECT current_setting('server_version_num')::int")[0]
    assert num >= 160000, (
        f"server_version_num is {num}: this repository needs PostgreSQL 16+ -- `GRANT role TO role "
        "WITH INHERIT FALSE` (db/roles.sql) and pg_auth_members.inherit_option / set_option exist "
        "only from 16 on, and on 15 membership inheritance is a property of the member role, so "
        "the reconciler's function owner could not be kept from migration_owner's privileges")


def test_ci_runs_the_major_version_the_repository_needs():
    workflow = (REPO / ".github" / "workflows" / "test.yml").read_text()
    images = re.findall(r"image:\s*postgres:(\d+)", workflow)
    assert images and all(int(v) >= 16 for v in images), images


# ---------------------------------------------------------------------------------------------
# memberships
# ---------------------------------------------------------------------------------------------

def test_the_complete_list_of_role_memberships_is_the_pinned_one(db_available):
    found = {(m, g): (bool(i), bool(s), bool(a)) for m, g, i, s, a in _rows(
        "SELECT m.rolname, g.rolname, am.inherit_option, am.set_option, am.admin_option "
        "FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member "
        "JOIN pg_roles g ON g.oid = am.roleid "
        "WHERE m.rolname !~ '^pg_' AND g.rolname !~ '^pg_'")}
    assert found == EXPECTED_MEMBERSHIPS, (
        "role memberships differ from the pinned list; a membership lets one role act with "
        f"another's privileges and policies. found: {found}")


def test_no_role_of_the_repository_is_a_member_of_a_built_in_role(db_available):
    found = _rows("SELECT m.rolname, g.rolname FROM pg_auth_members am "
                  "JOIN pg_roles m ON m.oid = am.member JOIN pg_roles g ON g.oid = am.roleid "
                  "WHERE g.rolname ~ '^pg_' AND m.rolname !~ '^pg_'")
    assert found == [], found


def _membership_grants() -> list[tuple[str, str]]:
    """(file, statement) for each ``GRANT <role> TO <role>`` in the repository's SQL and scripts."""
    files = [REPO / "db" / "roles.sql", REPO / "scripts" / "init_db.sh",
             *sorted((REPO / "db" / "migrations" / "versions").glob("*.py"))]
    out = []
    for path in files:
        for match in re.finditer(r"\bGRANT\s+([a-z_][a-z0-9_]*)\s+TO\s+[^;\"]*", path.read_text(),
                                 re.IGNORECASE):
            if match.group(1).lower() not in PRIVILEGES:
                out.append((path.name, match.group(0).strip()))
    return out


def test_a_membership_statement_without_inherit_false_is_refused():
    grants = _membership_grants()
    assert grants, "the scan found no membership grant (db/roles.sql has one): the scan is broken"
    bad = [(f, s) for f, s in grants
           if not re.search(r"WITH\s+INHERIT\s+FALSE", s, re.IGNORECASE)]
    assert bad == [], f"role membership granted with the default INHERIT TRUE: {bad}"


def test_the_membership_scan_recognises_a_bad_statement():
    """Positive control for the regex: it flags what it should and passes what it should."""
    sample = "GRANT some_owner TO some_member;\nGRANT SELECT ON t TO r;\n"
    hits = [m.group(0) for m in re.finditer(r"\bGRANT\s+([a-z_][a-z0-9_]*)\s+TO\s+[^;\"]*", sample,
                                             re.IGNORECASE) if m.group(1).lower() not in PRIVILEGES]
    assert hits == ["GRANT some_owner TO some_member"], hits


# ---------------------------------------------------------------------------------------------
# role attributes
# ---------------------------------------------------------------------------------------------

def test_no_role_but_the_bootstrap_superuser_has_a_powerful_attribute(db_available):
    found = _rows("SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' AND rolname <> :b AND "
                  "(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)",
                  b=BOOTSTRAP)
    assert found == [], f"roles with SUPERUSER/BYPASSRLS/CREATEROLE/CREATEDB/REPLICATION: {found}"


def test_every_role_of_the_repository_exists_and_has_the_expected_login(db_available):
    login = {name: can for name, can in _rows("SELECT rolname, rolcanlogin FROM pg_roles")}
    missing = REPO_ROLES - set(login)
    assert not missing, missing
    assert login["reconciler_fn_owner"] is False, "the function owner must not be able to log in"
    assert all(login[r] for r in REPO_ROLES - {"reconciler_fn_owner"})


def test_a_role_the_repository_does_not_know_holds_nothing_here(db_available):
    """A developer's own role (a benchmark user, say) is not this file's business -- unless it can
    reach the schema. Such a role must be in no group and hold no privilege on any relation."""
    strangers = [r[0] for r in _rows("SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' "
                                     "AND rolname <> :b", b=BOOTSTRAP) if r[0] not in REPO_ROLES]
    for role in strangers:
        groups = _rows("SELECT g.rolname FROM pg_auth_members am "
                       "JOIN pg_roles g ON g.oid = am.roleid "
                       "WHERE am.member = CAST(:r AS regrole)", r=role)
        assert groups == [], (role, groups)
        reach = _rows(
            "SELECT c.relname FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace "
            "AND c.relkind IN ('r','v','m','S') AND CASE WHEN c.relkind = 'S' THEN "
            "has_sequence_privilege(CAST(:r AS regrole), c.oid, 'USAGE,SELECT,UPDATE') ELSE "
            "has_table_privilege(CAST(:r AS regrole), c.oid, "
            "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') END", r=role)
        assert reach == [], (role, reach)
        assert not _rows("SELECT 1 FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace "
                         "AND p.prosecdef AND p.prorettype <> 'pg_catalog.trigger'::regtype "
                         "AND has_function_privilege(CAST(:r AS regrole), p.oid, 'EXECUTE')",
                         r=role), role


# ---------------------------------------------------------------------------------------------
# SECURITY DEFINER functions
# ---------------------------------------------------------------------------------------------

def _definers() -> dict[str, dict]:
    rows = _rows("""
        SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS sig,
               pg_get_userbyid(p.proowner) AS owner,
               p.proconfig,
               CASE WHEN p.prorettype = 'pg_catalog.trigger'::regtype THEN 'trigger'
                    WHEN p.proretset THEN 'record' ELSE p.prorettype::regtype::text END AS ret,
               p.proacl IS NULL AS default_acl,
               COALESCE((SELECT array_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                                               ELSE pg_get_userbyid(a.grantee) END)
                         FROM aclexplode(p.proacl) a WHERE a.privilege_type = 'EXECUTE'),
                        ARRAY[]::text[]) AS execs
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema')""")
    return {r.sig: dict(r._mapping) for r in rows}


def _search_path(config) -> list[str] | None:
    for item in config or ():
        if item.startswith("search_path="):
            return [part.strip() for part in item.split("=", 1)[1].split(",")]
    return None


def test_the_complete_list_of_security_definer_functions_is_the_pinned_one(db_available):
    assert set(_definers()) == set(EXPECTED_DEFINERS), (
        "a SECURITY DEFINER function was added or removed: it runs with its owner's privileges, so "
        f"it must be reviewed and listed in EXPECTED_DEFINERS. found: {sorted(_definers())}")


@pytest.mark.parametrize("signature", sorted(EXPECTED_DEFINERS))
def test_each_definer_function_has_its_pinned_owner_search_path_and_callers(
        db_available, signature):
    want, got = EXPECTED_DEFINERS[signature], _definers()[signature]
    assert got["owner"] == want["owner"], got["owner"]
    assert got["ret"] == want["returns"], got["ret"]
    path = _search_path(got["proconfig"])
    assert path == want["search_path"], f"search_path is {path}; pg_temp must be pinned, and last"
    assert path[-1] == "pg_temp", path
    if want["execute"] is None:
        assert want["returns"] == "trigger", "only a trigger function may keep the default ACL"
        assert got["default_acl"] is True
    else:
        assert got["default_acl"] is False, "EXECUTE is still at the default (PUBLIC)"
        assert "PUBLIC" not in got["execs"], got["execs"]
        assert set(got["execs"]) == want["execute"], got["execs"]


def test_a_definer_functions_owner_cannot_bypass_row_security_or_be_a_superuser(db_available):
    owners = {d["owner"] for d in _definers().values()}
    bad = _rows("SELECT rolname FROM pg_roles WHERE rolname = ANY(:o) AND "
                "(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)",
                o=sorted(owners))
    assert bad == [], bad
    # an owner that can log in is the table owner (its authority is the schema's, and FORCE row
    # security binds it); any other owner must be a role nobody can connect as
    for owner in owners - {"migration_owner"}:
        (can_login,) = _rows("SELECT rolcanlogin FROM pg_roles WHERE rolname = :o", o=owner)[0]
        assert can_login is False, owner


def test_search_path_schemas_cannot_be_written_by_public(db_available):
    """A pinned path is only as safe as the schemas on it: PUBLIC must not be able to create objects
    in ``public`` (PostgreSQL 15 removed that default; this keeps it removed)."""
    (can,) = _rows(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) a "
        "WHERE n.nspname = 'public' AND a.grantee = 0 AND a.privilege_type = 'CREATE')")[0]
    assert can is False, "PUBLIC can create objects in schema public"


def test_the_database_does_not_let_public_create_or_make_temporary_objects(db_available):
    found = _rows("SELECT a.privilege_type FROM pg_database d, aclexplode(d.datacl) a "
                  "WHERE d.datname = current_database() AND a.grantee = 0")
    assert sorted(r[0] for r in found) == ["CONNECT"], found


def test_only_the_migrations_that_were_reviewed_contain_a_security_definer_function():
    found = set()
    for path in sorted((REPO / "db" / "migrations" / "versions").glob("*.py")):
        if re.search(r"SECURITY\s+DEFINER\b", path.read_text(), re.IGNORECASE):
            found.add(path.name)
    assert found == DEFINER_MIGRATIONS, (
        f"SECURITY DEFINER appears in {sorted(found)}; a new one must be reviewed and added to "
        "DEFINER_MIGRATIONS together with its entry in EXPECTED_DEFINERS")


# ---------------------------------------------------------------------------------------------
# views
# ---------------------------------------------------------------------------------------------

def test_the_complete_list_of_views_is_the_pinned_one_with_its_owner_and_grantees(db_available):
    rows = _rows("""
        SELECT c.relname, pg_get_userbyid(c.relowner), c.reloptions,
               COALESCE((SELECT array_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                                               ELSE pg_get_userbyid(a.grantee) END)
                         FROM aclexplode(c.relacl) a), ARRAY[]::text[])
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('v', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')""")
    found = {r[0]: {"owner": r[1], "options": list(r[2] or []), "grantees": set(r[3])}
             for r in rows}
    assert found == EXPECTED_VIEWS, (
        "a view runs with its owner's privileges: every one must be listed with its grantees. "
        f"found: {found}")


# ---------------------------------------------------------------------------------------------
# the rest of the surface
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT defaclobjtype FROM pg_default_acl",
    "SELECT evtname FROM pg_event_trigger",
    "SELECT srvname FROM pg_foreign_server",
    "SELECT pubname FROM pg_publication",
    "SELECT rolname FROM pg_roles r JOIN pg_db_role_setting s ON s.setrole = r.oid",
])
def test_the_catalog_has_no_object_that_changes_authority_behind_a_grant(db_available, sql):
    """Default privileges hand every future object to someone; event triggers run on DDL; a
    foreign server or publication reaches outside; a per-role setting can change a search_path."""
    assert _rows(sql) == []
