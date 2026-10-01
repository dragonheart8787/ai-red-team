-- ARCHITECTURE.md §8.6 — DB role separation.
--
-- PostgreSQL RLS is silently bypassed by superusers, by roles carrying
-- BYPASSRLS, and by a table's owner unless FORCE ROW LEVEL SECURITY is set.
-- So a complete RLS policy set is worth nothing if the application happens to
-- connect as the table owner. Two roles, with different jobs:
--
--   migration_owner  runs DDL/alembic and owns every table.
--   cyberorch_app    the runtime connection. NOSUPERUSER, NOBYPASSRLS, and
--                    owner of nothing. RLS therefore always applies to it.
--   registry_admin   the Engagement Manager's connection. Identical to
--                    cyberorch_app except that it may write scope_registry and
--                    metadata_registry (§5). Not an administrator: same RLS,
--                    same engagement boundary, two extra tables it can write.
--   ui_reader        the web console's read connection (D29). SELECT on the
--                    tables the dashboard shows, and nothing else: no INSERT
--                    anywhere, not even audit_log. Same RLS, same engagement
--                    boundary. The console's approve/deny actions do NOT use
--                    this role -- they run through the D24 path as
--                    cyberorch_app -- so a bug in a read endpoint cannot write.
--   global_auditor   reads the globally-scoped audit rows and nothing else
--                    (D11-7). NOSUPERUSER, NOBYPASSRLS, owner of nothing; an
--                    RLS policy limits it to SELECT on audit_log WHERE
--                    scope='global'. No write anywhere, no other table.
--   credential_admin the Credential Vault's write path (D44). A new role,
--                    not registry_admin widened: writing a real customer
--                    credential is a strictly higher-sensitivity category
--                    than scope/metadata, so it gets its own connection
--                    rather than growing an existing one's blast radius,
--                    the same reasoning that kept ui_reader and
--                    global_auditor from ever being folded into
--                    registry_admin. SELECT+INSERT on credential_material
--                    and credentials, nothing else -- see migration 0012.
--
--   global_policy_admin  the only role that publishes or retires a *global* policy
--                    layer (baseline_global, emergency_overlay, a global customer
--                    layer -- every row with engagement_id IS NULL), 5.37 / D54.
--                    A new role for a new duty, as credential_admin was for the
--                    Vault: the runtime role every Worker, Reviewer and Supervisor
--                    call runs as could publish and retire global layers, which
--                    made retiring an emergency overlay -- a relaxation -- a
--                    runtime-credential operation. Its reach is INSERT/SELECT and
--                    UPDATE (active) on policy_layers, confined by a restrictive RLS
--                    policy to rows with engagement_id IS NULL, and nothing else. It
--                    is used by an operator's CLI (scripts/manage_global_policy.py),
--                    never by a service: no dispatch, agent or console path may open
--                    its connection (a test scans for that).
--
-- Run as a superuser, before the first migration. Passwords come from psql
-- variables so none is committed: see scripts/init_db.sh.
--
-- Roles are cluster-global, so this is deliberately idempotent.

\set ON_ERROR_STOP on

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'migration_owner') THEN
        CREATE ROLE migration_owner LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cyberorch_app') THEN
        CREATE ROLE cyberorch_app LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'registry_admin') THEN
        CREATE ROLE registry_admin LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'global_auditor') THEN
        CREATE ROLE global_auditor LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ui_reader') THEN
        CREATE ROLE ui_reader LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'global_policy_admin') THEN
        CREATE ROLE global_policy_admin LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'credential_admin') THEN
        CREATE ROLE credential_admin LOGIN;
    END IF;
END
$$;

ALTER ROLE migration_owner
    WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
    PASSWORD :'migration_owner_password';

-- The runtime role. Every attribute here is load-bearing: drop NOSUPERUSER or
-- NOBYPASSRLS and I4 (Engagement Isolation) stops being enforced by the
-- database, leaving only application-layer filtering.
ALTER ROLE cyberorch_app
    WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
    PASSWORD :'cyberorch_app_password';

-- The Engagement Manager's role (§5). Deliberately NOBYPASSRLS: the ability to
-- write the registries is not the ability to reach across engagements. It is
-- cyberorch_app plus write access to exactly two tables, nothing more — an
-- administrator role here would trade one over-broad grant for another.
ALTER ROLE registry_admin
    WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
    PASSWORD :'registry_admin_password';

-- The global-audit reader (D11-7). NOBYPASSRLS for the same reason as the
-- others: its reach is defined by an RLS policy (SELECT on audit_log WHERE
-- scope='global'), not by trusting it to stay in its lane. It owns nothing and
-- writes nothing; a globally-scoped record needs a reader that belongs to no
-- single engagement, and this is the whole of that reader's power.
ALTER ROLE global_auditor
    WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
    PASSWORD :'global_auditor_password';

-- The web console's read connection (D29). NOBYPASSRLS for the same reason as
-- every other role here: its reach is defined by the engagement_isolation
-- policy, not by trusting a web process to stay in its lane. It owns nothing
-- and -- unlike cyberorch_app -- holds no INSERT on any table, so the read
-- endpoints of a browser-facing service are structurally incapable of writing.
-- The console still needs to approve and deny, and does that through the
-- existing D24 functions on the cyberorch_app connection; splitting the two
-- means a defect in a read path is a read defect.
ALTER ROLE ui_reader
    WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
    PASSWORD :'ui_reader_password';

-- The Credential Vault's write path (D44). NOBYPASSRLS like every other role
-- here: its reach is defined by the engagement_isolation policy on
-- credential_material (migration 0012), not by trusting it to stay in its
-- lane. It cannot read scope_registry/metadata_registry (registry_admin's
-- tables) and registry_admin cannot read credential_material -- the two
-- write paths this system now has for its most sensitive data stay apart.
ALTER ROLE credential_admin
    WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
    PASSWORD :'credential_admin_password';

-- The global policy writer (5.37, D54). NOBYPASSRLS like every other role here:
-- what confines it to global rows is the restrictive policy in migration 0014, not
-- trust. It holds no grant on any registry, credential or audit table -- its audit
-- record is written by the ordinary audit path, as for every other operation.
ALTER ROLE global_policy_admin
    WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION
    PASSWORD :'global_policy_admin_password';
