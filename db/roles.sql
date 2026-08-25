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
--   global_auditor   reads the globally-scoped audit rows and nothing else
--                    (D11-7). NOSUPERUSER, NOBYPASSRLS, owner of nothing; an
--                    RLS policy limits it to SELECT on audit_log WHERE
--                    scope='global'. No write anywhere, no other table.
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
