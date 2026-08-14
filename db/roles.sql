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
