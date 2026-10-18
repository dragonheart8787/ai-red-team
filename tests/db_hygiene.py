"""State a killed test or a killed mutation run can leave in the database, and how to see it.

The migration round-trip tests (``tests/test_migrations_roundtrip.py``) run the chain, down and
up, in a **scratch schema** (``migtest_*``) of the development database -- and the chain's first
read-side migration (0023) and its downgrade turn the **database-wide** ``TEMPORARY`` privilege
of PUBLIC off and on. A test process killed in the middle leaves both: a schema nobody drops and,
if it was killed below 0023, ``TEMPORARY`` granted to everyone. That is exactly what an
interrupted mutation sweep did on 2026-10-14 (the next full run put the privilege back and the
schema had to be dropped by hand).

This module only *sees*: ``problems`` returns what is wrong, as sentences. The session end
(``tests/residue.py``, ACCEPTANCE 5.71) fails the run on any; the mutation runner
(``scripts/mutation_check.py``) puts the state right at start and after every mutation, and says
that it did.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine, text

SCRATCH_PREFIX = "migtest_"
#: the migration from which PUBLIC holds no TEMPORARY on the database (0023's upgrade revokes it)
REVOKES_TEMPORARY_FROM = 23


def _owner_engine():
    return create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)


def scratch_schemas(conn) -> list[str]:
    return sorted(r[0] for r in conn.execute(text(
        "SELECT nspname FROM pg_namespace WHERE nspname LIKE :p"), {"p": SCRATCH_PREFIX + "%"}))


def public_holds_temporary(conn) -> bool:
    return bool(conn.execute(text(
        "SELECT EXISTS (SELECT 1 FROM pg_database d, aclexplode(d.datacl) a "
        "WHERE d.datname = current_database() AND a.grantee = 0 "
        "AND a.privilege_type = 'TEMPORARY')")).scalar_one())


def migration_number(conn) -> int | None:
    version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    return int(version) if version and str(version).isdigit() else None


def problems(conn) -> list[str]:
    """What a killed run left: scratch schemas, and a ``TEMPORARY`` grant to PUBLIC that the
    applied migrations have revoked."""
    found = [f"a scratch schema of a round-trip test was left: {name}"
             for name in scratch_schemas(conn)]
    number = migration_number(conn)
    if number is not None and number >= REVOKES_TEMPORARY_FROM and public_holds_temporary(conn):
        found.append("PUBLIC holds TEMPORARY on the database although migration 0023 or later "
                     "is applied (a round trip was killed below 0023)")
    return found


def current_problems() -> list[str]:
    engine = _owner_engine()
    try:
        with engine.connect() as conn:
            return problems(conn)
    finally:
        engine.dispose()
