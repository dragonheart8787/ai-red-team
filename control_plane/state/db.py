"""Engine and the engagement-scoped session (§8.6).

Every read and write goes through :func:`engagement_scope`, which pins the
current engagement into a transaction-local GUC that the RLS policies read.
There is deliberately no way to get a connection without naming an engagement:
§8.6 asks for a repository layer that cannot be bypassed, and an escape hatch
"just for admin queries" is how such layers stop being unbypassable.

The GUC is set with ``set_config(..., is_local => true)`` so it dies with the
transaction. A session-level SET would survive being returned to the pool and
leak one engagement's scope into the next checkout.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Connection, Engine, create_engine, text

from control_plane.config import require_env

_ENGINE: Engine | None = None


def database_url() -> str:
    """The runtime connection string — always from the environment.

    No fallback: a default containing a password is a credential committed to
    the repository, and one that silently works locally is one nobody notices
    shipping.
    """
    return require_env(
        "DATABASE_URL",
        hint="Run scripts/init_db.sh to provision the database and write .env, "
             "or export DATABASE_URL for the cyberorch_app role.",
    )


def get_engine() -> Engine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = create_engine(database_url(), pool_pre_ping=True, future=True)
    return _ENGINE


def reset_engine() -> None:
    """Drop the cached engine (tests switch roles between connections)."""
    global _ENGINE
    if _ENGINE is not None:
        _ENGINE.dispose()
    _ENGINE = None


@contextmanager
def engagement_scope(engagement_id: str) -> Iterator[Connection]:
    """Open a transaction bound to one engagement.

    Commits on success, rolls back on exception. Everything the caller can see
    inside is filtered by the RLS policy for ``engagement_id``.
    """
    if not engagement_id:
        raise ValueError("engagement_id is required: RLS fails closed without it")
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('cyberorch.engagement_id', :eid, true)"),
            {"eid": engagement_id},
        )
        yield conn
