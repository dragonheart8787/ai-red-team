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
_REGISTRY_ADMIN_ENGINE: Engine | None = None
_GLOBAL_AUDITOR_ENGINE: Engine | None = None
_UI_READER_ENGINE: Engine | None = None
_CREDENTIAL_ADMIN_ENGINE: Engine | None = None
_GLOBAL_POLICY_ADMIN_ENGINE: Engine | None = None
_SCHEDULER_READER_ENGINE: Engine | None = None
_SCHEDULER_ADMIN_ENGINE: Engine | None = None
_SCHEDULER_STATE_WRITER_ENGINE: Engine | None = None


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


def registry_admin_url() -> str:
    """The Engagement Manager's connection string (§5)."""
    return require_env(
        "REGISTRY_ADMIN_DATABASE_URL",
        hint="Run scripts/init_db.sh, or export REGISTRY_ADMIN_DATABASE_URL "
             "for the registry_admin role.",
    )


def global_auditor_url() -> str:
    """The global-audit reader's connection string (D11-7).

    Same no-fallback rule as the others: a default with a password is a
    committed credential.
    """
    return require_env(
        "GLOBAL_AUDITOR_DATABASE_URL",
        hint="Run scripts/init_db.sh, or export GLOBAL_AUDITOR_DATABASE_URL "
             "for the global_auditor role.",
    )


def ui_reader_url() -> str:
    """The web console's read connection string (D29)."""
    return require_env("UI_READER_DATABASE_URL")


def credential_admin_url() -> str:
    """The Credential Vault's write connection string (D44)."""
    return require_env(
        "CREDENTIAL_ADMIN_DATABASE_URL",
        hint="Run scripts/init_db.sh, or export CREDENTIAL_ADMIN_DATABASE_URL "
             "for the credential_admin role.",
    )


def global_policy_admin_url() -> str:
    """The global policy writer's connection string (5.37, D54).

    Read only by ``global_policy_admin_scope``, which only the operator CLI
    (``scripts/manage_global_policy.py``) opens; ``tests/test_global_policy_admin.py``
    fails if any other control-plane, agent or tool-gateway module reaches for it.
    """
    return require_env(
        "GLOBAL_POLICY_ADMIN_DATABASE_URL",
        hint="Run scripts/init_db.sh, or export GLOBAL_POLICY_ADMIN_DATABASE_URL "
             "for the global_policy_admin role.",
    )


def scheduler_reader_url() -> str:
    """The scheduler's read connection string (D62): ``scheduler_reader``, decision inputs only."""
    return require_env(
        "SCHEDULER_READER_DATABASE_URL",
        hint="Run scripts/init_db.sh, or export SCHEDULER_READER_DATABASE_URL "
             "for the scheduler_reader role.",
    )


def scheduler_admin_url() -> str:
    """The enrollment writer's connection string (D62). Read only by the operator CLI."""
    return require_env(
        "SCHEDULER_ADMIN_DATABASE_URL",
        hint="Run scripts/init_db.sh, or export SCHEDULER_ADMIN_DATABASE_URL "
             "for the scheduler_admin role.",
    )


def scheduler_state_writer_url() -> str:
    """The scheduler's state writer connection string (D62). Writes ``scheduler_state`` only."""
    return require_env(
        "SCHEDULER_STATE_WRITER_DATABASE_URL",
        hint="Run scripts/init_db.sh, or export SCHEDULER_STATE_WRITER_DATABASE_URL "
             "for the scheduler_state_writer role.",
    )


def get_engine() -> Engine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = create_engine(database_url(), pool_pre_ping=True, future=True)
    return _ENGINE


def get_registry_admin_engine() -> Engine:
    """A second pool, for the one role allowed to write the registries.

    Two pools rather than one connection that switches roles: SET ROLE can be
    reset from inside a session, so a single pool would make the privilege
    boundary something SQL could step across. Separate connections,
    authenticated as separate roles, cannot be talked out of their grants.
    """
    global _REGISTRY_ADMIN_ENGINE
    if _REGISTRY_ADMIN_ENGINE is None:
        _REGISTRY_ADMIN_ENGINE = create_engine(
            registry_admin_url(), pool_pre_ping=True, future=True
        )
    return _REGISTRY_ADMIN_ENGINE


def get_global_auditor_engine() -> Engine:
    """A third pool, for the role that reads global audit rows (D11-7).

    Separate connection for the same reason registry_admin has one: the reach of
    this role is an RLS policy the database enforces, and mixing it into a pool
    that also connects as another role would make the boundary something SQL
    could step across.
    """
    global _GLOBAL_AUDITOR_ENGINE
    if _GLOBAL_AUDITOR_ENGINE is None:
        _GLOBAL_AUDITOR_ENGINE = create_engine(
            global_auditor_url(), pool_pre_ping=True, future=True
        )
    return _GLOBAL_AUDITOR_ENGINE


def get_ui_reader_engine() -> Engine:
    """Pool for ``ui_reader`` — the console's reads, SELECT and nothing else."""
    global _UI_READER_ENGINE
    if _UI_READER_ENGINE is None:
        _UI_READER_ENGINE = create_engine(ui_reader_url(), pool_pre_ping=True,
                                          future=True)
    return _UI_READER_ENGINE


def get_global_policy_admin_engine() -> Engine:
    """Engine for the global policy writer (5.37, D54). Operator CLI only."""
    global _GLOBAL_POLICY_ADMIN_ENGINE
    if _GLOBAL_POLICY_ADMIN_ENGINE is None:
        _GLOBAL_POLICY_ADMIN_ENGINE = create_engine(
            global_policy_admin_url(), pool_pre_ping=True, future=True
        )
    return _GLOBAL_POLICY_ADMIN_ENGINE


def get_scheduler_reader_engine() -> Engine:
    """Pool for ``scheduler_reader`` (D62): the scheduling decision's inputs, SELECT only."""
    global _SCHEDULER_READER_ENGINE
    if _SCHEDULER_READER_ENGINE is None:
        _SCHEDULER_READER_ENGINE = create_engine(
            scheduler_reader_url(), pool_pre_ping=True, future=True
        )
    return _SCHEDULER_READER_ENGINE


def get_scheduler_admin_engine() -> Engine:
    """Engine for the enrollment writer (D62). Operator CLI only."""
    global _SCHEDULER_ADMIN_ENGINE
    if _SCHEDULER_ADMIN_ENGINE is None:
        _SCHEDULER_ADMIN_ENGINE = create_engine(
            scheduler_admin_url(), pool_pre_ping=True, future=True
        )
    return _SCHEDULER_ADMIN_ENGINE


def get_scheduler_state_writer_engine() -> Engine:
    """Pool for ``scheduler_state_writer`` (D62): ``scheduler_state`` and nothing else."""
    global _SCHEDULER_STATE_WRITER_ENGINE
    if _SCHEDULER_STATE_WRITER_ENGINE is None:
        _SCHEDULER_STATE_WRITER_ENGINE = create_engine(
            scheduler_state_writer_url(), pool_pre_ping=True, future=True
        )
    return _SCHEDULER_STATE_WRITER_ENGINE


def get_credential_admin_engine() -> Engine:
    """A fifth pool, for the one role allowed to write credential material (D44).

    Same reasoning as registry_admin's own pool: a privilege boundary that a
    session-level ``SET ROLE`` could step across is not a boundary. Separate
    connection, separate role, nothing SQL can talk out of.
    """
    global _CREDENTIAL_ADMIN_ENGINE
    if _CREDENTIAL_ADMIN_ENGINE is None:
        _CREDENTIAL_ADMIN_ENGINE = create_engine(
            credential_admin_url(), pool_pre_ping=True, future=True
        )
    return _CREDENTIAL_ADMIN_ENGINE


def reset_engine() -> None:
    """Drop the cached engines (tests switch roles between connections)."""
    global _ENGINE, _REGISTRY_ADMIN_ENGINE, _GLOBAL_AUDITOR_ENGINE, _UI_READER_ENGINE
    global _CREDENTIAL_ADMIN_ENGINE, _GLOBAL_POLICY_ADMIN_ENGINE
    global _SCHEDULER_READER_ENGINE, _SCHEDULER_ADMIN_ENGINE, _SCHEDULER_STATE_WRITER_ENGINE
    for engine in (_ENGINE, _REGISTRY_ADMIN_ENGINE, _GLOBAL_AUDITOR_ENGINE,
                   _UI_READER_ENGINE, _CREDENTIAL_ADMIN_ENGINE,
                   _GLOBAL_POLICY_ADMIN_ENGINE, _SCHEDULER_READER_ENGINE,
                   _SCHEDULER_ADMIN_ENGINE, _SCHEDULER_STATE_WRITER_ENGINE):
        if engine is not None:
            engine.dispose()
    _ENGINE = None
    _REGISTRY_ADMIN_ENGINE = None
    _GLOBAL_AUDITOR_ENGINE = None
    _UI_READER_ENGINE = None
    _CREDENTIAL_ADMIN_ENGINE = None
    _GLOBAL_POLICY_ADMIN_ENGINE = None
    _SCHEDULER_READER_ENGINE = None
    _SCHEDULER_ADMIN_ENGINE = None
    _SCHEDULER_STATE_WRITER_ENGINE = None


REGISTRY_ADMIN_ROLE = "registry_admin"
GLOBAL_AUDITOR_ROLE = "global_auditor"
UI_READER_ROLE = "ui_reader"
CREDENTIAL_ADMIN_ROLE = "credential_admin"
GLOBAL_POLICY_ADMIN_ROLE = "global_policy_admin"
SCHEDULER_READER_ROLE = "scheduler_reader"
SCHEDULER_ADMIN_ROLE = "scheduler_admin"
SCHEDULER_STATE_WRITER_ROLE = "scheduler_state_writer"


def assert_registry_admin(conn: Connection) -> None:
    """Refuse a registry write on a connection that is not registry_admin.

    The database already refuses it — that is the real enforcement, and the
    tests assert it directly. This turns "permission denied for table
    scope_registry" three frames deep into a message naming the actual mistake,
    which is passing the wrong connection.
    """
    role = conn.execute(text("SELECT current_user")).scalar_one()
    if role != REGISTRY_ADMIN_ROLE:
        raise PermissionError(
            f"registry writes require the {REGISTRY_ADMIN_ROLE} connection (§5); "
            f"this connection is {role!r}. Use registry_admin_scope()."
        )


def assert_credential_admin(conn: Connection) -> None:
    """Refuse a credential write on a connection that is not credential_admin (D44).

    Same shape as :func:`assert_registry_admin`: the database's own grants are
    the real enforcement, this only turns a permission-denied three frames deep
    into a message naming the actual mistake.
    """
    role = conn.execute(text("SELECT current_user")).scalar_one()
    if role != CREDENTIAL_ADMIN_ROLE:
        raise PermissionError(
            f"credential writes require the {CREDENTIAL_ADMIN_ROLE} connection "
            f"(D44); this connection is {role!r}. Use credential_admin_scope()."
        )


def assert_global_policy_admin(conn: Connection) -> None:
    """Refuse a global-layer write on a connection that is not global_policy_admin (5.37).

    The database already refuses it (a restrictive RLS policy on ``policy_layers``), and
    the tests assert that directly; this names the actual mistake -- the wrong connection
    -- instead of "new row violates row-level security policy" three frames down.
    """
    role = conn.execute(text("SELECT current_user")).scalar_one()
    if role != GLOBAL_POLICY_ADMIN_ROLE:
        raise PermissionError(
            f"publishing or retiring a global policy layer requires the "
            f"{GLOBAL_POLICY_ADMIN_ROLE} connection (5.37); this connection is {role!r}. "
            "It is an operator's action: use scripts/manage_global_policy.py."
        )


def assert_scheduler_admin(conn: Connection) -> None:
    """Refuse an enrollment write on a connection that is not scheduler_admin (D62)."""
    role = conn.execute(text("SELECT current_user")).scalar_one()
    if role != SCHEDULER_ADMIN_ROLE:
        raise PermissionError(
            f"changing the scheduler's enrollment requires the {SCHEDULER_ADMIN_ROLE} "
            f"connection (D62); this connection is {role!r}. It is an operator's action: "
            "use scripts/manage_scheduler_enrollment.py."
        )


@contextmanager
def _scoped(engine: Engine, engagement_id: str) -> Iterator[Connection]:
    if not engagement_id:
        raise ValueError("engagement_id is required: RLS fails closed without it")
    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('cyberorch.engagement_id', :eid, true)"),
            {"eid": engagement_id},
        )
        yield conn


@contextmanager
def engagement_scope(engagement_id: str) -> Iterator[Connection]:
    """Open a transaction bound to one engagement, as ``cyberorch_app``.

    Commits on success, rolls back on exception. Everything the caller can see
    inside is filtered by the RLS policy for ``engagement_id``. This connection
    can read the registries but not write them (§5).
    """
    with _scoped(get_engine(), engagement_id) as conn:
        yield conn


@contextmanager
def audit_scope(engagement_id: str) -> Iterator[Connection]:
    """A short transaction used only for writing audit records (§4.4).

    Separate from :func:`engagement_scope` so an audit record commits on its
    own, independent of whether the caller's transaction later succeeds. Uses
    the ``cyberorch_app`` engine, which holds INSERT and SELECT on audit_log
    and nothing else — both registry_admin and the app role audit through here,
    so there is one write path rather than one per caller role.
    """
    with _scoped(get_engine(), engagement_id) as conn:
        yield conn


@contextmanager
def registry_admin_scope(engagement_id: str) -> Iterator[Connection]:
    """Open a transaction as ``registry_admin`` — Engagement Manager only (§5).

    The only connection in the system that can write the Scope Registry or the
    Authoritative Metadata Registry. Still bound to one engagement and still
    subject to RLS: writing the registries is not permission to cross an
    engagement boundary.

    Reach for this only in engagement setup and registry maintenance. Every
    other component -- canonicalizer, resolvers, orchestrator, agents -- uses
    :func:`engagement_scope`, and the database will refuse them if they do not.
    """
    with _scoped(get_registry_admin_engine(), engagement_id) as conn:
        yield conn


@contextmanager
def credential_admin_scope(engagement_id: str) -> Iterator[Connection]:
    """Open a transaction as ``credential_admin`` — the Vault's write path (D44).

    The only connection that can write ``credential_material`` or insert a new
    ``credentials`` row. Still bound to one engagement and still subject to
    RLS: writing a credential is not permission to cross an engagement
    boundary, the same limit ``registry_admin_scope`` places on registry
    writes.

    Reach for this only when storing a new credential. Every dispatch
    function reads credential material through :func:`engagement_scope`
    (``cyberorch_app`` holds SELECT on ``credential_material`` — migration
    0012), the same read/write split ``scope_registry``/``metadata_registry``
    already established.
    """
    with _scoped(get_credential_admin_engine(), engagement_id) as conn:
        yield conn


@contextmanager
def global_audit_scope() -> Iterator[Connection]:
    """Write a globally-scoped audit record (D11-7).

    The ``cyberorch_app`` engine, deliberately with **no** engagement bound:
    a global operation belongs to no engagement, and the row carries
    ``engagement_id IS NULL``. The ``audit_global_insert`` policy lets that row
    through; the per-engagement policy would reject it, and being OR'd, does not.
    This path only ever inserts ``scope='global'`` rows — the engagement path is
    :func:`audit_scope`.
    """
    with get_engine().begin() as conn:
        yield conn


@contextmanager
def global_auditor_scope() -> Iterator[Connection]:
    """Read global audit rows as ``global_auditor`` (D11-7).

    No engagement is set: this role reads across the global rows, which belong to
    no single engagement, and its RLS policy returns exactly those. The
    per-engagement policy also applies and, with no engagement bound, matches
    nothing — so this connection sees the global rows and no engagement's. It can
    read ``audit_log`` and touch nothing else; the database enforces both.
    """
    with get_global_auditor_engine().begin() as conn:
        yield conn


@contextmanager
def ui_reader_scope(engagement_id: str) -> Iterator[Connection]:
    """Read one engagement as ``ui_reader`` — the web console's reads (D29).

    Same engagement pinning and the same ``engagement_isolation`` policy as
    :func:`engagement_scope`; the difference is entirely in what the role may
    do, which is SELECT on the tables the dashboard shows and nothing else. It
    holds no INSERT anywhere, ``audit_log`` included.

    So this is not a way to see more, it is a way for a browser-facing read
    endpoint to be incapable of writing. The console's approve and deny actions
    deliberately do **not** come through here: they run the existing D24
    functions on :func:`engagement_scope`, which is the one write path and the
    one audit path, shared with ``scripts/approvals.py``.

    There is no unscoped variant, for the reason the module docstring gives: an
    escape hatch "just for the dashboard" is how a repository layer stops being
    unbypassable. A console that wants to show two engagements opens this twice.
    """
    with _scoped(get_ui_reader_engine(), engagement_id) as conn:
        yield conn


@contextmanager
def global_policy_admin_scope() -> Iterator[Connection]:
    """Write a *global* policy layer as ``global_policy_admin`` (5.37, D54).

    No engagement is bound, on purpose: a global layer belongs to none, and a
    restrictive policy on ``policy_layers`` confines this role to rows with
    ``engagement_id IS NULL`` whatever an engagement setting might say. The only
    connection in the system that can publish or retire a baseline, an emergency
    overlay or a global customer layer.

    **Operator use only.** ``scripts/manage_global_policy.py`` is the intended caller. It
    is not for the dispatch path, an agent, the console or any service, for the reason
    that the role exists: retiring an emergency overlay is a relaxation, the same
    seriousness as the kill switch, and it must be a person's decision made with a
    credential no automated component holds. ``tests/test_global_policy_admin.py`` scans
    the control plane, the agents and the tool gateway for any other reference to this
    function or to its connection string, and fails on one.
    """
    with get_global_policy_admin_engine().begin() as conn:
        yield conn


@contextmanager
def scheduler_reader_scope(engagement_id: str) -> Iterator[Connection]:
    """A read transaction bound to one engagement, as ``scheduler_reader`` (D62).

    The scheduling decision's only window onto an engagement: the columns and the view the role was
    granted, filtered by the same ``engagement_isolation`` policy as every other role. It cannot
    write, and it holds no grant on the content tables, so code that is handed this connection
    cannot read what it must not decide on.
    """
    with _scoped(get_scheduler_reader_engine(), engagement_id) as conn:
        yield conn


@contextmanager
def scheduler_reader_enrollment_scope() -> Iterator[Connection]:
    """The enrollment list, as ``scheduler_reader``, no engagement bound (D62).

    ``scheduler_enrollment`` is global by design -- the reader has to list ids to know which
    engagement to open -- and is the only thing readable without one. Every engagement table still
    returns nothing on this connection.
    """
    with get_scheduler_reader_engine().begin() as conn:
        yield conn


@contextmanager
def scheduler_state_writer_scope(engagement_id: str) -> Iterator[Connection]:
    """A write transaction on ``scheduler_state`` for one engagement (D62); nothing else."""
    with _scoped(get_scheduler_state_writer_engine(), engagement_id) as conn:
        yield conn


@contextmanager
def scheduler_admin_scope() -> Iterator[Connection]:
    """The enrollment writer's transaction (D62). The operator CLI only; a test scans for that."""
    with get_scheduler_admin_engine().begin() as conn:
        yield conn


def open_scheduler_lock_connection() -> Connection:
    """One dedicated, unpooled, autocommit connection for the singleton lock (D62, D58-2).

    Its own engine and no pool: the advisory lock belongs to *this* session, so the session must
    not be shared, recycled or pre-pinged away. TCP keepalives make a vanished server noticed in
    seconds. The caller owns it and closes it.
    """
    from sqlalchemy.pool import NullPool

    engine = create_engine(
        scheduler_reader_url(), poolclass=NullPool, future=True,
        isolation_level="AUTOCOMMIT",
        connect_args={"keepalives": 1, "keepalives_idle": 5, "keepalives_interval": 2,
                      "keepalives_count": 3},
    )
    return engine.connect()
