"""The migrations go up, come down and go up again, and arrive at the same schema (D63).

Until now only ``upgrade head`` on an empty database was ever exercised (by CI, once, at
provisioning). A ``downgrade`` that was never run is a claim, not a property -- and 0020 rewrites
data and swaps constraints, which is exactly the kind of step whose way back is easy to get
wrong. So these tests run the real chain, as the real ``migration_owner``, with the real
``alembic``, in a **scratch schema** (``search_path`` is set on the migration connection), so the
shared test database that every other test uses is never touched.

**Why a rewritten copy of the migrations.** Two migrations name the ``public`` schema outright
(``GRANT ... ON ALL TABLES IN SCHEMA public`` in 0001; ``GRANT/REVOKE USAGE ON SCHEMA public``
in the role migrations and their downgrades). Run against a scratch ``search_path`` they would
still reach the shared ``public`` schema -- and 0001's blanket grant would silently *widen* what
every later migration had narrowed (the first version of this test did exactly that, and the
privilege tests caught it). So the chain is run from a temporary copy in which ``SCHEMA public``
and the ``search_path = public`` of the 0015 functions name the scratch schema instead; nothing
else is touched. The fixture then **asserts that the shared schema's privileges are exactly what
they were**, so a migration that starts reaching outside its schema fails here, loudly.

What is established:

* an empty schema upgrades to the script head, and the head is not hard-coded here;
* head -> ``0015`` -> head, and head -> base -> head, each arrive at a schema whose columns,
  constraints, policies, indexes, triggers, functions and grants are **identical** to the first
  head;
* 0016-0020 are really undone by their downgrades (the scheduler's tables, the stage column);
* 0020 specifically: a row holding the retired skip code is **rewritten** on the way up, the
  database then refuses that code, and on the way down the old constraint accepts it again.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

REPO = Path(__file__).resolve().parents[1]
RETIRED = "no_usable_block_for_address"
REWRITTEN_TO = "scope_narrower_than_sandbox_minimum"


def _head() -> str:
    return ScriptDirectory.from_config(Config(str(REPO / "alembic.ini"))).get_current_head()


def _scoped_copy_of_the_migrations(schema: str, workdir: Path) -> Path:
    """An alembic config whose migrations name ``schema`` where the originals name ``public``."""
    target = workdir / "migrations"
    shutil.copytree(REPO / "db" / "migrations", target,
                    ignore=shutil.ignore_patterns("__pycache__"))
    for path in (target / "versions").glob("*.py"):
        text_ = path.read_text()
        text_ = re.sub(r"\bSCHEMA public\b", f"SCHEMA {schema}", text_)
        text_ = text_.replace("search_path = public, pg_temp", f"search_path = {schema}, pg_temp")
        path.write_text(text_)
    ini = workdir / "alembic.ini"
    ini.write_text((REPO / "alembic.ini").read_text().replace(
        "script_location = db/migrations", f"script_location = {target}"))
    return ini


def _public_privileges(engine) -> list:
    """Every privilege recorded on the shared ``public`` schema and what is in it."""
    with engine.begin() as conn:
        return [
            [tuple(r) for r in conn.execute(text(q)).all()] for q in (
                "SELECT nspname, nspacl::text FROM pg_namespace WHERE nspname = 'public'",
                "SELECT relname, relkind::text, relacl::text FROM pg_class "
                "WHERE relnamespace = 'public'::regnamespace ORDER BY 1",
                "SELECT attrelid::regclass::text, attname, attacl::text FROM pg_attribute "
                "WHERE attacl IS NOT NULL AND attrelid IN (SELECT oid FROM pg_class "
                "WHERE relnamespace = 'public'::regnamespace) ORDER BY 1, 2",
                "SELECT proname, proacl::text FROM pg_proc "
                "WHERE pronamespace = 'public'::regnamespace ORDER BY 1",
            )]


class Scratch:
    """A scratch schema that migrations run in, and the means to look at it."""

    def __init__(self, base_url: str, workdir: Path):
        self.name = f"migtest_{uuid.uuid4().hex[:10]}"
        self.ini = _scoped_copy_of_the_migrations(self.name, workdir)
        self.admin = create_engine(base_url, future=True)
        self.url = f"{base_url}?options=-csearch_path={self.name}"
        self.engine = create_engine(self.url, future=True)

    def alembic(self, *args: str) -> None:
        done = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(self.ini), *args], cwd=REPO,
            capture_output=True, text=True,
            env={**os.environ, "MIGRATION_DATABASE_URL": self.url}, timeout=300)
        assert done.returncode == 0, f"alembic {' '.join(args)} failed:\n{done.stderr[-2000:]}"

    def revision(self) -> str | None:
        with self.engine.begin() as conn:
            exists = conn.execute(text(
                "SELECT to_regclass(:t)"), {"t": f"{self.name}.alembic_version"}).scalar_one()
            if exists is None:
                return None
            return conn.execute(
                text("SELECT version_num FROM alembic_version")).scalar_one_or_none()

    def tables(self) -> set[str]:
        with self.engine.begin() as conn:
            return {r[0] for r in conn.execute(text(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = :s"),
                {"s": self.name})}

    def columns(self, table: str) -> set[str]:
        with self.engine.begin() as conn:
            return {r[0] for r in conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = :s AND table_name = :t"), {"s": self.name, "t": table})}

    def fingerprint(self) -> dict[str, list]:
        s = {"s": self.name}
        queries = {
            "columns": "SELECT table_name, column_name, data_type, is_nullable "
                       "FROM information_schema.columns WHERE table_schema = :s ORDER BY 1, 2",
            "constraints": "SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) "
                           "FROM pg_constraint WHERE connamespace = CAST(:s AS regnamespace) "
                           "ORDER BY 1, 2",
            "policies": "SELECT tablename, policyname, cmd, roles::text, qual, with_check "
                        "FROM pg_policies WHERE schemaname = :s ORDER BY 1, 2",
            "indexes": "SELECT indexname, indexdef FROM pg_indexes "
                       "WHERE schemaname = :s ORDER BY 1",
            "triggers": "SELECT tgname, tgrelid::regclass::text FROM pg_trigger "
                        "WHERE NOT tgisinternal AND tgrelid IN (SELECT oid FROM pg_class "
                        "WHERE relnamespace = CAST(:s AS regnamespace)) ORDER BY 1",
            "functions": "SELECT proname, pg_get_functiondef(oid) FROM pg_proc "
                         "WHERE pronamespace = CAST(:s AS regnamespace) ORDER BY 1",
            "table_grants": "SELECT table_name, grantee, privilege_type "
                            "FROM information_schema.role_table_grants WHERE table_schema = :s "
                            "ORDER BY 1, 2, 3",
            "column_grants": "SELECT table_name, column_name, grantee, privilege_type "
                             "FROM information_schema.column_privileges WHERE table_schema = :s "
                             "AND grantee <> 'migration_owner' ORDER BY 1, 2, 3, 4",
        }
        with self.engine.begin() as conn:
            return {k: [tuple(r) for r in conn.execute(text(q), s).all()]
                    for k, q in queries.items()}

    def drop(self) -> None:
        self.engine.dispose()
        with self.admin.begin() as conn:
            conn.execute(text(f"DROP SCHEMA IF EXISTS {self.name} CASCADE"))
        self.admin.dispose()


@pytest.fixture
def scratch(db_available, tmp_path):
    base = os.environ.get("MIGRATION_DATABASE_URL")
    assert base, "MIGRATION_DATABASE_URL is not set (scripts/init_db.sh writes it to .env)"
    box = Scratch(base, tmp_path)
    before = _public_privileges(box.admin)
    with box.admin.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {box.name}"))
    try:
        yield box
    finally:
        box.drop()
        after = _public_privileges(create_engine(base, future=True))
    assert after == before, "the migrations reached outside their schema: `public` changed"


def test_an_empty_schema_upgrades_to_the_script_head(scratch):
    assert scratch.revision() is None
    scratch.alembic("upgrade", "head")
    assert scratch.revision() == _head() == ScriptDirectory.from_config(
        Config(str(scratch.ini))).get_current_head()      # the copy has every revision
    assert {"scheduler_enrollment", "scheduler_state", "approvals", "action_proposals"} <= \
        scratch.tables()


def test_the_chain_goes_down_to_0015_and_to_base_and_comes_back_identical(scratch):
    scratch.alembic("upgrade", "head")
    first = scratch.fingerprint()

    # --- down to 0015: what 0016-0020 added is gone, what was there before is not
    scratch.alembic("downgrade", "0015")
    assert scratch.revision() == "0015"
    assert not ({"scheduler_enrollment", "scheduler_state"} & scratch.tables())
    proposals = scratch.columns("action_proposals")
    assert not ({"pipeline_stage", "decided_policy_version", "reviewer_hints"} & proposals)
    assert "snapshot" not in scratch.columns("approvals")
    assert {"proposal_id", "action", "target"} <= proposals           # the table itself is intact
    scratch.alembic("upgrade", "head")
    assert scratch.fingerprint() == first, "head -> 0015 -> head changed the schema"

    # --- and the whole way down
    scratch.alembic("downgrade", "base")
    assert scratch.tables() <= {"alembic_version"}
    scratch.alembic("upgrade", "head")
    assert scratch.revision() == _head()
    assert scratch.fingerprint() == first, "head -> base -> head changed the schema"


def _bind(conn, engagement_id: str) -> None:
    conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                 {"e": engagement_id})


def _add_proposal(conn, engagement_id: str) -> str:
    pid = f"PROP-MIG-{uuid.uuid4().hex[:8]}"
    conn.execute(text(
        'INSERT INTO action_proposals (proposal_id, engagement_id, agent_id, '
        'request_idempotency_key, action, target, "authorization", discovery) '
        "VALUES (:p, :e, 'a', :k, 'network.scan', '{}', '{}', '{}')"),
        {"p": pid, "e": engagement_id, "k": f"k-{pid}"})
    return pid


def _skip_it(conn, engagement_id: str, proposal_id: str, code: str) -> None:
    conn.execute(text(
        "INSERT INTO scheduler_state (engagement_id, proposal_id, kind, disposition, reason_code) "
        "VALUES (:e, :p, 'proposal', 'skipped', :c)"),
        {"e": engagement_id, "p": proposal_id, "c": code})


def _seed_a_skipped_proposal(scratch: Scratch, code: str) -> tuple[str, str]:
    """An engagement, a proposal and a ``scheduler_state`` row holding ``code``, written the way the
    scheduler writes it (an engagement bound, row-level security on)."""
    eid = f"ENG-MIG-{uuid.uuid4().hex[:8]}"
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        conn.execute(text(
            "INSERT INTO engagements (engagement_id, customer_id, policy_snapshot_version) "
            "VALUES (:e, 'CUST', 1)"), {"e": eid})
        pid = _add_proposal(conn, eid)
        _skip_it(conn, eid, pid, code)
    return eid, pid


def _state_code(scratch: Scratch, eid: str, pid: str) -> str:
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        return conn.execute(text(
            "SELECT reason_code FROM scheduler_state WHERE proposal_id = :p"),
            {"p": pid}).scalar_one()


def _insert_state(scratch: Scratch, eid: str, code: str) -> None:
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        _skip_it(conn, eid, _add_proposal(conn, eid), code)


def test_0020_rewrites_the_retired_code_up_refuses_it_after_and_accepts_it_again_down(scratch):
    scratch.alembic("upgrade", "0019")
    eid, pid = _seed_a_skipped_proposal(scratch, RETIRED)       # 0019 has six skip codes
    assert _state_code(scratch, eid, pid) == RETIRED

    scratch.alembic("upgrade", "0020")
    assert _state_code(scratch, eid, pid) == REWRITTEN_TO       # rewritten, not lost, not left
    with pytest.raises(IntegrityError):
        _insert_state(scratch, eid, RETIRED)                     # the database now refuses it
    _insert_state(scratch, eid, "target_is_reserved_address")    # and still takes the five

    scratch.alembic("downgrade", "0019")
    assert scratch.revision() == "0019"
    _insert_state(scratch, eid, RETIRED)                         # the old constraint is back
    assert _state_code(scratch, eid, pid) == REWRITTEN_TO        # (the rewrite is not undone: it
                                                                 # was a correction, not a mapping)
    scratch.alembic("upgrade", "head")
    assert scratch.revision() == _head()
