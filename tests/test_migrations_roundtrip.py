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
* after **every** migration step, up or down, ``scheduler_state`` and ``scheduler_enrollment`` (when
  they exist) have ``FORCE ROW LEVEL SECURITY`` on -- the table owner is bound by the policies;
* 0020 switches ``FORCE`` off for one statement to rewrite rows (the owner is otherwise blind to
  them) and back on: that pair is shown to be **atomic** -- a failure between them rolls both back,
  so there is no committed state in which the table's isolation is off;
* 0020 specifically: a row holding the retired skip code is **rewritten** on the way up, the
  database then refuses that code, and on the way down the old constraint accepts it again;
* 0021 specifically: a proposal past ``received`` with no decision **blocks** the upgrade (and
  nothing of it is committed), once the row is corrected the upgrade goes through and the database
  refuses every stage but ``received`` without a decision, and the downgrade takes the constraint
  away again.
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

from control_plane.state.schema_snapshot import diff as snapshot_diff
from control_plane.state.schema_snapshot import snapshot_schema

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

    def alembic_fails(self, *args: str) -> str:
        done = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(self.ini), *args], cwd=REPO,
            capture_output=True, text=True,
            env={**os.environ, "MIGRATION_DATABASE_URL": self.url}, timeout=300)
        assert done.returncode != 0, f"alembic {' '.join(args)} was expected to fail"
        return done.stderr

    def force_rls(self) -> dict[str, bool]:
        """``relforcerowsecurity`` of the scheduler's tables that exist at the current revision."""
        with self.engine.begin() as conn:
            return {r[0]: r[1] for r in conn.execute(text(
                "SELECT relname, relforcerowsecurity FROM pg_class "
                "WHERE relnamespace = CAST(:s AS regnamespace) "
                "AND relname IN ('scheduler_state', 'scheduler_enrollment')"), {"s": self.name})}

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

    def snapshot(self) -> dict[str, str]:
        """Everything ``snapshot_schema`` covers (COMMENTs, ACLs, RLS flags, function attributes),
        which ``fingerprint`` above does not."""
        with self.engine.begin() as conn:
            return snapshot_schema(conn, self.name)

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
    first_snapshot = scratch.snapshot()

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
    assert not snapshot_diff(first_snapshot, scratch.snapshot()), snapshot_diff(
        first_snapshot, scratch.snapshot())

    # --- and the whole way down
    scratch.alembic("downgrade", "base")
    assert scratch.tables() <= {"alembic_version"}
    scratch.alembic("upgrade", "head")
    assert scratch.revision() == _head()
    assert scratch.fingerprint() == first, "head -> base -> head changed the schema"
    assert not snapshot_diff(first_snapshot, scratch.snapshot()), (
        "head -> base -> head changed something the fingerprint does not look at (a COMMENT, an "
        "ACL, an RLS flag, a function attribute):\n"
        + "\n".join(snapshot_diff(first_snapshot, scratch.snapshot())))


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


SCHEDULER_TABLES = {"scheduler_state", "scheduler_enrollment"}


def _revisions_from(first: str) -> list[str]:
    """Revision ids from ``first`` to head, oldest first, read from the script directory."""
    script = ScriptDirectory.from_config(Config(str(REPO / "alembic.ini")))
    return [r.revision for r in reversed(list(script.walk_revisions())) if r.revision >= first]


def test_the_schedulers_tables_keep_force_row_security_after_every_step_up_and_down(scratch):
    steps = _revisions_from("0018")
    assert steps[-1] == _head() and "0019" in steps and "0020" in steps

    def check(revision: str) -> None:
        present = scratch.force_rls()
        if revision >= "0019":
            assert set(present) == SCHEDULER_TABLES, (revision, present)
        else:
            assert present == {}, (revision, present)
        assert all(present.values()), f"FORCE ROW LEVEL SECURITY is off at {revision}: {present}"

    scratch.alembic("upgrade", steps[0])
    check(steps[0])
    for revision in steps[1:]:                                  # up, one migration at a time
        scratch.alembic("upgrade", revision)
        check(revision)
    for revision in reversed(steps[:-1]):                       # and down, one at a time
        scratch.alembic("downgrade", revision)
        check(revision)
    scratch.alembic("upgrade", "head")                          # and up the whole way again
    check(_head())


def test_0020_switches_force_row_security_off_and_on_inside_one_transaction(scratch):
    """The rewrite needs ``NO FORCE`` for one statement. If a failure (or a crash) could leave it
    off, a committed state would exist in which the owner is not bound by the isolation policy.
    Two proofs: the pair is in one ``upgrade()`` with nothing that commits in between, and a failure
    injected between them leaves the committed schema exactly as it was at 0019."""
    path = REPO / "db" / "migrations" / "versions" / "0020_scheduler_state_narrow.py"
    source = path.read_text()
    upgrade = source[source.index("def upgrade()"):source.index("def downgrade()")]
    off = upgrade.find("ALTER TABLE scheduler_state NO FORCE ROW LEVEL SECURITY")
    rewrite = upgrade.find("UPDATE scheduler_state")
    on = upgrade.find("ALTER TABLE scheduler_state FORCE ROW LEVEL SECURITY")
    assert min(off, rewrite, on) >= 0, (
        f"0020 must switch FORCE off, rewrite, and switch it on again (positions {off}, "
        f"{rewrite}, {on}; -1 = missing)")
    assert off < rewrite < on, "0020 does not do NO FORCE, then the rewrite, then FORCE"
    assert "autocommit" not in source and "COMMIT" not in source.upper().replace("COMMENT", "")

    scratch.alembic("upgrade", "0019")
    eid, pid = _seed_a_skipped_proposal(scratch, RETIRED)
    before = scratch.fingerprint()
    assert scratch.force_rls()["scheduler_state"] is True

    broken = Path(scratch.ini).parent / "migrations" / "versions" / "0020_scheduler_state_narrow.py"
    text_ = broken.read_text()
    marker = '    op.execute("ALTER TABLE scheduler_state FORCE ROW LEVEL SECURITY;")\n'
    assert text_.count(marker) == 1
    broken.write_text(text_.replace(marker, '    op.execute("SELECT 1/0;")\n' + marker))

    scratch.alembic_fails("upgrade", "0020")

    assert scratch.revision() == "0019"                          # nothing of 0020 was committed
    assert scratch.force_rls()["scheduler_state"] is True        # in particular, not the NO FORCE
    assert scratch.fingerprint() == before                       # nor the dropped constraints
    assert _state_code(scratch, eid, pid) == RETIRED             # nor the rewrite


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
    try:
        _insert_state(scratch, eid, RETIRED)                     # the old constraint is back
    except IntegrityError as refused:
        pytest.fail(f"after the downgrade the database still refuses the retired code: "
                    f"{str(refused.orig).splitlines()[0]}")
    assert _state_code(scratch, eid, pid) == REWRITTEN_TO        # (the rewrite is not undone: it
                                                                 # was a correction, not a mapping)
    scratch.alembic("upgrade", "head")
    assert scratch.revision() == _head()


# ---------------------------------------------------------------------------------------------
# 0021: a proposal past `received` has a decision
# ---------------------------------------------------------------------------------------------

CONSTRAINT_0021 = "action_proposals_decision_past_received"


def _set_stage(scratch: Scratch, eid: str, pid: str, stage: str, decision: str | None) -> None:
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        conn.execute(text(
            "UPDATE action_proposals SET pipeline_stage = :s, decision = :d "
            "WHERE proposal_id = :p"),
            {"s": stage, "d": decision, "p": pid})


def test_0021_blocks_on_an_undecided_proposal_past_received_and_leaves_nothing_behind(scratch):
    from control_plane.orchestrator.stages import RECEIVED, STAGES

    scratch.alembic("upgrade", "0020")
    eid = f"ENG-MIG-{uuid.uuid4().hex[:8]}"
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        conn.execute(text("INSERT INTO engagements (engagement_id, customer_id, "
                          "policy_snapshot_version) VALUES (:e, 'CUST', 1)"), {"e": eid})
        pid = _add_proposal(conn, eid)
    _set_stage(scratch, eid, pid, "recorded", None)             # 0020 lets this exist
    before = scratch.fingerprint()

    error = scratch.alembic_fails("upgrade", "0021")

    assert CONSTRAINT_0021 in error and "violated by some row" in error, error[-600:]
    assert scratch.revision() == "0020"
    assert scratch.fingerprint() == before                       # the failed step left no trace

    _set_stage(scratch, eid, pid, "recorded", "ALLOW")           # the row is corrected by a person
    scratch.alembic("upgrade", "0021")
    assert scratch.revision() == "0021"

    for stage in STAGES:                                         # every stage 0021 knows
        if stage == "abandoned":                                 # (0022's: not legal here yet)
            continue
        if stage == RECEIVED:
            _set_stage(scratch, eid, pid, stage, None)
            continue
        with pytest.raises(IntegrityError) as refused:
            _set_stage(scratch, eid, pid, stage, None)
        assert CONSTRAINT_0021 in str(refused.value), stage
        _set_stage(scratch, eid, pid, stage, "ALLOW")            # and with one, accepted

    scratch.alembic("downgrade", "0020")
    assert scratch.revision() == "0020"
    _set_stage(scratch, eid, pid, "recorded", None)              # the way back is open again
    assert "violated by some row" in scratch.alembic_fails("upgrade", "head")   # and blocks again
    _set_stage(scratch, eid, pid, "recorded", "ALLOW")
    scratch.alembic("upgrade", "head")
    assert scratch.revision() == _head()


# ---------------------------------------------------------------------------------------------
# 0017 with rows (ACCEPTANCE 5.75): the data statements of a migration under FORCE RLS
# ---------------------------------------------------------------------------------------------

def _seed_at_0016(scratch: Scratch) -> tuple[str, dict[str, str]]:
    """An engagement and one proposal for each stage 0016 knows, plus the three ways a proposal that
    was ``closed`` for ``HUMAN_APPROVAL`` can have ended -- written with an engagement bound, the
    way the application writes them."""
    eid = f"ENG-MIG-{uuid.uuid4().hex[:8]}"
    ids: dict[str, str] = {}
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        conn.execute(text("INSERT INTO engagements (engagement_id, customer_id, "
                          "policy_snapshot_version) VALUES (:e, 'CUST', 1)"), {"e": eid})
        shapes = {                       # name -> (stage, detail, decision)
            "received": ("received", None, None),
            "decided": ("decided", None, "ALLOW"),
            "capability_issued": ("capability_issued", None, "ALLOW"),
            "dispatching": ("dispatching", None, "ALLOW"),
            "recorded": ("recorded", "succeeded", "ALLOW"),
            "closed_deny": ("closed", "decision_DENY", "DENY"),
            "ha_pending": ("closed", "decision_HUMAN_APPROVAL", "HUMAN_APPROVAL"),
            "ha_approved": ("closed", "decision_HUMAN_APPROVAL", "HUMAN_APPROVAL"),
            "ha_denied": ("closed", "decision_HUMAN_APPROVAL", "HUMAN_APPROVAL"),
        }
        for name, (stage, detail, decision) in shapes.items():
            ids[name] = _add_proposal(conn, eid)
            conn.execute(text(
                "UPDATE action_proposals SET pipeline_stage = :s, stage_detail = :d, decision = :x "
                "WHERE proposal_id = :p"),
                {"s": stage, "d": detail, "x": decision, "p": ids[name]})
        conn.execute(text(
            "INSERT INTO approvals (approval_id, engagement_id, proposal_id, action_class, "
            "valid_until, approved_by, approved_scope) VALUES "
            "(:a, :e, :p, 'network.scan', now() + interval '1 day', 'human', "
            "'this_proposal_only')"),
            {"a": f"APPR-{uuid.uuid4().hex[:6]}", "e": eid, "p": ids["ha_approved"]})
        conn.execute(text(
            "INSERT INTO audit_log (engagement_id, actor, event_type, subject_type, subject_id) "
            "VALUES (:e, 'human', 'approval.denied', 'action_proposal', :p)"),
            {"e": eid, "p": ids["ha_denied"]})
    return eid, ids


def _stage_of(scratch: Scratch, eid: str, pid: str) -> tuple[str, str | None]:
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        return tuple(conn.execute(text(
            "SELECT pipeline_stage, stage_detail FROM action_proposals WHERE proposal_id = :p"),
            {"p": pid}).one())


def test_0017_backfills_the_right_proposals_and_its_downgrade_works_with_rows(scratch):
    scratch.alembic("upgrade", "0016")
    eid, ids = _seed_at_0016(scratch)
    untouched = {n: _stage_of(scratch, eid, ids[n]) for n in
                 ("received", "decided", "capability_issued", "dispatching", "recorded",
                  "closed_deny")}

    scratch.alembic("upgrade", "0017")

    # The back-fill: a HUMAN_APPROVAL that was waiting becomes `awaiting_approval`; one a human
    # approved stays closed (no old approval is resurrected); one that was denied says so.
    assert _stage_of(scratch, eid, ids["ha_pending"]) == ("awaiting_approval", None)
    assert _stage_of(scratch, eid, ids["ha_approved"]) == ("closed", "decision_HUMAN_APPROVAL")
    assert _stage_of(scratch, eid, ids["ha_denied"]) == ("closed", "approval_denied")
    assert {n: _stage_of(scratch, eid, ids[n]) for n in untouched} == untouched
    assert scratch.force_rls() == {}                            # (the scheduler's tables: not yet)

    # A proposal that is `approved` at 0017 has nowhere to go in the old vocabulary.
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        ids["approved"] = _add_proposal(conn, eid)
        conn.execute(text(
            "UPDATE action_proposals SET pipeline_stage = 'approved', stage_detail = 'APPR-X', "
            "decision = 'HUMAN_APPROVAL' WHERE proposal_id = :p"), {"p": ids["approved"]})

    scratch.alembic("downgrade", "0016")                         # fails today without the repair
    assert scratch.revision() == "0016"
    for name in ("ha_pending", "approved"):                      # both read as the old `closed`
        assert _stage_of(scratch, eid, ids[name]) == ("closed", "decision_HUMAN_APPROVAL"), name
    assert {n: _stage_of(scratch, eid, ids[n]) for n in untouched} == untouched

    scratch.alembic("upgrade", "head")                           # and the way back up is clean
    assert scratch.revision() == _head()
    assert _stage_of(scratch, eid, ids["ha_approved"]) == ("closed", "decision_HUMAN_APPROVAL")
    # every table the data statements touched has FORCE ROW LEVEL SECURITY back
    with scratch.engine.begin() as conn:
        off = [r[0] for r in conn.execute(text(
            "SELECT relname FROM pg_class WHERE relnamespace = CAST(:s AS regnamespace) "
            "AND relkind = 'r' AND relrowsecurity AND NOT relforcerowsecurity"),
            {"s": scratch.name})]
    assert off == [], f"FORCE ROW LEVEL SECURITY is off after the migrations for: {off}"


# ---------------------------------------------------------------------------------------------
# 0022: the stage `abandoned` -- every stage has a row, and the COMMENTs come back (ST7)
# ---------------------------------------------------------------------------------------------

#: name -> (stage, detail, decision) for every stage 0021 knows; `abandoned` joins at 0022.
SHAPES_0021 = {
    "received": ("received", None, None),
    "decided": ("decided", None, "ALLOW"),
    "awaiting_approval": ("awaiting_approval", None, "HUMAN_APPROVAL"),
    "approved": ("approved", "APPR-X", "HUMAN_APPROVAL"),
    "capability_issued": ("capability_issued", None, "ALLOW"),
    "dispatching": ("dispatching", None, "ALLOW"),
    "recorded": ("recorded", "succeeded", "ALLOW"),
    "closed": ("closed", "decision_DENY", "DENY"),
}
ABANDONED_SHAPE = ("abandoned", "undecided_past_grace", None)

#: What 0022 changes, as snapshot keys -- and nothing else may change.
CHANGED_BY_0022 = {
    "constraint:action_proposals.action_proposals_pipeline_stage_check",
    "constraint:action_proposals.action_proposals_decision_past_received",
    "constraint:action_proposals.action_proposals_abandoned_is_undecided",       # (new)
    "index:action_proposals_open_stage",
    "column:action_proposals.pipeline_stage",                                    # its COMMENT
}


def _seed_stages(scratch: Scratch, shapes: dict) -> tuple[str, dict[str, str]]:
    eid = f"ENG-MIG-{uuid.uuid4().hex[:8]}"
    ids: dict[str, str] = {}
    with scratch.engine.begin() as conn:
        _bind(conn, eid)
        conn.execute(text("INSERT INTO engagements (engagement_id, customer_id, "
                          "policy_snapshot_version) VALUES (:e, 'CUST', 1)"), {"e": eid})
        for name, (stage, detail, decision) in shapes.items():
            ids[name] = _add_proposal(conn, eid)
            conn.execute(text(
                "UPDATE action_proposals SET pipeline_stage = :s, stage_detail = :d, "
                "decision = :x WHERE proposal_id = :p"),
                {"s": stage, "d": detail, "x": decision, "p": ids[name]})
    return eid, ids


def _all_stages(scratch: Scratch, eid: str, ids: dict[str, str]) -> dict[str, tuple]:
    return {name: _stage_of(scratch, eid, pid) for name, pid in ids.items()}


def _force_off(scratch: Scratch) -> list[str]:
    with scratch.engine.begin() as conn:
        return [r[0] for r in conn.execute(text(
            "SELECT relname FROM pg_class WHERE relnamespace = CAST(:s AS regnamespace) "
            "AND relkind = 'r' AND relrowsecurity AND NOT relforcerowsecurity"),
            {"s": scratch.name})]


def test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored(scratch):
    scratch.alembic("upgrade", "0021")
    eid, ids = _seed_stages(scratch, SHAPES_0021)
    before_rows = _all_stages(scratch, eid, ids)
    s21 = scratch.snapshot()
    assert len(before_rows) == 8

    # --- up: only the named objects change, no row moves, and the new stage is legal
    scratch.alembic("upgrade", "0022")
    assert scratch.revision() == "0022"
    s22 = scratch.snapshot()
    changed = {line.split(": ", 1)[1].split("  [")[0].strip() for line in snapshot_diff(s21, s22)
               if not line.startswith(("~ changed:       alembic", "~ changed:       relation"))}
    assert changed >= CHANGED_BY_0022, (changed, snapshot_diff(s21, s22))
    unexpected = {k for k in changed if k not in CHANGED_BY_0022 and not k.startswith("alembic:")}
    assert not unexpected, f"0022 changed something it does not name: {unexpected}"
    assert _all_stages(scratch, eid, ids) == before_rows
    assert "abandoned" in s22["constraint:action_proposals.action_proposals_pipeline_stage_check"]
    assert "abandoned" in s22[
        "constraint:action_proposals.action_proposals_decision_past_received"]
    assert "comment=NULL decision is legal at `received`" in s22[
        "constraint:action_proposals.action_proposals_decision_past_received"]
    assert "comment=An abandoned proposal was never decided" in s22[
        "constraint:action_proposals.action_proposals_abandoned_is_undecided"]
    assert "'abandoned'" in s22["index:action_proposals_open_stage"]

    # --- a row at the new stage too, written the way the application writes it
    try:
        with scratch.engine.begin() as conn:
            _bind(conn, eid)
            ids["abandoned"] = _add_proposal(conn, eid)
            conn.execute(text(
                "UPDATE action_proposals SET pipeline_stage = 'abandoned', "
                "stage_detail = 'undecided_past_grace' WHERE proposal_id = :p"),
                {"p": ids["abandoned"]})
    except IntegrityError as refused:
        pytest.fail(f"after 0022 the database refuses an abandoned proposal with its one reason: "
                    f"{str(refused.orig).splitlines()[0]}")
    with_abandoned = _all_stages(scratch, eid, ids)
    assert with_abandoned["abandoned"] == ("abandoned", "undecided_past_grace")
    # the database refuses an abandoned row with no reason, and one with a decision
    for detail, decision in ((None, None), ("undecided_past_grace", "ALLOW"), ("other", None)):
        with pytest.raises(IntegrityError):
            with scratch.engine.begin() as conn:
                _bind(conn, eid)
                conn.execute(text(
                    "UPDATE action_proposals SET pipeline_stage = 'abandoned', stage_detail = :d, "
                    "decision = :x WHERE proposal_id = :p"),
                    {"d": detail, "x": decision, "p": ids["decided"]})

    # --- down: the abandoned row is moved back to `received`, and everything else is left alone
    scratch.alembic("downgrade", "0021")
    assert scratch.revision() == "0021"
    after_down = _all_stages(scratch, eid, ids)
    assert after_down["abandoned"] == ("received", None), "the abandoned proposal was not moved"
    assert {k: v for k, v in after_down.items() if k != "abandoned"} == before_rows
    assert not snapshot_diff(s21, scratch.snapshot()), "\n".join(
        snapshot_diff(s21, scratch.snapshot()))
    assert _force_off(scratch) == [], "FORCE ROW LEVEL SECURITY was left off by the downgrade"
    assert set(scratch.force_rls()) == SCHEDULER_TABLES and all(scratch.force_rls().values())

    # --- and up again: identical to the first time
    scratch.alembic("upgrade", "0022")
    assert scratch.revision() == "0022"
    assert not snapshot_diff(s22, scratch.snapshot()), "\n".join(
        snapshot_diff(s22, scratch.snapshot()))
    assert _all_stages(scratch, eid, ids)["abandoned"] == ("received", None)


def test_0022_downgrade_fails_cleanly_if_it_cannot_move_the_rows(scratch):
    """The downgrade's data statement runs inside its transaction. A failure between the move and
    the end leaves the committed schema exactly as it was at 0022, FORCE included."""
    scratch.alembic("upgrade", "0022")
    eid, ids = _seed_stages(scratch, {**SHAPES_0021, "abandoned": ABANDONED_SHAPE})
    before = scratch.snapshot()
    broken = Path(scratch.ini).parent / "migrations" / "versions" / "0022_abandoned_stage.py"
    source = broken.read_text()
    marker = '    op.execute(f"ALTER TABLE action_proposals DROP CONSTRAINT {ABANDONED_CHECK};")\n'
    assert source.count(marker) == 1
    broken.write_text(source.replace(marker, '    op.execute("SELECT 1/0;")\n' + marker))

    scratch.alembic_fails("downgrade", "0021")

    assert scratch.revision() == "0022"
    assert not snapshot_diff(before, scratch.snapshot())              # incl. FORCE RLS and COMMENTs
    assert _stage_of(scratch, eid, ids["abandoned"]) == ("abandoned", "undecided_past_grace")


def test_0022_downgrade_moves_every_abandoned_row_not_only_one(scratch):
    scratch.alembic("upgrade", "0022")
    shapes = {f"a{i}": ABANDONED_SHAPE for i in range(5)} | {"decided": SHAPES_0021["decided"]}
    eid, ids = _seed_stages(scratch, shapes)
    scratch.alembic("downgrade", "0021")
    stages_now = _all_stages(scratch, eid, ids)
    assert [v for k, v in stages_now.items() if k.startswith("a")] == [("received", None)] * 5
    assert stages_now["decided"] == ("decided", None)


# ---------------------------------------------------------------------------------------------
# 0023: the reconciler's read side -- functions, policies, grants and indexes come and go whole
# ---------------------------------------------------------------------------------------------

READER_FUNCTIONS = ("reconciler_stuck_proposals()", "reconciler_run_states(p_run_ids text[])")
STUCK_SHAPES = {"received", "decided", "approved", "capability_issued", "dispatching"}


def _temp_privilege(scratch: Scratch) -> bool:
    """Whether PUBLIC may create temporary tables in this database (a cluster-wide fact)."""
    with scratch.admin.begin() as conn:
        return conn.execute(text(
            "SELECT has_database_privilege('reconciler_reader', current_database(), 'TEMPORARY')"
        )).scalar_one()


def _set_temp_privilege(scratch: Scratch, granted: bool) -> None:
    """Put the database's ``TEMPORARY`` grant to PUBLIC where the schema under test expects it.

    The grant is a fact of the database, not of the scratch schema, so a test that moves the schema
    below 0023 has to make the database agree first, and put it back however the test ends: the
    migrations leave it revoked, and a test killed in between must not leave it granted (the
    hygiene check of the mutation sweep and ``tests/residue.py`` look for exactly that)."""
    verb = "GRANT TEMPORARY ON DATABASE {db} TO PUBLIC" if granted else (
        "REVOKE TEMPORARY ON DATABASE {db} FROM PUBLIC")
    with scratch.admin.begin() as conn:
        database = conn.execute(text("SELECT quote_ident(current_database())")).scalar_one()
        conn.execute(text(verb.format(db=database)))


def test_0023_adds_exactly_the_reader_s_objects_and_the_downgrade_removes_them_all(scratch):
    scratch.alembic("upgrade", "0022")
    _set_temp_privilege(scratch, True)                  # what a database at 0022 looks like
    try:
        _check_0023_round_trip(scratch)
    finally:
        _set_temp_privilege(scratch, False)             # what the migrations leave
    assert not _temp_privilege(scratch)


def line_has_revoked_temporary(line: str) -> bool:
    """The one changed ``database:acl`` line: PUBLIC's entry went from ``=Tc`` to ``=c``."""
    before, after = line.split("] -> [", 1)
    return "=Tc/" in before and "=c/" in after and "=Tc/" not in after


def _check_0023_round_trip(scratch: Scratch) -> None:
    eid, ids = _seed_stages(scratch, {**SHAPES_0021, "abandoned": ABANDONED_SHAPE})
    s22 = scratch.snapshot()

    scratch.alembic("upgrade", "0023")
    s23 = scratch.snapshot()
    added = {line.split(": ", 1)[1].split("  [")[0].strip()
             for line in snapshot_diff(s22, s23) if line.startswith("+ new")}
    assert {f"function:{f}" for f in READER_FUNCTIONS} <= added, added
    assert {f"policy:{t}.reconciler_owner_select" for t in (
        "action_proposals", "capabilities", "approvals", "engagements", "scheduler_enrollment",
        "tool_runs")} <= added, added
    assert {f"index:{n}" for n in (
        "capabilities_by_proposal", "approvals_by_proposal", "tool_runs_by_proposal",
        "action_proposals_reconciler_stuck")} <= added, added
    functions = [v for k, v in s23.items() if k.startswith("function:reconciler_")]
    assert len(functions) == 2
    for definition in functions:
        assert ("owner=reconciler_fn_owner secdef=true "
                'config={"search_path=pg_catalog, <schema>, pg_temp"}') in definition
    assert not _temp_privilege(scratch), "TEMP was not revoked from PUBLIC"
    changed = snapshot_diff(s22, s23)
    acl = [line for line in changed if "database:acl" in line]
    assert len(acl) == 1 and line_has_revoked_temporary(acl[0]), changed

    # --- the functions work in the schema the migration ran in, and see the stuck rows only
    with scratch.engine.begin() as conn:
        conn.execute(text("SET LOCAL ROLE reconciler_fn_owner"))     # it is not inherited
        rows = conn.execute(text(
            f"SELECT proposal_id, pipeline_stage FROM {scratch.name}.reconciler_stuck_proposals()"
        )).all()
    assert {r[1] for r in rows} == STUCK_SHAPES
    assert {r[0] for r in rows} == {ids[n] for n in STUCK_SHAPES}

    # --- down: nothing of 0023 is left, TEMP is back, the rows are untouched
    scratch.alembic("downgrade", "0022")
    assert scratch.revision() == "0022"
    assert not snapshot_diff(s22, scratch.snapshot()), "\n".join(
        snapshot_diff(s22, scratch.snapshot()))
    assert _temp_privilege(scratch), "TEMP was not given back by the downgrade"
    assert _all_stages(scratch, eid, ids)["abandoned"] == ("abandoned", "undecided_past_grace")

    # --- and up again: identical, and the database ends the test as the migrations leave it
    scratch.alembic("upgrade", "0023")
    assert not snapshot_diff(s23, scratch.snapshot()), "\n".join(
        snapshot_diff(s23, scratch.snapshot()))
    assert not _temp_privilege(scratch)


# ---------------------------------------------------------------------------------------------
# 0025: tool_runs.refusal_code and the network-conflict read come and go whole, rows kept
# ---------------------------------------------------------------------------------------------

def test_0025_adds_the_column_its_two_checks_the_index_and_the_function_and_takes_them_back(
        scratch):
    scratch.alembic("upgrade", "0024")
    eid, _ids = _seed_stages(scratch, {"decided": SHAPES_0021["decided"]})
    with scratch.engine.begin() as conn:  # bound: row security
        _bind(conn, eid)
        conn.execute(text("""
            INSERT INTO tool_runs (run_id, engagement_id, tool, tool_version, normalized_target,
                execution_fingerprint, status, network_allowlist)
            VALUES ('RUN-RT25', :e, 'nmap', '1', 't', 'fp', 'failed', '{10.1.0.0/24}')"""),
            {"e": eid})
    s24 = scratch.snapshot()

    scratch.alembic("upgrade", "0025")
    s25 = scratch.snapshot()
    added = {line.split(": ", 1)[1].split("  [")[0].strip()
             for line in snapshot_diff(s24, s25) if line.startswith("+ new")}
    assert "column:tool_runs.refusal_code" in added, added
    assert {"constraint:tool_runs.tool_runs_refusal_code_vocabulary",
            "constraint:tool_runs.tool_runs_refusal_code_means_never_ran",
            "index:tool_runs_refused",
            "function:reconciler_network_conflicts(p_window_s integer)"} <= added, added
    definition = s25["function:reconciler_network_conflicts(p_window_s integer)"]
    assert ("owner=reconciler_fn_owner secdef=true "
            'config={"search_path=pg_catalog, <schema>, pg_temp"}') in definition
    with scratch.engine.begin() as conn:                          # works in the migration's schema
        conn.execute(text("SET LOCAL ROLE reconciler_fn_owner"))
        assert conn.execute(text(
            f"SELECT count(*) FROM {scratch.name}.reconciler_network_conflicts(60)")).scalar() == 0
    with scratch.engine.begin() as conn:                          # the old row has no code
        _bind(conn, eid)
        assert conn.execute(text("SELECT refusal_code FROM tool_runs "
                                 "WHERE run_id = 'RUN-RT25'")).scalar_one() is None
        conn.execute(text("UPDATE tool_runs SET refusal_code = 'docker_unreachable' "
                          "WHERE run_id = 'RUN-RT25'"))

    scratch.alembic("downgrade", "0024")
    assert scratch.revision() == "0024"
    assert not snapshot_diff(s24, scratch.snapshot()), "\n".join(
        snapshot_diff(s24, scratch.snapshot()))
    with scratch.engine.begin() as conn:                          # the row is kept, the code is not
        _bind(conn, eid)
        assert conn.execute(text("SELECT status FROM tool_runs "
                                 "WHERE run_id = 'RUN-RT25'")).scalar_one() == "failed"

    scratch.alembic("upgrade", "0025")
    assert not snapshot_diff(s25, scratch.snapshot()), "\n".join(
        snapshot_diff(s25, scratch.snapshot()))


# ---------------------------------------------------------------------------------------------
# 0026: has_decision on both read functions, and nothing else; rows untouched in both directions
# ---------------------------------------------------------------------------------------------

def test_0026_adds_one_boolean_column_to_both_functions_and_one_column_grant_and_takes_them_back(
        scratch):
    scratch.alembic("upgrade", "0025")
    eid, ids = _seed_stages(scratch, {"decided": SHAPES_0021["decided"],
                                      "received": SHAPES_0021["received"]})
    with scratch.engine.begin() as conn:       # the shape the development database held 400+ of
        _bind(conn, eid)
        odd = _add_proposal(conn, eid)
        conn.execute(text("UPDATE action_proposals SET decision = 'DENY' WHERE proposal_id = :p"),
                     {"p": odd})
    s25 = scratch.snapshot()
    rows_25 = _all_stages(scratch, eid, {**ids, "odd": odd})

    scratch.alembic("upgrade", "0026")
    s26 = scratch.snapshot()
    changed = {line.split(": ", 1)[1].split("  [")[0].strip() for line in snapshot_diff(s25, s26)}
    assert changed, "0026 changed nothing"
    # exactly these four keys: the two functions (result type, hence definition and COMMENT), the
    # decision column (its ACL: one column-level SELECT for the owner) and the version row
    assert changed == {
        "alembic:version", "column:action_proposals.decision",
        "function:reconciler_stuck_proposals()",
        "function:reconciler_stuck_proposals_after(p_after_us bigint, p_after_id text)"}, changed
    for signature in ("reconciler_stuck_proposals()",
                      "reconciler_stuck_proposals_after(p_after_us bigint, p_after_id text)"):
        definition = s26[f"function:{signature}"]
        assert ("owner=reconciler_fn_owner secdef=true "
                'config={"search_path=pg_catalog, <schema>, pg_temp"}') in definition, signature
        assert "has_decision" in definition, signature
    with scratch.engine.begin() as conn:                # both answer, in the migration's schema
        conn.execute(text("SET LOCAL ROLE reconciler_fn_owner"))
        first = conn.execute(text(
            f"SELECT proposal_id, has_decision FROM {scratch.name}.reconciler_stuck_proposals()"
        )).all()
        after = conn.execute(text(
            f"SELECT proposal_id, has_decision "
            f"FROM {scratch.name}.reconciler_stuck_proposals_after(0, '')")).all()
    assert dict(first)[ids["received"]] is False
    assert dict(first)[ids["decided"]] is True and dict(first)[odd] is True
    assert dict(after) == dict(first)
    assert _all_stages(scratch, eid, {**ids, "odd": odd}) == rows_25      # no row was touched

    scratch.alembic("downgrade", "0025")
    assert scratch.revision() == "0025"
    assert not snapshot_diff(s25, scratch.snapshot()), "\n".join(
        snapshot_diff(s25, scratch.snapshot()))
    assert _all_stages(scratch, eid, {**ids, "odd": odd}) == rows_25

    scratch.alembic("upgrade", "0026")
    assert not snapshot_diff(s26, scratch.snapshot()), "\n".join(
        snapshot_diff(s26, scratch.snapshot()))


def test_0026_refuses_to_patch_a_definition_it_was_not_written_against():
    import importlib.util
    from pathlib import Path
    path = (Path(__file__).resolve().parents[1]
            / "db/migrations/versions/0026_reconciler_has_decision.py")
    spec = importlib.util.spec_from_file_location("m0026_unit", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(RuntimeError):
        module._with_has_decision("CREATE FUNCTION f() RETURNS TABLE (x text) AS $$ $$;")
    earlier = module._earlier("0023_reconciler_reader.py")
    patched = module._with_has_decision(earlier._stuck_function("public"))
    assert patched.count("has_decision") == 1 and "p.decision IS NOT NULL" in patched
    assert "p.decision IS NOT NULL" not in earlier._stuck_function("public")


# ---------------------------------------------------------------------------------------------
# 0027-0030 (D68 DP-15): Q1 per action class. Each step adds objects and nothing else, comes back
# identical when taken down, and keeps (or, for the one data statement, rewrites) the rows.
# ---------------------------------------------------------------------------------------------

def _additions_only(before: dict[str, str], after: dict[str, str]) -> set[str]:
    """The keys a step added -- and a failure if it also changed or removed anything but the
    revision row."""
    lines = snapshot_diff(before, after)
    foreign = [line for line in lines
               if not line.startswith("+ new") and "alembic:version" not in line]
    assert not foreign, foreign
    return {line.split(": ", 1)[1].split("  [")[0].strip() for line in lines
            if line.startswith("+ new")}


def _unforced(scratch: Scratch, table: str, *statements: str) -> None:
    """Run seed statements on a table whose FORCE ROW LEVEL SECURITY is off for the moment, the
    way a migration's own data statement does it, and put it back."""
    with scratch.engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))
        for statement in statements:
            conn.execute(text(statement))
        conn.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))


def _read_unforced(scratch: Scratch, table: str, query: str) -> list[tuple]:
    with scratch.engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))
        rows = [tuple(r) for r in conn.execute(text(query)).all()]
        conn.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
    return rows


def test_0027_adds_the_two_class_tables_with_their_guard_and_takes_them_all_back(scratch):
    scratch.alembic("upgrade", "0026")
    s26 = scratch.snapshot()

    scratch.alembic("upgrade", "0027")
    s27 = scratch.snapshot()
    added = _additions_only(s26, s27)
    assert {"column:goal_fit_calls.call_id", "column:goal_fit_calls.action",
            "column:goal_fit_calls.outcome", "column:goal_fit_suspensions.action",
            "column:goal_fit_suspensions.cleared_at", "index:goal_fit_calls_recent",
            "index:goal_fit_suspensions_live",
            "policy:goal_fit_calls.runtime_insert",
            "policy:goal_fit_suspensions.operator_clear"} <= added, sorted(added)
    assert any(k.startswith("function:goal_fit_suspensions_guard") for k in added), sorted(added)
    assert scratch.revision() == "0027"

    scratch.alembic("downgrade", "0026")
    assert scratch.revision() == "0026"
    assert not snapshot_diff(s26, scratch.snapshot()), "\n".join(
        snapshot_diff(s26, scratch.snapshot()))
    assert not {"goal_fit_calls", "goal_fit_suspensions"} & scratch.tables()

    scratch.alembic("upgrade", "0027")
    assert not snapshot_diff(s27, scratch.snapshot()), "\n".join(
        snapshot_diff(s27, scratch.snapshot()))


def test_0028_adds_one_column_and_its_checks_and_gives_old_clearings_a_reason(scratch):
    scratch.alembic("upgrade", "0027")
    _unforced(scratch, "goal_fit_suspensions",
              "INSERT INTO goal_fit_suspensions (action, window_n, window_failed) "
              "VALUES ('rt.live', 30, 30)",
              "INSERT INTO goal_fit_suspensions (action, window_n, window_failed, cleared_at, "
              "cleared_by) VALUES ('rt.cleared', 30, 30, now(), 'someone')")
    s27 = scratch.snapshot()

    scratch.alembic("upgrade", "0028")
    s28 = scratch.snapshot()
    added = _additions_only(s27, s28)
    assert {"column:goal_fit_suspensions.cleared_reason",
            "constraint:goal_fit_suspensions.goal_fit_suspensions_reason_shape",
            "constraint:goal_fit_suspensions.goal_fit_suspensions_reason_with_clearing"} <= added
    rows = dict(_read_unforced(
        scratch, "goal_fit_suspensions",
        "SELECT action, cleared_reason FROM goal_fit_suspensions ORDER BY action"))
    assert rows == {"rt.cleared": "(cleared before reasons were recorded)", "rt.live": None}

    scratch.alembic("downgrade", "0027")
    assert scratch.revision() == "0027"
    assert not snapshot_diff(s27, scratch.snapshot()), "\n".join(
        snapshot_diff(s27, scratch.snapshot()))
    kept = _read_unforced(scratch, "goal_fit_suspensions",
                          "SELECT action, cleared_by FROM goal_fit_suspensions ORDER BY action")
    assert kept == [("rt.cleared", "someone"), ("rt.live", None)]        # rows kept, reason gone

    scratch.alembic("upgrade", "0028")
    assert not snapshot_diff(s28, scratch.snapshot()), "\n".join(
        snapshot_diff(s28, scratch.snapshot()))


def test_0029_adds_the_kind_and_the_outage_table_and_old_failures_become_unclassified(scratch):
    scratch.alembic("upgrade", "0028")
    _unforced(scratch, "goal_fit_calls",
              "INSERT INTO goal_fit_calls (action, outcome) VALUES "
              "('rt.a', 'answered'), ('rt.a', 'failed'), ('rt.b', 'failed'), ('rt.b', 'answered')")
    s28 = scratch.snapshot()

    scratch.alembic("upgrade", "0029")
    s29 = scratch.snapshot()
    added = _additions_only(s28, s29)
    assert {"column:goal_fit_calls.failure_kind",
            "constraint:goal_fit_calls.goal_fit_calls_kind_vocabulary",
            "constraint:goal_fit_calls.goal_fit_calls_kind_with_failure",
            "index:goal_fit_calls_all_recent",
            "column:goal_fit_outage_suspicions.window_transport",
            "policy:goal_fit_outage_suspicions.operator_read"} <= added, sorted(added)
    kinds = _read_unforced(scratch, "goal_fit_calls",
                           "SELECT outcome, failure_kind FROM goal_fit_calls ORDER BY call_id")
    assert kinds == [("answered", None), ("failed", "unclassified"),
                     ("failed", "unclassified"), ("answered", None)]

    scratch.alembic("downgrade", "0028")
    assert scratch.revision() == "0028"
    assert not snapshot_diff(s28, scratch.snapshot()), "\n".join(
        snapshot_diff(s28, scratch.snapshot()))
    assert len(_read_unforced(scratch, "goal_fit_calls", "SELECT 1 FROM goal_fit_calls")) == 4
    assert "goal_fit_outage_suspicions" not in scratch.tables()

    scratch.alembic("upgrade", "0029")
    assert not snapshot_diff(s29, scratch.snapshot()), "\n".join(
        snapshot_diff(s29, scratch.snapshot()))
    assert _read_unforced(scratch, "goal_fit_calls",
                          "SELECT count(*) FROM goal_fit_calls WHERE failure_kind IS NOT NULL"
                          ) == [(2,)]


def test_0030_adds_only_the_record_of_looks_and_takes_it_back(scratch):
    scratch.alembic("upgrade", "0029")
    s29 = scratch.snapshot()

    scratch.alembic("upgrade", "0030")
    s30 = scratch.snapshot()
    added = _additions_only(s29, s30)
    assert {"column:goal_fit_report_views.window_n", "column:goal_fit_report_views.viewer",
            "index:goal_fit_report_views_action", "policy:goal_fit_report_views.runtime_insert",
            "policy:goal_fit_report_views.runtime_read"} <= added, sorted(added)
    assert not any("operator" in key for key in added if key.startswith("policy:"))

    scratch.alembic("downgrade", "0029")
    assert scratch.revision() == "0029"
    assert not snapshot_diff(s29, scratch.snapshot()), "\n".join(
        snapshot_diff(s29, scratch.snapshot()))
    assert "goal_fit_report_views" not in scratch.tables()

    scratch.alembic("upgrade", "0030")
    assert not snapshot_diff(s30, scratch.snapshot()), "\n".join(
        snapshot_diff(s30, scratch.snapshot()))
