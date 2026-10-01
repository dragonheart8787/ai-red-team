"""Who may publish or retire a *global* policy layer (ACCEPTANCE 5.37, D54).

A row in ``policy_layers`` with ``engagement_id IS NULL`` applies to every engagement: the
baseline (which can widen), the emergency overlay (whose retirement is a relaxation) and a global
customer layer. Row-level security admitted such a row on both sides of a write from *any*
engagement's connection, so until migration 0014 the runtime role every Worker, Reviewer and
Supervisor call runs as could publish and retire them. Executed at D54, before this fix: a
connection scoped to an engagement id that does not exist deactivated two global layers other
engagements had published.

This is the D5 / D39 / D44 pattern -- a new duty gets a new role -- with D11-7's ``global_auditor``
as the closest precedent. ``global_policy_admin`` writes global rows and only global rows;
``cyberorch_app`` writes engagement-scoped rows and only those. The tests, in order: the runtime
role is refused (including the exact case that was executed); the new role does its job and is
confined to global rows; nothing in the pipeline can reach the new connection; and the operator CLI
that owns it behaves.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from control_plane.policy.layers import (
    EMERGENCY_OVERLAY,
    deactivate_policy_layer,
    load_effective_policy,
    publish_policy_layer,
)
from control_plane.state.db import (
    engagement_scope,
    global_auditor_scope,
    global_policy_admin_scope,
)
from tests.helpers import deactivate_global_layer, make_engagement, publish_global_layer

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "scripts" / "manage_global_policy.py"


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _version() -> int:
    return uuid.uuid4().int % 2_000_000_000


def _refused(err) -> bool:
    return isinstance(err.value.orig, psycopg.errors.InsufficientPrivilege)


def _active(layer_id: int) -> bool:
    with global_policy_admin_scope() as conn:
        row = conn.execute(text("SELECT active FROM policy_layers WHERE id = :i"),
                           {"i": layer_id}).scalar_one_or_none()
    return bool(row)


@pytest.fixture
def global_overlay():
    """A real global emergency overlay, published the only permitted way, retired afterwards."""
    token = _uid("overlay_class")
    layer_id = publish_global_layer(
        layer=EMERGENCY_OVERLAY, version=_version(), document={"data_deny": [token]},
        actor="incident-commander",
    )
    yield {"id": layer_id, "token": token}
    with global_policy_admin_scope() as conn:
        conn.execute(text("UPDATE policy_layers SET active = FALSE WHERE id = :i"),
                     {"i": layer_id})


# ---------------------------------------------------------------------------
# 1. The runtime role is refused
# ---------------------------------------------------------------------------

def test_a_connection_for_an_engagement_that_does_not_exist_cannot_retire_a_global_overlay(
    global_overlay,
):
    """The case that was executed at D54, as a regression test. The engagement id names
    nothing; RLS never checked that it did, and a global row is writable from any of them."""
    ghost = _uid("ENG-GHOST")
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(ghost) as conn:
            conn.execute(text("UPDATE policy_layers SET active = FALSE WHERE id = :i"),
                         {"i": global_overlay["id"]})
    assert _refused(err)
    assert _active(global_overlay["id"]), "the overlay was retired despite the refusal"

    with pytest.raises(PermissionError, match="global_policy_admin"):
        with engagement_scope(ghost) as conn:
            deactivate_policy_layer(conn, layer_id=global_overlay["id"], actor="attacker")
    assert _active(global_overlay["id"])


def test_the_runtime_role_cannot_retire_a_global_layer_from_a_real_engagement_either(
    engagement_id, global_overlay
):
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text("UPDATE policy_layers SET active = FALSE WHERE id = :i"),
                         {"i": global_overlay["id"]})
    assert _refused(err)
    assert _active(global_overlay["id"])


@pytest.mark.parametrize("layer, document, customer", [
    ("baseline_global", '{"actions": {"web.get": "ALLOW"}}', None),
    ("emergency_overlay", '{"data_deny": ["x"]}', None),
    ("customer", '{"data_deny": ["x"]}', "CUST-ATTACK"),
])
def test_the_runtime_role_cannot_publish_a_global_layer(engagement_id, layer, document, customer):
    """A baseline that widens every engagement is the worse half of the gap; an overlay that
    only tightens is refused too, because *who* may write global policy is the point."""
    version = _version()
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(
                text("INSERT INTO policy_layers (layer, version, customer_id, document) "
                     "VALUES (:l, :v, :c, CAST(:d AS jsonb))"),
                {"l": layer, "v": version, "c": customer, "d": document})
    assert _refused(err)
    with global_policy_admin_scope() as conn:
        assert conn.execute(text("SELECT count(*) FROM policy_layers WHERE version = :v"),
                            {"v": version}).scalar_one() == 0


def test_publishing_a_global_layer_from_an_engagement_connection_says_why(engagement_id):
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(PermissionError, match="global_policy_admin"):
            publish_policy_layer(
                conn, engagement_id=None, layer=EMERGENCY_OVERLAY, version=_version(),
                document={"data_deny": ["x"]}, actor="incident-commander")


def test_the_runtime_role_still_reads_global_layers_and_writes_its_own(
    engagement_id, global_overlay
):
    """The negative controls: the merge still sees a global layer, and the role still
    publishes and retires the engagement-scoped kind."""
    with engagement_scope(engagement_id) as conn:
        assert global_overlay["token"] in load_effective_policy(conn, engagement_id).data_deny
        layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=_version(),
            document={"data_deny": ["y"]}, actor="engagement-manager",
            scoped_to_engagement=True)
        assert deactivate_policy_layer(
            conn, engagement_id=engagement_id, layer_id=layer_id, actor="engagement-manager")


# ---------------------------------------------------------------------------
# 2. The new role does the job, and only that job
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("layer, customer", [
    ("baseline_global", None), ("emergency_overlay", None), ("customer", "CUST-GPA"),
])
def test_global_policy_admin_publishes_and_retires_global_layers(engagement_id, layer, customer):
    token = _uid("class")
    layer_id = publish_global_layer(
        layer=layer, version=_version(), document={"data_deny": [token]},
        actor="platform-owner", customer_id=customer)
    try:
        assert _active(layer_id)
        if customer is None:     # a customer-scoped row applies to that customer only (5.35)
            # A baseline reaches only engagements created after it (5.20), so the one that
            # checks it is created now; the others are live and the fixture's serves.
            target = engagement_id
            if layer == "baseline_global":
                target = _uid("ENG-AFTER")
                make_engagement(target, "CUST-GPA-AFTER")
            with engagement_scope(target) as conn:
                assert token in load_effective_policy(conn, target).data_deny
        # The publication is on the global trail, attributed to the actor.
        with global_auditor_scope() as conn:
            rows = conn.execute(text(
                "SELECT actor, scope FROM audit_log WHERE event_type = 'policy_layer.published' "
                "AND subject_id = :s"), {"s": str(layer_id)}).all()
        assert rows and rows[0][0] == "platform-owner" and rows[0][1] == "global"
    finally:
        assert deactivate_global_layer(layer_id, actor="platform-owner")
    assert not _active(layer_id)
    with global_auditor_scope() as conn:
        assert conn.execute(text(
            "SELECT count(*) FROM audit_log WHERE event_type = 'policy_layer.deactivated' "
            "AND subject_id = :s AND scope = 'global'"), {"s": str(layer_id)}).scalar_one() == 1


def _engagement_layer(engagement_id):
    with engagement_scope(engagement_id) as conn:
        return publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=_version(),
            document={"data_deny": ["z"]}, actor="engagement-manager",
            scoped_to_engagement=True)


@pytest.mark.parametrize("bind_engagement", [False, True])
def test_global_policy_admin_cannot_publish_an_engagement_scoped_layer(
    engagement_id, bind_engagement
):
    """Even with the target engagement bound to the session, which is the harder attack."""
    version = _version()
    with pytest.raises(ProgrammingError) as err:
        with global_policy_admin_scope() as conn:
            if bind_engagement:
                conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                             {"e": engagement_id})
            conn.execute(
                text("INSERT INTO policy_layers (layer, version, engagement_id, document) "
                     "VALUES ('engagement', :v, :e, '{}'::jsonb)"),
                {"v": version, "e": engagement_id})
    assert _refused(err)
    with engagement_scope(engagement_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM policy_layers WHERE version = :v"),
                            {"v": version}).scalar_one() == 0


@pytest.mark.parametrize("bind_engagement", [False, True])
def test_global_policy_admin_cannot_retire_an_engagement_scoped_layer(
    engagement_id, bind_engagement
):
    layer_id = _engagement_layer(engagement_id)
    with global_policy_admin_scope() as conn:
        if bind_engagement:
            conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                         {"e": engagement_id})
        result = conn.execute(text("UPDATE policy_layers SET active = FALSE WHERE id = :i"),
                              {"i": layer_id})
        assert result.rowcount == 0, "the role reached an engagement-scoped row"
        assert deactivate_policy_layer(conn, layer_id=layer_id, actor="platform-owner") is False
    with engagement_scope(engagement_id) as conn:
        assert conn.execute(text("SELECT active FROM policy_layers WHERE id = :i"),
                            {"i": layer_id}).scalar_one() is True


def test_global_policy_admin_cannot_even_see_an_engagement_scoped_layer(engagement_id):
    layer_id = _engagement_layer(engagement_id)
    with global_policy_admin_scope() as conn:
        conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                     {"e": engagement_id})
        seen = conn.execute(text("SELECT count(*) FROM policy_layers WHERE id = :i"),
                            {"i": layer_id}).scalar_one()
    assert seen == 0


@pytest.mark.parametrize("statement", [
    "UPDATE policy_layers SET document = '{}'::jsonb WHERE id = :i",
    "UPDATE policy_layers SET engagement_id = 'ENG-X' WHERE id = :i",
    "DELETE FROM policy_layers WHERE id = :i",
])
def test_global_policy_admin_can_neither_rewrite_nor_delete_a_layer(global_overlay, statement):
    with pytest.raises(ProgrammingError) as err:
        with global_policy_admin_scope() as conn:
            conn.execute(text(statement), {"i": global_overlay["id"]})
    assert _refused(err)


def test_global_policy_admin_holds_nothing_but_policy_layers():
    """The catalogue: no table other than ``policy_layers`` is touched, and there only INSERT,
    SELECT and ``UPDATE (active)``. A later blanket GRANT fails here."""
    with global_policy_admin_scope() as conn:
        tables = [r[0] for r in conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))]
        held = {}
        for table in tables:
            privileges = {
                p for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES")
                if conn.execute(text("SELECT has_table_privilege(current_user, :t, :p)"),
                                {"t": table, "p": p}).scalar_one()
            }
            if privileges:
                held[table] = privileges
        updatable = {
            c for (c,) in conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = 'policy_layers'"))
            if conn.execute(text(
                "SELECT has_column_privilege(current_user, 'policy_layers', :c, 'UPDATE')"),
                {"c": c}).scalar_one()
        }
        sequences = {
            s for (s,) in conn.execute(text(
                "SELECT sequencename FROM pg_sequences WHERE schemaname = 'public'"))
            if conn.execute(text("SELECT has_sequence_privilege(current_user, :s, 'USAGE')"),
                            {"s": f"public.{s}"}).scalar_one()
        }
        attrs = conn.execute(text(
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles "
            "WHERE rolname = current_user")).one()
    assert held == {"policy_layers": {"SELECT", "INSERT"}}, held
    assert updatable == {"active"}
    assert sequences == {"policy_layers_id_seq"}
    assert tuple(attrs) == (False, False, False, False)


# ---------------------------------------------------------------------------
# 3. Nothing in the pipeline can reach the connection
# ---------------------------------------------------------------------------

_CONNECTION = re.compile(
    r"global_policy_admin_scope|get_global_policy_admin_engine|global_policy_admin_url"
    r"|GLOBAL_POLICY_ADMIN_DATABASE_URL")

#: The only files outside ``tests/`` allowed to name the connection: where it is defined, the
#: operator's CLI, and the two live-run harnesses that stand up a baseline by hand (they are
#: operator-run scripts, not services).
ALLOWED_TO_OPEN_IT = {
    "control_plane/state/db.py",
    "scripts/manage_global_policy.py",
    "scripts/live_run/live_run.py",
    "scripts/live_run/d40_three_role.py",
}


def test_no_pipeline_component_can_open_the_global_policy_connection():
    """Publishing or retiring global policy is an operator's decision, the seriousness of
    engaging the kill switch. So no dispatch, agent, console, tool-gateway or registry module
    may name the connection; ``layers.py`` may use only the *assertion* that refuses a wrong
    one. Adding a caller is a deliberate edit to ``ALLOWED_TO_OPEN_IT`` and this test."""
    offenders = []
    for root in ("control_plane", "agents", "tool_gateway", "scripts"):
        for path in (REPO / root).rglob("*.py"):
            rel = str(path.relative_to(REPO))
            if rel in ALLOWED_TO_OPEN_IT:
                continue
            if _CONNECTION.search(path.read_text(encoding="utf-8")):
                offenders.append(rel)
    assert not offenders, f"these may not open the global policy connection: {offenders}"


def test_the_allowed_list_is_not_stale():
    """Each exemption must still be a real caller, or it is a hole with a reason attached."""
    for rel in ALLOWED_TO_OPEN_IT:
        assert _CONNECTION.search((REPO / rel).read_text(encoding="utf-8")), rel


# ---------------------------------------------------------------------------
# 4. The operator CLI
# ---------------------------------------------------------------------------

def _cli(*args, stdin=subprocess.DEVNULL):
    return subprocess.run(
        [sys.executable, str(CLI), *args], cwd=REPO, env=os.environ.copy(),
        capture_output=True, text=True, stdin=stdin, timeout=60)


def _layer_by_version(version):
    with global_policy_admin_scope() as conn:
        return conn.execute(text("SELECT id, active FROM policy_layers WHERE version = :v"),
                            {"v": version}).first()


def test_the_cli_publishes_lists_and_retires_a_global_layer():
    version, token = _version(), _uid("cli_class")
    done = _cli("publish", "--layer", "baseline_global", "--version", str(version),
                "--document", f'{{"data_deny": ["{token}"]}}', "--actor", "alice", "--yes")
    assert done.returncode == 0, done.stderr
    layer_id, active = _layer_by_version(version)
    try:
        assert active is True
        listing = _cli("list")
        assert listing.returncode == 0 and f"id={layer_id} " in listing.stdout
    finally:
        retired = _cli("deactivate", "--layer-id", str(layer_id), "--actor", "alice", "--yes")
    assert retired.returncode == 0, retired.stderr
    assert not _active(layer_id)


def test_the_cli_will_not_act_without_a_person_to_confirm():
    version = _version()
    done = _cli("publish", "--layer", "baseline_global", "--version", str(version),
                "--document", '{"data_deny": ["x"]}', "--actor", "alice")
    assert done.returncode == 2, (done.stdout, done.stderr)
    assert "no terminal" in done.stderr
    assert _layer_by_version(version) is None


def test_the_cli_refuses_an_overlay_that_would_relax():
    version = _version()
    done = _cli("publish", "--layer", "emergency_overlay", "--version", str(version),
                "--document", '{"actions": {"network.scan": "ALLOW"}}', "--actor", "alice",
                "--yes")
    assert done.returncode == 1 and "refused" in done.stderr
    assert _layer_by_version(version) is None


def test_the_cli_will_not_retire_an_engagement_scoped_layer(engagement_id):
    layer_id = _engagement_layer(engagement_id)
    done = _cli("deactivate", "--layer-id", str(layer_id), "--actor", "alice", "--yes")
    assert done.returncode == 1 and "no active global layer" in done.stderr
    with engagement_scope(engagement_id) as conn:
        assert conn.execute(text("SELECT active FROM policy_layers WHERE id = :i"),
                            {"i": layer_id}).scalar_one() is True


def test_the_cli_warns_that_retiring_an_overlay_relaxes(global_overlay):
    """The summary a person sees before typing the word must say what the act is."""
    done = _cli("deactivate", "--layer-id", str(global_overlay["id"]), "--actor", "alice")
    assert done.returncode == 2
    assert "RELAXES policy" in done.stdout
    assert _active(global_overlay["id"])


# ---------------------------------------------------------------------------
# 5. A retirement that did not happen is not audited
# ---------------------------------------------------------------------------

def test_a_retirement_that_changed_no_row_is_not_recorded(monkeypatch):
    """Row-level security can hide a row from an UPDATE that the earlier SELECT saw. The old
    code audited ``policy_layer.deactivated`` regardless of what the UPDATE did, which would
    have put a retirement that never happened on the trail. No live path produces the
    mismatch since 0014, so it is exercised with a connection that does."""
    from control_plane.policy import layers

    class _Result:
        def __init__(self, row=None, rowcount=0):
            self._row, self.rowcount = row, rowcount

        def mappings(self):
            return self

        def one_or_none(self):
            return self._row

    class _Conn:
        def execute(self, statement, params=None):
            if str(statement).lstrip().upper().startswith("SELECT CURRENT_USER"):
                return type("R", (), {"scalar_one": lambda self: "global_policy_admin"})()
            if str(statement).lstrip().upper().startswith("SELECT"):
                return _Result({"layer": "emergency_overlay", "version": 1,
                                "document": {}, "engagement_id": None})
            return _Result(rowcount=0)       # the UPDATE that changed nothing

    recorded = []
    monkeypatch.setattr(layers, "record_audit", lambda **kw: recorded.append(kw))
    assert layers.deactivate_policy_layer(_Conn(), layer_id=1, actor="alice") is False
    assert recorded == []
