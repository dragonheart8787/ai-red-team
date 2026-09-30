"""The frozen Baseline Global Snapshot (ACCEPTANCE 5.20, D54).

§4.5: ``Effective Policy = Baseline Global Snapshot (frozen when the engagement is created) ∩
Emergency Overlay (live) ∩ Customer ∩ Engagement``. Until D54 every layer was live-merged, so a
baseline published after an engagement existed reached it -- tightening or *widening*.
``docs/D54_POLICY_SNAPSHOT_FREEZE_DESIGN.md`` has the analysis; the decisions this file pins:

1. only the *global baseline* freezes -- customer layers, engagement layers and the overlay stay
   live;
2. a baseline published after the freeze never reaches the engagement, whichever way it cuts; only
   an emergency overlay (tighten-only, written by ``global_policy_admin``) does;
3. a baseline row in force at the freeze **stays** in force after it is retired -- the freeze is the
   baseline the customer signed against, not "whatever hasn't been retired since";
4. a pointer, not a copy: one number on the engagement, in the one order (``policy_change_seq``) in
   which layers are published and retired and engagements freeze;
5. an engagement with no recorded freeze is live, exactly as before ("absent means unknown");
6. (done at 5.35-5.37) the shared predicate and the immutable rows;
7. what the freeze left out is reported, and the report decides nothing.
"""

from __future__ import annotations

import ast
import random
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from control_plane.capability.broker import current_policy_version
from control_plane.policy import layers as layers_module
from control_plane.policy.layers import (
    PUBLISHED_AFTER_FREEZE,
    RETIRED_AFTER_FREEZE,
    list_effective_policy_layers,
    list_frozen_out_baseline_changes,
    load_effective_policy,
    max_applicable_layer_id,
    publish_policy_layer,
)
from control_plane.policy.merge import ALLOW, DENY
from control_plane.state.db import (
    engagement_scope,
    global_policy_admin_scope,
    registry_admin_scope,
)
from tests.helpers import deactivate_global_layer, make_engagement, publish_global_layer

REPO = Path(__file__).resolve().parents[1]


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _version() -> int:
    return uuid.uuid4().int % 2_000_000_000


class Globals:
    """Global rows a test publishes, retired afterwards whatever happened."""

    def __init__(self) -> None:
        self.ids: list[int] = []

    def publish(self, layer: str, document: dict, customer_id: str | None = None) -> int:
        layer_id = publish_global_layer(
            layer=layer, version=_version(), document=document, actor="platform-owner",
            customer_id=customer_id)
        self.ids.append(layer_id)
        return layer_id

    def retire(self, layer_id: int) -> None:
        assert deactivate_global_layer(layer_id, actor="platform-owner")

    def cleanup(self) -> None:
        for layer_id in self.ids:
            deactivate_global_layer(layer_id)


@pytest.fixture
def glob(db_available):
    g = Globals()
    yield g
    g.cleanup()


def _engagement(customer: str = "CUST-FREEZE") -> str:
    eid = _uid("ENG-FRZ")
    make_engagement(eid, customer)
    return eid


def _legacy_engagement(customer: str = "CUST-LEGACY") -> str:
    """An engagement as created before 0015: no freeze recorded. registry_admin may INSERT the
    row; it simply does not go through ``create_engagement``."""
    eid = _uid("ENG-LEGACY")
    with registry_admin_scope(eid) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, policy_snapshot_version) "
                 "VALUES (:e, :c, 1)"), {"e": eid, "c": customer})
    return eid


def _policy(eid):
    with engagement_scope(eid) as conn:
        return load_effective_policy(conn, eid)


def _version_of(eid) -> int:
    with engagement_scope(eid) as conn:
        return current_policy_version(conn, eid)


def _frozen_through(eid):
    with engagement_scope(eid) as conn:
        return conn.execute(
            text("SELECT baseline_frozen_through FROM engagements WHERE engagement_id = :e"),
            {"e": eid}).scalar_one()


# ---------------------------------------------------------------------------
# 1. The end-to-end scenario
# ---------------------------------------------------------------------------

def test_a_frozen_engagement_ignores_a_new_baseline_and_obeys_a_new_overlay(glob):
    """Engagement A freezes at baseline B0. B1 widens, B2 tightens: A is untouched by both, and a
    live (pre-0015) engagement, as the control, is touched by both. An emergency overlay published
    by ``global_policy_admin`` then reaches A -- and retiring it lifts it again."""
    allowed, widened = _uid("act_allowed"), _uid("act_widened")
    tok0, tok_tight, tok_overlay = _uid("t0"), _uid("t_tight"), _uid("t_overlay")

    glob.publish("baseline_global", {"actions": {allowed: ALLOW}, "data_deny": [tok0]})
    a = _engagement()
    live = _legacy_engagement()           # created after B0, but with no freeze recorded
    assert _frozen_through(a) is not None and _frozen_through(live) is None
    assert _policy(a).action_decision(allowed) == ALLOW and tok0 in _policy(a).data_deny
    version_before = _version_of(a)
    live_version_before = _version_of(live)

    # A new baseline, widening: a whole new action allowed.
    glob.publish("baseline_global", {"actions": {widened: ALLOW}})
    # A new baseline, tightening: a new denied class.
    glob.publish("baseline_global", {"data_deny": [tok_tight]})

    frozen = _policy(a)
    assert frozen.action_decision(widened) == DENY, (
        "a widening baseline reached a frozen engagement")
    assert tok_tight not in frozen.data_deny, (
        "a tightening baseline reached a frozen engagement")
    assert frozen.action_decision(allowed) == ALLOW and tok0 in frozen.data_deny
    assert _version_of(a) == version_before, (
        "an unrelated baseline moved the frozen engagement's policy version, which would revoke "
        "its capabilities at the next heartbeat for a policy that is not in force")

    control = _policy(live)
    assert control.action_decision(widened) == ALLOW and tok_tight in control.data_deny
    assert _version_of(live) != live_version_before

    # The emergency overlay is the channel that does reach a frozen engagement.
    overlay = glob.publish("emergency_overlay", {
        "data_deny": [tok_overlay], "actions": {allowed: DENY}})
    reached = _policy(a)
    assert tok_overlay in reached.data_deny
    assert reached.action_decision(allowed) == DENY, "the overlay did not penetrate the freeze"
    assert _version_of(a) != version_before, "an overlay must revoke the frozen engagement's caps"

    glob.retire(overlay)                  # an operator's decision, over global_policy_admin
    assert _policy(a).action_decision(allowed) == ALLOW

    # The report: exactly the two newer baselines, neither applied.
    with engagement_scope(a) as conn:
        report = list_frozen_out_baseline_changes(conn, a)
    assert [r.change for r in report] == [PUBLISHED_AFTER_FREEZE] * 2
    assert not any(r.still_applied for r in report)
    assert {tok_tight} <= {t for r in report for t in r.document.get("data_deny", [])}
    with engagement_scope(live) as conn:
        assert list_frozen_out_baseline_changes(conn, live) == ()


# ---------------------------------------------------------------------------
# 2. A retired baseline stays in force for an engagement that froze it in
# ---------------------------------------------------------------------------

def test_a_baseline_retired_after_the_freeze_stays_in_force_for_that_engagement(glob):
    tok = _uid("frozen_in")
    row = glob.publish("baseline_global", {"data_deny": [tok]})
    a = _engagement()
    assert tok in _policy(a).data_deny

    glob.retire(row)                      # an operator retires the baseline after A froze it

    assert tok in _policy(a).data_deny, "the engagement followed a retirement it must not follow"
    later = _engagement()                 # created after the retirement: the baseline is gone
    assert tok not in _policy(later).data_deny
    live = _legacy_engagement()
    assert tok not in _policy(live).data_deny, "a live engagement follows a retirement, as before"

    with engagement_scope(a) as conn:
        (item,) = [r for r in list_frozen_out_baseline_changes(conn, a) if r.id == row]
    assert item.change == RETIRED_AFTER_FREEZE and item.still_applied is True
    # Still listed among what is in force, because it is:
    with engagement_scope(a) as conn:
        assert row in {layer.id for layer in list_effective_policy_layers(conn, a)}


def test_a_baseline_retired_before_the_freeze_is_not_part_of_it(glob):
    tok = _uid("retired_first")
    row = glob.publish("baseline_global", {"data_deny": [tok]})
    glob.retire(row)
    a = _engagement()                     # nothing published in between: the tie case
    assert tok not in _policy(a).data_deny


def test_retirement_and_freeze_are_ordered_even_with_nothing_published_between(glob):
    """The reason ``id`` alone is not enough: a retirement and a freeze that happen back to back
    compare equal on ``max(id)``. Both orders, on the sequence that does distinguish them."""
    tok = _uid("tie")
    row = glob.publish("baseline_global", {"data_deny": [tok]})
    before = _engagement()                # frozen while the row is in force
    glob.retire(row)
    after = _engagement()                 # frozen after it is gone; no publication between
    assert tok in _policy(before).data_deny
    assert tok not in _policy(after).data_deny


# ---------------------------------------------------------------------------
# 3. Only the global baseline freezes
# ---------------------------------------------------------------------------

def test_the_other_layers_stay_live_for_a_frozen_engagement(glob):
    customer = _uid("CUST-LIVE")
    a = _engagement(customer)
    tok_customer, tok_scoped, tok_named = _uid("c"), _uid("s"), _uid("n")

    glob.publish("customer", {"data_deny": [tok_customer]}, customer_id=customer)
    with engagement_scope(a) as conn:
        publish_policy_layer(
            conn, engagement_id=a, layer="engagement", version=_version(),
            document={"data_deny": [tok_scoped]}, actor="engagement-manager",
            scoped_to_engagement=True)
        # Named baseline_global but scoped to this engagement: not a *global* baseline.
        publish_policy_layer(
            conn, engagement_id=a, layer="baseline_global", version=_version(),
            document={"data_deny": [tok_named]}, actor="engagement-manager",
            scoped_to_engagement=True)

    denied = _policy(a).data_deny
    assert {tok_customer, tok_scoped, tok_named} <= denied


# ---------------------------------------------------------------------------
# 4. A freeze is recorded, allocated by the database, and cannot be written by the runtime role
# ---------------------------------------------------------------------------

def test_create_engagement_records_a_strictly_increasing_freeze_point():
    first, second = _engagement(), _engagement()
    a, b = _frozen_through(first), _frozen_through(second)
    assert a is not None and b is not None and b > a


def test_the_freeze_point_is_in_the_creation_audit_record():
    eid = _engagement()
    with engagement_scope(eid) as conn:
        payload = conn.execute(text(
            "SELECT payload FROM audit_log WHERE event_type = 'engagement.created' "
            "AND subject_id = :e"), {"e": eid}).scalar_one()
    assert payload["baseline_frozen_through"] == _frozen_through(eid)


def test_the_runtime_role_can_neither_write_nor_allocate_a_freeze_point():
    eid = _engagement()
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(eid) as conn:
            conn.execute(text("UPDATE engagements SET baseline_frozen_through = NULL "
                              "WHERE engagement_id = :e"), {"e": eid})
    assert "permission denied" in str(err.value).lower()
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(eid) as conn:
            conn.execute(text("SELECT policy_freeze_point()"))
    assert "permission denied" in str(err.value).lower()
    assert _frozen_through(eid) is not None


def test_a_layers_position_is_stamped_by_the_database_not_supplied(glob):
    """Neither column is writable by any role and an INSERT's supplied value is overwritten."""
    with global_policy_admin_scope() as conn:
        layer_id = conn.execute(text(
            "INSERT INTO policy_layers (layer, version, document, created_seq, deactivated_seq) "
            "VALUES ('emergency_overlay', :v, '{\"data_deny\": [\"x\"]}'::jsonb, 0, 0) "
            "RETURNING id"), {"v": _version()}).scalar_one()
    glob.ids.append(layer_id)
    with global_policy_admin_scope() as conn:
        created, deactivated = conn.execute(text(
            "SELECT created_seq, deactivated_seq FROM policy_layers WHERE id = :i"),
            {"i": layer_id}).one()
    assert created > 0 and deactivated is None
    glob.retire(layer_id)
    with global_policy_admin_scope() as conn:
        created2, deactivated2 = conn.execute(text(
            "SELECT created_seq, deactivated_seq FROM policy_layers WHERE id = :i"),
            {"i": layer_id}).one()
    assert created2 == created and deactivated2 > created


def test_a_retired_layer_stays_retired(glob):
    """A second life would break the interval a frozen baseline is defined by."""
    layer_id = glob.publish("emergency_overlay", {"data_deny": [_uid("x")]})
    glob.retire(layer_id)
    with pytest.raises(DBAPIError, match="stays retired"):
        with global_policy_admin_scope() as conn:
            conn.execute(text("UPDATE policy_layers SET active = TRUE WHERE id = :i"),
                         {"i": layer_id})


# ---------------------------------------------------------------------------
# 5. One predicate: listing, merge and version cannot disagree
# ---------------------------------------------------------------------------

SCENARIOS = ["baseline_after", "overlay_after", "engagement_layer_after",
             "frozen_in_retired", "retired_before_freeze"]


@pytest.mark.parametrize("frozen", [True, False])
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_listing_merge_and_version_describe_the_same_layers(glob, monkeypatch, frozen, scenario):
    tok_in, tok_out = _uid("in"), _uid("out")
    pre_retired = glob.publish("baseline_global", {"data_deny": [_uid("pre")]})
    glob.retire(pre_retired)
    frozen_in = glob.publish("baseline_global", {"data_deny": [tok_in]})
    eid = _engagement() if frozen else _legacy_engagement()

    if scenario == "baseline_after":
        glob.publish("baseline_global", {"data_deny": [tok_out]})
    elif scenario == "overlay_after":
        glob.publish("emergency_overlay", {"data_deny": [tok_out]})
    elif scenario == "engagement_layer_after":
        with engagement_scope(eid) as conn:
            publish_policy_layer(
                conn, engagement_id=eid, layer="engagement", version=_version(),
                document={"data_deny": [tok_out]}, actor="engagement-manager",
                scoped_to_engagement=True)
    elif scenario == "frozen_in_retired":
        glob.retire(frozen_in)

    consumed: list[set[int]] = []
    real = layers_module._select_applicable

    def spy(*args, **kwargs):
        rows = real(*args, **kwargs)
        consumed.append({r["id"] for r in rows})
        return rows

    monkeypatch.setattr(layers_module, "_select_applicable", spy)
    with engagement_scope(eid) as conn:
        policy = load_effective_policy(conn, eid)
        merge_ids = consumed[-1]
        listed = {layer.id for layer in list_effective_policy_layers(conn, eid)}
        version = current_policy_version(conn, eid)
        fragment = max_applicable_layer_id(conn, eid)
    assert listed == merge_ids, "the listing shows a different set from the one the merge used"
    assert version == fragment == max(listed, default=0), (
        "the policy version is computed over a different set from the one in force")

    # ...and that set is the right one: the freeze's expectations, scenario by scenario.
    assert pre_retired not in listed
    if frozen:
        assert (frozen_in in listed) is True
        assert tok_in in policy.data_deny
        expected_out = scenario in ("overlay_after", "engagement_layer_after")
    else:
        assert (frozen_in in listed) is (scenario != "frozen_in_retired")
        expected_out = scenario in ("baseline_after", "overlay_after", "engagement_layer_after")
    assert (tok_out in policy.data_deny) is expected_out


# ---------------------------------------------------------------------------
# 6. A model of §4.5, written from the section and not from the SQL
# ---------------------------------------------------------------------------

class Oracle:
    """§4.5 in a dozen lines. Keeps a log of what happened, in order, and answers what a frozen
    engagement should see -- the baseline rows in force when it was created, every active
    overlay, and its own layers -- without any of the query's clauses."""

    def __init__(self) -> None:
        self.clock = 0
        self.rows: dict[int, dict] = {}       # id -> {kind, token, born, died}
        self.engagements: dict[str, int] = {}  # eid -> freeze time

    def tick(self) -> int:
        self.clock += 1
        return self.clock

    def published(self, layer_id: int, kind: str, token: str) -> None:
        self.rows[layer_id] = {"kind": kind, "token": token, "born": self.tick(), "died": None}

    def retired(self, layer_id: int) -> None:
        self.rows[layer_id]["died"] = self.tick()

    def froze(self, eid: str) -> None:
        self.engagements[eid] = self.tick()

    def expected(self, eid: str) -> set[str]:
        at = self.engagements[eid]
        out = set()
        for row in self.rows.values():
            alive_now = row["died"] is None
            if row["kind"] == "baseline":
                in_force_at_freeze = row["born"] < at and (row["died"] is None or row["died"] > at)
                if in_force_at_freeze:
                    out.add(row["token"])
            elif alive_now:                    # overlays are live
                out.add(row["token"])
        return out


@pytest.mark.parametrize("seed", range(20))
def test_the_query_agrees_with_a_model_of_the_section_over_random_histories(glob, seed):
    """Random publishes, retirements and freezes of baselines and overlays. After every step,
    for every engagement, the denied classes the database yields (restricted to this test's own
    tokens) are exactly the model's. Equality both ways is also the fail-open guard: a frozen
    engagement must never lose a baseline deny it froze in."""
    rng = random.Random(seed)
    oracle = Oracle()
    live_ids: dict[str, list[int]] = {"baseline": [], "overlay": []}
    engagements: list[str] = []
    tokens: set[str] = set()

    def check() -> None:
        for eid in engagements:
            with engagement_scope(eid) as conn:
                denied = load_effective_policy(conn, eid).data_deny & tokens
            want = oracle.expected(eid)
            assert want <= denied, f"seed {seed}: {eid} lost {want - denied} (fail-open)"
            assert denied == want, f"seed {seed}: {eid} gained {denied - want}"

    for _ in range(12):
        step = rng.choice(["pub_b", "pub_b", "retire_b", "pub_o", "retire_o", "freeze", "freeze"])
        if step in ("pub_b", "pub_o"):
            kind = "baseline" if step == "pub_b" else "overlay"
            token = _uid(f"m{seed}")
            tokens.add(token)
            layer = "baseline_global" if kind == "baseline" else "emergency_overlay"
            layer_id = glob.publish(layer, {"data_deny": [token]})
            oracle.published(layer_id, kind, token)
            live_ids[kind].append(layer_id)
        elif step in ("retire_b", "retire_o"):
            kind = "baseline" if step == "retire_b" else "overlay"
            if live_ids[kind]:
                layer_id = live_ids[kind].pop(rng.randrange(len(live_ids[kind])))
                glob.retire(layer_id)
                oracle.retired(layer_id)
        else:
            eid = _engagement()
            engagements.append(eid)
            oracle.froze(eid)
        check()


# ---------------------------------------------------------------------------
# 7. The report decides nothing
# ---------------------------------------------------------------------------

def test_the_frozen_out_report_cannot_change_a_decision(glob, monkeypatch):
    tok = _uid("hidden")
    a = _engagement()
    glob.publish("baseline_global", {"data_deny": [tok]})
    with engagement_scope(a) as conn:
        before = load_effective_policy(conn, a).as_dict()
    # The decision path must not so much as call the report.
    monkeypatch.setattr(layers_module, "list_frozen_out_baseline_changes",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("consulted")))
    with engagement_scope(a) as conn:
        assert load_effective_policy(conn, a).as_dict() == before
        list_effective_policy_layers(conn, a)
        current_policy_version(conn, a)


def test_the_report_writes_nothing(glob):
    a = _engagement()
    glob.publish("baseline_global", {"data_deny": [_uid("x")]})
    with engagement_scope(a) as conn:
        audits = conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one()
        layer_rows = conn.execute(text("SELECT count(*) FROM policy_layers")).scalar_one()
        list_frozen_out_baseline_changes(conn, a)
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one() == audits
        assert conn.execute(text("SELECT count(*) FROM policy_layers")).scalar_one() == layer_rows


def test_the_cli_shows_what_was_frozen_out(glob):
    """``scripts/policy_layers.py`` gains the section; rendered here from real rows."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("policy_layers_cli",
                                                  REPO / "scripts" / "policy_layers.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)

    tok = _uid("cli_hidden")
    a = _engagement()
    row = glob.publish("baseline_global", {"data_deny": [tok]})
    with engagement_scope(a) as conn:
        layers = list_effective_policy_layers(conn, a)
        policy = load_effective_policy(conn, a)
        frozen_out = list_frozen_out_baseline_changes(conn, a)
    text_out = cli.render(layers, policy, None, frozen_out)
    assert "frozen out" in text_out.lower()
    assert f"id={row}" in text_out and "NOT in force" in text_out
    assert "frozen out" not in cli.render(layers, policy, None, ()).lower()


# ---------------------------------------------------------------------------
# 8. The scripts that stand up a baseline do it before the engagement exists
# ---------------------------------------------------------------------------

BASELINE_CALLS = {"publish_baseline", "ensure_baseline"}
ENGAGEMENT_CALLS = {"setup", "seed_engagement", "setup_engagement", "create_engagement"}
LIVE_RUN = ["live_run", "verify_d12", "d13_worker", "d15_lookalike", "d17_supervisor",
            "d40_three_role", "d45_ad_collection_e2e", "d50_ad_collector_auth_probe"]


def _called_names(node):
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            yield name, child.lineno


@pytest.mark.parametrize("script", LIVE_RUN)
def test_a_live_run_publishes_its_baseline_before_it_creates_its_engagement(script):
    """An engagement freezes the baseline that exists when it is created (5.20). A harness that
    published it afterwards would run an engagement with no baseline and be denied everything."""
    tree = ast.parse((REPO / "scripts" / "live_run" / f"{script}.py").read_text())
    checked = 0
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef):
            continue
        calls = list(_called_names(func))
        baseline = [line for name, line in calls if name in BASELINE_CALLS]
        creation = [line for name, line in calls if name in ENGAGEMENT_CALLS]
        if baseline and creation:
            checked += 1
            assert min(baseline) < min(creation), (
                f"{script}.{func.name}: the baseline is published at line {min(baseline)}, after "
                f"the engagement is created at line {min(creation)}")
    assert checked, f"{script}: nothing to check -- the script's shape changed"

