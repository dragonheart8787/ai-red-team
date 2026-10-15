"""The stage vocabulary: where it is written down, and the tests that keep every copy true (D64).

A pipeline stage is named in the code (``stages.py`` and the modules that move proposals), in four
database objects (the stage CHECK, the decision CHECK, the abandoned CHECK, the partial index) and
in tests. Adding ``abandoned`` (migration 0022) meant finding every one of them by hand; these tests
are what makes the next stage find them instead (docs/D64_RECONCILER_DESIGN.md §1.9, ST1-ST7).

* ST1  every stage literal in a SQL string of the code is a stage;
* ST2  the database and ``stages.py`` agree (stage list, undecided stages, terminal stages in the
       index, the abandon reasons);
* ST3  the file registry: every module that names a stage is listed with why;
* ST4  one writer: ``abandoned`` is written by ``stages.abandon`` and by nothing else, and
       ``stages.abandon`` is called only by the modules listed here (the reconciler, later);
* ST5  every stage is classified exactly once;
* ST6  behaviour, over every stage: what a caller is told, what the scheduler counts, what the
       dispatch functions do;
* ST7  the migration round trip with a row at every stage -- in ``test_migrations_roundtrip.py``.

And, for ``abandoned`` specifically: A5 (the reason vocabulary is registered once and the database
CHECK is held equal to it) and A7 (an abandoned proposal has nothing that follows a decision, shown
by ``assert_coherent`` after both orders of the race with the decision stage and a genuinely
concurrent one).
"""

from __future__ import annotations

import ast
import re
import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.api import function_api as fa
from control_plane.orchestrator import dispatch, stages
from control_plane.state.db import engagement_scope
from tests.test_pipeline_stages import (
    CIDR,
    CountingReviewer,
    assert_coherent,
    go,
    only,
    snapshot,
)

REPO = Path(__file__).resolve().parents[1]
CODE_DIRS = ("control_plane", "scripts", "agents", "tool_gateway")

STAGE_NAMES = {n for n in dir(stages) if n.isupper() and isinstance(getattr(stages, n), str)
               and getattr(stages, n) in stages.STAGES}


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id,
            "key": f"key-{uuid.uuid4().hex[:8]}"}


def _python_files(*, mutations: bool = True):
    """The code under ``CODE_DIRS``. The mutation catalogues quote *broken* code on purpose (a
    stage that does not exist, a statement that writes ``abandoned``), so the checks that read
    literals for truth pass ``mutations=False``."""
    for directory in CODE_DIRS:
        for path in sorted((REPO / directory).rglob("*.py")):
            if "vendor" in path.parts or "__pycache__" in path.parts:
                continue
            if not mutations and path.name.startswith("mutations_"):
                continue
            yield path


def _strings(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value


# ---------------------------------------------------------------------------
# ST1 -- every stage literal in code is a stage
# ---------------------------------------------------------------------------

COMPARE = re.compile(r"pipeline_stage\s*(?:=|<>|!=)\s*'(\w+)'", re.I)
MEMBER = re.compile(r"pipeline_stage\s+(?:NOT\s+)?IN\s*\(([^)]*)\)", re.I)
ASSIGN = re.compile(r"SET\s+pipeline_stage\s*=\s*'(\w+)'", re.I)


def stage_literals(sql: str) -> set[str]:
    """Stage names written as quoted literals next to ``pipeline_stage`` in one SQL string."""
    found = set(COMPARE.findall(sql)) | set(ASSIGN.findall(sql))
    for group in MEMBER.findall(sql):
        found |= set(re.findall(r"'(\w+)'", group))
    return found


def test_st1_the_extractor_finds_what_it_should_and_a_typo_is_caught():
    sql = ("UPDATE action_proposals SET pipeline_stage = 'closed' WHERE pipeline_stage IN "
           "('received', 'abandonned') AND pipeline_stage <> 'recorded' AND pipeline_stage "
           "NOT IN ('x_stage')")
    assert stage_literals(sql) == {"closed", "received", "abandonned", "recorded", "x_stage"}
    assert stage_literals(sql) - set(stages.STAGES) == {"abandonned", "x_stage"}
    assert stage_literals("dispatch_state = 'dispatching' AND other = 'closed'") == set()


def test_st1_every_stage_literal_in_the_codes_sql_is_a_stage():
    bad = {}
    seen: set[str] = set()
    for path in _python_files(mutations=False):
        for line, value in _strings(ast.parse(path.read_text())):
            if "pipeline_stage" not in value:
                continue
            literals = stage_literals(value)
            seen |= literals
            unknown = literals - set(stages.STAGES)
            if unknown:
                bad[f"{path.relative_to(REPO)}:{line}"] = sorted(unknown)
    assert {"approved", "dispatching", "capability_issued"} <= seen, (
        f"the scan did not find the scheduler's stage literals ({sorted(seen)}): the extractor "
        "is broken")
    assert not bad, f"stage literals that are not stages: {bad}"


def test_st1_every_stages_attribute_the_code_uses_exists():
    missing = {}
    for path in _python_files():
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id == "stages" and node.attr.isupper()
                    and not hasattr(stages, node.attr)):
                missing[f"{path.relative_to(REPO)}:{node.lineno}"] = node.attr
    assert not missing, missing


# ---------------------------------------------------------------------------
# ST2 -- the database and stages.py agree
# ---------------------------------------------------------------------------

def _definition(name: str) -> str:
    with engagement_scope("ENG-NONE") as conn:
        return conn.execute(text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :n"),
            {"n": name}).scalar_one()


def _quoted(definition: str) -> set[str]:
    return set(re.findall(r"'(\w+)'::text", definition)) | set(
        re.findall(r"= '(\w+)'(?!::)", definition))


def test_st2_the_stage_check_lists_exactly_the_stages():
    assert _quoted(_definition("action_proposals_pipeline_stage_check")) == set(stages.STAGES)


def test_st2_the_decision_check_names_exactly_the_undecided_stages():
    definition = _definition("action_proposals_decision_past_received")
    assert "decision IS NOT NULL" in definition
    assert _quoted(definition) == set(stages.UNDECIDED_STAGES)


def test_st2_the_open_stage_index_leaves_out_exactly_the_terminal_stages():
    with engagement_scope("ENG-NONE") as conn:
        definition = conn.execute(text(
            "SELECT indexdef FROM pg_indexes WHERE indexname = 'action_proposals_open_stage'"
        )).scalar_one()
    predicate = definition.split(" WHERE ", 1)[1]
    assert set(re.findall(r"'(\w+)'::text", predicate)) == set(stages.TERMINAL)
    assert "<> ALL" in predicate or "NOT IN" in predicate.upper()


def test_a5_the_abandon_reasons_are_registered_once_and_the_check_holds_them_equal():
    """The vocabulary is ``stages.ABANDON_REASONS``. The CHECK names the same codes (and excludes
    NULL explicitly: it says ``stage_detail IS NOT NULL``), so adding a reason is a migration and a
    line in ``stages.py`` together, and either alone fails here."""
    definition = _definition("action_proposals_abandoned_is_undecided")
    assert "stage_detail IS NOT NULL" in definition
    assert "decision IS NULL" in definition
    assert set(re.findall(r"'(\w+)'::text", definition)) - {"abandoned"} == set(
        stages.ABANDON_REASONS)
    assert len(set(stages.ABANDON_REASONS)) == len(stages.ABANDON_REASONS) >= 1


def test_a5_the_abandoned_outcome_reason_is_not_an_abandon_reason():
    """Two different vocabularies: why the stage was written (stored) and what a caller is told
    (computed from the rows). They must not be mistaken for each other."""
    assert not set(fa.ABANDONED_REASONS) & set(stages.ABANDON_REASONS)


# ---------------------------------------------------------------------------
# ST3 -- the file registry
# ---------------------------------------------------------------------------

MENTIONS = re.compile(
    r"pipeline_stage|\bstages\.(?:" + "|".join(sorted(STAGE_NAMES | {
        "TERMINAL", "BEFORE_DISPATCH", "WAITING", "STAGES", "UNDECIDED_STAGES"})) + r")\b"
    r"|from control_plane\.orchestrator\.stages import")

#: Every module outside ``tests/`` that names a stage, and why. A new module that starts naming one
#: fails until it is listed (the same device as ``NULL_IS_A_STATE``): the point is a person reading
#: whether the new stage ``abandoned`` needs anything there.
FILE_REGISTRY = {
    "scripts/drill_reconciler_docker.py":
        "seeds proposals at `dispatching` / `recorded` for the drill's containers and reads the "
        "stages the command line moved them to; it moves none itself",
    "scripts/drill_reconciler_full_chain.py":
        "runs the real pipeline in a child process to `dispatching`, then only reads the stages "
        "the command line moves the proposal through (`dispatching`, `recorded`); moves none",
    "scripts/check_reconciler_run.py":
        "reads the stage of each proposal a state-only run moved and compares it with "
        "`vocab.PROPOSAL_TRANSITIONS`; writes nothing",
    "control_plane/orchestrator/stages.py":
        "the vocabulary, the transitions, and the one writer of `abandoned`",
    "control_plane/orchestrator/dispatch.py":
        "takes `dispatching`/`recorded`/`closed`; never expects `abandoned` (a hand-written "
        "dispatch of one is refused by the BEFORE_DISPATCH take)",
    "control_plane/api/function_api.py":
        "`_drive`/`_outcome_from_rows`: the explicit `abandoned` outcome (A8)",
    "control_plane/api/approved_dispatch.py":
        "reads the stage; `approved` only; any other stage is reported from the rows",
    "control_plane/api/approvals.py":
        "`awaiting_approval -> approved/closed`; none expects `abandoned`",
    "control_plane/reconciler/act.py":
        "the one caller of `stages.abandon`; closes and records by compare-and-set on the stage "
        "and `stage_updated_at` the plan saw; verifies the stage afterwards",
    "control_plane/reconciler/model.py":
        "plain data the plan hands on (`expected_stage`, `pipeline_stage`); decides no stage",
    "control_plane/reconciler/observe.py":
        "reads `pipeline_stage` from `reconciler_stuck_proposals()` and refuses a stage outside "
        "the five stuck ones",
    "control_plane/reconciler/plan.py":
        "decides, per stuck stage, whether and how to move a proposal (the residue table); never "
        "writes",
    "control_plane/scheduler/decide.py":
        "counts `approved`, `dispatching`, `capability_issued`; `abandoned` is invisible to it",
    "control_plane/state/models.py":
        "declares the column",
    "control_plane/provenance/graph.py":
        "records provenance for `recorded`/`closed` only; an abandoned proposal has no outcome",
    "scripts/mutations_d62_d63.py": "mutation text quoting stage literals",
    "scripts/mutations_d64.py": "mutation text quoting stage literals",
    "scripts/mutations_d65a.py": "mutation text quoting a `stages.` constant (resumed-call edit)",
}


def test_st3_every_module_that_names_a_stage_is_registered_with_its_reason():
    found = {str(p.relative_to(REPO)) for p in _python_files() if MENTIONS.search(p.read_text())}
    unlisted, stale = sorted(found - set(FILE_REGISTRY)), sorted(set(FILE_REGISTRY) - found)
    assert not unlisted and not stale, (
        f"modules naming a stage but not in FILE_REGISTRY: {unlisted}; listed but no longer "
        f"naming one: {stale}. Read each for whether the new stage needs anything there.")


# ---------------------------------------------------------------------------
# ST4 -- one writer
# ---------------------------------------------------------------------------

#: Modules allowed to call ``stages.abandon``: the reconciler's act half (D64 step 6c), which does
#: it only as a compare-and-set on the stage and on the ``stage_updated_at`` the plan observed.
ABANDON_CALLERS: set[str] = {"control_plane/reconciler/act.py"}

STAGES_PACKAGE, STAGES_MODULE = "control_plane.orchestrator", "control_plane.orchestrator.stages"


def refers_to_abandon(tree: ast.AST) -> bool:
    """Does this module reach ``stages.abandon`` by any route a person would write? Through the
    module under its own name or under an alias (``from control_plane.orchestrator import stages
    as st``; ``import control_plane.orchestrator.stages as s``), through the function imported by
    name or under another (``from ...stages import abandon as a``, used or not), through
    ``getattr``, or by naming it without calling it (``fn = stages.abandon``). The earlier check
    looked for the spelling ``stages.abandon(`` and nothing else, which an alias walks round (D64
    pre-deletion item 7)."""
    module_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == STAGES_PACKAGE:
                module_names |= {a.asname or a.name for a in node.names if a.name == "stages"}
            elif node.module == STAGES_MODULE:
                # importing it at all is a route, called or not: nothing else needs it by name
                if any(a.name in ("abandon", "*") for a in node.names):
                    return True
        elif isinstance(node, ast.Import):
            module_names |= {a.asname or a.name for a in node.names if a.name == STAGES_MODULE}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "abandon" \
                and ast.unparse(node.value) in module_names:
            return True
        if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "getattr"
                and len(node.args) >= 2 and ast.unparse(node.args[0]) in module_names
                and isinstance(node.args[1], ast.Constant) and node.args[1].value == "abandon"):
            return True
    return False


def test_st4_the_walker_sees_every_route_to_abandon_and_not_a_namesake():
    flagged = [
        "from control_plane.orchestrator import stages\nstages.abandon(c, p, stage_updated_at=t)",
        "from control_plane.orchestrator import stages as st\nst.abandon(c, p, stage_updated_at=t)",
        "import control_plane.orchestrator.stages as s\ns.abandon(c, p, stage_updated_at=t)",
        "from control_plane.orchestrator.stages import abandon\nabandon(c, p, stage_updated_at=t)",
        "from control_plane.orchestrator.stages import abandon as a\na(c, p, stage_updated_at=t)",
        "from control_plane.orchestrator import stages\nfn = stages.abandon",
        "from control_plane.orchestrator import stages\ngetattr(stages, 'abandon')(c, p)",
        "from control_plane.orchestrator.stages import *\nabandon(c, p)",
        "from control_plane.orchestrator.stages import abandon as _unused",      # never used
    ]
    for source in flagged:
        assert refers_to_abandon(ast.parse(source)), source
    for source in (
            "thing.abandon()", "def abandon(): pass",
            "from control_plane.orchestrator import stages\nstages.advance()",
            "import control_plane.orchestrator.dispatch as d\nd.abandon()"):
        assert not refers_to_abandon(ast.parse(source)), source


def test_st4_abandoned_is_written_by_stages_abandon_and_nothing_else():
    writers, callers = [], set()
    for path in _python_files(mutations=False):
        relative = str(path.relative_to(REPO))
        tree = ast.parse(path.read_text())
        for line, value in _strings(tree):
            if "abandoned" in value and re.search(r"SET\s+pipeline_stage", value, re.I):
                writers.append(f"{relative}:{line}")
        if relative != "control_plane/orchestrator/stages.py" and refers_to_abandon(tree):
            callers.add(relative)
        for node in ast.walk(tree):
            # a move written through the generic helpers
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("advance", "take")):
                for kw in node.keywords:
                    if kw.arg == "new" and ast.unparse(kw.value) in ("stages.ABANDONED",
                                                                      "'abandoned'"):
                        writers.append(f"{relative}:{node.lineno} (advance/take)")
    assert len(writers) == 1 and writers[0].startswith("control_plane/orchestrator/stages.py:"), (
        f"`abandoned` is written in {writers}; stages.abandon is the one writer (A3)")
    assert callers <= ABANDON_CALLERS, (
        f"modules that reach stages.abandon: {sorted(callers - ABANDON_CALLERS)}; the writer of "
        "`abandoned` is the reconciler's alone (A3) -- add a module here only deliberately")
    assert callers == ABANDON_CALLERS, "ABANDON_CALLERS lists a module that no longer calls it"


@pytest.mark.parametrize("helper", ["advance", "take"])
def test_st4_the_generic_helpers_refuse_to_write_abandoned_whatever_the_caller_computes(
        engagement_id, helper):
    """The scan above reads spellings; this refuses at run time, so a ``new`` that is computed
    (``new=target``, ``new=STAGE_OF[x]``) cannot reach the stage."""
    from control_plane.state.db import engagement_scope
    from tests.reconciler_support import _proposal
    pid = _proposal(engagement_id, "received")
    outcome = "no exception"
    with engagement_scope(engagement_id) as conn:
        try:
            getattr(stages, helper)(conn, pid, expected=stages.RECEIVED, new="aband" + "oned")
        except ValueError as exc:
            outcome = "refused" if "abandon" in str(exc) else f"ValueError: {exc}"
        except Exception as exc:                  # noqa: BLE001  (the database's CHECK is next)
            outcome = f"reached the database: {type(exc).__name__}"
    assert outcome == "refused", outcome
    with engagement_scope(engagement_id) as conn:
        assert stages.stage_of(conn, pid)[0] == "received"


# ---------------------------------------------------------------------------
# ST5 -- every stage is classified once
# ---------------------------------------------------------------------------

STAGE_CLASS = {
    stages.RECEIVED: "before_dispatch",
    stages.DECIDED: "before_dispatch",
    stages.AWAITING_APPROVAL: "waiting",
    stages.APPROVED: "waiting",
    stages.CAPABILITY_ISSUED: "before_dispatch",
    stages.DISPATCHING: "in_flight",
    stages.RECORDED: "terminal",
    stages.CLOSED: "terminal",
    stages.ABANDONED: "terminal",
}


def test_st5_every_stage_has_exactly_one_class_and_stages_py_agrees():
    assert set(STAGE_CLASS) == set(stages.STAGES), "a stage was added: which class is it?"
    by_class: dict[str, set[str]] = {}
    for stage, klass in STAGE_CLASS.items():
        by_class.setdefault(klass, set()).add(stage)
    assert by_class["terminal"] == set(stages.TERMINAL)
    assert by_class["waiting"] == set(stages.WAITING)
    assert by_class["before_dispatch"] == set(stages.BEFORE_DISPATCH)
    assert by_class["in_flight"] == {stages.DISPATCHING}
    assert stages.ABANDONED in stages.TERMINAL
    assert stages.ABANDONED not in stages.BEFORE_DISPATCH and stages.ABANDONED not in stages.WAITING
    assert len(stages.STAGES) == len(set(stages.STAGES))


# ---------------------------------------------------------------------------
# ST6 -- behaviour over the stages
# ---------------------------------------------------------------------------

class Tripwire:
    """A reviewer or sandbox that must not be reached."""

    def __init__(self):
        self.calls = 0

    def run(self, **_kwargs):
        self.calls += 1
        raise AssertionError("the sandbox was reached")


def _try_abandon(conn, pid, planned) -> bool:
    """``stages.abandon``, with a refusal by the database reported as what it means here: the move
    was attempted on a proposal it should not have touched."""
    from sqlalchemy.exc import IntegrityError
    try:
        with conn.begin_nested():
            return stages.abandon(conn, pid, stage_updated_at=planned)
    except IntegrityError as refused:
        pytest.fail("abandon() tried to move a proposal that is not an undecided `received` one "
                    f"(the database refused: {str(refused.orig).splitlines()[0]})")


def _abandon_a_received_proposal(world):
    """A proposal whose decision stage never committed (the reviewer 'crashed'), then abandoned the
    way the reconciler does it: the compare-and-set of :func:`stages.abandon`."""
    eid = world["engagement_id"]

    def crash():
        raise RuntimeError("the caller died here")

    with pytest.raises(RuntimeError):
        go(world, reviewer=CountingReviewer(hook=crash))
    with engagement_scope(eid) as conn:
        pid, updated = conn.execute(text(
            "SELECT proposal_id, stage_updated_at FROM action_proposals")).one()
        assert stages.abandon(conn, pid, stage_updated_at=updated) is True
    return pid


def test_st6_an_abandoned_proposal_is_reported_as_never_decided_not_as_a_reasonless_deny(world):
    eid = world["engagement_id"]
    pid = _abandon_a_received_proposal(world)
    reviewer, sandbox = CountingReviewer(), Tripwire()

    outcome = go(world, reviewer=reviewer, sandbox=sandbox)        # the same key, again

    assert outcome.proposal_id == pid
    assert outcome.decision == fa.DENY and outcome.failure == "abandoned"
    assert outcome.deny_reasons == fa.ABANDONED_REASONS == ("abandoned_before_decision",)
    assert outcome.run_id is None and outcome.capability_id is None
    assert reviewer.calls == 0 and sandbox.calls == 0, "an abandoned proposal was driven again"
    snap = snapshot(eid)
    p = only(snap)
    assert (p["stage"], p["detail"], p["decision"]) == (
        stages.ABANDONED, "undecided_past_grace", None)
    assert snap["capabilities"] == 0 and snap["runs"] == [] and snap["evidence"] == 0
    assert_coherent(snap)


def test_st6_a_new_key_is_a_new_proposal_and_the_abandoned_one_stays_abandoned(world):
    eid = world["engagement_id"]
    old = _abandon_a_received_proposal(world)
    outcome = go(world, key=f"fresh-{uuid.uuid4().hex[:6]}")
    assert outcome.decision == "ALLOW" and outcome.proposal_id != old
    stage_of = {p["proposal_id"]: p["stage"] for p in snapshot(eid)["proposals"]}
    assert stage_of[old] == stages.ABANDONED
    assert_coherent(snapshot(eid))


REPORTED_FROM_ROWS = [stages.AWAITING_APPROVAL, stages.APPROVED, stages.DISPATCHING,
                      stages.RECORDED, stages.CLOSED, stages.ABANDONED]


@pytest.mark.parametrize("stage", REPORTED_FROM_ROWS)
def test_st6_a_resumed_proposal_in_a_stage_this_call_cannot_drive_is_reported_with_a_reason(
    world, stage,
):
    """For every stage that ``_drive`` only reports: nothing is re-run, and the answer is never a
    bare DENY (no reasons, no failure) -- the case that gave ``abandoned`` an unexplained
    refusal."""
    eid = world["engagement_id"]
    if stage == stages.ABANDONED:
        _abandon_a_received_proposal(world)
    else:
        go(world)                                              # runs the whole pipeline once
        detail = {stages.AWAITING_APPROVAL: None, stages.APPROVED: "APPR-X",
                  stages.DISPATCHING: None, stages.RECORDED: "succeeded",
                  stages.CLOSED: "manual"}[stage]
        decision = "HUMAN_APPROVAL" if stage in (stages.AWAITING_APPROVAL,
                                                 stages.APPROVED) else "ALLOW"
        with engagement_scope(eid) as conn:
            conn.execute(text(
                "UPDATE action_proposals SET pipeline_stage = :s, stage_detail = :d, "
                "decision = :x"), {"s": stage, "d": detail, "x": decision})
    reviewer, sandbox = CountingReviewer(), Tripwire()

    outcome = go(world, reviewer=reviewer, sandbox=sandbox)

    assert reviewer.calls == 0 and sandbox.calls == 0
    bare_deny = outcome.decision == fa.DENY and not outcome.deny_reasons and not outcome.failure
    assert not bare_deny, f"{stage}: a DENY with no reason and no failure"


def test_st6_the_scheduler_does_not_see_an_abandoned_proposal(world):
    from control_plane.scheduler import decide

    eid = world["engagement_id"]
    _abandon_a_received_proposal(world)
    seen = decide.observe(eid)
    assert seen.waiting == () and seen.dispatching == 0 and seen.capability_issued == 0
    assert seen.decided == frozenset()
    assert decide.stage_of(eid, only(snapshot(eid))["proposal_id"]) == "abandoned"


def test_st6_dispatch_approved_reports_an_abandoned_proposal_and_runs_nothing(world):
    from control_plane.api.approved_dispatch import dispatch_approved
    from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy

    pid = _abandon_a_received_proposal(world)
    policy = merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"))
    sandbox = Tripwire()
    outcome = dispatch_approved(
        engagement_id=world["engagement_id"], proposal_id=pid, policy=policy, sandbox=sandbox)
    assert outcome.failure == "abandoned" and outcome.run_id is None and sandbox.calls == 0


def test_st6_a_hand_written_dispatch_of_an_abandoned_proposal_is_refused(world):
    eid = world["engagement_id"]
    pid = _abandon_a_received_proposal(world)
    with engagement_scope(eid) as conn:
        with pytest.raises(stages.StageConflict):
            stages.take(conn, pid, expected=stages.BEFORE_DISPATCH, new=stages.DISPATCHING)
        assert stages.stage_of(conn, pid) == (stages.ABANDONED, "undecided_past_grace")
    assert not [s for s in (stages.ABANDONED,) if s in stages.BEFORE_DISPATCH]
    assert dispatch.claim_for_dispatch is not None


def test_st6_only_a_received_proposal_can_be_abandoned_and_only_if_nothing_touched_it(world):
    eid = world["engagement_id"]
    outcome = go(world)                                            # decided, issued, run, recorded
    with engagement_scope(eid) as conn:
        pid, updated = conn.execute(text(
            "SELECT proposal_id, stage_updated_at FROM action_proposals")).one()
        assert _try_abandon(conn, pid, updated) is False                    # not `received`
    assert outcome.decision == "ALLOW"

    _fresh = f"k-{uuid.uuid4().hex[:6]}"
    with pytest.raises(RuntimeError):
        go(world, key=_fresh, reviewer=CountingReviewer(hook=lambda: (_ for _ in ()).throw(
            RuntimeError("died"))))
    with engagement_scope(eid) as conn:
        pid, updated = conn.execute(text(
            "SELECT proposal_id, stage_updated_at FROM action_proposals "
            "WHERE pipeline_stage = 'received'")).one()
        # touched since the plan: the compare-and-set on stage_updated_at fails
        conn.execute(text("UPDATE action_proposals SET stage_updated_at = now() "
                          "WHERE proposal_id = :p"), {"p": pid})
        assert _try_abandon(conn, pid, updated) is False
        assert stages.stage_of(conn, pid)[0] == stages.RECEIVED


# ---------------------------------------------------------------------------
# A7 -- nothing that follows a decision exists for an abandoned proposal: both orders of the race
# ---------------------------------------------------------------------------

def _plan(eid: str, pid: str):
    with engagement_scope(eid) as conn:
        return conn.execute(text(
            "SELECT stage_updated_at FROM action_proposals WHERE proposal_id = :p"),
            {"p": pid}).scalar_one()


def test_a7_abandoned_while_the_decision_stage_is_in_flight_nothing_follows(world):
    """Abandon wins: it lands while the reviewer is being called. The decision's own conditional
    UPDATE then matches no row, writes no ``policy.decided``, and the caller is told so."""
    eid = world["engagement_id"]
    result: dict = {}

    def abandon_now():
        with engagement_scope(eid) as conn:
            pid, updated = conn.execute(text(
                "SELECT proposal_id, stage_updated_at FROM action_proposals")).one()
            result["moved"] = stages.abandon(conn, pid, stage_updated_at=updated)

    outcome = go(world, reviewer=CountingReviewer(hook=abandon_now), sandbox=Tripwire())

    assert result["moved"] is True
    assert outcome.failure == "abandoned" and outcome.run_id is None
    snap = snapshot(eid)
    assert only(snap)["stage"] == stages.ABANDONED and only(snap)["decision"] is None
    assert snap["capabilities"] == 0 and snap["runs"] == []
    assert "policy.decided" not in snap["audit"], "the loser of the race wrote a decision record"
    assert snap["audit"].get("policy_reviewer.opinion") == 1      # the wasted call, and only that
    assert_coherent(snap)


def test_a7_decided_first_then_the_abandon_finds_nothing(world):
    eid = world["engagement_id"]
    pid_updated: dict = {}

    def note_the_plan():                       # the reconciler planned while it was `received`
        with engagement_scope(eid) as conn:
            pid_updated["row"] = conn.execute(text(
                "SELECT proposal_id, stage_updated_at FROM action_proposals")).one()

    outcome = go(world, reviewer=CountingReviewer(hook=note_the_plan))
    assert outcome.decision == "ALLOW"
    pid, planned = pid_updated["row"]
    with engagement_scope(eid) as conn:
        assert stages.abandon(conn, pid, stage_updated_at=planned) is False
    snap = snapshot(eid)
    assert only(snap)["stage"] == stages.RECORDED and snap["audit"].get("policy.decided") == 1
    assert_coherent(snap)


def test_a7_genuinely_concurrent_the_abandon_waits_on_the_decisions_row_lock(world, monkeypatch):
    """The decision transaction is open (its UPDATE has run, nothing has committed) when the
    abandon is attempted from another connection: it must wait, and after the commit find the
    proposal decided."""
    eid = world["engagement_id"]
    in_decision, release = threading.Event(), threading.Event()
    real = fa._record_decision

    def slow(*args, **kwargs):
        value = real(*args, **kwargs)           # the row is now updated and locked
        in_decision.set()
        assert release.wait(30)
        return value

    monkeypatch.setattr(fa, "_record_decision", slow)
    box: dict = {}
    worker = threading.Thread(target=lambda: box.update(outcome=go(world)))
    worker.start()
    assert in_decision.wait(30)
    with engagement_scope(eid) as conn:        # (a read does not wait on a row lock)
        pid, planned = conn.execute(text(
            "SELECT proposal_id, stage_updated_at FROM action_proposals")).one()

    def try_abandon():
        with engagement_scope(eid) as conn:
            box["abandoned"] = stages.abandon(conn, pid, stage_updated_at=planned)

    abandoner = threading.Thread(target=try_abandon)
    abandoner.start()
    abandoner.join(timeout=1.5)
    assert abandoner.is_alive(), "the abandon should be waiting on the decision's row lock"
    release.set()
    worker.join(30)
    abandoner.join(30)

    assert box["abandoned"] is False
    assert box["outcome"].decision == "ALLOW"
    snap = snapshot(eid)
    assert only(snap)["stage"] != stages.ABANDONED
    assert_coherent(snap)


def test_a7_the_coherence_check_catches_each_thing_an_abandoned_proposal_must_not_have():
    """The check itself, on constructed snapshots: it is only worth something if it can fail."""
    base = {"proposals": [{"proposal_id": "P", "stage": stages.ABANDONED, "detail":
                           "undecided_past_grace", "decision": None, "dispatch_state": "queued",
                           "provenance_complete": False}],
            "capabilities": 0, "runs": [], "evidence": 0, "audit": {}, "approved": set(),
            "with_capability": set(), "with_run": set(), "any_approval": set(),
            "decided_audit": set()}
    assert_coherent(base)

    def broken(**change):
        snap = {**base, "proposals": [dict(base["proposals"][0])]}
        for key, value in change.items():
            if key.startswith("p_"):
                snap["proposals"][0][key[2:]] = value
            else:
                snap[key] = value
        with pytest.raises(AssertionError):
            assert_coherent(snap)

    broken(p_decision="ALLOW")
    broken(p_detail="something_else")
    broken(p_dispatch_state="running")
    broken(with_capability={"P"}, capabilities=1)
    broken(with_run={"P"}, runs=["succeeded"], capabilities=1)
    broken(any_approval={"P"})
    broken(decided_audit={"P"})
