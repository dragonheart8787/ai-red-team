"""D69 H5c2 repair: the loop visits the engagements the banner named (``harness/frozen_enrolment``).

The banner states the engagements read at the start and the switches of those. The enrolment reader
answers from the database each time it is asked, and the loop asks once per round; before this
repair an engagement enrolled after the start was visited from the next round although the banner
never listed it. These tests run the entry script in this process on the real test database, with
scripted roles and a fake sandbox, and make the enrolment change *during* the run (inside the first
plan call of an engagement, so the change falls between two rounds' reads):

* an engagement enrolled after the start (holding a queued task) is never visited and is not the
  cause of an exit with code 10, and its rows are unchanged;
* an engagement withdrawn after the start is not visited from the next round (the round in progress
  completes, as the loop reads the list once per round);
* the order is the start-up order, also when the database's order has changed; an engagement of the
  start-up list that was withdrawn and enrolled again comes back;
* on a run with no change, the banner's list is the list the loop visits.
"""

from __future__ import annotations

import ast
import contextlib
import re
from pathlib import Path

import pytest

from agents.base_agent import ProposedAction
from harness.enrolment_db import EnrolledFromDatabase
from harness.exit_codes import EXIT_CAP_REACHED, EXIT_STARTUP_REFUSED
from harness.frozen_enrolment import FrozenEnrolment
from harness.lock import HarnessLock
from scripts import run_harness
from tests.harness_h5c2_roles import Roles
from tests.test_harness_h5c1_support import (
    CountingReviewer,
    FakeSandbox,
    ScriptedSupervisor,
    ScriptedWorker,
    count_rows,
    make_world,
    proposal_rows,
    queued_task,
    task_rows,
)
from tests.test_harness_h5c2_support import cli, enrolled

ROOT = Path(__file__).resolve().parents[1]
FROZEN = "harness/frozen_enrolment.py"


class _Reader:
    """A reader that answers what it is told (the 'current' enrolment of a unit test)."""

    def __init__(self, ids):
        self.ids = tuple(ids)
        self.calls = 0

    def enrolled(self):
        self.calls += 1
        return self.ids


# -- the reader itself, on its own -------------------------------------------------------------


def test_the_frozen_reader_gives_the_start_up_engagements_that_are_still_enrolled_in_start_order():
    current = _Reader(("a", "b", "c", "d"))
    frozen = FrozenEnrolment(("c", "a", "b"), current)
    assert frozen.enrolled() == ("c", "a", "b")           # start order, not the reader's order
    current.ids = ("b", "d", "a")                          # c withdrawn, d enrolled after the start
    assert frozen.enrolled() == ("a", "b")
    current.ids = ()
    assert frozen.enrolled() == ()
    current.ids = ("d", "e", "b", "c", "a")                # c is back; d and e were never on it
    assert frozen.enrolled() == ("c", "a", "b")


def test_the_frozen_reader_never_returns_what_was_enrolled_after_the_start():
    current = _Reader(("a",))
    frozen = FrozenEnrolment(("a",), current)
    current.ids = ("a", "late")
    assert "late" not in frozen.enrolled()
    assert FrozenEnrolment((), _Reader(("a", "late"))).enrolled() == ()


def test_the_frozen_reader_keeps_its_own_copy_of_the_start_list_and_only_reads():
    start = ["a", "b"]
    current = _Reader(("a", "b"))
    frozen = FrozenEnrolment(start, current)
    start.append("late")
    current.ids = ("a", "b", "late")
    assert frozen.enrolled() == ("a", "b")
    assert current.calls == 1                              # one read of the current reader per call
    assert frozen.enrolled() == ("a", "b") and current.calls == 2


# -- the entry script, with the enrolment changing during a run ---------------------------------


class _Supervisor(ScriptedSupervisor):
    """Plans one task of the engagement it is asked about, and records every call; ``hooks`` maps
    (engagement, n) to a function run at the start of that engagement's n-th plan call."""

    def __init__(self, worlds, hooks):
        super().__init__(lambda call: [])
        self.worlds = worlds
        self.hooks = hooks
        self.visits: list[str] = []

    def plan(self, *, state, candidates):
        engagement_id = state.engagement_id
        self.visits.append(engagement_id)
        nth = self.visits.count(engagement_id)
        hook = self.hooks.get((engagement_id, nth))
        if hook is not None:
            hook()
        return [self.worlds[engagement_id].task(4 + nth)]


def _proposal(task, task_id):
    return ProposedAction(
        action=task.action, target=dict(task.target),
        authorization={"source": "engagement_scope", "scope_object_id": task.scope_object_id},
        discovery={"source": "explicit_scope"}, task_id=task_id)


@pytest.fixture
def worlds(engagement_id, registry, engagement_factory):
    other_id, other_registry = engagement_factory()
    return make_world(engagement_id, registry), make_world(other_id, other_registry)


def _argv(rounds: int) -> list[str]:
    return ["run", "--role-factory", "tests.harness_h5c2_roles:build", "--objective", "o",
            "--window-limit", "25", "--max-rounds", str(rounds), "--max-model-calls", "100",
            "--no-progress-limit", "5", "--live-task-limit", "200"]


def _run(worlds, monkeypatch, *, rounds: int, hooks=None):
    """Run the script in this process; the supervisor is returned with what it visited."""
    supervisor = _Supervisor({w.engagement_id: w for w in worlds}, hooks or {})
    roles = Roles(supervisor, ScriptedWorker(_proposal), CountingReviewer(), FakeSandbox())
    monkeypatch.setattr(run_harness, "_roles", lambda spec: roles)
    code = run_harness.main(_argv(rounds), lock=HarnessLock(), register=lambda *a: None)
    return code, supervisor


def _register(engagement_id: str) -> None:
    with cli._connect(False) as conn:
        assert cli.register(conn, engagement_id, "harness_lab", "h5c2-test") is None


def _withdraw(engagement_id: str) -> None:
    with cli._connect(False) as conn:
        assert cli.withdraw(conn, engagement_id, "h5c2-test") is None


def _banner_engagements(out: str) -> list[str]:
    (line,) = [ln for ln in out.splitlines() if ln.startswith("engagements:")]
    return re.findall(r"ENG-TEST-[0-9a-f]+", line)


def test_an_engagement_enrolled_after_the_start_is_never_visited_and_is_no_cause_of_code_10(
        worlds, monkeypatch, capsys):
    first, late = worlds
    queued = queued_task(late, 40)                         # it holds a queued task, as in 'refused'
    rows_before = task_rows(late.engagement_id)
    in_database = []
    stack = contextlib.ExitStack()

    def enrol_the_late_one():
        stack.enter_context(enrolled(late.engagement_id))
        in_database.append(late.engagement_id in EnrolledFromDatabase().enrolled())

    try:
        with enrolled(first.engagement_id):
            code, supervisor = _run(worlds, monkeypatch, rounds=3,
                                    hooks={(first.engagement_id, 1): enrol_the_late_one})
            enrolled_now = EnrolledFromDatabase().enrolled()
    finally:
        stack.close()

    out = capsys.readouterr().out
    assert in_database == [True]                           # it was enrolled while the run went
    assert late.engagement_id in enrolled_now
    assert supervisor.visits == [first.engagement_id] * 3  # zero plan calls for the late one
    assert code == EXIT_CAP_REACHED and code != EXIT_STARTUP_REFUSED
    assert task_rows(late.engagement_id) == rows_before    # its queued task is untouched
    assert [row[0] for row in rows_before] == [queued]
    assert proposal_rows(late.engagement_id) == []
    assert count_rows(late.engagement_id, "tasks") == 1
    assert _banner_engagements(out) == [first.engagement_id]


def test_an_engagement_withdrawn_after_the_start_is_not_visited_from_the_next_round(
        worlds, monkeypatch, capsys):
    first, second = worlds
    with enrolled(first.engagement_id, second.engagement_id):
        code, supervisor = _run(worlds, monkeypatch, rounds=3,
                                hooks={(first.engagement_id, 1): lambda: _withdraw(
                                    second.engagement_id)})

    # round 1 had read its list before the withdrawal and is carried out whole; rounds 2 and 3 have
    # only the first engagement
    assert supervisor.visits == [first.engagement_id, second.engagement_id,
                                 first.engagement_id, first.engagement_id]
    assert code == EXIT_CAP_REACHED
    assert _banner_engagements(capsys.readouterr().out) == [first.engagement_id,
                                                            second.engagement_id]


def test_an_engagement_of_the_start_list_that_is_withdrawn_and_enrolled_again_comes_back(
        worlds, monkeypatch, capsys):
    first, second = worlds
    hooks = {(first.engagement_id, 1): lambda: _withdraw(second.engagement_id),
             (first.engagement_id, 2): lambda: _register(second.engagement_id)}
    with enrolled(first.engagement_id, second.engagement_id):
        code, supervisor = _run(worlds, monkeypatch, rounds=3, hooks=hooks)

    # round 2 read its list while the second was withdrawn; round 3 reads it enrolled again
    assert supervisor.visits == [first.engagement_id, second.engagement_id, first.engagement_id,
                                 first.engagement_id, second.engagement_id]
    assert code == EXIT_CAP_REACHED
    assert second.engagement_id in _banner_engagements(capsys.readouterr().out)


def test_the_visit_order_is_the_start_up_order_when_the_databases_order_has_changed(
        worlds, monkeypatch):
    first, second = worlds

    def first_goes_out_and_comes_back():
        _withdraw(first.engagement_id)
        _register(first.engagement_id)                     # the database now lists it last

    with enrolled(first.engagement_id, second.engagement_id):
        _, supervisor = _run(worlds, monkeypatch, rounds=2,
                             hooks={(first.engagement_id, 1): first_goes_out_and_comes_back})
        in_database = EnrolledFromDatabase().enrolled()

    assert in_database == (second.engagement_id, first.engagement_id)
    assert supervisor.visits == [first.engagement_id, second.engagement_id,
                                 first.engagement_id, second.engagement_id]


def test_on_an_unchanged_run_the_banners_engagements_are_the_ones_the_loop_visits(
        worlds, monkeypatch, capsys):
    first, second = worlds
    with enrolled(first.engagement_id, second.engagement_id):
        code, supervisor = _run(worlds, monkeypatch, rounds=2)

    on_banner = _banner_engagements(capsys.readouterr().out)
    assert on_banner == [first.engagement_id, second.engagement_id]
    assert supervisor.visits == on_banner * 2              # both rounds, in the banner's order
    assert code == EXIT_CAP_REACHED


# -- what the repair is made of -----------------------------------------------------------------


def _imports(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(("." * node.level) + (node.module or ""))
    return found


def test_the_frozen_module_reads_only_and_does_not_reach_into_the_loop_or_the_scripts():
    tree = ast.parse((ROOT / FROZEN).read_text())
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef))
                  and n.body and isinstance(n.body[0], ast.Expr)
                  and isinstance(n.body[0].value, ast.Constant)}
    strings = [n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)
               and id(n) not in docstrings]
    assert [s for s in strings if re.search(r"\b(INSERT|UPDATE|DELETE|SELECT)\b", s, re.I)] == []
    for name in _imports(tree):
        assert name.split(".")[0] not in ("sqlalchemy", "scripts"), name
        assert name not in ("harness.loop", "harness.loop_adapter"), name
        assert not name.startswith("control_plane"), name


def test_the_script_makes_one_read_for_the_banner_and_the_frozen_start_list():
    tree = ast.parse((ROOT / "scripts" / "run_harness.py").read_text())
    run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run")
    calls = [n for n in ast.walk(run) if isinstance(n, ast.Call)]

    def named(call):
        return call.func.attr if isinstance(call.func, ast.Attribute) else getattr(
            call.func, "id", None)

    reads = [c for c in calls if named(c) == "enrolled"]
    assert len(reads) == 1                                  # the one read of the assembly
    (frozen,) = [c for c in calls if named(c) == "FrozenEnrolment"]
    assert [a.id for a in frozen.args] == ["engagements", "reader"]
    (facts,) = [c for c in calls if named(c) == "collect_banner_facts"]
    shown = {k.arg: k.value for k in facts.keywords}["engagements"]
    assert isinstance(shown, ast.Name) and shown.id == "engagements"
    (adapter,) = [c for c in calls if named(c) == "LoopAdapter"]
    given = {k.arg: k.value for k in adapter.keywords}["enrolment"]
    assert isinstance(given, ast.Name) and given.id == "frozen"
