"""D69 H5c2 (F): the tasks a run leaves behind, listed read-only (plan item 47, 3.7 B).

The state is made for real: a fault inside ``propose_action`` (exit code 12) leaves the task it
happened on ``claimed`` and the rest of the plan ``queued``, and nothing cleans them up. The listing
shows them, writes nothing, runs in a read-only transaction, and says that no tool clears them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from harness import residue_listing
from harness.exit_codes import StopReason
from harness.residue_listing import NO_TOOL, format_residue, list_residue
from scripts import run_harness
from tests.test_harness_h5c1_support import (
    completed_task,
    drive,
    make_rig,
    make_world,
    task_rows,
)
from tests.test_harness_h5c2_support import enrolled

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


def _boom():
    raise RuntimeError("injected into the pipeline")


def _after_a_fault(world):
    """The state after exit code 12: one claimed task and one queued -- and, from an earlier run,
    one completed, which is not residue and must not be listed."""
    completed_task(world, 9)
    rig = make_rig(world, reviewer_hook=_boom,
                   tasks_for_call=lambda call: [world.task(5), world.task(6)])
    assert drive(rig.adapter).reason is StopReason.FAULT_OUTSIDE_LIST
    assert sorted(row[1] for row in task_rows(world.engagement_id)) == [
        "claimed", "completed", "queued"]
    return rig


def test_the_listing_shows_the_claimed_and_the_queued_task_a_fault_left(world):
    _after_a_fault(world)

    found = list_residue([world.engagement_id], limit=10)

    by_status = {t.status: t for t in found}
    assert sorted(by_status) == ["claimed", "queued"]
    assert by_status["claimed"].owner_agent_id == "scripted-worker"
    assert by_status["claimed"].lease_expires_at is not None
    assert by_status["queued"].owner_agent_id is None
    live = {row[0] for row in task_rows(world.engagement_id) if row[1] != "completed"}
    assert {t.task_id for t in found} == live


def test_the_listing_changes_nothing(world):
    _after_a_fault(world)
    before = task_rows(world.engagement_id)

    list_residue([world.engagement_id], limit=10)

    assert task_rows(world.engagement_id) == before


def test_the_read_is_made_in_a_read_only_transaction(world, monkeypatch):
    _after_a_fault(world)
    modes = []
    real = residue_listing.query_state

    def watching(conn, **kwargs):
        modes.append(conn.exec_driver_sql("SHOW transaction_read_only").scalar())
        return real(conn, **kwargs)

    monkeypatch.setattr(residue_listing, "query_state", watching)

    list_residue([world.engagement_id], limit=10)

    assert modes == ["on"]


def test_the_text_says_that_no_tool_clears_them_and_names_no_goal(world):
    _after_a_fault(world)

    text = format_residue(list_residue([world.engagement_id], limit=10))

    assert text.splitlines()[0] == "2 live task(s)"
    assert NO_TOOL in text and "claimed" in text and "queued" in text
    assert "Scan 10.82.0.5" not in text                    # a Supervisor's words are not printed


def test_an_engagement_with_no_live_task_has_an_empty_listing(world):
    assert list_residue([world.engagement_id], limit=10) == ()
    assert format_residue(()).splitlines()[0] == "0 live task(s)"


@pytest.mark.parametrize("bad", [0, -1, True, None, "5"])
def test_the_limit_is_required_and_positive(world, bad):
    with pytest.raises(ValueError):
        list_residue([world.engagement_id], limit=bad)


def test_the_command_lists_the_enrolled_engagements_and_exits_0(world, capsys):
    _after_a_fault(world)
    before = task_rows(world.engagement_id)
    with enrolled(world.engagement_id):
        code = run_harness.main(["residue", "--live-task-limit", "10"])
    out = capsys.readouterr().out
    assert code == 0
    assert world.engagement_id in out and "status=claimed" in out and "status=queued" in out
    assert NO_TOOL in out
    assert task_rows(world.engagement_id) == before


def test_no_script_but_the_live_run_ones_names_complete_task_so_none_clears_leftovers():
    named = []
    for path in sorted((ROOT / "scripts").rglob("*.py")):
        names = {n.attr if isinstance(n, ast.Attribute) else n.id if isinstance(n, ast.Name)
                 else n.name for n in ast.walk(ast.parse(path.read_text()))
                 if isinstance(n, (ast.Attribute, ast.Name, ast.alias))}
        if "complete_task" in names:
            named.append(path.relative_to(ROOT).as_posix())
    assert named == ["scripts/live_run/d17_supervisor.py", "scripts/live_run/d40_three_role.py",
                     "scripts/live_run/live_run.py"]
