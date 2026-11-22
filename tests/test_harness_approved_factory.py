"""D69 plan item 131: the entry script accepts only the factories in ``APPROVED_ROLE_FACTORIES``.

``scripts/run_harness.py run`` compares ``--role-factory`` with the tuple, as a string, before it
takes the lock and before it imports anything; any other factory is refused with exit 10 and the
line ``refused: the role factory is not an approved one``. The two approved factories are the tests'
scripted ones and still run. No model, no container.
"""

from __future__ import annotations

import importlib.util
import sys

import pytest

from harness.exit_codes import EXIT_LOCK_HELD, EXIT_OK, EXIT_STARTUP_REFUSED
from harness.lock import HarnessLock
from scripts import run_harness
from tests.test_harness_h5c1_support import proposal_rows, task_rows
from tests.test_harness_h5c2_entry import _argv, _run, world  # noqa: F401 - world is a fixture
from tests.test_harness_h5c2_support import enrolled

PROBE = "tests.harness_unapproved_roles"
UNAPPROVED = f"{PROBE}:build"
REFUSAL = "refused: the role factory is not an approved one"
H5C2 = "tests.harness_h5c2_roles:build"
H7 = "tests.harness_h7_roles:build"


class _HeldElsewhere:
    """A lock that counts how often it is asked for and says another instance holds it, so a run
    that gets past the gate ends with 2 having read nothing."""

    def __init__(self) -> None:
        self.asked = 0

    def acquire(self) -> bool:
        self.asked += 1
        return False


def _refused_argv() -> list[str]:
    return _argv(**{"--role-factory": UNAPPROVED})


# -- the list ---------------------------------------------------------------------------------


def test_the_approved_factories_are_exactly_the_two_scripted_ones():
    approved = run_harness.APPROVED_ROLE_FACTORIES
    assert isinstance(approved, tuple)
    assert sorted(approved) == sorted([H5C2, H7])


def test_the_probe_is_a_real_module_that_could_be_imported():
    # without this, "the probe was not imported" could hold because there is nothing to import
    assert UNAPPROVED not in run_harness.APPROVED_ROLE_FACTORIES
    assert importlib.util.find_spec(PROBE) is not None


# -- a factory that is not on the list ----------------------------------------------------------


def test_an_unapproved_factory_ends_with_10_and_says_why(capsys):
    code = _run(_refused_argv(), lock=_HeldElsewhere())
    out = capsys.readouterr()
    assert code == EXIT_STARTUP_REFUSED == 10
    assert out.out == ""
    assert out.err.splitlines() == [REFUSAL]


def test_an_unapproved_factory_is_not_imported():
    sys.modules.pop(PROBE, None)
    code = _run(_refused_argv(), lock=_HeldElsewhere())
    assert code == EXIT_STARTUP_REFUSED
    assert PROBE not in sys.modules


def test_an_unapproved_factory_takes_no_lock_and_reads_no_database(monkeypatch):
    connected = []

    def connect():
        connected.append(True)
        raise AssertionError("the database must not be touched")

    called = []
    monkeypatch.setattr(run_harness, "_roles", lambda spec: called.append(spec))
    monkeypatch.setattr(run_harness, "EnrolledFromDatabase", lambda: called.append("enrolment"))
    held = _HeldElsewhere()
    assert _run(_refused_argv(), lock=held) == EXIT_STARTUP_REFUSED
    assert held.asked == 0
    assert _run(_refused_argv(), lock=HarnessLock(connect=connect)) == EXIT_STARTUP_REFUSED
    assert connected == []
    assert called == []


@pytest.mark.parametrize("factory", ["tests.harness_h5c2_roles", "tests.harness_h5c2_roles:build ",
                                     "tests.harness_h5c2_roles:Build", "harness_h5c2_roles:build",
                                     "tests/harness_h5c2_roles.py:build"])
def test_a_near_miss_of_an_approved_name_is_refused(factory, capsys):
    code = _run(_argv(**{"--role-factory": factory}), lock=_HeldElsewhere())
    assert code == EXIT_STARTUP_REFUSED
    assert capsys.readouterr().err.splitlines() == [REFUSAL]


# -- the two approved factories ----------------------------------------------------------------


@pytest.mark.parametrize("factory", [H5C2, H7])
def test_an_approved_factory_passes_the_gate_and_reaches_the_lock(factory, capsys):
    held = _HeldElsewhere()
    code = _run(_argv(**{"--role-factory": factory}), lock=held)
    err = capsys.readouterr().err
    assert code == EXIT_LOCK_HELD == 2
    assert held.asked == 1
    assert REFUSAL not in err and "holds the harness lock" in err


@pytest.mark.parametrize("factory", [H5C2, H7])
def test_an_approved_factory_still_runs_a_round(factory, world, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setenv("H7_SCOPES", f"{world.engagement_id}={world.scope_id}")
    with enrolled(world.engagement_id):
        code = _run(_argv(**{"--role-factory": factory}) + ["--once"])
    out = capsys.readouterr()
    assert code == EXIT_OK == 0
    assert REFUSAL not in out.err
    assert "harness stopped (exit 0)" in out.err
    assert [row[1] for row in task_rows(world.engagement_id)] == ["completed"] * 3
    assert len(proposal_rows(world.engagement_id)) == 3
