"""The end-of-session residue check (tests/residue.py) sees what it is there to see (D63).

A check that has never been shown to fail is a claim. Each kind of residue is created for real --
a global layer on the real database, a container and a network on the real daemon -- and the
comparison against a snapshot taken before is shown to report it; then everything is taken back,
and a snapshot compared with itself is clean.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from tests import residue
from tests.helpers import deactivate_global_layer, publish_global_layer

docker = pytest.importorskip("docker")

#: Any image with ``sleep`` will do. CI has this one (the Semgrep and BloodHound image builds pull
#: it); a workstation has it from the same builds. Pulled if missing, and a failure to get it fails
#: the test -- a residue check that could not create the residue has shown nothing.
BASE_IMAGE = "python:3.12-slim"


@pytest.fixture
def client(db_available):
    c = residue._docker()
    if c is None:
        pytest.skip("no Docker daemon")
    try:
        c.images.get(BASE_IMAGE)
    except docker.errors.ImageNotFound:
        try:
            c.images.pull(BASE_IMAGE)
        except docker.errors.DockerException as exc:
            pytest.fail(f"{BASE_IMAGE} is neither present nor pullable: {exc}")
    return c


def test_a_snapshot_compared_with_itself_is_clean(client):
    before = residue.snapshot()
    found = residue.leftovers(before)
    assert found.failures() == [] and found.networks_removed == []


def test_an_active_global_layer_is_residue_and_is_not_cleaned_up(db_available):
    before = residue.snapshot()
    layer_id = publish_global_layer(
        layer="emergency_overlay", version=uuid.uuid4().int % 2_000_000_000, document={})
    try:
        found = residue.leftovers(before)
        assert [row[0] for row in found.layers] == [layer_id]
        assert found.failures() and "policy layers" in found.failures()[0]
    finally:
        deactivate_global_layer(layer_id)
    assert residue.leftovers(before).layers == []                # retired: no longer residue


def test_a_retired_global_layer_is_not_residue(db_available):
    before = residue.snapshot()
    layer_id = publish_global_layer(
        layer="emergency_overlay", version=uuid.uuid4().int % 2_000_000_000, document={})
    deactivate_global_layer(layer_id)
    assert residue.leftovers(before).failures() == []


def test_a_container_is_residue_even_if_it_never_started(client):
    before = residue.snapshot()
    container = client.containers.create(BASE_IMAGE, name=f"residue-{uuid.uuid4().hex[:8]}")
    try:
        found = residue.leftovers(before)
        assert any(container.name in entry for entry in found.containers)
        assert found.failures() and "containers" in found.failures()[0]
    finally:
        container.remove(force=True)
    assert residue.leftovers(before).containers == []


def test_a_sandbox_network_is_removed_and_counted_not_failed(client):
    before = residue.snapshot()
    name = f"cyberorch-allow-residue{uuid.uuid4().hex[:6]}"
    client.networks.create(name)
    try:
        found = residue.leftovers(before)
        assert found.networks_removed == [name] and found.failures() == []
    finally:
        for n in client.networks.list(names=[name]):
            n.remove()
    assert not client.networks.list(names=[name])


def test_a_network_with_something_attached_is_a_failure(client):
    before = residue.snapshot()
    name = f"cyberorch-allow-residue{uuid.uuid4().hex[:6]}"
    network = client.networks.create(name)
    container = client.containers.run(BASE_IMAGE, ["sleep", "60"], detach=True,
                                      name=f"residue-{uuid.uuid4().hex[:8]}", network=name)
    try:
        found = residue.leftovers(before)
        assert found.networks_stuck == [name]
        assert any("could not be removed" in f for f in found.failures())
    finally:
        container.remove(force=True)
        network.remove()


# ---------------------------------------------------------------------------------------------
# the rows the session made are closed, and the ones nobody registered are found
# ---------------------------------------------------------------------------------------------

def _stages_and_runs(eid):
    from sqlalchemy import text

    from control_plane.state.db import engagement_scope
    with engagement_scope(eid) as conn:
        stages = dict(conn.execute(text(
            "SELECT proposal_id, pipeline_stage || '/' || coalesce(stage_detail, '') "
            "FROM action_proposals")).all())
        runs = dict(conn.execute(text("SELECT run_id, status FROM tool_runs")).all())
    return stages, runs


def test_a_registered_engagements_stuck_rows_and_in_flight_runs_are_closed(
        engagement_id, monkeypatch):
    from tests.reconciler_support import _capability, _proposal, _run, freshen
    assert engagement_id in residue.CREATED                      # make_engagement registered it
    monkeypatch.setattr(residue, "CREATED", {engagement_id})     # (the session's others: not here)
    monkeypatch.setattr(residue, "FILE_CAP", {"tests/test_residue_check.py": 6})   # what it leaves
    before = residue.snapshot()
    stuck = {stage: _proposal(engagement_id, stage) for stage in
             ("received", "decided", "approved", "capability_issued", "dispatching")}
    done = _proposal(engagement_id, "abandoned")
    cap = _capability(engagement_id, stuck["dispatching"], '{"max_duration_seconds": 60}')
    live, over = _run(engagement_id, stuck["dispatching"], cap, "running"), _run(
        engagement_id, done, None, "succeeded")
    freshen(engagement_id, stuck["approved"])

    closed = residue.close_session_rows(before)

    stages_after, runs_after = _stages_and_runs(engagement_id)
    assert stages_after[stuck["received"]] == "abandoned/undecided_past_grace"
    for stage in ("decided", "approved", "capability_issued", "dispatching"):
        assert stages_after[stuck[stage]] == "closed/test_cleanup", stage
    assert stages_after[done] == "abandoned/undecided_past_grace"            # untouched
    assert runs_after[live] == "unknown_outcome" and runs_after[over] == "succeeded"
    assert closed.proposals == {"received": 1, "decided": 1, "approved": 1,
                                "capability_issued": 1, "dispatching": 1}
    assert closed.runs >= 1 and closed.failures() == []
    assert residue.close_session_rows(before).proposals == {}                # and nothing twice


def test_an_engagement_nobody_registered_is_left_alone_and_its_new_stuck_row_is_found(
        engagement_factory, monkeypatch):
    from tests.reconciler_support import _proposal, freshen
    eid, _ = engagement_factory()
    monkeypatch.setattr(residue, "CREATED", set())     # as if it were made by some other route
    before = residue.snapshot()
    old = _proposal(eid, "approved")                   # backdated to 1970: older than the session
    new = _proposal(eid, "received")
    freshen(eid, new)                                  # touched now: newer than the session
    try:
        found = residue.close_session_rows(before)
        stages_after, _ = _stages_and_runs(eid)
        assert stages_after[old] == "approved/" and stages_after[new] == "received/"   # not ours
        assert found.proposals == {} and found.unregistered == [(eid, "received")]
        assert found.failures() and "did not register" in found.failures()[0]
    finally:
        monkeypatch.setattr(residue, "CREATED", {eid})
        residue.close_session_rows(before)             # take it back, as the session end would


# ---------------------------------------------------------------------------------------------
# the count, per test file, and its cap (completion 3, item 3)
# ---------------------------------------------------------------------------------------------

def test_an_engagement_remembers_the_test_file_that_made_it(engagement_id):
    assert residue.FILE_OF[engagement_id] == "tests/test_residue_check.py"
    assert residue.current_file() == "tests/test_residue_check.py"


def test_outside_a_test_the_file_is_said_not_to_be_one(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert residue.current_file() == residue.NOT_IN_A_TEST
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/test_x.py::test_y[param::with::colons] (call)")
    assert residue.current_file() == "tests/test_x.py"


def _leave(eid, n_proposals, n_runs):
    from tests.reconciler_support import _proposal, _run
    pids = [_proposal(eid, "approved") for _ in range(max(n_proposals, 1))]
    for _ in range(n_runs):
        _run(eid, pids[0], None, "running")
    return pids


def test_the_rows_a_file_left_are_counted_per_file(engagement_factory, monkeypatch):
    a, _ = engagement_factory()
    b, _ = engagement_factory()
    monkeypatch.setattr(residue, "CREATED", {a, b})
    monkeypatch.setattr(residue, "FILE_OF", {a: "tests/test_a.py", b: "tests/test_b.py"})
    before = residue.snapshot()
    _leave(a, 3, 2)
    _leave(b, 1, 0)
    closed = residue.close_session_rows(before)
    assert closed.by_file == {"tests/test_a.py": (3, 2), "tests/test_b.py": (1, 0)}
    assert closed.table()[0].startswith("  tests/test_a.py: 3 proposal(s) + 2 run(s)")


def test_an_engagement_with_nothing_left_is_not_in_the_count(engagement_id, monkeypatch):
    monkeypatch.setattr(residue, "CREATED", {engagement_id})
    monkeypatch.setattr(residue, "FILE_OF", {engagement_id: "tests/test_a.py"})
    assert residue.close_session_rows(residue.snapshot()).by_file == {}


def test_a_file_that_left_more_than_its_cap_fails_the_session_naming_it(
        engagement_id, monkeypatch):
    monkeypatch.setattr(residue, "CREATED", {engagement_id})
    monkeypatch.setattr(residue, "FILE_OF", {engagement_id: "tests/test_leaky.py"})
    before = residue.snapshot()
    _leave(engagement_id, 2, 1)                           # three rows
    closed = residue.close_session_rows(before)
    assert closed.by_file == {"tests/test_leaky.py": (2, 1)}
    assert closed.over_cap() == {"tests/test_leaky.py": (3, 0)}         # unlisted: may leave none
    assert any("tests/test_leaky.py left 3 stuck row(s)" in f for f in closed.failures())
    closed.caps = {"tests/test_leaky.py": 2}
    assert closed.over_cap() == {"tests/test_leaky.py": (3, 2)}         # one over is over
    closed.caps = {"tests/test_leaky.py": 3}
    assert closed.over_cap() == {} and closed.failures() == []          # exactly the cap is fine
    closed.caps = {"tests/test_leaky.py": 4}
    assert closed.over_cap() == {}


#: The most any file may be allowed to leave for the session end. Empty since completion 4: the
#: tests close their own rows (below). It only ever shrinks: a cap above it fails
#: (``test_a_cap_is_never_above_the_ceiling``), and so does a ceiling above the main line's
#: (``test_the_ceiling_is_never_above_the_main_lines``).
FILE_CAP_CEILING: dict[str, int] = {}


def test_the_caps_name_files_that_exist_and_are_whole_positive_numbers():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for file, cap in residue.FILE_CAP.items():
        assert (root / file).is_file(), f"{file}: no such test file"
        assert isinstance(cap, int) and cap >= 1, (file, cap)


def test_a_cap_is_never_above_the_ceiling():
    for file, cap in residue.FILE_CAP.items():
        assert cap <= FILE_CAP_CEILING.get(file, 0), (
            f"{file}: cap {cap} is above its ceiling {FILE_CAP_CEILING.get(file, 0)}; a cap is "
            "lowered, never raised -- fix the test that leaves the rows")


def ceiling_above_the_main_lines(main_source: str, ours: dict[str, int]) -> list[str]:
    """The files whose ceiling is above the one in ``main_source`` (the text of this file on the
    main line). A main line with no ceiling yet has nothing for ours to be above."""
    import ast
    import re
    found = re.search(r"^FILE_CAP_CEILING[^=]*= (\{.*?\})$", main_source, re.M)
    if found is None:
        return []
    main = ast.literal_eval(found.group(1))
    return [f"{file}: {ceiling} > {main.get(file, 0)}" for file, ceiling in ours.items()
            if ceiling > main.get(file, 0)]


def test_the_ceiling_is_never_above_the_main_lines():
    """Raising the ceiling beside the cap would defeat the first test, so the ceiling is compared
    with the one on ``origin/main``. This test never skips (CI fails a run that skips): where
    ``origin/main`` is missing it fails and says to fetch it -- the CI job checks out the whole
    history for exactly this -- and where the main line has no ceiling yet there is nothing for
    this one to be above, so it holds."""
    import subprocess
    try:
        shown = subprocess.run(
            ["git", "show", "origin/main:tests/test_residue_check.py"], capture_output=True,
            text=True, check=True, timeout=30, cwd=Path(__file__).resolve().parents[1]).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.fail("origin/main is not in this checkout: fetch it (git fetch origin main)")
    assert ceiling_above_the_main_lines(shown, FILE_CAP_CEILING) == []


def test_the_comparison_with_the_main_line_says_which_ceiling_is_raised():
    main_text = "FILE_CAP_CEILING: dict[str, int] = {'tests/test_a.py': 3}\n"
    assert ceiling_above_the_main_lines(main_text, {"tests/test_a.py": 3}) == []
    assert ceiling_above_the_main_lines(main_text, {"tests/test_a.py": 2}) == []
    assert ceiling_above_the_main_lines(main_text, {}) == []
    assert ceiling_above_the_main_lines(main_text, {"tests/test_a.py": 4}) == [
        "tests/test_a.py: 4 > 3"]
    assert ceiling_above_the_main_lines(main_text, {"tests/test_b.py": 1}) == [
        "tests/test_b.py: 1 > 0"]                      # a file the main line did not allow at all
    assert ceiling_above_the_main_lines("nothing here\n", {"tests/test_b.py": 1}) == []


def test_finishing_a_test_closes_what_its_engagements_left_and_says_which_file(
        engagement_factory, monkeypatch):
    a, _ = engagement_factory()
    monkeypatch.setattr(residue, "CLOSED_AT_TEST_END", {})
    monkeypatch.setattr(residue, "FILE_OF", {a: "tests/test_a.py"})
    _leave(a, 2, 1)
    residue.finish_test({a})
    assert residue.CLOSED_AT_TEST_END == {"tests/test_a.py": 3}
    stages, runs = _stages_and_runs(a)
    assert not [v for v in stages.values() if v.startswith(("approved", "received"))]
    assert set(runs.values()) == {"unknown_outcome"}
    residue.finish_test({a})                                       # and nothing twice
    assert residue.CLOSED_AT_TEST_END == {"tests/test_a.py": 3}


_LEFT_BY_AN_EARLIER_TEST: list[str] = []


def test_ends_zero_a_test_leaves_a_stuck_row_in_its_own_engagement(engagement_id):
    from tests import reconciler_support
    _leave(engagement_id, 2, 1)
    # (the reconciler tests' own cleanup would close it: it is the end of *every* test that has to)
    reconciler_support.TOUCHED.discard(engagement_id)
    _LEFT_BY_AN_EARLIER_TEST.append(engagement_id)


def test_ends_one_and_by_the_next_test_it_has_been_closed():
    (eid,) = _LEFT_BY_AN_EARLIER_TEST
    stages, runs = _stages_and_runs(eid)
    assert not [v for v in stages.values() if v.startswith("approved")], stages
    assert set(runs.values()) <= {"unknown_outcome"}, runs


@pytest.fixture(scope="module")
def a_module_scoped_engagement(db_available):
    import uuid

    from tests.helpers import make_engagement
    eid = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    from tests import reconciler_support
    make_engagement(eid)
    _leave(eid, 1, 0)
    reconciler_support.TOUCHED.discard(eid)    # that cleanup is per test; this row outlives one
    yield eid
    residue.close_rows({eid})


def test_module_one_a_module_scoped_engagement_has_its_row(a_module_scoped_engagement):
    stages, _ = _stages_and_runs(a_module_scoped_engagement)
    assert [v for v in stages.values() if v.startswith("approved")]


def test_module_two_and_the_first_test_did_not_close_it_early(a_module_scoped_engagement):
    stages, _ = _stages_and_runs(a_module_scoped_engagement)
    assert [v for v in stages.values() if v.startswith("approved")], (
        "a test closed an engagement it did not make")


def test_a_session_start_after_a_rows_last_touch_makes_it_not_the_sessions(monkeypatch):
    from dataclasses import replace
    monkeypatch.setattr(residue, "CREATED", set())
    before = residue.snapshot()
    later = replace(before, started_us=before.started_us + 10 * 60 * 1_000_000)
    assert residue.close_session_rows(later).unregistered == []


# --- scheduler enrollments (ACCEPTANCE 5.109) ----------------------------------------------------

def test_an_enrollment_made_after_the_snapshot_is_residue_and_one_before_it_is_not(engagement_id):
    from tests import scheduler_support as sup
    sup.enroll(engagement_id)
    try:
        before = residue.snapshot()                              # it is live now: not residue
        assert engagement_id in before.enrollments
        assert residue.leftovers(before).enrollments == []
        other = "ENG-RESIDUE-" + uuid.uuid4().hex[:8]
        from tests.helpers import make_engagement
        make_engagement(other)
        sup.enroll(other)
        try:
            found = residue.leftovers(before)
            assert found.enrollments == [other]
            assert any(other in line for line in found.failures())
        finally:
            sup.withdraw(other)
    finally:
        sup.withdraw(engagement_id)
    assert residue.leftovers(residue.snapshot()).enrollments == []


def test_the_end_of_a_test_withdraws_what_it_enrolled_and_nothing_that_was_live_before(
        engagement_id):
    from tests import scheduler_support as sup
    from tests.helpers import make_engagement
    older = "ENG-RESIDUE-" + uuid.uuid4().hex[:8]
    make_engagement(older)
    sup.enroll(older)
    try:
        before = residue.live_enrollments()
        sup.enroll(engagement_id)
        assert residue.finish_test_enrollments(before) == 1
        live = residue.live_enrollments()
        assert engagement_id not in live and older in live
        assert residue.finish_test_enrollments(before) == 0       # nothing more to withdraw
    finally:
        sup.withdraw(older)
        sup.withdraw(engagement_id)
