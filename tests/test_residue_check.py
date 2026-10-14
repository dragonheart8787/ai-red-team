"""The end-of-session residue check (tests/residue.py) sees what it is there to see (D63).

A check that has never been shown to fail is a claim. Each kind of residue is created for real --
a global layer on the real database, a container and a network on the real daemon -- and the
comparison against a snapshot taken before is shown to report it; then everything is taken back,
and a snapshot compared with itself is clean.
"""

from __future__ import annotations

import uuid

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


def test_the_caps_name_files_that_exist_and_are_whole_positive_numbers():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for file, cap in residue.FILE_CAP.items():
        assert (root / file).is_file(), f"{file}: no such test file"
        assert isinstance(cap, int) and cap >= 1, (file, cap)


def test_a_session_start_after_a_rows_last_touch_makes_it_not_the_sessions(monkeypatch):
    from dataclasses import replace
    monkeypatch.setattr(residue, "CREATED", set())
    before = residue.snapshot()
    later = replace(before, started_us=before.started_us + 10 * 60 * 1_000_000)
    assert residue.close_session_rows(later).unregistered == []
