"""Negative experiments, end to end: things the reconciler must NOT do, on a real Docker daemon
and the real database (D64 pre-deletion item 7, ACCEPTANCE 5.89).

Every other test of the act half builds one object and shows one refusal. This puts them in one
picture, the way a deletion would meet them: containers that belong to nobody we know, containers
that wear our labels but are not ours, a live run that must not be touched, and one container that
is exactly what the reconciler is for. The plan is made from the **real** observation of this host
(no engagement filter), the deletion flag is on (tests only), and what has to be true afterwards is
that **one** container is gone and every other object is exactly as it was.

The cases (E24):

* **V**  a victim: no labels at all, running. Not in the observation, never selected.
* **L**  a lab script's container wearing only ``cyberorch.owner``. Not in the observation either.
* **F1** a forged copy of a *live* run's labels, running. Left alone (the database says the run is
  live).
* **F2** forged labels naming a run the database has never heard of, at rest and old. This one *is*
  removed: the forger's own container, which is the worst a forgery can do (D64 §2.4).
* **N**  a lookalike network (the prefix, no label), idle and old. Never selected.
"""

from __future__ import annotations

import os
import time
import uuid

import docker
import pytest
from docker.errors import APIError, NotFound

from control_plane.reconciler import act, emit, flags, observe, vocab
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.plan import plan
from control_plane.state.db import reconciler_reader_scope
from tests.reconciler_support import _capability, _proposal, _run
from tests.test_reconciler_act import TH
from tests.test_reconciler_order import events_of

IMAGE = "python:3.12-slim"


@pytest.fixture
def client():
    c = docker.from_env()
    try:
        c.ping()
    except Exception as exc:                                         # noqa: BLE001
        pytest.fail(f"Docker is required for this test: {exc}")
    return c


@pytest.fixture
def made(client):
    things = []
    yield things
    for thing in reversed(things):
        try:
            thing.remove(force=True) if hasattr(thing, "attrs") and "State" in thing.attrs \
                else thing.remove()
        except (NotFound, APIError):
            pass


def create(client, made, *, labels=None, command=("sleep", "300"), start=True):
    c = client.containers.create(IMAGE, command=list(command), labels=labels or {})
    made.append(c)
    if start:
        c.start()
    return c


def test_e24_a_whole_host_pass_removes_the_forgers_container_and_touches_nothing_else(
        client, made, engagement_id):
    pid = _proposal(engagement_id, "dispatching")
    cid = _capability(engagement_id, pid, '{"max_duration_seconds": 600}')
    live_run = _run(engagement_id, pid, cid, "running")

    victim = create(client, made)
    lab = create(client, made, labels={"cyberorch.owner": engagement_id})
    forged_live = create(client, made, labels={"cyberorch.run_id": live_run,
                                                "cyberorch.owner": engagement_id})
    forged_unknown = create(client, made, command=("true",), labels={
        "cyberorch.run_id": f"RUN-NOBODY-{uuid.uuid4().hex[:6]}", "cyberorch.owner": engagement_id})
    forged_unknown.wait(timeout=30)
    time.sleep(2)                       # "old": past a retention window of one second
    lookalike = client.networks.create(f"cyberorch-allow-{uuid.uuid4().hex[:12]}", internal=True)
    made.append(lookalike)
    th = Thresholds(**{**TH.__dict__, "retention_s": 1})
    ours = {victim.id, lab.id, forged_live.id, forged_unknown.id}

    with reconciler_reader_scope() as conn:
        obs = observe.observe(conn, client, directory="/tmp", expected_uid=os.getuid(),
                              clock_us=lambda: time.time_ns() // 1000, max_pages=1)
    # the observation lists containers by label (a run label or the proxy label), so the two
    # without a run label are not even seen; the two forged ones are
    seen = {c.container_id for c in obs.containers}
    assert {forged_live.id, forged_unknown.id} <= seen
    assert not {victim.id, lab.id} & seen
    planned = plan(obs, th)
    mine = [a for a in planned.actions if a.subject_id in ours]
    assert [(a.kind, a.subject_id, a.reason_code) for a in mine] == [
        (vocab.REMOVE_CONTAINER, forged_unknown.id, vocab.NO_RUN_ROW_PAST_GRACE)]
    assert all(a.subject_id != lookalike.id for a in planned.actions)       # no network, either

    def intend(action):
        event_type, payload, eid, stype, sid = emit.intent_for(action)
        emit.emit(event_type, payload, engagement_id=eid, subject_type=stype, subject_id=sid)

    results = act.carry_out(mine, Settings(Mode.STATE_ONLY, enabled=flags.EVERYTHING), th=th,
                            client=client, intend=intend)
    assert [r.outcome for r in results] == ["done"]
    with pytest.raises(NotFound):
        client.containers.get(forged_unknown.id)                    # the forger's, gone
    for survivor in (victim, lab, forged_live):
        survivor.reload()
        assert survivor.status == "running", survivor.name          # untouched
    assert client.networks.get(lookalike.id)
    written = events_of(engagement_id, emit.ACTION_INTENDED)
    assert [e["subject_id"] for e in written] == [forged_unknown.labels["cyberorch.run_id"]]
