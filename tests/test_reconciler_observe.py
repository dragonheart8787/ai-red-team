"""What the plan reads, and that it reads it strictly (D64 step 6b).

* the database side accepts exactly the columns, types and stages migration 0023's function returns
  and refuses anything else (a changed function is an ``ObservationError``, never a silently wrong
  plan); chunks the run-id lookup under the function's own limit;
* the Docker side is shown on fakes (every state, every label shape) and on **real Docker** (a
  created container with the sandbox's labels; a labelled network with a created and an exited
  container attached -- the cases Docker itself does not count);
* the file side is shown on a real directory (a symlink is not followed; another prefix is not
  listed; a mounted file is marked);
* and the whole thing end to end: real rows in the database, read through the reader role, planned.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import docker
import pytest

from control_plane.reconciler import observe, vocab
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.model import US, StuckRow
from control_plane.reconciler.observe import ObservationError
from control_plane.reconciler.plan import plan
from control_plane.state.db import reconciler_reader_scope
from tests.test_reconciler_reader import (
    EPOCH,
    STUCK_COLUMNS,
    M,
    _approval,
    _capability,
    _proposal,
    _run,
)

TH = Thresholds(
    stage_grace_s=3600, lease_grace_s=30, approval_grace_s=30, b_cap_s=1800, p_proxy_s=915,
    q_proxy_s=300, kill_margin_s=60, retention_s=86400, network_idle_s=3600,
    network_sweep_period_s=86400, verify_wait_s=10)


# ---------------------------------------------------------------------------------------------
# the contract with migration 0023
# ---------------------------------------------------------------------------------------------

def test_the_observed_columns_are_the_functions_columns_in_order():
    assert observe.STUCK_COLUMNS == tuple(name for name, _ in STUCK_COLUMNS)


def test_the_page_size_is_the_functions():
    assert observe.STUCK_ROW_LIMIT == M.LIMIT_ROWS
    assert observe.RUN_IDS_PER_CALL == M.MAX_RUN_IDS


def test_the_stuck_stages_are_the_functions_and_stage_names_are_stages_py():
    from control_plane.orchestrator import stages
    assert vocab.STUCK_STAGES == M.STUCK_STAGES
    for name in ("RECEIVED", "DECIDED", "APPROVED", "CAPABILITY_ISSUED", "DISPATCHING", "RECORDED",
                 "CLOSED", "ABANDONED"):
        assert getattr(vocab, f"STAGE_{name}") == getattr(stages, name)


def test_every_transition_the_plan_can_ask_for_is_one_the_database_and_stages_py_allow():
    from control_plane.orchestrator import stages
    for (_kind, reason), (expected, new, detail) in vocab.PROPOSAL_TRANSITIONS.items():
        assert expected in vocab.STUCK_STAGES and new in stages.STAGES
        assert reason == detail
        assert expected not in stages.TERMINAL and new != expected
    assert vocab.UNDECIDED_PAST_GRACE in stages.ABANDON_REASONS
    assert set(stages.ABANDON_REASONS) == {r for (k, _), (_, _, r) in
                                           vocab.PROPOSAL_TRANSITIONS.items()
                                           if k == vocab.ABANDON}


def test_the_reason_codes_of_every_action_kind_are_the_designs():
    assert set(vocab.REASONS) == set(vocab.ACTION_KINDS)
    assert vocab.REASONS[vocab.CLOSE] == (
        "abandoned_after_decision", "capability_not_live", "approval_expired", "approval_revoked",
        "engagement_killed")
    assert vocab.REASONS[vocab.REMOVE_CONTAINER] == ("run_finished", "no_run_row_past_grace")
    assert vocab.REASONS[vocab.REMOVE_PROXY] == ("owner_run_ended", "overran_deadline")
    assert vocab.REASONS[vocab.KILL_CONTAINER] == ("overran_deadline",)


# ---------------------------------------------------------------------------------------------
# the database side, on a fake connection
# ---------------------------------------------------------------------------------------------

def assert_refused(call) -> None:
    """The call must raise ``ObservationError`` -- any other outcome is a failed expectation."""
    try:
        call()
    except ObservationError:
        return
    except Exception as exc:                                         # noqa: BLE001
        pytest.fail(f"expected ObservationError, got {type(exc).__name__}: {exc}")
    pytest.fail("the contract violation was accepted")


class FakeResult:
    def __init__(self, columns, rows):
        self._columns, self._rows = columns, rows

    def keys(self):
        return self._columns

    def __iter__(self):
        return iter(self._rows)


class FakeConn:
    def __init__(self, columns=observe.STUCK_COLUMNS, rows=(), run_rows=()):
        self.columns, self.rows, self.run_rows = columns, list(rows), list(run_rows)
        self.calls = []

    def execute(self, statement, params=None):
        self.calls.append((str(statement), params))
        if "reconciler_run_states" in str(statement):
            return FakeResult(("run_id", "status"), self.run_rows)
        return FakeResult(self.columns, self.rows)


def good(**kw) -> tuple:
    base = dict(engagement_id="E", proposal_id="P", pipeline_stage="received", stage_updated_us=1,
                db_now_us=2, engagement_status="active", kill_switch_engaged=False, enrolled=False,
                capability_id=None, max_duration_s=None, lease_expires_us=None,
                capability_revoked=None, approval_id=None, approval_valid_until_us=None,
                approval_revoked=None, run_id=None, run_status=None)
    base.update(kw)
    return tuple(base[c] for c in observe.STUCK_COLUMNS)


def test_a_well_formed_row_is_read_into_the_model():
    rows, truncated = observe.read_stuck(FakeConn(rows=[good()]))
    assert truncated is False
    assert rows == (StuckRow(*good()),)


def test_a_full_page_is_reported_as_truncated():
    rows, truncated = observe.read_stuck(FakeConn(rows=[good()] * observe.STUCK_ROW_LIMIT))
    assert truncated is True and len(rows) == observe.STUCK_ROW_LIMIT
    _, truncated = observe.read_stuck(FakeConn(rows=[good()] * (observe.STUCK_ROW_LIMIT - 1)))
    assert truncated is False


@pytest.mark.parametrize("columns", [
    observe.STUCK_COLUMNS[:-1], observe.STUCK_COLUMNS[::-1],
    (*observe.STUCK_COLUMNS, "budget"), ("x",) * len(observe.STUCK_COLUMNS)])
def test_a_function_that_returns_other_columns_is_refused(columns):
    assert_refused(lambda: observe.read_stuck(FakeConn(columns=columns, rows=[good()])))


@pytest.mark.parametrize("kw", [
    dict(pipeline_stage="recorded"), dict(pipeline_stage="abandoned"),
    dict(pipeline_stage="awaiting_approval"), dict(pipeline_stage="nonsense"),
    dict(engagement_id=None), dict(proposal_id=None), dict(stage_updated_us=None),
    dict(db_now_us=None), dict(enrolled=None), dict(pipeline_stage=None),
    dict(stage_updated_us="5"), dict(stage_updated_us=1.5), dict(stage_updated_us=True),
    dict(max_duration_s="120"), dict(max_duration_s=True), dict(enrolled=1),
    dict(kill_switch_engaged="f"), dict(run_status=5),
])
def test_a_value_the_contract_does_not_allow_is_refused(kw):
    assert_refused(lambda: observe.read_stuck(FakeConn(rows=[good(**kw)])))


def test_run_states_are_looked_up_in_chunks_under_the_functions_limit():
    ids = [f"RUN-{i:05d}" for i in range(observe.RUN_IDS_PER_CALL * 2 + 17)]
    conn = FakeConn(run_rows=[("RUN-00001", "running")])
    out = observe.read_run_states(conn, ids + ids[:50])           # duplicates are asked once
    assert len(conn.calls) == 3
    assert [len(c[1]["ids"]) for c in conn.calls] == [2000, 2000, 17]
    assert max(len(c[1]["ids"]) for c in conn.calls) <= observe.RUN_IDS_PER_CALL
    assert out == {"RUN-00001": "running"}
    assert observe.read_run_states(FakeConn(), []) == {}


def test_a_run_state_that_is_not_text_is_refused():
    assert_refused(lambda: observe.read_run_states(FakeConn(run_rows=[("R", 5)]), ["R"]))


# ---------------------------------------------------------------------------------------------
# the database side, for real: the reader role, the function, the model
# ---------------------------------------------------------------------------------------------

def test_the_real_function_is_read_into_the_model_and_the_run_lookup_works(engagement_id):
    pid = _proposal(engagement_id, "dispatching")
    cid = _capability(engagement_id, pid, '{"max_duration_seconds": 120}')
    rid = _run(engagement_id, pid, cid, "running")
    with reconciler_reader_scope() as conn:
        rows, _truncated = observe.read_stuck(conn)
        states = observe.read_run_states(conn, [rid, "RUN-nobody-knows"])
    mine = [r for r in rows if r.proposal_id == pid]
    assert len(mine) == 1
    r = mine[0]
    assert (r.engagement_id, r.pipeline_stage, r.capability_id, r.max_duration_s, r.run_id,
            r.run_status) == (engagement_id, "dispatching", cid, 120, rid, "running")
    assert states == {rid: "running"}


# ---------------------------------------------------------------------------------------------
# Docker, on fakes
# ---------------------------------------------------------------------------------------------

def fake_container(cid="a" * 64, *, labels=None, status="running", created="2026-10-12T06:20:10.5Z",
                   started="2026-10-12T06:20:11.123456789Z", finished="0001-01-01T00:00:00Z",
                   mounts=()):
    return SimpleNamespace(
        id=cid, labels=labels if labels is not None else {},
        attrs={"Created": created, "Mounts": [{"Source": m} for m in mounts],
               "State": {"Status": status, "StartedAt": started, "FinishedAt": finished}})


@pytest.mark.parametrize("text, expected", [
    ("2026-10-12T06:20:11Z", 1791786011 * US),
    ("2026-10-12T06:20:11.5Z", 1791786011 * US + 500_000),
    ("2026-10-12T06:20:11.123456789Z", 1791786011 * US + 123_456),
    ("2026-10-12T06:20:11.000000001Z", 1791786011 * US),
    ("0001-01-01T00:00:00Z", None), ("0001-01-01T00:00:00.000000000Z", None),
    ("", None), (None, None),
])
def test_docker_time_to_microseconds(text, expected):
    assert observe.parse_docker_time(text) == expected


def test_a_container_is_read_with_its_labels_and_times():
    c = fake_container(labels={"cyberorch.run_id": "RUN-1", "cyberorch.owner": "ENG"})
    o = observe.container_obs(c)
    assert (o.container_id, o.status, o.run_id, o.owner, o.is_proxy) == (
        "a" * 64, "running", "RUN-1", "ENG", False)
    assert o.started_us == 1791786011 * US + 123_456 and o.finished_us is None
    assert o.created_us == 1791786010 * US + 500_000


@pytest.mark.parametrize("labels, run_id, owner, proxy", [
    ({"cyberorch.run_id": "", "cyberorch.owner": ""}, None, None, False),     # NO_OWNER, no run
    ({"cyberorch.egress_proxy": "1", "cyberorch.run_id": "R", "cyberorch.owner": "E"},
     "R", "E", True),
    ({"cyberorch.egress_proxy": "1", "cyberorch.run_id": ""}, None, None, True),
])
def test_empty_labels_are_none_and_the_proxy_label_marks_a_proxy(labels, run_id, owner, proxy):
    o = observe.container_obs(fake_container(labels=labels))
    assert (o.run_id, o.owner, o.is_proxy) == (run_id, owner, proxy)


class FakeClient:
    def __init__(self, containers=(), networks=()):
        self._containers, self._networks = list(containers), list(networks)
        self.calls = []
        client = self

        class Containers:
            def list(self, all=False, filters=None):
                client.calls.append(("containers.list", all, filters))
                label = (filters or {}).get("label")
                network = (filters or {}).get("network")
                out = client._containers
                if label:
                    out = [c for c in out if label in c.labels]
                if network:
                    out = [c for c in out if network in getattr(c, "networks", ())]
                return out

        class Networks:
            def list(self):
                return client._networks

        self.containers, self.networks = Containers(), Networks()


def test_containers_are_listed_by_label_in_any_state_and_each_once():
    both = fake_container("b" * 64, labels={"cyberorch.run_id": "R", "cyberorch.egress_proxy": "1"})
    tool = fake_container("a" * 64, labels={"cyberorch.run_id": "R"}, status="exited")
    stranger = fake_container("c" * 64, labels={"app": "x"})
    client = FakeClient([tool, both, stranger])
    out = observe.list_containers(client)
    assert [c.container_id for c in out] == ["a" * 64, "b" * 64]
    assert all(call[1] is True for call in client.calls)                 # all=True: every state


def test_only_read_calls_are_made_on_the_client():
    client = FakeClient([fake_container(labels={"cyberorch.run_id": "R"})])
    observe.list_containers(client)
    assert {c[0] for c in client.calls} == {"containers.list"}


def test_mount_sources_count_only_containers_that_could_still_read_them():
    a = fake_container("a" * 64, status="running", mounts=["/tmp/cyberorch-cred-aaaaaaaa"])
    b = fake_container("b" * 64, status="created", mounts=["/tmp/cyberorch-cred-bbbbbbbb"])
    c = fake_container("c" * 64, status="exited", mounts=["/tmp/cyberorch-cred-cccccccc"])
    d = fake_container("d" * 64, status="paused", mounts=["/tmp/cyberorch-tls-dddddddd.pem"])
    e = fake_container("e" * 64, status="restarting", mounts=["/tmp/cyberorch-tls-eeeeeeee.pem"])
    assert observe.live_mount_sources(FakeClient([a, b, c, d, e])) == frozenset({
        "/tmp/cyberorch-cred-aaaaaaaa", "/tmp/cyberorch-cred-bbbbbbbb",
        "/tmp/cyberorch-tls-dddddddd.pem", "/tmp/cyberorch-tls-eeeeeeee.pem"})


# ---------------------------------------------------------------------------------------------
# Docker, for real
# ---------------------------------------------------------------------------------------------

IMAGE = "python:3.12-slim"


@pytest.fixture
def client():
    c = docker.from_env()
    try:
        c.ping()
    except Exception as exc:                                         # noqa: BLE001
        pytest.fail(f"Docker is required for this test: {exc}")
    return c


def _clean(client, containers=(), networks=()):
    for c in containers:
        try:
            c.remove(force=True)
        except docker.errors.NotFound:
            pass
    for n in networks:
        try:
            n.remove()
        except docker.errors.NotFound:
            pass


def test_real_docker_a_created_container_with_the_sandbox_labels_is_read(client):
    run_id = f"RUN-{uuid.uuid4().hex[:10]}"
    c = client.containers.create(IMAGE, command=["true"], labels={
        "cyberorch.run_id": run_id, "cyberorch.owner": "ENG-OBS", "cyberorch.deadline": "none"})
    stranger = client.containers.create(IMAGE, command=["true"], labels={"app": "other"})
    try:
        seen = {o.container_id: o for o in observe.list_containers(client)}
        assert c.id in seen and stranger.id not in seen
        o = seen[c.id]
        assert len(o.container_id) == 64                       # the FULL id, the only handle
        assert (o.status, o.run_id, o.owner, o.is_proxy) == ("created", run_id, "ENG-OBS", False)
        assert o.started_us is None and o.finished_us is None   # never ran: Docker's 0001-01-01
        assert abs(o.created_us - time.time() * US) < 120 * US
    finally:
        _clean(client, [c, stranger])


def test_real_docker_a_network_lists_containers_of_every_state_attached(client):
    suffix = uuid.uuid4().hex[:12]
    name = f"cyberorch-allow-{suffix}"
    net = client.networks.create(name, internal=True,
                                 labels={"cyberorch.allowlist": "10.99.0.0/29"})
    lookalike = client.networks.create(f"cyberorch-allow-look{suffix[:6]}", internal=True)
    created = client.containers.create(IMAGE, command=["true"], network=name,
                                       labels={"cyberorch.run_id": "R", "cyberorch.owner": "E"})
    try:
        seen = {n.name: n for n in observe.list_networks(client)}
        assert seen[name].has_allowlist_label is True
        assert seen[lookalike.name].has_allowlist_label is False
        assert [c.container_id for c in seen[name].attached] == [created.id]
        assert seen[name].attached[0].status == "created"       # Docker's own refusal ignores this
        assert seen[name].created_us > 0
        idle = observe.list_networks(client, idle_seen={net.id: 123})
        assert {n.name: n.idle_seen_since_us for n in idle}[name] == 123
        # nothing else of the host is listed: no 'bridge', no 'host'
        assert all(n.name.startswith("cyberorch-allow-") for n in seen.values())
    finally:
        _clean(client, [created], [net, lookalike])


# ---------------------------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------------------------

def test_files_are_listed_with_lstat_and_a_symlink_is_not_followed(tmp_path):
    real = tmp_path / "cyberorch-cred-ab12_xyz"
    real.write_text("secret")
    tls = tmp_path / "cyberorch-tls-ab12_xyz.pem"
    tls.write_text("pem")
    target = tmp_path / "victim"
    target.write_text("do not touch")
    link = tmp_path / "cyberorch-cred-linkxxxx"
    link.symlink_to(target)
    directory = tmp_path / "cyberorch-tls-dirdirdi"
    directory.mkdir()
    (tmp_path / "unrelated.txt").write_text("x")
    (tmp_path / "other-prefix-file").write_text("x")
    old = time.time() - 5000
    os.utime(real, (old, old))
    mounted = frozenset({str(tls)})

    found = {f.name: f for f in observe.list_files(str(tmp_path), mounted)}
    assert set(found) == {"cyberorch-cred-ab12_xyz", "cyberorch-tls-ab12_xyz.pem",
                          "cyberorch-cred-linkxxxx", "cyberorch-tls-dirdirdi"}
    assert found["cyberorch-cred-ab12_xyz"].is_regular is True
    assert found["cyberorch-cred-ab12_xyz"].uid == os.getuid()
    assert abs(found["cyberorch-cred-ab12_xyz"].mtime_us - old * US) < US
    assert found["cyberorch-cred-linkxxxx"].is_regular is False        # the link, not its target
    assert found["cyberorch-tls-dirdirdi"].is_regular is False
    assert found["cyberorch-tls-ab12_xyz.pem"].mounted_by_live_container is True
    assert found["cyberorch-cred-ab12_xyz"].mounted_by_live_container is False
    assert target.read_text() == "do not touch"
    assert all(f.directory == str(tmp_path) for f in found.values())


def test_a_file_that_vanishes_between_the_listing_and_the_stat_is_skipped(tmp_path, monkeypatch):
    (tmp_path / "cyberorch-cred-ab12_xyz").write_text("x")
    real_lstat = os.lstat

    def vanishing(path, *a, **kw):
        if path == "cyberorch-cred-ab12_xyz":
            raise FileNotFoundError(path)
        return real_lstat(path, *a, **kw)

    monkeypatch.setattr(os, "lstat", vanishing)
    assert observe.list_files(str(tmp_path), frozenset()) == ()


# ---------------------------------------------------------------------------------------------
# end to end: real rows, the reader role, a (fake) Docker, the plan
# ---------------------------------------------------------------------------------------------

def test_real_rows_are_read_through_the_reader_role_and_planned(engagement_id, tmp_path):
    received = _proposal(engagement_id, "received")
    decided = _proposal(engagement_id, "decided")
    lapsed = _proposal(engagement_id, "capability_issued")
    _capability(engagement_id, lapsed, '{"max_duration_seconds": 60}',
                lease=f"TIMESTAMPTZ '{EPOCH}' + interval '1 hour'")
    killed = _proposal(engagement_id, "approved")
    _approval(engagement_id, killed)
    from tests import scheduler_support as sup
    sup.kill(engagement_id)
    dispatching = _proposal(engagement_id, "dispatching")
    cap = _capability(engagement_id, dispatching, '{"max_duration_seconds": 120}')
    run_id = _run(engagement_id, dispatching, cap, "running")
    unreadable = _proposal(engagement_id, "dispatching")
    _capability(engagement_id, unreadable, '{"max_duration_seconds": "abc"}')

    a_day_ago = datetime.fromtimestamp(time.time() - 86400, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    overdue = fake_container("f" * 64, labels={"cyberorch.run_id": run_id,
                                               "cyberorch.owner": engagement_id},
                             started=a_day_ago)
    client = FakeClient([overdue])
    client.networks = SimpleNamespace(list=lambda: [])
    with reconciler_reader_scope() as conn:
        obs = observe.observe(conn, client, directory=str(tmp_path), expected_uid=os.getuid(),
                              clock_us=lambda: time.time_ns() // 1000)
    result = plan(obs, TH)
    mine = {(a.kind, a.subject_id): a for a in result.actions if a.engagement_id == engagement_id}
    assert {(a.kind, a.reason_code) for a in mine.values()} >= {
        (vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE),
        (vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION),
        (vocab.CLOSE, vocab.CAPABILITY_NOT_LIVE),
        (vocab.CLOSE, vocab.ENGAGEMENT_KILLED),
        (vocab.MARK_UNKNOWN_OUTCOME, vocab.UNKNOWN_OUTCOME),
        (vocab.KILL_CONTAINER, vocab.OVERRAN_DEADLINE)}
    by_subject = {a.subject_id: a for a in mine.values()}
    assert by_subject[received].expected_stage == "received"
    assert by_subject[received].planned_stage_updated_us == 24 * 3600 * US
    assert by_subject[decided].kind == vocab.CLOSE
    assert by_subject[lapsed].reason_code == vocab.CAPABILITY_NOT_LIVE
    assert by_subject[killed].reason_code == vocab.ENGAGEMENT_KILLED
    assert by_subject[dispatching].run_id == run_id
    assert unreadable not in by_subject
    assert ("proposal", vocab.BUDGET_UNREADABLE) in {
        (r.subject, r.reason_code) for r in result.reports if r.subject_id == unreadable}
