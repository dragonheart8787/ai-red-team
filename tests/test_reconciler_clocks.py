"""Which clock judges what, and what happens when two disagree (completion 3, item 6;
ACCEPTANCE 5.93; docs/D64_CLOCKS.md).

Three clocks are in play and a threshold is a comparison between two *readings of the same one*:

* **the database's** judges every proposal: ``now()`` and ``stage_updated_at`` are both its own, so
  nothing the host's clock says can move a proposal (shown by moving the host's clock);
* **the host's** judges every file (``mtime`` is the kernel's on this machine) and is the "now"
  of every Docker object;
* **the Docker daemon's** is where a container's ``StartedAt`` and a network's ``Created`` come
  from. Against the host's "now" a skew of ``s`` moves every Docker deadline by ``s``. So the skew
  is measured on every pass, and when it is more than ``MAX_CLOCK_SKEW_S`` -- or cannot be
  measured -- nothing that kills or removes a Docker object is asked for, and the pass says why.
"""

from __future__ import annotations

import dataclasses
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from control_plane.reconciler import config, observe, vocab
from control_plane.reconciler.model import US, ContainerObs, NetworkObs, Observation, StuckRow
from control_plane.reconciler.plan import plan
from tests.test_reconciler_config import VALID
from tests.test_reconciler_plan import NOW, TH, s
from tests.test_reconciler_plan import row as plan_row

KILL_AFTER = TH.kill_after_s(TH.b_cap_s)        # no stuck proposal: judged by the cap
LIMIT_US = TH.max_clock_skew_s * US


def overdue_tool(**kw) -> ContainerObs:
    base = dict(container_id="a" * 64, status="running", run_id="R", owner="E", is_proxy=False,
                created_us=NOW - s(KILL_AFTER + 100), started_us=NOW - s(KILL_AFTER + 10),
                finished_us=None)
    base.update(kw)
    return ContainerObs(**base)


def seen(**kw) -> Observation:
    base = dict(containers=(overdue_tool(),), run_states={"R": "running"}, host_now_us=NOW)
    base.update(kw)
    return Observation(**base)


def kinds(result) -> list[str]:
    return [a.kind for a in result.actions]


def reasons(result) -> list[str]:
    return [r.reason_code for r in result.reports]


# ---------------------------------------------------------------------------------------------
# reading the daemon's clock
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("2026-10-14T04:33:18Z", "2026-10-14T04:33:18+00:00"),
    ("2026-10-14T04:33:18.275269076Z", "2026-10-14T04:33:18.275269+00:00"),
    ("2026-10-14T04:33:18.27Z", "2026-10-14T04:33:18.270000+00:00"),
    ("2026-10-14T12:33:18.275269076+08:00", "2026-10-14T04:33:18.275269+00:00"),
    ("2026-10-13T23:33:18.5-05:00", "2026-10-14T04:33:18.500000+00:00"),
    ("2026-10-14T04:33:18.275269+00:00", "2026-10-14T04:33:18.275269+00:00"),
])
def test_the_daemons_time_is_read_in_any_zone_it_reports_in(text, expected):
    want = datetime.fromisoformat(expected)
    assert observe.parse_rfc3339_us(text) == int(want.timestamp()) * US + want.microsecond


class Daemon:
    """A Docker client whose clock is ``offset_us`` behind the host's and whose ``info`` takes
    ``rtt_us`` of the (fake) host clock."""

    def __init__(self, clock, offset_us, rtt_us=0):
        self.clock, self.offset_us, self.rtt_us = clock, offset_us, rtt_us

    def info(self):
        self.clock.now += self.rtt_us // 2
        stamp = datetime.fromtimestamp((self.clock.now - self.offset_us) / US, UTC)
        self.clock.now += self.rtt_us - self.rtt_us // 2
        return {"SystemTime": stamp.isoformat()}


class HostClock:
    def __init__(self, now=1_800_000_000 * US):
        self.now = now

    def __call__(self):
        return self.now


@pytest.mark.parametrize("offset_s", [0, 1, 4, 5, 6, 3600, -3600, -1])
def test_the_skew_is_the_hosts_clock_minus_the_daemons(offset_s):
    clock = HostClock()
    skew = observe.docker_skew_us(Daemon(clock, offset_s * US), clock)
    assert skew == offset_s * US


def test_the_reading_is_taken_at_the_middle_of_the_round_trip():
    clock = HostClock()
    assert observe.docker_skew_us(Daemon(clock, 2 * US, rtt_us=400_000), clock) == 2 * US


def test_the_error_of_the_reading_is_at_most_half_the_round_trip():
    """A daemon that stamps its reply at the very start of the call is off by half the round trip
    at most -- which is why the bound is a thousand times that on a local daemon."""
    class Early(Daemon):
        def info(self):
            stamp = datetime.fromtimestamp((self.clock.now - self.offset_us) / US, UTC)
            self.clock.now += self.rtt_us
            return {"SystemTime": stamp.isoformat()}

    clock = HostClock()
    skew = observe.docker_skew_us(Early(clock, 2 * US, rtt_us=400_000), clock)
    assert abs(skew - 2 * US) <= 200_000


@pytest.mark.parametrize("client", [
    object(),                                                       # no `info` at all
    type("C", (), {"info": lambda self: {}})(),                      # no SystemTime
    type("C", (), {"info": lambda self: {"SystemTime": "yesterday"}})(),
    type("C", (), {"info": lambda self: {"SystemTime": None}})(),
    type("C", (), {"info": lambda self: 1 / 0})(),                  # the call fails
])
def test_a_clock_the_daemon_does_not_give_is_unknown_not_zero(client):
    assert observe.docker_skew_us(client, lambda: 0) is None


# ---------------------------------------------------------------------------------------------
# what the plan does with it
# ---------------------------------------------------------------------------------------------

def test_with_the_clocks_agreeing_an_overdue_tool_container_is_asked_to_be_killed():
    result = plan(seen(docker_skew_us=0), TH)
    assert kinds(result) == [vocab.KILL_CONTAINER] and reasons(result) == []


@pytest.mark.parametrize("skew_us", [LIMIT_US, -LIMIT_US, 1, -1, LIMIT_US - 1])
def test_a_skew_up_to_the_bound_changes_nothing(skew_us):
    result = plan(seen(docker_skew_us=skew_us), TH)
    assert kinds(result) == [vocab.KILL_CONTAINER] and reasons(result) == []


@pytest.mark.parametrize("skew_us", [LIMIT_US + 1, -LIMIT_US - 1, 3600 * US, -86400 * US])
def test_a_skew_beyond_the_bound_asks_for_nothing_on_Docker_and_says_so(skew_us):
    result = plan(seen(docker_skew_us=skew_us), TH)
    assert result.actions == ()
    assert reasons(result) == [vocab.DOCKER_CLOCK_SKEWED]
    assert [(r.subject, r.subject_id) for r in result.reports] == [("result", "docker_clock")]


def test_a_skew_nobody_could_measure_is_treated_as_too_large():
    result = plan(seen(docker_skew_us=None), TH)
    assert result.actions == () and reasons(result) == [vocab.DOCKER_CLOCK_UNKNOWN]


def test_the_bound_is_the_configured_one():
    wider = dataclasses.replace(TH, max_clock_skew_s=TH.max_clock_skew_s + 10)
    over = TH.max_clock_skew_s * US + 5 * US
    assert plan(seen(docker_skew_us=over), TH).actions == ()
    assert kinds(plan(seen(docker_skew_us=over), wider)) == [vocab.KILL_CONTAINER]


def test_every_kind_of_docker_action_is_withheld_not_only_the_kill():
    proxy = overdue_tool(container_id="b" * 64, is_proxy=True, run_id="P",
                         started_us=NOW - s(TH.proxy_overdue_after_s(TH.b_cap_s) + 10))
    at_rest = overdue_tool(container_id="c" * 64, status="exited", run_id="D", started_us=0,
                           finished_us=NOW - s(TH.retention_s + 10))
    idle = NetworkObs(network_id="n" * 64, name="cyberorch-allow-0123456789ab",
                      has_allowlist_label=True, created_us=NOW - s(TH.network_idle_s * 3))
    obs = dict(containers=(overdue_tool(), proxy, at_rest), networks=(idle,),
               run_states={"R": "running", "P": "running", "D": "succeeded"})
    ok = plan(seen(docker_skew_us=0, **obs), TH)
    assert sorted(kinds(ok)) == sorted([vocab.KILL_CONTAINER, vocab.REMOVE_PROXY,
                                        vocab.REMOVE_CONTAINER, vocab.REMOVE_NETWORK])
    skewed = plan(seen(docker_skew_us=60 * US, **obs), TH)
    assert skewed.actions == () and reasons(skewed) == [vocab.DOCKER_CLOCK_SKEWED]


def test_the_reports_that_need_no_clock_are_still_made_when_the_clocks_disagree():
    no_owner = overdue_tool(container_id="d" * 64, owner=None)
    result = plan(seen(docker_skew_us=60 * US, containers=(no_owner,)), TH)
    assert sorted(reasons(result)) == sorted([vocab.NO_OWNER_LABEL, vocab.DOCKER_CLOCK_SKEWED])


def row() -> StuckRow:
    """A ``received`` proposal past the grace, by the database's clock."""
    return plan_row("received", proposal_id="P1", engagement_id="E",
                    stage_updated_us=NOW - s(TH.stage_grace_s + 1))


def test_proposals_are_judged_by_the_databases_clock_alone_whatever_the_hosts_says():
    expected = None
    for host_now in (0, NOW, NOW * 7, NOW - s(10 ** 6)):
        for skew in (0, 3600 * US, None):
            result = plan(Observation(rows=(row(),), host_now_us=host_now, docker_skew_us=skew), TH)
            moved = [(a.kind, a.reason_code, a.subject_id) for a in result.actions]
            expected = expected or moved
            assert moved == expected == [(vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE, "P1")]


def test_a_skew_does_not_hold_back_a_proposal_transition_or_a_file():
    from control_plane.reconciler.model import FileObs
    old_file = FileObs(directory="/tmp", name="cyberorch-cred-ab12_xyz", is_regular=True, uid=0,
                       mtime_us=NOW - s(TH.file_age_s() + 10), mounted_by_live_container=False)
    result = plan(Observation(rows=(row(),), files=(old_file,), host_now_us=NOW, expected_uid=0,
                              docker_skew_us=3600 * US), TH)
    assert sorted(kinds(result)) == sorted([vocab.ABANDON, vocab.UNLINK_FILE])
    assert reasons(result) == [vocab.DOCKER_CLOCK_SKEWED]


# ---------------------------------------------------------------------------------------------
# the setting
# ---------------------------------------------------------------------------------------------

def test_the_setting_is_a_key_like_the_others_and_has_no_default():
    assert "RECONCILER_MAX_CLOCK_SKEW_S" in config.KEYS
    problems = _problems({k: v for k, v in VALID.items() if k != "RECONCILER_MAX_CLOCK_SKEW_S"})
    assert any("RECONCILER_MAX_CLOCK_SKEW_S" in p and "missing" in p for p in problems)


def _problems(env):
    with pytest.raises(config.ConfigError) as caught:
        config.load(env)
    return caught.value.problems


@pytest.mark.parametrize("value", ["0", "-1", "five", "5.5", ""])
def test_it_must_be_a_positive_whole_number(value):
    assert _problems({**VALID, "RECONCILER_MAX_CLOCK_SKEW_S": value})


def test_it_is_at_most_a_quarter_of_the_kill_margin():
    margin = int(VALID["RECONCILER_KILL_MARGIN_S"])
    assert config.load({**VALID, "RECONCILER_MAX_CLOCK_SKEW_S": str(margin // 4)})
    problems = _problems({**VALID, "RECONCILER_MAX_CLOCK_SKEW_S": str(margin // 4 + 1)})
    assert any("quarter of KILL_MARGIN_S" in p for p in problems)
    # and the margin is what it is checked against, not a number of its own
    assert config.load({**VALID, "RECONCILER_KILL_MARGIN_S": "120",
                        "RECONCILER_MAX_CLOCK_SKEW_S": "30"})


# ---------------------------------------------------------------------------------------------
# on this host's own Docker daemon
# ---------------------------------------------------------------------------------------------

docker = pytest.importorskip("docker")
IMAGE = "python:3.12-slim"


@pytest.fixture(scope="module")
def client():
    try:
        c = docker.from_env()
        c.ping()
        c.images.get(IMAGE)
    except Exception:                                           # noqa: BLE001
        pytest.skip("no Docker daemon with the image")
    return c


def test_real_the_daemon_on_this_host_agrees_with_the_host_to_well_inside_the_bound(client):
    readings = [observe.docker_skew_us(client, lambda: time.time_ns() // 1000) for _ in range(5)]
    assert None not in readings
    assert max(abs(r) for r in readings) < LIMIT_US / 10, readings    # (milliseconds, in fact)


def test_real_a_host_clock_a_day_ahead_would_kill_a_container_and_the_guard_stops_it(client):
    """A container started a moment ago. By a host clock one day ahead it is a day overdue: without
    the guard (a bound as wide as the day) the plan asks for its kill; with the configured bound it
    asks for nothing and says the clocks disagree."""
    run = f"RUN-clock-{uuid.uuid4().hex[:8]}"
    box = client.containers.run(IMAGE, ["sleep", "120"], detach=True,
                                labels={"cyberorch.run_id": run, "cyberorch.owner": "E-clock"})
    try:
        box.reload()
        day = 86400 * US
        host = lambda: time.time_ns() // 1000 + day               # noqa: E731
        skew = observe.docker_skew_us(client, host)
        assert abs(skew - day) < LIMIT_US, skew
        obs = Observation(containers=(observe.container_obs(box),), run_states={run: "running"},
                          host_now_us=host(), docker_skew_us=skew)
        unguarded = dataclasses.replace(TH, max_clock_skew_s=2 * 86400)
        assert [(a.kind, a.subject_id) for a in plan(obs, unguarded).actions] == [
            (vocab.KILL_CONTAINER, box.id)]
        guarded = plan(obs, TH)
        assert guarded.actions == () and reasons(guarded) == [vocab.DOCKER_CLOCK_SKEWED]
        # and by a host clock that agrees, the same container is simply not overdue
        honest = dataclasses.replace(obs, host_now_us=time.time_ns() // 1000, docker_skew_us=0)
        assert plan(honest, TH).actions == ()
    finally:
        box.remove(force=True)


def test_a_daemon_zone_ten_hours_east_is_the_same_instant():
    clock = HostClock()
    east = timezone_east(clock, hours=10)
    assert observe.docker_skew_us(east, clock) == 0


def timezone_east(clock, hours):
    class East:
        def info(self):
            local = datetime.fromtimestamp(clock.now / US, UTC) + timedelta(hours=hours)
            return {"SystemTime": local.strftime("%Y-%m-%dT%H:%M:%S.%f") + f"+{hours:02d}:00"}
    return East()
