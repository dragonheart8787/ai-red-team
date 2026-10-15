"""The soak's checks can fail (D66): each pure part of ``scripts/soak/checks.py`` is shown a
series it must refuse and one it must accept.

A check that has never been seen to fail proves nothing about a four-hour run; these are the ones
that need no database, no Docker and no hours.
"""

from __future__ import annotations

import random

from scripts.soak import audit_pairs, checks, faults, report, worker

WINDOW = 900.0


def series(*floors_per_window: float, per_window: int = 10, noise: float = 0.0, seed: int = 1):
    """Samples one a minute, whose smallest value in window ``i`` is ``floors_per_window[i]`` and
    which go up and down above it by up to ``noise``."""
    rng = random.Random(seed)
    out = []
    for i, floor in enumerate(floors_per_window):
        for j in range(per_window):
            ts = i * WINDOW + j * (WINDOW / per_window)
            out.append((ts, floor + (rng.uniform(0, noise) if j else 0.0)))
    return out


def test_a_floor_that_rises_three_windows_in_a_row_is_a_leak():
    rising, floors = checks.rising_floor(series(0, 1, 2, 3), WINDOW)
    assert rising and floors == [0, 1, 2, 3]


def test_a_floor_that_rises_and_noise_above_it_is_still_a_leak():
    assert checks.rising_floor(series(2, 3, 4, 5, noise=9), WINDOW)[0]


def test_a_count_that_goes_up_and_down_with_the_traffic_is_not():
    assert not checks.rising_floor(series(0, 0, 0, 0, noise=9), WINDOW)[0]
    assert not checks.rising_floor(series(3, 1, 4, 2, noise=5), WINDOW)[0]


def test_a_floor_that_rose_once_and_then_stood_still_is_not():
    assert not checks.rising_floor(series(0, 5, 5, 5), WINDOW)[0]


def test_two_rises_are_not_enough_and_a_long_series_looks_at_its_end():
    assert not checks.rising_floor(series(0, 1, 2), WINDOW)[0]                 # too short to say
    assert not checks.rising_floor(series(0, 1, 2, 3, 3), WINDOW)[0]           # it levelled off
    assert checks.rising_floor(series(9, 0, 1, 2, 3), WINDOW)[0]               # and rose again


def test_an_empty_series_has_no_floor():
    assert checks.rising_floor([], WINDOW) == (False, [])


def create(container: str, run: str, **more) -> dict:
    return {"action": "create", "id": container, "run_id": run, "owner": "E", "proxy": False,
            **more}


def test_one_container_per_run_is_clean():
    assert checks.duplicate_creates([create("c1", "RUN-1"), create("c2", "RUN-2")],
                                    {"RUN-1": "P1", "RUN-2": "P2"}) == {}


def test_two_containers_for_one_run_are_found():
    found = checks.duplicate_creates([create("c1", "RUN-1"), create("c2", "RUN-1")])
    assert found == {"run_with_several_containers": ["RUN-1"]}


def test_two_runs_of_one_proposal_each_with_a_container_are_found():
    found = checks.duplicate_creates([create("c1", "RUN-1"), create("c2", "RUN-2")],
                                     {"RUN-1": "P1", "RUN-2": "P1"})
    assert found == {"proposal_with_several_containers": ["P1"]}


def test_a_proxy_beside_its_tool_container_is_not_a_second_run():
    events = [create("c1", "RUN-1"), create("p1", "RUN-1", proxy=True),
              {"action": "start", "id": "c1", "run_id": "RUN-1", "owner": "E", "proxy": False}]
    assert checks.duplicate_creates(events, {"RUN-1": "P1"}) == {}


def test_the_same_container_reported_twice_is_one_container():
    assert checks.duplicate_creates([create("c1", "RUN-1"), create("c1", "RUN-1")]) == {}


def sample(ts, *, containers=0, pid=11, conns=2, backends=5, idle=0):
    return {"ts": ts, "docker": {"tools": {"running": containers, "paused": 0, "exited": 0,
                                           "other": 0},
                                 "proxies": {"running": 0, "paused": 0, "exited": 0, "other": 0},
                                 "networks": 3, "files": 0, "evidence_files": 0},
            "procs": {"scheduler": {"pid": pid, "pg_connections": conns, "rss_kb": 1, "fds": 1,
                                    "threads": 1}},
            "pg": {"total": backends, "idle_in_transaction_max_age_s": idle, "by_role": {}}}


def test_residue_that_climbs_fails_and_one_that_returns_to_zero_passes():
    climbing = [sample(w * WINDOW + m * 60, containers=w + (m % 3)) for w in range(5)
                for m in range(15)]
    assert not checks.residue_does_not_grow(climbing, WINDOW).ok
    flat = [sample(w * WINDOW + m * 60, containers=m % 4) for w in range(5) for m in range(15)]
    assert checks.residue_does_not_grow(flat, WINDOW).ok


def test_a_process_whose_connections_climb_fails_and_a_replaced_one_does_not():
    leaking = [sample(w * WINDOW + m * 60, conns=2 + w) for w in range(5) for m in range(15)]
    assert not checks.no_connection_leak(leaking, WINDOW).ok
    # restarted every window: each incarnation's own floor is flat, whatever the sum does
    restarted = [sample(w * WINDOW + m * 60, pid=100 + w, conns=2) for w in range(6)
                 for m in range(15)]
    assert checks.no_connection_leak(restarted, WINDOW).ok


def test_a_transaction_left_open_for_over_a_minute_fails():
    ok = [sample(i * 60.0, idle=30) for i in range(5)]
    bad = ok + [sample(400.0, idle=61)]
    assert checks.no_connection_leak(ok, WINDOW).ok
    assert not checks.no_connection_leak(bad, WINDOW).ok


def test_the_fault_bag_draws_every_kind_once_before_any_twice():
    bag = faults.Bag(random.Random(3))
    for _round in range(3):
        assert sorted(bag.draw() for _ in faults.KINDS) == sorted(faults.KINDS)


def test_the_worker_retries_half_of_the_requests_a_kill_interrupted_and_always_the_same_half():
    keys = [f"soak-{i:04d}" for i in range(400)]
    chosen = [k for k in keys if worker.retried_after_a_crash(k)]
    assert 150 < len(chosen) < 250
    assert chosen == [k for k in keys if worker.retried_after_a_crash(k)]


def test_the_kinds_of_request_follow_their_weights():
    rng = random.Random(5)
    counts = {"allow": 0, "human": 0, "deny": 0}
    for _ in range(5000):
        counts[worker.pick_kind(rng)] += 1
    assert 0.55 < counts["allow"] / 5000 < 0.65
    assert 0.25 < counts["human"] / 5000 < 0.35
    assert 0.07 < counts["deny"] / 5000 < 0.13


def test_the_slope_of_a_flat_series_is_zero_and_of_a_growing_one_is_the_growth():
    assert report.slope_per_hour([(0, 5), (60, 5), (120, 5)]) == 0
    slope = report.slope_per_hour([(0, 0), (1800, 10), (3600, 20)])
    assert abs(slope - 20) < 1e-6
    assert report.slope_per_hour([(0, 1)]) is None


WINDOWS = [{"kind": "kill9_control_plane", "began": 1000.0, "ended": 1002.0,
            "began_at": "t1000"},
           {"kind": "kill9_reconciler", "began": 5000.0, "ended": 5001.0, "began_at": "t5000"}]


def test_a_state_row_with_no_audit_event_is_never_allowed_even_inside_a_fault_window():
    failures, allowed = audit_pairs.classify([("missing", "PROP-1", 0, 0.0)], True, WINDOWS)
    assert failures and not allowed


def test_an_audit_event_ahead_of_its_state_is_allowed_only_inside_a_killer_fault_window():
    inside = ("extra", "PROP-1", 1, 1100.0)                       # 100 s after the kill
    outside = ("extra", "PROP-2", 1, 2000.0)
    windows = [w for w in WINDOWS if w["kind"] in audit_pairs.KILLERS]
    failures, allowed = audit_pairs.classify([inside, outside], True, windows)
    assert [a.split(":")[0] for a in allowed] == ["PROP-1"]
    assert [f.split(":")[0] for f in failures] == ["PROP-2"]


def test_a_second_event_for_one_subject_is_the_same_kind_of_thing():
    failures, allowed = audit_pairs.classify([("duplicate", "PROP-1", 2, 1100.0),
                                              ("duplicate", "PROP-2", 2, 9000.0)], True,
                                             [WINDOWS[0]])
    assert len(allowed) == 1 and len(failures) == 1


def test_the_reconcilers_proposal_events_have_no_window():
    failures, allowed = audit_pairs.classify([("extra", "PROP-1", 1, 1100.0)], False, [WINDOWS[0]])
    assert failures and not allowed


def test_the_window_ends_five_minutes_after_the_fault_does():
    assert audit_pairs.explained_by(1002.0 + 299, WINDOWS[:1])
    assert not audit_pairs.explained_by(1002.0 + 301, WINDOWS[:1])
    assert not audit_pairs.explained_by(990.0, WINDOWS[:1])          # before it began


def test_a_reconciler_kill_does_not_explain_an_audit_event():
    killers = [w for w in WINDOWS if w["kind"] in audit_pairs.KILLERS]
    assert [w["kind"] for w in killers] == ["kill9_control_plane"]
