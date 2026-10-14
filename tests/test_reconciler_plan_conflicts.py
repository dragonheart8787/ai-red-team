"""The plan side of the network-conflict trigger (D64-N1; ACCEPTANCE 5.90).

A refused run says its range overlaps a network Docker already has. The database names that network
by the *number* its name spells (``ConflictObs.blocking_hash_n``), the plan matches it to a Docker
network of ours, and removes it only if every one of five conditions holds
(``plan._conflict_blocker``). One test per condition, each from both sides; then what is reported
and left alone; then that the plan is still pure (the same observation in another order gives the
same plan) and takes every number from its thresholds.
"""

from __future__ import annotations

import dataclasses
import random

import pytest

from control_plane.reconciler import vocab
from control_plane.reconciler.model import (
    NO_BLOCKER,
    US,
    ConflictObs,
    ContainerObs,
    NetworkObs,
    Observation,
    name_hash_n,
)
from control_plane.reconciler.plan import plan
from tests.test_reconciler_plan import NOW, TH, s, th

HASH = 0x0123456789AB
NAME = "cyberorch-allow-0123456789ab"
DB_NOW = 9_000_000 * US                        # the database's clock, apart from the host's NOW
IDLE = TH.network_conflict_min_idle_s


def net(**kw) -> NetworkObs:
    base = dict(network_id="n" * 64, name=NAME, has_allowlist_label=True, created_us=NOW - s(10))
    base.update(kw)
    return NetworkObs(**base)


def conflict(**kw) -> ConflictObs:
    base = dict(blocking_hash_n=HASH, conflicts_n=1, last_conflict_us=DB_NOW - s(5),
                last_used_us=DB_NOW - s(IDLE + 60), live_runs_n=0, db_now_us=DB_NOW)
    base.update(kw)
    return ConflictObs(**base)


def run(networks, conflicts, *, removals=None, thresholds=TH):
    return plan(Observation(networks=tuple(networks), conflicts=tuple(conflicts),
                            conflict_removals_24h=removals or {}, host_now_us=NOW), thresholds)


def removed(result):
    return [(a.kind, a.reason_code, a.subject_id, a.name) for a in result.actions]


WANTED = [(vocab.REMOVE_NETWORK, vocab.RANGE_CONFLICT, "n" * 64, NAME)]


# ---------------------------------------------------------------------------------------------
# the name is a number
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name, number", [
    ("cyberorch-allow-0123456789ab", 0x0123456789AB),
    ("cyberorch-allow-000000000000", 0),
    ("cyberorch-allow-ffffffffffff", 2 ** 48 - 1),
])
def test_a_networks_name_spells_the_number_the_database_uses(name, number):
    assert name_hash_n(name) == number


@pytest.mark.parametrize("name", [
    "cyberorch-allow-0123456789a", "cyberorch-allow-0123456789abc", "cyberorch-allow-0123456789AB",
    "cyberorch-allow-0123456789ag", "cyberorch-allow-", "cyberorch-allow-lookalike", "bridge",
    "x-cyberorch-allow-0123456789ab", "cyberorch-allow--0123456789a"])
def test_any_other_name_is_not_a_number(name):
    assert name_hash_n(name) is None


# ---------------------------------------------------------------------------------------------
# the five conditions
# ---------------------------------------------------------------------------------------------

def test_a_blocking_network_that_is_ours_idle_and_unattached_is_removed_for_the_conflict():
    assert removed(run([net()], [conflict()])) == WANTED


@pytest.mark.parametrize("kw", [
    dict(name="cyberorch-allow-lookalike", has_allowlist_label=False),
    dict(has_allowlist_label=False),                      # the name is right, the label is not
    dict(name="somebody-elses-net"),                      # the label is right, the name is not
])
def test_1_a_network_that_is_not_ours_is_never_removed_whatever_the_database_says(kw):
    result = run([net(**kw)], [conflict()])
    assert result.actions == () and result.reports == ()


def test_1_a_blocker_with_no_docker_network_of_that_name_is_nothing_to_do():
    result = run([net(name="cyberorch-allow-aaaaaaaaaaaa")], [conflict()])
    assert result.actions == () and result.reports == ()


@pytest.mark.parametrize("last_conflict_after_use_by, acts", [(-1, False), (0, False), (1, True)])
def test_2_only_a_refusal_after_the_last_use_counts(last_conflict_after_use_by, acts):
    used = DB_NOW - s(IDLE + 60)
    c = conflict(last_used_us=used, last_conflict_us=used + last_conflict_after_use_by * US)
    result = run([net()], [c])
    assert bool(result.actions) is acts
    assert result.reports == ()                          # a conflict that was overtaken is silent


def test_2_no_refusal_in_the_window_is_no_reason():
    assert run([net()], [conflict(conflicts_n=0)]).actions == ()


@pytest.mark.parametrize("idle_for, acts", [
    (IDLE - 0.000001, False), (IDLE, True), (IDLE * 10, True)])
def test_3_the_allowlist_must_have_been_unused_for_the_configured_time(idle_for, acts):
    c = conflict(last_used_us=DB_NOW - s(idle_for), last_conflict_us=DB_NOW - s(1))
    result = run([net()], [c])
    assert bool(result.actions) is acts
    if not acts:
        assert [r.reason_code for r in result.reports] == [vocab.NETWORK_CONFLICT_UNRESOLVED]
        assert [(r.subject, r.subject_id) for r in result.reports] == [("network", "n" * 64)]


def test_3_the_idle_time_is_the_configured_one_and_the_database_clock_is_the_one_used():
    c = conflict(last_used_us=DB_NOW - s(IDLE + 1))
    assert run([net()], [c]).actions
    assert not run([net()], [c], thresholds=th(network_conflict_min_idle_s=IDLE + 2)).actions
    # the host's clock is nowhere near the database's here and changes nothing
    far = Observation(networks=(net(),), conflicts=(c,), host_now_us=NOW * 7)
    assert plan(far, TH).actions and plan(
        dataclasses.replace(far, host_now_us=0), TH).actions


@pytest.mark.parametrize("live", [1, 2, 100])
def test_3_a_run_on_the_allowlist_that_is_not_over_blocks_it_however_old_the_last_one_is(live):
    c = conflict(live_runs_n=live, last_used_us=DB_NOW - s(IDLE * 100))
    result = run([net()], [c])
    assert result.actions == ()
    assert [r.reason_code for r in result.reports] == [vocab.NETWORK_CONFLICT_UNRESOLVED]


@pytest.mark.parametrize("status", ["created", "running", "paused", "restarting", "exited"])
def test_4_a_container_of_any_state_attached_keeps_the_network(status):
    attached = ContainerObs(container_id="c" * 64, status=status, run_id="R", owner="E",
                            is_proxy=False, created_us=0, started_us=None, finished_us=NOW)
    result = run([net(attached=(attached,))], [conflict()])
    assert result.actions == ()
    assert [r.reason_code for r in result.reports] == [vocab.NETWORK_CONFLICT_UNRESOLVED]


@pytest.mark.parametrize("done, acts", [(0, True), (1, True), (2, True), (3, False), (9, False)])
def test_5_a_blocking_network_is_removed_at_most_the_daily_cap_of_times(done, acts):
    result = run([net()], [conflict()], removals={HASH: done})
    assert bool(result.actions) is acts
    if not acts:
        assert [r.reason_code for r in result.reports] == [vocab.NETWORK_CONFLICT_UNRESOLVED]


def test_5_the_cap_is_the_configured_one_and_counts_each_blocker_apart():
    assert not run([net()], [conflict()], removals={HASH: 1},
                   thresholds=th(network_conflict_daily_cap=1)).actions
    assert run([net()], [conflict()], removals={HASH + 1: 50}).actions       # someone else's count


# ---------------------------------------------------------------------------------------------
# what is reported, and what is not
# ---------------------------------------------------------------------------------------------

def test_refusals_no_network_of_ours_explains_are_reported_as_foreign_and_nothing_is_removed():
    foreign = conflict(blocking_hash_n=NO_BLOCKER, conflicts_n=4, last_used_us=0, live_runs_n=0)
    result = run([net()], [foreign])
    assert result.actions == ()
    assert [(r.subject, r.subject_id, r.reason_code) for r in result.reports] == [
        ("result", "network_conflicts", vocab.NETWORK_CONFLICT_FOREIGN)]


def test_the_foreign_row_is_never_taken_for_a_network_even_if_a_name_were_all_ones():
    foreign = conflict(blocking_hash_n=NO_BLOCKER, conflicts_n=1)
    assert run([net(name="cyberorch-allow-ffffffffffff")], [foreign]).actions == ()


def test_a_foreign_row_with_no_refusal_in_it_reports_nothing():
    assert run([net()], [conflict(blocking_hash_n=NO_BLOCKER, conflicts_n=0)]).reports == ()


def test_both_a_blocker_and_foreign_refusals_are_handled_in_the_same_pass():
    result = run([net()], [conflict(), conflict(blocking_hash_n=NO_BLOCKER, conflicts_n=2)])
    assert removed(result) == WANTED
    assert [r.reason_code for r in result.reports] == [vocab.NETWORK_CONFLICT_FOREIGN]


def test_the_idle_sweep_keeps_its_own_reason_for_a_network_that_is_both_idle_and_blocking():
    old = net(created_us=NOW - s(TH.network_idle_s * 10))
    assert [a.reason_code for a in run([old], [conflict()]).actions] == [vocab.IDLE_SWEEP]


def test_no_conflict_rows_changes_nothing_in_a_plan_that_has_none_of_this():
    assert run([net()], []).actions == () and run([net()], []).reports == ()


# ---------------------------------------------------------------------------------------------
# the plan is still a pure function of what it is given
# ---------------------------------------------------------------------------------------------

def test_the_same_observation_in_another_order_gives_the_same_plan():
    nets = [net(network_id=str(i) * 64, name=f"cyberorch-allow-{i:012x}") for i in range(1, 9)]
    rows = [conflict(blocking_hash_n=i, last_used_us=DB_NOW - s(IDLE * (i % 3 + 1)),
                     live_runs_n=(i % 4 == 0)) for i in range(1, 9)]
    rows.append(conflict(blocking_hash_n=NO_BLOCKER, conflicts_n=2))
    expected = run(nets, rows)
    assert expected.actions and expected.reports
    rng = random.Random(7)
    for _ in range(20):
        rng.shuffle(nets)
        rng.shuffle(rows)
        assert run(nets, rows) == expected


def test_a_conflict_row_is_plain_data_of_integers():
    assert all(type(getattr(conflict(), f.name)) is int for f in dataclasses.fields(ConflictObs))
