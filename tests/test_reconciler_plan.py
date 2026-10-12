"""The reconciler's plan, class by class, as tables (D64 step 6b).

Each residue of docs/D64_RECONCILER_DESIGN.md §1.1 has a table: the row it is judged on, the
threshold's edge on both sides (the plan acts *at* the bound, not a microsecond before), and the
cases it must leave alone. The thresholds come from a ``Thresholds`` built here from the
design's recommended values, and every table that depends on one is run again with that threshold
changed -- a number that the plan took from anywhere but its argument would not move.

The plan is a pure function, so nothing here needs a database or a daemon.
"""

from __future__ import annotations

import dataclasses
import random

import pytest

from control_plane.reconciler import vocab
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.model import (
    US,
    Action,
    ContainerObs,
    FileObs,
    NetworkObs,
    Observation,
    Report,
    StuckRow,
)
from control_plane.reconciler.plan import EXECUTION_ORDER, plan

TH = Thresholds(
    stage_grace_s=3600, lease_grace_s=30, approval_grace_s=30, b_cap_s=1800, p_proxy_s=915,
    q_proxy_s=300, kill_margin_s=60, retention_s=86400, network_idle_s=3600,
    network_sweep_period_s=86400, verify_wait_s=10)
NOW = 5_000_000 * US                      # an arbitrary instant, in microseconds


def th(**changes) -> Thresholds:
    return dataclasses.replace(TH, **changes)


def s(seconds: float) -> int:
    return int(seconds * US)


# ---------------------------------------------------------------------------------------------
# proposals
# ---------------------------------------------------------------------------------------------

def row(stage: str, **kw) -> StuckRow:
    base = dict(
        engagement_id="ENG", proposal_id="PROP-1", pipeline_stage=stage,
        stage_updated_us=NOW - s(10), db_now_us=NOW, engagement_status="active",
        kill_switch_engaged=False, enrolled=True, capability_id=None, max_duration_s=None,
        lease_expires_us=None, capability_revoked=None, approval_id=None,
        approval_valid_until_us=None, approval_revoked=None, run_id=None, run_status=None)
    base.update(kw)
    return StuckRow(**base)


def decide(*rows: StuckRow, thresholds: Thresholds = TH):
    result = plan(Observation(rows=tuple(rows), host_now_us=NOW), thresholds)
    return result.actions, result.reports


def only(result_list):
    assert len(result_list) == 1, result_list
    return result_list[0]


def assert_move(actions, kind, reason, row_):
    action = only(actions)
    assert (action.kind, action.reason_code) == (kind, reason)
    assert action.subject_id == row_.proposal_id and action.engagement_id == row_.engagement_id
    # the compare-and-set the act half runs is on exactly what was observed
    assert action.expected_stage == row_.pipeline_stage
    assert action.planned_stage_updated_us == row_.stage_updated_us
    assert vocab.PROPOSAL_TRANSITIONS[(kind, reason)][0] == row_.pipeline_stage


GRACE = TH.stage_grace_s


@pytest.mark.parametrize("stage, kind, reason", [
    ("received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE),
    ("decided", vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION),
])
@pytest.mark.parametrize("age_s, acts", [
    (0, False), (GRACE - 1, False), (GRACE - 0.000001, False),
    (GRACE, True), (GRACE + 0.000001, True), (GRACE * 100, True),
])
def test_r6_received_and_decided_are_acted_on_at_the_grace_and_not_before(
        stage, kind, reason, age_s, acts):
    r = row(stage, stage_updated_us=NOW - s(age_s))
    actions, reports = decide(r)
    if acts:
        assert_move(actions, kind, reason, r)
    else:
        assert actions == () and reports == ()


@pytest.mark.parametrize("stage", ["received", "decided"])
def test_r6_the_grace_is_the_configured_one(stage):
    r = row(stage, stage_updated_us=NOW - s(GRACE))
    assert decide(r)[0]
    assert decide(r, thresholds=th(stage_grace_s=GRACE + 1))[0] == ()
    assert decide(r, thresholds=th(stage_grace_s=GRACE - 1))[0]


LEASE = TH.lease_grace_s


@pytest.mark.parametrize("lapsed_s, acts", [
    (-3600, False), (0, False), (LEASE - 0.000001, False),
    (LEASE, True), (LEASE + 0.000001, True), (86400, True),
])
def test_r3_a_lapsed_lease_is_closed_after_the_grace_and_not_before(lapsed_s, acts):
    r = row("capability_issued", capability_id="CAP-1", lease_expires_us=NOW - s(lapsed_s),
            max_duration_s=120, capability_revoked=False)
    actions, reports = decide(r)
    if acts:
        assert_move(actions, vocab.CLOSE, vocab.CAPABILITY_NOT_LIVE, r)
    else:
        assert actions == () and reports == ()
    # the grace is configured
    assert bool(decide(r, thresholds=th(lease_grace_s=LEASE * 2))[0]) == (lapsed_s >= LEASE * 2)


def test_r3_a_capability_issued_proposal_without_a_capability_is_reported_not_closed():
    actions, reports = decide(row("capability_issued"))
    assert actions == ()
    assert only(reports) == Report("proposal", "PROP-1", vocab.CAPABILITY_MISSING, "ENG")


def approved(**kw) -> StuckRow:
    base = dict(approval_id="APR-1", approval_valid_until_us=NOW + s(3600), approval_revoked=False)
    base.update(kw)
    return row("approved", **base)


APPROVAL_GRACE = TH.approval_grace_s


@pytest.mark.parametrize("case, kwargs, expected", [
    # --- killed: one-way, closed whether or not the scheduler serves the engagement
    ("killed_flag_enrolled", dict(kill_switch_engaged=True, enrolled=True),
     (vocab.CLOSE, vocab.ENGAGEMENT_KILLED)),
    ("killed_flag_not_enrolled", dict(kill_switch_engaged=True, enrolled=False),
     (vocab.CLOSE, vocab.ENGAGEMENT_KILLED)),
    ("killed_status_only", dict(engagement_status="killed", kill_switch_engaged=False),
     (vocab.CLOSE, vocab.ENGAGEMENT_KILLED)),
    ("killed_beats_a_valid_approval", dict(kill_switch_engaged=True, enrolled=False,
                                           approval_valid_until_us=NOW + s(99999)),
     (vocab.CLOSE, vocab.ENGAGEMENT_KILLED)),
    # --- enrolled: the scheduler resolves expiry and revocation itself (E7); we do not
    ("enrolled_expired", dict(enrolled=True, approval_valid_until_us=NOW - s(99999)), None),
    ("enrolled_revoked", dict(enrolled=True, approval_revoked=True), None),
    # --- not enrolled: expired / revoked approvals are closed
    ("unenrolled_valid", dict(enrolled=False), None),
    ("unenrolled_expired_just_inside_the_grace",
     dict(enrolled=False, approval_valid_until_us=NOW - s(APPROVAL_GRACE - 0.000001)), None),
    ("unenrolled_expired_at_the_grace",
     dict(enrolled=False, approval_valid_until_us=NOW - s(APPROVAL_GRACE)),
     (vocab.CLOSE, vocab.APPROVAL_EXPIRED)),
    ("unenrolled_expired_long_ago",
     dict(enrolled=False, approval_valid_until_us=NOW - s(86400 * 30)),
     (vocab.CLOSE, vocab.APPROVAL_EXPIRED)),
    ("unenrolled_revoked", dict(enrolled=False, approval_revoked=True),
     (vocab.CLOSE, vocab.APPROVAL_REVOKED)),
    ("unenrolled_revoked_and_expired_says_revoked",
     dict(enrolled=False, approval_revoked=True, approval_valid_until_us=NOW - s(99999)),
     (vocab.CLOSE, vocab.APPROVAL_REVOKED)),
    # --- paused is reversible: not touched for being paused (a valid approval stays)
    ("paused_unenrolled_valid", dict(enrolled=False, engagement_status="paused"), None),
    ("paused_enrolled", dict(enrolled=True, engagement_status="paused"), None),
])
def test_r4_r5_approved_rows(case, kwargs, expected):
    r = approved(**kwargs)
    actions, reports = decide(r)
    assert reports == ()
    if expected is None:
        assert actions == ()
    else:
        assert_move(actions, *expected, r)


def test_r4_the_approval_grace_is_the_configured_one():
    r = approved(enrolled=False, approval_valid_until_us=NOW - s(APPROVAL_GRACE))
    assert decide(r)[0]
    assert decide(r, thresholds=th(approval_grace_s=APPROVAL_GRACE + 1))[0] == ()


def test_r4_an_approved_proposal_with_no_approval_row_is_reported_not_closed():
    actions, reports = decide(row("approved", enrolled=False))
    assert actions == ()
    assert only(reports).reason_code == vocab.APPROVAL_MISSING


def unknown_after(budget_s: int, thresholds: Thresholds = TH) -> int:
    return min(budget_s, thresholds.b_cap_s) + thresholds.p_proxy_s + thresholds.q_proxy_s


@pytest.mark.parametrize("budget, over", [
    (1, 0), (120, 0), (600, 0), (1800, 0), (1801, 0), (99999999, 0),
    (120, 1), (1800, 1)])
def test_r1_a_dispatch_is_unknown_at_budget_plus_p_plus_q_capped(budget, over):
    bound = unknown_after(budget)
    for offset, acts in ((-0.000001, False), (0, True), (over, True)):
        r = row("dispatching", capability_id="CAP-1", max_duration_s=budget, run_id="RUN-1",
                stage_updated_us=NOW - s(bound + offset))
        actions, reports = decide(r)
        assert reports == ()
        if acts:
            assert_move(actions, vocab.MARK_UNKNOWN_OUTCOME, vocab.UNKNOWN_OUTCOME, r)
            assert only(actions).run_id == "RUN-1"
        else:
            assert actions == ()


def test_r1_a_budget_above_the_cap_is_judged_by_the_cap():
    r = row("dispatching", capability_id="CAP-1", max_duration_s=86400,
            stage_updated_us=NOW - s(unknown_after(1800)))
    assert decide(r)[0], "the bound used the uncapped budget"
    assert decide(r, thresholds=th(b_cap_s=3600))[0] == ()      # and the cap is the configured one


@pytest.mark.parametrize("name, changes", [
    ("p", dict(p_proxy_s=TH.p_proxy_s + 1)), ("q", dict(q_proxy_s=TH.q_proxy_s + 1)),
    ("cap", dict(b_cap_s=TH.b_cap_s + 1))])
def test_r1_every_term_of_the_bound_is_the_configured_one(name, changes):
    r = row("dispatching", capability_id="CAP-1", max_duration_s=99999,
            stage_updated_us=NOW - s(unknown_after(99999)))
    assert decide(r)[0]
    assert decide(r, thresholds=th(**changes))[0] == ()


def test_r1_an_unreadable_budget_or_no_capability_is_reported_and_nothing_is_done():
    old = NOW - s(10 ** 7)
    unreadable = row("dispatching", capability_id="CAP-1", max_duration_s=None,
                     stage_updated_us=old, proposal_id="P-unreadable")
    missing = row("dispatching", capability_id=None, stage_updated_us=old, proposal_id="P-missing")
    actions, reports = decide(unreadable, missing)
    assert actions == ()
    assert {(r.subject_id, r.reason_code) for r in reports} == {
        ("P-unreadable", vocab.BUDGET_UNREADABLE), ("P-missing", vocab.CAPABILITY_MISSING)}


def test_a_stage_the_reconciler_does_not_handle_is_reported():
    actions, reports = decide(row("awaiting_approval"))
    assert actions == () and only(reports).reason_code == vocab.UNEXPECTED_STATE


def test_every_proposal_action_names_a_transition_the_vocabulary_knows():
    rows = [row("received", stage_updated_us=0),
            row("decided", stage_updated_us=0, proposal_id="B"),
            approved(kill_switch_engaged=True, proposal_id="C"),
            row("capability_issued", capability_id="X", lease_expires_us=0, proposal_id="D"),
            row("dispatching", capability_id="X", max_duration_s=1, stage_updated_us=0,
                proposal_id="E")]
    actions, _ = decide(*rows)
    assert len(actions) == 5
    for a in actions:
        assert (a.kind, a.reason_code) in vocab.PROPOSAL_TRANSITIONS


# ---------------------------------------------------------------------------------------------
# containers and proxies
# ---------------------------------------------------------------------------------------------

def container(**kw) -> ContainerObs:
    base = dict(container_id="c" * 64, status="running", run_id="RUN-1", owner="ENG",
                is_proxy=False, created_us=NOW - s(10), started_us=NOW - s(5), finished_us=None)
    base.update(kw)
    return ContainerObs(**base)


def observe(*, rows=(), containers=(), run_states=None, **kw) -> Observation:
    return Observation(rows=tuple(rows), containers=tuple(containers),
                       run_states=dict(run_states or {}), host_now_us=NOW, **kw)


def dispatching_row(budget: int | None = 120, **kw) -> StuckRow:
    return row("dispatching", capability_id="CAP-1", max_duration_s=budget, run_id="RUN-1", **kw)


KILL = TH.kill_margin_s


@pytest.mark.parametrize("budget", [1, 120, 1800, 5000])
def test_r2_a_running_container_is_killed_at_started_plus_budget_plus_margin(budget):
    bound = min(budget, TH.b_cap_s) + KILL
    for offset, acts in ((-0.000001, False), (0, True), (1, True)):
        c = container(started_us=NOW - s(bound + offset))
        result = plan(observe(rows=[dispatching_row(budget)], containers=[c],
                              run_states={"RUN-1": "running"}), TH)
        if acts:
            a = only(result.actions)
            assert (a.kind, a.reason_code, a.subject_id) == (
                vocab.KILL_CONTAINER, vocab.OVERRAN_DEADLINE, c.container_id)
            assert (a.expected_owner, a.engagement_id, a.run_id) == ("ENG", "ENG", "RUN-1")
        else:
            assert result.actions == ()


def test_r2_the_margin_and_the_cap_are_the_configured_ones():
    c = container(started_us=NOW - s(120 + KILL))
    o = observe(rows=[dispatching_row(120)], containers=[c], run_states={"RUN-1": "running"})
    assert plan(o, TH).actions
    assert plan(o, th(kill_margin_s=KILL + 1)).actions == ()
    far = container(started_us=NOW - s(1800 + KILL))
    o = observe(rows=[dispatching_row(99999)], containers=[far], run_states={"RUN-1": "running"})
    assert plan(o, TH).actions and plan(o, th(b_cap_s=1801)).actions == ()


@pytest.mark.parametrize("status", ["running", "paused", "restarting"])
def test_r2_every_live_state_is_judged(status):
    c = container(status=status, started_us=NOW - s(10 ** 6))
    o = observe(containers=[c], run_states={"RUN-1": "running"})
    assert only(plan(o, TH).actions).kind == vocab.KILL_CONTAINER


def test_r2_a_container_whose_proposal_is_no_longer_stuck_is_judged_by_the_cap():
    # run finished / proposal moved on: no stuck row gives a budget, so the cap bounds it
    for status in ("running", "unknown_outcome", "succeeded", "failed"):
        young = container(started_us=NOW - s(TH.b_cap_s + KILL - 1))
        old = container(started_us=NOW - s(TH.b_cap_s + KILL))
        assert plan(observe(containers=[young], run_states={"RUN-1": status}), TH).actions == ()
        killed = plan(observe(containers=[old], run_states={"RUN-1": status}), TH).actions
        assert only(killed).kind == vocab.KILL_CONTAINER


def test_r2_nothing_is_killed_on_a_budget_that_cannot_be_read_or_a_run_nobody_knows():
    old = container(started_us=NOW - s(10 ** 7))
    unreadable = plan(observe(rows=[dispatching_row(None)], containers=[old],
                              run_states={"RUN-1": "running"}), TH)
    assert unreadable.actions == ()
    assert ("container", vocab.BUDGET_UNREADABLE) in {(r.subject, r.reason_code)
                                                      for r in unreadable.reports}
    unknown = plan(observe(containers=[old], run_states={}), TH)       # absent from run_states
    assert unknown.actions == ()
    assert only(unknown.reports).reason_code == vocab.RUN_UNKNOWN


@pytest.mark.parametrize("kw, reason", [
    (dict(owner=None), vocab.NO_OWNER_LABEL),
    (dict(run_id=None), vocab.NO_RUN_ID_LABEL),
    (dict(status="dead"), vocab.UNEXPECTED_STATE),
    (dict(status="removing"), vocab.UNEXPECTED_STATE),
    (dict(started_us=None), vocab.UNEXPECTED_STATE),
])
def test_a_container_that_is_not_ours_to_judge_is_reported_and_never_touched(kw, reason):
    for proxy in (False, True):
        c = container(is_proxy=proxy, created_us=0, **kw)
        result = plan(observe(containers=[c], run_states={"RUN-1": "running"}), TH)
        assert result.actions == (), (kw, proxy)
        assert only(result.reports).reason_code == reason


RETENTION = TH.retention_s


@pytest.mark.parametrize("status, finished, created", [
    ("exited", True, False), ("created", False, True)])
@pytest.mark.parametrize("run_state, reason", [
    ("succeeded", vocab.RUN_FINISHED), ("failed", vocab.RUN_FINISHED),
    ("unknown_outcome", vocab.RUN_FINISHED), (None, vocab.NO_RUN_ROW_PAST_GRACE)])
def test_r2_a_container_at_rest_is_removed_after_the_retention_and_not_before(
        status, finished, created, run_state, reason):
    states = {} if run_state is None else {"RUN-1": run_state}
    for offset, acts in ((-0.000001, False), (0, True), (1, True)):
        at = NOW - s(RETENTION + offset)
        c = container(status=status, started_us=at if finished else None,
                      finished_us=at if finished else None,
                      created_us=at if created else NOW - s(10 ** 7))
        result = plan(observe(containers=[c], run_states=states), TH)
        if acts:
            a = only(result.actions)
            assert (a.kind, a.reason_code) == (vocab.REMOVE_CONTAINER, reason)
            assert a.subject_id == c.container_id and a.expected_owner == "ENG"
        else:
            assert result.actions == ()
    assert plan(observe(containers=[container(status=status, finished_us=NOW - s(RETENTION),
                                              created_us=NOW - s(RETENTION))],
                        run_states=states), th(retention_s=RETENTION + 1)).actions == ()


@pytest.mark.parametrize("run_state", ["queued", "dispatching", "running"])
def test_r2_a_container_at_rest_whose_run_may_still_be_recording_is_kept(run_state):
    c = container(status="exited", finished_us=NOW - s(10 ** 7), created_us=0)
    assert plan(observe(containers=[c], run_states={"RUN-1": run_state}), TH).actions == ()


def test_r2_the_corpse_is_kept_and_a_running_container_is_never_removed_in_the_same_breath():
    running = container(container_id="a" * 64, started_us=NOW - s(10 ** 7))
    result = plan(observe(containers=[running], run_states={"RUN-1": "succeeded"}), TH)
    assert [a.kind for a in result.actions] == [vocab.KILL_CONTAINER]


def proxy(**kw) -> ContainerObs:
    kw.setdefault("container_id", "p" * 64)
    return container(is_proxy=True, **kw)


@pytest.mark.parametrize("run_state", ["succeeded", "failed", "unknown_outcome"])
@pytest.mark.parametrize("status", ["running", "created", "exited"])
def test_r7_the_proxy_of_a_finished_run_is_removed(run_state, status):
    c = proxy(status=status, started_us=NOW - s(1))
    a = only(plan(observe(containers=[c], run_states={"RUN-1": run_state}), TH).actions)
    assert (a.kind, a.reason_code, a.subject_id) == (
        vocab.REMOVE_PROXY, vocab.OWNER_RUN_ENDED, "p" * 64)


@pytest.mark.parametrize("budget", [120, 1800, 9999])
def test_r7_a_live_proxy_is_overdue_after_started_plus_budget_margin_and_p(budget):
    bound = min(budget, TH.b_cap_s) + KILL + TH.p_proxy_s
    for offset, acts in ((-0.000001, False), (0, True)):
        c = proxy(started_us=NOW - s(bound + offset))
        result = plan(observe(rows=[dispatching_row(budget)], containers=[c],
                              run_states={"RUN-1": "running"}), TH)
        if acts:
            a = only(result.actions)
            assert (a.kind, a.reason_code) == (vocab.REMOVE_PROXY, vocab.OVERRAN_DEADLINE)
        else:
            assert result.actions == ()
    c = proxy(started_us=NOW - s(bound))
    o = observe(rows=[dispatching_row(budget)], containers=[c], run_states={"RUN-1": "running"})
    assert plan(o, th(p_proxy_s=TH.p_proxy_s + 1)).actions == ()


def test_r7_a_proxy_of_a_run_nobody_knows_is_reported_and_one_not_yet_started_is_left():
    old = proxy(started_us=NOW - s(10 ** 7))
    result = plan(observe(containers=[old], run_states={}), TH)
    assert result.actions == () and only(result.reports).reason_code == vocab.RUN_UNKNOWN
    waiting = proxy(status="created", started_us=None)
    assert plan(observe(containers=[waiting], run_states={"RUN-1": "running"}), TH).actions == ()


# ---------------------------------------------------------------------------------------------
# networks
# ---------------------------------------------------------------------------------------------

IDLE = TH.network_idle_s


def network(**kw) -> NetworkObs:
    base = dict(network_id="n" * 64, name="cyberorch-allow-0123456789ab", has_allowlist_label=True,
                created_us=NOW - s(10 ** 6))
    base.update(kw)
    return NetworkObs(**base)


@pytest.mark.parametrize("idle_for, acts", [
    (IDLE - 0.000001, False), (IDLE, True), (10 ** 6, True)])
def test_r8_an_idle_network_is_removed_after_the_idle_time_and_not_before(idle_for, acts):
    n = network(created_us=NOW - s(idle_for))
    result = plan(observe(), TH)
    assert result.actions == ()
    result = plan(Observation(networks=(n,), host_now_us=NOW), TH)
    if acts:
        a = only(result.actions)
        assert (a.kind, a.reason_code, a.subject_id, a.name) == (
            vocab.REMOVE_NETWORK, vocab.IDLE_SWEEP, "n" * 64, n.name)
    else:
        assert result.actions == ()
    assert bool(plan(Observation(networks=(n,), host_now_us=NOW),
                     th(network_idle_s=IDLE + 1)).actions) is (idle_for >= IDLE + 1)


def test_r8_the_observers_memory_of_when_it_first_saw_the_network_idle_counts():
    n = network(created_us=NOW - s(10 ** 6), idle_seen_since_us=NOW - s(IDLE - 1))
    assert plan(Observation(networks=(n,), host_now_us=NOW), TH).actions == ()
    n = network(created_us=NOW - s(10 ** 6), idle_seen_since_us=NOW - s(IDLE))
    assert plan(Observation(networks=(n,), host_now_us=NOW), TH).actions


@pytest.mark.parametrize("status", ["created", "running", "paused", "restarting", "exited"])
def test_r8_a_container_of_any_state_attached_keeps_the_network(status):
    c = container(status=status, finished_us=NOW - s(10 ** 7), created_us=0)
    n = network(attached=(c,))
    assert plan(Observation(networks=(n,), host_now_us=NOW), TH).actions == ()


@pytest.mark.parametrize("kw", [
    dict(name="cyberorch-allow-lookalike", has_allowlist_label=False),      # prefix, no label
    dict(name="somebody-elses-net", has_allowlist_label=True),               # label, no prefix
    dict(name="bridge", has_allowlist_label=False),
])
def test_r8_a_network_that_is_not_ours_is_never_touched(kw):
    n = network(created_us=0, **kw)
    result = plan(Observation(networks=(n,), host_now_us=NOW), TH)
    assert result.actions == () and result.reports == ()


# ---------------------------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------------------------

AGE = TH.b_cap_s + TH.p_proxy_s + TH.q_proxy_s


def file(**kw) -> FileObs:
    base = dict(directory="/tmp", name="cyberorch-cred-ab12_xyz", is_regular=True, uid=1000,
                mtime_us=NOW - s(10 ** 6), mounted_by_live_container=False)
    base.update(kw)
    return FileObs(**base)


def run_files(*files, thresholds=TH):
    return plan(Observation(files=tuple(files), host_now_us=NOW, expected_uid=1000), thresholds)


@pytest.mark.parametrize("name, kind", [
    ("cyberorch-cred-ab12_xyz", "credential_mount"),
    ("cyberorch-tls-ab12_xyz.pem", "tls_leaf")])
def test_r9_a_file_is_removed_when_unmounted_and_older_than_cap_plus_p_plus_q(name, kind):
    for offset, acts in ((-0.000001, False), (0, True), (1, True)):
        result = run_files(file(name=name, mtime_us=NOW - s(AGE + offset)))
        if acts:
            a = only(result.actions)
            assert (a.kind, a.reason_code, a.name, a.directory) == (
                vocab.UNLINK_FILE, kind, name, "/tmp")
        else:
            assert result.actions == () and result.reports == ()
    young_for_bigger_cap = run_files(file(name=name, mtime_us=NOW - s(AGE)),
                                     thresholds=th(b_cap_s=TH.b_cap_s + 1))
    assert young_for_bigger_cap.actions == ()


def test_r9_neither_condition_alone_is_enough():
    mounted_and_old = file(mounted_by_live_container=True, mtime_us=0)
    assert run_files(mounted_and_old).actions == ()
    unmounted_and_young = file(mtime_us=NOW - s(1))
    assert run_files(unmounted_and_young).actions == ()


@pytest.mark.parametrize("kw, reason", [
    (dict(is_regular=False), vocab.NOT_A_REGULAR_FILE),            # a symlink, a directory, a fifo
    (dict(uid=0), vocab.FOREIGN_OWNER),
    (dict(uid=1001), vocab.FOREIGN_OWNER),
    (dict(name="cyberorch-cred-"), vocab.NAME_MISMATCH),
    (dict(name="cyberorch-cred-ab12_xyz.pem"), vocab.NAME_MISMATCH),
    (dict(name="cyberorch-cred-AB12_XYZ"), vocab.NAME_MISMATCH),
    (dict(name="cyberorch-cred-ab12_xy"), vocab.NAME_MISMATCH),
    (dict(name="cyberorch-tls-ab12_xyz"), vocab.NAME_MISMATCH),
    (dict(name="cyberorch-tls-ab12_xyz.pem.bak"), vocab.NAME_MISMATCH),
    (dict(name="cyberorch-cred-../etc/pw"), vocab.NAME_MISMATCH),
    (dict(name="cyberorch-cred-ab12_xyz\n"), vocab.NAME_MISMATCH),
])
def test_r9_what_is_not_a_regular_file_of_ours_with_its_name_is_reported_not_removed(kw, reason):
    result = run_files(file(mtime_us=0, **kw))
    assert result.actions == ()
    assert only(result.reports).reason_code == reason


# ---------------------------------------------------------------------------------------------
# the whole plan
# ---------------------------------------------------------------------------------------------

def busy() -> Observation:
    rows = [row("received", stage_updated_us=0, proposal_id="P-a"),
            row("decided", stage_updated_us=0, proposal_id="P-b"),
            approved(kill_switch_engaged=True, proposal_id="P-c"),
            row("capability_issued", capability_id="C", lease_expires_us=0, proposal_id="P-d"),
            dispatching_row(120, stage_updated_us=0, proposal_id="P-e"),
            row("dispatching", capability_id="C", max_duration_s=None, proposal_id="P-f"),
            row("approved", enrolled=False, proposal_id="P-g")]
    containers = [container(container_id="k" * 64, started_us=0),
                  container(container_id="r" * 64, status="exited", finished_us=0, run_id="RUN-2"),
                  proxy(status="running", run_id="RUN-2", container_id="x" * 64, started_us=1),
                  container(container_id="o" * 64, owner=None)]
    return Observation(
        rows=tuple(rows), containers=tuple(containers),
        run_states={"RUN-1": "running", "RUN-2": "succeeded"},
        networks=(network(),), files=(file(name="cyberorch-tls-ab12_xyz.pem", mtime_us=0),),
        host_now_us=NOW, expected_uid=1000, rows_truncated=True)


def test_the_plan_is_in_the_execution_order_kills_first_files_last():
    result = plan(busy(), TH)
    kinds = [a.kind for a in result.actions]
    assert kinds == sorted(kinds, key=EXECUTION_ORDER.index)
    assert kinds[0] == vocab.KILL_CONTAINER and kinds[-1] == vocab.UNLINK_FILE
    assert set(EXECUTION_ORDER) == set(vocab.ACTION_KINDS)
    assert vocab.REMOVE_NETWORK in kinds and vocab.REMOVE_PROXY in kinds


def test_the_plan_does_not_depend_on_the_order_things_were_read_in():
    obs = busy()
    expected = plan(obs, TH)
    rng = random.Random(7)
    for _ in range(25):
        shuffled = dataclasses.replace(
            obs, rows=tuple(rng.sample(obs.rows, len(obs.rows))),
            containers=tuple(rng.sample(obs.containers, len(obs.containers))))
        assert plan(shuffled, TH) == expected


def test_the_plan_is_repeatable_and_leaves_its_input_alone():
    obs = busy()
    before = dataclasses.replace(obs)
    assert plan(obs, TH) == plan(obs, TH)
    assert obs == before


def test_nothing_is_planned_twice_and_nothing_acts_on_a_row_it_also_reports():
    result = plan(busy(), TH)
    keys = [(a.kind, a.subject_id) for a in result.actions]
    assert len(keys) == len(set(keys))
    acted = {a.subject_id for a in result.actions}
    assert not [r for r in result.reports if r.subject_id in acted]


def test_a_full_page_of_stuck_rows_is_reported_as_truncated():
    result = plan(busy(), TH)
    assert Report("result", "stuck_proposals", vocab.RESULT_TRUNCATED) in result.reports
    quiet = plan(dataclasses.replace(busy(), rows_truncated=False), TH)
    assert Report("result", "stuck_proposals", vocab.RESULT_TRUNCATED) not in quiet.reports


def test_an_empty_observation_plans_nothing():
    result = plan(Observation(host_now_us=NOW), TH)
    assert result.actions == () and result.reports == ()


def test_every_action_names_a_kind_and_a_reason_of_the_closed_vocabulary():
    for a in plan(busy(), TH).actions:
        assert a.kind in vocab.ACTION_KINDS
        assert a.reason_code in vocab.REASONS[a.kind], a
    for r in plan(busy(), TH).reports:
        assert r.reason_code in vocab.REPORT_REASONS and r.subject in vocab.SUBJECTS


def test_an_action_is_plain_data():
    from control_plane.reconciler import model
    allowed = {"str", "int", "None"}
    for cls in (model.Action, model.Report):
        for f in dataclasses.fields(cls):
            parts = {p.strip() for p in str(f.type).replace("'", "").split("|")}
            assert parts <= allowed, (cls.__name__, f.name, f.type)
    assert isinstance(plan(busy(), TH).actions[0], Action)
