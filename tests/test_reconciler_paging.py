"""More than 5,000 stuck proposals: paging, a bound on a pass, and a wait that backs off
(D64 pre-deletion item 6, ACCEPTANCE 5.88).

**The problem, reproduced (E23).** ``reconciler_stuck_proposals()`` returns the *oldest* 5,000
stuck rows. The reconciler leaves some of them alone on purpose -- an ``approved`` proposal with no
approval row is *reported*, not acted on -- so when the oldest 5,000 are all like that, a proposal
behind them that does need closing is never seen, pass after pass. ``test_e23_...`` builds exactly
that (5,100 such rows and one proposal behind them that must be closed) and shows the first page
alone misses it, two pages find it, and the plan then asks for the right action.

Then the rest of the design, each part where it can fail:

* the keyset cursor: a page that does not move past the one before is an error, not a loop; a row
  seen twice because its timestamp moved while the pages were being read counts once;
* ``max_pages``: reading stops at the first page that is not full, or after that many, and says
  *truncated*;
* ``max_actions_per_pass``: a backlog is worked off in passes of bounded size, the rest planned
  again;
* the wait: doubles after a pass that was truncated or limited and did nothing, up to the
  configured cap; a pass that did something, or had no backlog, resets it.
"""

from __future__ import annotations

import os
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from control_plane.reconciler import observe, vocab
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.observe import STUCK_ROW_LIMIT, ObservationError
from control_plane.reconciler.plan import plan
from control_plane.reconciler.service import PassReport
from control_plane.state.db import engagement_scope, reconciler_reader_scope
from tests.reconciler_support import TOUCHED, _proposal, residue_world
from tests.test_reconciler_act import TH
from tests.test_reconciler_service import reconciler, state

BULK = STUCK_ROW_LIMIT + 100


def bulk_approved_without_approval(eid: str, n: int = BULK) -> str:
    """``n`` approved proposals with no approval row, the oldest in the table (1970-01-01 plus
    ``i`` seconds). The plan reports each (``approval_missing``) and acts on none. Returns the
    prefix of their ids."""
    TOUCHED.add(eid)
    prefix = f"PROP-PG{uuid.uuid4().hex[:6]}-"
    with engagement_scope(eid) as conn:
        conn.execute(text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, agent_id,
                request_idempotency_key, action, target, "authorization", discovery, decision,
                pipeline_stage, stage_detail, stage_updated_at)
            SELECT :p || lpad(g::text, 6, '0'), :e, 'agent', :p || 'k' || g, 'network.scan',
                   '{}', '{}', '{}', 'ALLOW', 'approved', NULL,
                   TIMESTAMPTZ '1970-01-01 00:00:00+00' + make_interval(secs => g)
            FROM generate_series(1, :n) g"""), {"p": prefix, "e": eid, "n": n})
    return prefix


def read(max_pages):
    with reconciler_reader_scope() as conn:
        return observe.read_stuck(conn, max_pages=max_pages)


# ---------------------------------------------------------------------------------------------
# E23: the problem
# ---------------------------------------------------------------------------------------------

def test_e23_five_thousand_rows_the_reconciler_leaves_alone_hide_one_it_must_close(engagement_id):
    prefix = bulk_approved_without_approval(engagement_id)
    behind = _proposal(engagement_id, "decided")            # 1970-01-02: behind all of the bulk
    first_page_only, truncated = read(1)
    assert truncated is True and len(first_page_only) == STUCK_ROW_LIMIT
    assert all(r.proposal_id.startswith(prefix) for r in first_page_only), \
        "the development database holds older stuck rows than this test made; clean it first"
    assert behind not in {r.proposal_id for r in first_page_only}        # the starvation

    two_pages, truncated = read(2)
    assert truncated is False
    assert behind in {r.proposal_id for r in two_pages}
    assert len({r.proposal_id for r in two_pages}) == len(two_pages)       # nothing repeated
    mine = [r for r in two_pages if r.engagement_id == engagement_id]
    assert len(mine) == BULK + 1

    obs = SimpleNamespace(rows=tuple(two_pages), run_states={}, containers=(), networks=(),
                          files=(), host_now_us=max(r.db_now_us for r in two_pages),
                          expected_uid=os.getuid(), rows_truncated=False)
    wanted = [a for a in plan(obs, TH).actions if a.subject_id == behind]
    assert [(a.kind, a.reason_code) for a in wanted] == [
        (vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION)]
    # and the 5,100 it leaves alone are reported, not acted on
    assert not [a for a in plan(obs, TH).actions if a.subject_id.startswith(prefix)]


def test_pages_come_back_in_the_functions_order_and_the_last_row_is_the_cursor(engagement_id):
    bulk_approved_without_approval(engagement_id)
    rows, _ = read(2)
    keys = [(r.stage_updated_us, r.proposal_id) for r in rows]
    assert keys == sorted(keys)
    first, _ = read(1)
    assert [r.proposal_id for r in rows][:STUCK_ROW_LIMIT] == [r.proposal_id for r in first]


# ---------------------------------------------------------------------------------------------
# the reader: pages, the cursor, duplicates
# ---------------------------------------------------------------------------------------------

def stuck_values(i: int, *, us: int | None = None, pid: str | None = None) -> tuple:
    row = {"engagement_id": "ENG-F", "proposal_id": pid or f"P-{i:06d}",
           "pipeline_stage": "approved", "stage_updated_us": us if us is not None else 1000 + i,
           "db_now_us": 10**15, "engagement_status": "active", "kill_switch_engaged": False,
           "enrolled": True, "capability_id": None, "max_duration_s": None,
           "lease_expires_us": None, "capability_revoked": None, "approval_id": None,
           "approval_valid_until_us": None, "approval_revoked": None, "run_id": None,
           "run_status": None}
    return tuple(row[c] for c in observe.STUCK_COLUMNS)


class Pages:
    """A connection that answers the first-page statement and the next-page statement from a list
    of pages, and remembers the cursors it was given."""

    def __init__(self, *pages):
        self.pages, self.cursors, self.calls = list(pages), [], 0

    def execute(self, statement, params=None):
        self.calls += 1
        if params:
            self.cursors.append((params["after_us"], params["after_id"]))
        return _Result(self.pages.pop(0) if self.pages else [])


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def keys(self):
        return observe.STUCK_COLUMNS

    def __iter__(self):
        return iter(self._rows)


def full_page(start: int):
    return [stuck_values(i) for i in range(start, start + STUCK_ROW_LIMIT)]


def test_reading_stops_at_the_first_page_that_is_not_full():
    conn = Pages(full_page(0), [stuck_values(STUCK_ROW_LIMIT)])
    rows, truncated = observe.read_stuck(conn, max_pages=10)
    assert (len(rows), truncated, conn.calls) == (STUCK_ROW_LIMIT + 1, False, 2)


def test_a_full_page_followed_by_an_empty_one_is_not_truncated():
    conn = Pages(full_page(0), [])
    rows, truncated = observe.read_stuck(conn, max_pages=10)
    assert (len(rows), truncated, conn.calls) == (STUCK_ROW_LIMIT, False, 2)


def test_reading_stops_after_max_pages_and_says_truncated():
    conn = Pages(full_page(0), full_page(STUCK_ROW_LIMIT), full_page(2 * STUCK_ROW_LIMIT))
    rows, truncated = observe.read_stuck(conn, max_pages=2)
    assert (len(rows), truncated, conn.calls) == (2 * STUCK_ROW_LIMIT, True, 2)


def test_the_next_page_starts_after_the_last_row_of_the_one_before():
    conn = Pages(full_page(0), [])
    observe.read_stuck(conn, max_pages=5)
    last = STUCK_ROW_LIMIT - 1
    assert conn.cursors == [(1000 + last, f"P-{last:06d}")]


def test_a_page_that_does_not_move_past_the_one_before_is_an_error_not_a_loop():
    same = full_page(0)
    conn = Pages(same, same, same)
    with pytest.raises(ObservationError, match="did not move"):
        observe.read_stuck(conn, max_pages=10)
    assert conn.calls == 2


def test_a_row_seen_on_two_pages_counts_once_and_the_later_reading_wins():
    first = full_page(0)
    moved = stuck_values(0, us=10**9, pid="P-000000")           # the same proposal, touched since
    conn = Pages(first, [moved])
    rows, _ = observe.read_stuck(conn, max_pages=3)
    assert len(rows) == STUCK_ROW_LIMIT
    (kept,) = [r for r in rows if r.proposal_id == "P-000000"]
    assert kept.stage_updated_us == 10**9


def test_zero_or_negative_max_pages_still_reads_one_page():
    for pages in (0, -3):
        conn = Pages([stuck_values(1)])
        assert observe.read_stuck(conn, max_pages=pages)[0][0].proposal_id == "P-000001"
        assert conn.calls == 1


# ---------------------------------------------------------------------------------------------
# the service: a bound on a pass, and the wait
# ---------------------------------------------------------------------------------------------

def th_with(**kw) -> Thresholds:
    return Thresholds(**{**TH.__dict__, **kw})


def test_a_pass_carries_out_at_most_the_configured_actions_and_the_next_does_the_rest(
        engagement_id, tmp_path):
    world = residue_world(engagement_id)
    r = reconciler(engagement_id, th=th_with(max_actions_per_pass=2), tmp_path=tmp_path)
    r.begin()
    try:
        first = r.pass_once()
        assert first.outcomes == {"done": 2} and first.limited == 3
        second = r.pass_once()
        assert second.outcomes == {"done": 2} and second.limited == 1
        third = r.pass_once()
        assert third.outcomes == {"done": 1} and third.limited == 0
        assert r.pass_once().outcomes == {}
    finally:
        r.finish("signal")
    assert all(state(engagement_id, pid)[0] in ("abandoned", "closed", "recorded")
               for pid in world.values())


def report(*, done=0, truncated=False, limited=0) -> PassReport:
    outcomes = {"done": done} if done else {}
    return PassReport(outcomes=outcomes, truncated=truncated, limited=limited)


def waits(sequence, interval=60.0, cap=900):
    r = reconciler("ENG-NONE", th=th_with(backoff_max_s=cap))
    return [r.next_wait(rep, interval) for rep in sequence]


def test_the_wait_doubles_after_a_backlog_that_got_nothing_done_up_to_the_cap():
    idle_backlog = report(truncated=True)
    assert waits([idle_backlog] * 6, cap=900) == [120, 240, 480, 900, 900, 900]


def test_a_pass_that_did_something_never_slows_down_and_resets_the_wait():
    idle_backlog, busy_backlog, clear = report(truncated=True), report(done=3, limited=4), report()
    assert waits([idle_backlog, idle_backlog, busy_backlog, idle_backlog]) == [120, 240, 60, 120]
    assert waits([idle_backlog, idle_backlog, clear, idle_backlog]) == [120, 240, 60, 120]


def test_a_limited_pass_that_did_nothing_also_backs_off():
    assert waits([report(limited=5), report(limited=5)]) == [120, 240]


def test_the_cap_never_makes_the_wait_shorter_than_the_interval():
    assert waits([report(truncated=True)] * 3, interval=60.0, cap=10) == [60, 60, 60]


def test_a_truncated_read_is_reported_by_the_pass(engagement_id, tmp_path):
    bulk_approved_without_approval(engagement_id)
    r = reconciler(engagement_id, th=th_with(max_pages=1), tmp_path=tmp_path)
    r.begin()
    try:
        # only_engagements keeps the rows; the pages are the whole table's
        report_ = r.pass_once()
    finally:
        r.finish("signal")
    assert report_.truncated is True
    r2 = reconciler(engagement_id, th=th_with(max_pages=3), tmp_path=tmp_path)
    r2.begin()
    try:
        assert r2.pass_once().truncated is False
    finally:
        r2.finish("signal")
