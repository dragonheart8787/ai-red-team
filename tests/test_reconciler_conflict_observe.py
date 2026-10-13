"""Reading the network-conflict function, and the daily cap's memory (migration 0025; 5.90).

The function is read like the others: every value is checked against the contract before the plan
sees it, and anything outside it stops the pass instead of being guessed at. The cap on removals of
one blocking network is the service's own memory (it must not be read back from the audit trail --
that is what D64-N1 refused to grant), so it is shown to be kept, to expire, and to be counted only
for removals that were carried out and verified.
"""

from __future__ import annotations

import dataclasses

import pytest

from control_plane.reconciler import emit, observe, vocab
from control_plane.reconciler.model import NO_BLOCKER, US, Action, ConflictObs
from control_plane.reconciler.observe import ObservationError
from control_plane.reconciler.outcome import DONE, FAILED, Result
from control_plane.reconciler.service import DAY_US
from tests.test_reconciler_concurrency import recon

COLUMNS = tuple(f.name for f in dataclasses.fields(ConflictObs))
GOOD = (0x0123456789AB, 2, 10 * US, 5 * US, 0, 20 * US)


class Rows:
    def __init__(self, columns=COLUMNS, *rows):
        self._columns, self._rows, self.params = columns, rows, None

    def execute(self, statement, params=None):
        self.params = params
        return self

    def keys(self):
        return self._columns

    def __iter__(self):
        return iter(self._rows)


def read(*rows, columns=COLUMNS, window=86400):
    conn = Rows(columns, *rows)
    return observe.read_network_conflicts(conn, window), conn


def test_a_good_row_is_read_with_its_window_passed_as_a_parameter():
    (c,), conn = read(GOOD, window=3600)
    assert c == ConflictObs(*GOOD) and conn.params == {"window_s": 3600}


def test_the_foreign_row_and_the_zero_hash_are_both_in_range():
    got, _ = read((NO_BLOCKER, 3, 1, 0, 0, 2), (0, 1, 1, 1, 0, 2), (2 ** 48 - 1, 1, 1, 1, 0, 2))
    assert [c.blocking_hash_n for c in got] == [NO_BLOCKER, 0, 2 ** 48 - 1]


@pytest.mark.parametrize("bad", [
    (-2, 1, 1, 1, 0, 2), (2 ** 48, 1, 1, 1, 0, 2),             # a hash outside 48 bits
    (1, -1, 1, 1, 0, 2), (1, 1, -1, 1, 0, 2), (1, 1, 1, -1, 0, 2),
    (1, 1, 1, 1, -1, 2), (1, 1, 1, 1, 0, -1),
    (1, 1.5, 1, 1, 0, 2), (1, "1", 1, 1, 0, 2), (1, None, 1, 1, 0, 2),
    (True, 1, 1, 1, 0, 2), (1, 1, 1, 1, False, 2),              # a boolean is not a count
    ("10.0.0.0/24", 1, 1, 1, 0, 2),                              # a range never comes back
])
def test_a_value_outside_the_contract_stops_the_pass(bad):
    with pytest.raises(ObservationError):
        read(bad)


def test_other_columns_stop_the_pass():
    with pytest.raises(ObservationError, match="columns"):
        read(GOOD, columns=COLUMNS[:-1])
    with pytest.raises(ObservationError, match="columns"):
        read(GOOD + ("10.0.0.0/24",), columns=(*COLUMNS, "cidr"))


def test_no_rows_is_no_conflicts():
    assert read()[0] == ()


def test_observe_reads_the_conflicts_only_when_it_is_given_a_window():
    import inspect
    src = inspect.getsource(observe.observe)
    assert "conflict_window_s" in src and "read_network_conflicts" in src


# ---------------------------------------------------------------------------------------------
# the daily cap's memory
# ---------------------------------------------------------------------------------------------

def removal(result=DONE, name="cyberorch-allow-0123456789ab", reason=vocab.RANGE_CONFLICT,
            kind=vocab.REMOVE_NETWORK, detail=None):
    return Result(Action(kind=kind, reason_code=reason, subject_id="n" * 64, name=name), result,
                  detail)


def service(clock):
    r = recon()
    r._wall_clock_us = lambda: clock[0]
    r._monotonic = lambda: clock[0] / US
    return r


def test_a_verified_removal_for_a_conflict_is_remembered_and_counted_against_the_cap():
    clock = [1_000 * US]
    r = service(clock)
    r._after([removal()])
    assert r.conflict_removals_24h(clock[0]) == {0x0123456789AB: 1}
    r._after([removal()])
    assert r.conflict_removals_24h(clock[0]) == {0x0123456789AB: 2}


@pytest.mark.parametrize("other", [
    removal(result=FAILED, detail="in_use"),                       # not carried out
    removal(reason=vocab.IDLE_SWEEP),                             # the idle sweep has no cap
    removal(kind=vocab.REMOVE_CONTAINER),
    removal(name="cyberorch-allow-lookalike"),                    # not a name that spells a number
])
def test_only_a_verified_removal_for_a_range_conflict_by_a_name_that_is_a_number_counts(
        other, monkeypatch):
    monkeypatch.setattr(emit, "emit", lambda *a, **k: None)       # a failed action writes an event
    clock = [1_000 * US]
    r = service(clock)
    r._after([other])
    assert r.conflict_removals_24h(clock[0]) == {}


def test_a_removal_is_forgotten_after_twenty_four_hours_and_not_before():
    clock = [1_000 * US]
    r = service(clock)
    r._after([removal()])
    assert r.conflict_removals_24h(clock[0] + DAY_US - 1) == {0x0123456789AB: 1}
    assert r.conflict_removals_24h(clock[0] + DAY_US + 1) == {}


def test_removals_of_different_blockers_are_counted_apart():
    clock = [1_000 * US]
    r = service(clock)
    r._after([removal(), removal(name="cyberorch-allow-ba9876543210")])
    assert r.conflict_removals_24h(clock[0]) == {0x0123456789AB: 1, 0xBA9876543210: 1}
