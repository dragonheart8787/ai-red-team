"""Q1 per action class (D68 DP-15): the numbers of the admission and exit rules, as a table."""

from __future__ import annotations

import pytest

from control_plane.plan_fit import classes as c


def test_wilson_upper_is_the_wilson_bound_and_not_the_rule_of_three():
    # k = 0: z^2 / (n + z^2)
    assert c.wilson_upper(0, 40) == pytest.approx(3.8416 / 43.8416, abs=1e-3)
    assert c.wilson_upper(0, 40) > 3 / 40 + 0.01            # the rule of three would say 7.5%
    assert c.wilson_upper(6, 40) == pytest.approx(0.291, abs=0.005)
    assert c.wilson_upper(1, 40) == pytest.approx(0.129, abs=0.002)
    assert c.wilson_upper(40, 40) == 1.0
    assert c.wilson_upper(0, 0) == 1.0
    # monotone in k, and in n the other way
    assert c.wilson_upper(1, 100) < c.wilson_upper(2, 100) < c.wilson_upper(5, 100)
    assert c.wilson_upper(0, 200) < c.wilson_upper(0, 100)


@pytest.mark.parametrize("n,failed,recommend", [
    (39, 0, False),          # one short of the 40 judgements, though nothing failed
    (40, 0, True),           # 40 and nothing failed: upper bound 8.8%
    (40, 1, True),           # 12.9%
    (40, 2, False),          # 16.5%: above 15%
    (100, 5, True),          # 11.2%
    (100, 9, False),         # 16.2%
    (200, 1, True),
    (0, 0, False),
])
def test_admission_needs_forty_judgements_and_an_upper_bound_of_fifteen_percent(
        n, failed, recommend):
    got = c.admission("code.secrets", n, failed)
    assert got.recommend is recommend
    assert (got.n, got.failed) == (n, failed)
    assert got.upper == pytest.approx(c.wilson_upper(failed, n))
    assert got.reason


def test_admission_reasons_say_which_condition_failed():
    assert "40 needed" in c.admission("a.b", 10, 0).reason
    assert "above 15%" in c.admission("a.b", 100, 20).reason
    assert "<= 15%" in c.admission("a.b", 200, 1).reason


def test_exit_reads_the_last_fifty_and_needs_thirty_of_them():
    ok, bad = c.ANSWERED, c.FAILED
    assert not c.review_exit([]).take_out
    assert not c.review_exit([bad] * 29).take_out                   # too few to judge, all failing
    assert c.review_exit([bad] * 30).take_out                       # 30 of 30
    assert c.review_exit([bad] * 10 + [ok] * 20).take_out is True   # 10/30 = 33%: above 30%
    assert c.review_exit([bad] * 9 + [ok] * 21).take_out is False   # 9/30 = exactly 30%: stays
    assert c.review_exit([bad] * 15 + [ok] * 35).take_out is False  # 15/50 = exactly 30%: stays
    assert c.review_exit([bad] * 16 + [ok] * 34).take_out is True   # 16/50 = 32%


def test_exit_looks_only_at_the_newest_fifty():
    ok, bad = c.ANSWERED, c.FAILED
    newest_first = [ok] * 50 + [bad] * 100            # a bad history behind a good window
    got = c.review_exit(newest_first)
    assert got.n == 50 and got.failed == 0 and not got.take_out
    newest_first = [bad] * 20 + [ok] * 30 + [ok] * 100   # 20/50 = 40% in the window
    assert c.review_exit(newest_first).take_out is True


def test_action_names_are_family_dot_verb_and_nothing_else():
    for good in ("network.scan", "web.get", "code.secrets", "ad.collect"):
        assert c.valid_action_name(good)
    for bad in ("", "scan", "Network.scan", "network.", ".scan", "a.b.c", "net work.scan", None,
                7, ["network.scan"], "network.scan; DROP"):
        assert not c.valid_action_name(bad), bad


def test_admission_over_a_window_reads_only_the_newest_fifty():
    recent = ["failed"] * 8 + ["answered"] * 42 + ["answered"] * 200         # newest first
    got = c.admission_over_window("a.b", recent)
    assert (got.n, got.failed) == (50, 8) and not got.recommend
    assert c.admission_over_window("a.b", ["answered"] * 39).recommend is False
    assert c.admission_over_window("a.b", ["answered"] * 40).recommend is True
    assert c.admission_over_window("a.b", ["answered"] * 300).n == c.ADMIT_WINDOW


def test_admission_window_is_the_exit_window():
    assert c.ADMIT_WINDOW == c.EXIT_WINDOW


@pytest.mark.parametrize("reason,ok", [
    ("the goal template was changed", True),
    ("  padded with spaces around it  ", True),
    ("x" * 10, True), ("x" * 9, False), ("x" * 500, True), ("x" * 501, False),
    ("", False), ("          ", False), ("line one\nline two here", False),
    ("tab\tseparated reason", False), (None, False), (7, False), (["a reason of text"], False)])
def test_a_reason_is_a_printable_line_of_ten_to_five_hundred_characters(reason, ok):
    assert c.valid_reason(reason) is ok


def test_suspension_lines_say_how_each_ended():
    import datetime as dt

    at = dt.datetime(2026, 10, 24, 9, 30)
    rows = [{"suspension_id": 1, "action": "a.b", "suspended_at": at, "window_n": 40,
             "window_failed": 20, "cleared_at": at, "cleared_by": "ann",
             "cleared_reason": "fixed it", "live": False},
            {"suspension_id": 2, "action": "c.d", "suspended_at": at, "window_n": 30,
             "window_failed": 30, "cleared_at": None, "cleared_by": None,
             "cleared_reason": None, "live": True}]
    lines = c.suspension_lines(rows, "2026-10-01")
    assert lines[0] == ("classes suspended this period (since 2026-10-01): 2 class(es), "
                        "2 suspension(s)")
    assert "20 of 40 failed; cleared 2026-10-24 09:30 by ann: fixed it" in lines[1]
    assert lines[2].endswith("30 of 30 failed; STILL SUSPENDED")
    assert c.suspension_lines([], None) == ["classes suspended this period (all time): none"]


# -- the validator outage suspicion (D68 DP-15) --------------------------------------------------

T, R, U, A = "transport", "refusal", "unclassified", None            # a call's kind; None answered


def test_the_outage_needs_thirty_calls_and_strictly_more_than_half_in_transport():
    assert c.OUTAGE_WINDOW == 30 and c.OUTAGE_RATE == 0.5
    assert not c.review_outage([T] * 29).suspected                    # too few to say
    assert not c.review_outage([T] * 15 + [A] * 15).suspected         # exactly half
    assert c.review_outage([T] * 16 + [A] * 14).suspected
    assert c.review_outage([T] * 30).suspected
    got = c.review_outage([T] * 16 + [A] * 14)
    assert (got.n, got.transport) == (30, 16) and got.rate == pytest.approx(16 / 30)


def test_only_transport_counts_toward_the_outage_and_only_the_last_thirty_are_read():
    assert not c.review_outage([R] * 30).suspected
    assert not c.review_outage([U] * 30).suspected
    assert not c.review_outage([T] * 15 + [R] * 15).suspected
    assert not c.review_outage([A] * 30 + [T] * 100).suspected        # the transport is older
    assert c.review_outage([T] * 30 + [A] * 100).suspected            # newest first


def test_the_alert_fires_on_the_call_that_crosses_the_line_and_not_while_the_outage_lasts():
    started = [T] * 16 + [A] * 14 + [A]          # newest first: 16 transport in the last 30
    before = [T] * 15 + [A] * 14 + [A] * 2       # the window one call earlier
    assert c.outage_started(started)
    assert not c.outage_started([T] * 17 + [A] * 14)           # still over: no second alert
    assert not c.outage_started(before)
    assert not c.outage_started([T] * 5)
    assert not c.outage_started([])


def test_outage_lines_say_when_and_that_nothing_was_suspended():
    import datetime as dt

    at = dt.datetime(2026, 10, 24, 9, 30)
    rows = [{"suspicion_id": 4, "detected_at": at, "window_n": 30, "window_transport": 17}]
    lines = c.outage_lines(rows, "2026-10-01")
    assert lines[0].startswith(
        "validator outage suspected this period (since 2026-10-01): 1 time(s)")
    assert "nothing was suspended" in lines[0]
    assert "17 of the last 30 calls failed in transport" in lines[1]
    assert c.outage_lines([], None) == ["validator outage suspected this period (all time): none"]
