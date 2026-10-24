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
