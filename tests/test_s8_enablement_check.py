"""The S8 enablement check (D68 plan 8.1): each way of being "on and doing nothing" is named."""

from __future__ import annotations

from collections import Counter

from scripts import s8_enablement_check as c

ON = {"ENG-1": True, "ENG-2": True}


def test_p1_with_the_switch_everywhere_and_a_recorded_comparison_is_clean():
    assert c.verdict_p1(switches=ON, decided=10, with_plan_fit=10) == []


def test_p1_switch_missing_from_one_engagement_is_named():
    got = c.verdict_p1(switches={"ENG-1": True, "ENG-2": False}, decided=0, with_plan_fit=0)
    assert len(got) == 1 and "ENG-2" in got[0]


def test_p1_enabled_and_recording_nothing_is_an_anomaly():
    got = c.verdict_p1(switches=ON, decided=7, with_plan_fit=0)
    assert any("not running" in p for p in got)


def test_p1_with_no_engagement_read_is_an_anomaly_not_a_pass():
    assert c.verdict_p1(switches={}, decided=0, with_plan_fit=0)


def test_q1_needs_the_switch_and_a_validator_and_an_answer():
    answered = Counter({"plausible/-": 5, "not_assessed/failed": 1})
    assert c.verdict_q1(switches=ON, backend="claude_code", goal_fit=answered, decided=6) == []


def test_q1_switch_on_with_no_validator_is_the_silent_no_op_and_is_reported():
    only_disabled = Counter({"not_assessed/disabled": 9})
    for backend in (None, "", "fake", " FAKE "):
        got = c.verdict_q1(switches=ON, backend=backend, goal_fit=only_disabled, decided=9)
        assert any("no validator is configured" in p for p in got), backend
        assert any("doing nothing" in p for p in got), backend


def test_q1_validator_present_but_switch_off_is_reported():
    got = c.verdict_q1(switches={"ENG-1": False}, backend="claude_code",
                       goal_fit=Counter({"plausible/-": 3}), decided=3)
    assert len(got) == 1 and "goal_fit_enforce is not true" in got[0]


def test_q1_decisions_from_before_the_validator_do_not_count_as_answers():
    got = c.verdict_q1(switches=ON, backend="claude_code",
                       goal_fit=Counter({"absent (decided before Q1)": 4}), decided=4)
    assert any("doing nothing" in p for p in got)


def test_q1_with_no_traffic_yet_judges_only_the_switch_and_the_configuration():
    assert c.verdict_q1(switches=ON, backend="claude_code", goal_fit=Counter(), decided=0) == []


def test_q1_the_measured_configuration_is_clean_and_each_departure_is_named():
    ok = dict(backend="claude_code", model="sonnet", fallback_off="1")
    assert c.config_problems(**ok) == []
    assert any("model" in p for p in c.config_problems(**{**ok, "model": None}))
    assert any("model" in p for p in c.config_problems(**{**ok, "model": "opus"}))
    assert any("fallback" in p for p in c.config_problems(**{**ok, "fallback_off": None}))
    assert any("fallback" in p for p in c.config_problems(**{**ok, "fallback_off": "0"}))
    assert any("not measured" in p for p in c.config_problems(**{**ok, "backend": "api"}))
    # no validator at all is a different anomaly, reported by verdict_q1 and not twice
    assert c.config_problems(backend=None, model=None, fallback_off=None) == []


def test_q1_verdict_reports_an_unmeasured_configuration_beside_the_other_anomalies():
    got = c.verdict_q1(switches=ON, backend="claude_code", model="opus", fallback_off=None,
                       goal_fit=Counter({"plausible/-": 4}), decided=4)
    assert len(got) == 2 and any("opus" in p for p in got) and any("fallback" in p for p in got)


def test_q1_an_empty_list_is_noted_and_is_not_an_anomaly():
    quiet = Counter({"not_assessed/class_not_enabled": 30})
    assert c.verdict_q1(switches=ON, backend="claude_code", goal_fit=quiet, decided=30) == []
    assert "outside the list" in c.notes_q1(goal_fit=quiet)[0]
    assert c.notes_q1(goal_fit=Counter({"plausible/-": 3})) == []
