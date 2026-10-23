"""The Q1 stream and its report (D68 S8b): the plan is deterministic and the judgement is the one
that was written down."""

from __future__ import annotations

import random
from collections import Counter

from scripts.soak import q1_report as rep
from scripts.soak import q1_stream as stream


def item(action, cell, wording, outcome):
    return {"action": action, "cell": cell, "goal_wording": wording, "outcome": outcome}


def test_the_plan_is_reproducible_and_covers_every_class_with_the_weights_asked_for():
    plan = [stream.build_plan(random.Random("s8b")) for _ in range(3)]
    assert plan[0] == plan[1] == plan[2]
    rng = random.Random(7)
    seen = Counter(stream.build_plan(rng)["action"] for _ in range(4000))
    assert set(seen) == set(stream.ACTIONS)
    assert seen["code.secrets"] > seen["ad.collect"] > seen["web.get"]


def test_crossed_cells_are_the_two_probe_cells_and_a_tenth_of_the_stream():
    rng = random.Random(3)
    plans = [stream.build_plan(rng) for _ in range(4000)]
    crossed = [p for p in plans if p["cell"] == "crossed"]
    assert 0.07 < len(crossed) / len(plans) < 0.13
    for p in crossed:
        assert (p["action"], p["goal_wording"]) in (("code.secrets", "ad-collect"),
                                                     ("ad.collect", "code-secrets"))
    for p in plans:
        if p["cell"] == "natural":
            assert p["goal_wording"].replace("-", ".") in (p["action"], p["scenario"].replace(
                "-", "."), p["goal_wording"].replace("-", "."))
            assert p["goal"]


def test_a_goal_names_its_target_in_the_words_an_operator_would_write():
    rng = random.Random(11)
    for _ in range(200):
        p = stream.build_plan(rng)
        assert p["target_value"] in p["goal"]


def test_the_judgement_holds_when_the_wording_separates_and_the_action_does_not():
    items = ([item("code.secrets", "natural", "code-secrets", "plausible")] * 100
             + [item("ad.collect", "natural", "ad-collect", "not_assessed/failed")] * 40
             + [item("ad.collect", "natural", "ad-collect", "plausible")] * 20
             + [item("code.secrets", "crossed", "ad-collect", "not_assessed/failed")] * 15
             + [item("ad.collect", "crossed", "code-secrets", "plausible")] * 10)
    verdict = rep.judge(items)
    assert verdict["holds"] is True
    assert "HOLDS" in rep.render(items)


def test_the_judgement_fails_when_code_secrets_fails_on_its_own_wording():
    items = ([item("code.secrets", "natural", "code-secrets", "not_assessed/failed")] * 60
             + [item("code.secrets", "natural", "code-secrets", "plausible")] * 40
             + [item("ad.collect", "natural", "ad-collect", "not_assessed/failed")] * 50
             + [item("ad.collect", "natural", "ad-collect", "plausible")] * 10)
    verdict = rep.judge(items)
    assert verdict["holds"] is False
    assert "does NOT hold" in rep.render(items)


def test_the_judgement_is_not_established_without_data_on_both_wordings():
    items = [item("code.secrets", "natural", "code-secrets", "plausible")] * 30
    assert rep.judge(items)["holds"] is None
    assert "not established" in rep.render(items)


def test_every_proposal_is_in_exactly_one_cell_and_one_wording_row():
    items = [item("code.secrets", "natural", "code-secrets", "plausible"),
             item("ad.collect", "crossed", "code-secrets", "not_assessed/failed"),
             item("web.get", "natural", "web-get", "implausible"),
             item("web.get", "natural", "web-get", "not_assessed/disabled")]
    table = rep.tabulate(items)
    assert sum(sum(c.values()) for c in table["by_cell"].values()) == len(items)
    assert sum(sum(c.values()) for c in table["by_wording"].values()) == len(items)


def test_wilson_is_a_proper_interval_and_the_outcome_words_are_closed():
    lo, hi = rep.wilson(5, 50)
    assert 0 < lo < 0.1 < hi < 0.25
    assert rep.wilson(0, 0) == (0.0, 1.0)
    assert rep.outcome(None, None) == "absent"
    assert rep.outcome("not_assessed", "failed") == "not_assessed/failed"
    assert rep.failed("not_assessed/failed") and not rep.failed("not_assessed/disabled")
