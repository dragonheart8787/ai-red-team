"""The baseline runner (D68 S6), offline: its analysis is right and its guards hold.

No model is called. The runner is exercised against the scripted fakes and against purpose-built
validators whose behaviour is known exactly (an oracle, a validator a lure works on, one that
flips), so a rate it reports can be checked against the one that was put in.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.base_agent import GoalFitAssessment, PlanFitQuery
from agents.fake.fake_plan_fit import (
    AdversarialFakePlanFit,
    HonestFakePlanFit,
    UnavailableFakePlanFit,
)
from control_plane.plan_fit.shadow import upper95
from scripts import plan_fit_baseline as pb
from tests import plan_fit_corpus as pc

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def corpus():
    return pc.build_corpus()


@pytest.fixture(scope="module")
def small():
    return pc.build_corpus(per_class=6)


class Oracle:
    """Right on everything: plausible for matched, implausible for the rest. ``fooled`` names lure
    classes it calls plausible (the validator a lure works on)."""

    validator_id = "oracle"

    def __init__(self, items, fooled=()):
        self.expect = {i.query: i for i in items}
        self.fooled = set(fooled)
        self.calls = []

    def assess(self, *, query: PlanFitQuery):
        item = self.expect[query]
        if item.group == pc.MATCHED or item.lure in self.fooled:
            return GoalFitAssessment(self.validator_id, "plausible")
        return GoalFitAssessment(self.validator_id, "implausible")

    def provenance(self):
        return {"prompt_sha256": "p" * 64}


def run(validator, items, **kw):
    return pb.run_corpus(validator, items, **kw)


def test_the_honest_fake_finds_everything_plausible_and_the_report_shows_it_for_what_it_is(corpus):
    a = pb.analyse(run(HonestFakePlanFit(), corpus), corpus)
    assert a["calls"] == 480
    assert a["groups"]["matched"]["plausible"]["k"] == 60
    assert a["false_positive_on_matched"]["k"] == 0
    assert a["detection_on_mismatched"]["k"] == 0 and a["detection_on_mismatched"]["n"] == 60
    assert a["plausible_on_mismatched"]["k"] == 60
    # everything plausible: the control is as plausible as the lure, so a lure buys nothing
    for row in a["lures"].values():
        assert row["n"] == 60 and row["delta_points"] == 0.0 and row["bought_by_the_lure"] == 0


def test_the_adversarial_fake_is_the_same_as_the_honest_one_to_the_report(corpus):
    honest = pb.analyse(run(HonestFakePlanFit(), corpus), corpus)
    liar = pb.analyse(run(AdversarialFakePlanFit(), corpus), corpus)
    assert honest["groups"] == liar["groups"] and honest["lures"] == liar["lures"]


def test_a_correct_validator_has_no_false_positive_full_detection_and_no_lure_success(corpus):
    a = pb.analyse(run(Oracle(corpus), corpus), corpus)
    assert a["groups"]["matched"]["plausible"] == {"k": 60, "n": 60, "upper95": a[
        "groups"]["matched"]["plausible"]["upper95"]}
    assert a["false_positive_on_matched"]["k"] == 0
    assert a["detection_on_mismatched"]["k"] == 60
    for row in a["lures"].values():
        assert row["lured_plausible"]["k"] == 0 and row["control_plausible"]["k"] == 0
        assert row["delta_points"] == 0.0


def test_a_validator_a_lure_works_on_shows_exactly_that_lure_as_bought(corpus):
    a = pb.analyse(run(Oracle(corpus, fooled=("L3",)), corpus), corpus)
    assert a["lures"]["L3"]["lured_plausible"]["k"] == 60
    assert a["lures"]["L3"]["control_plausible"]["k"] == 0
    assert a["lures"]["L3"]["bought_by_the_lure"] == 60
    assert a["lures"]["L3"]["delta_points"] == 100.0
    for cls in pc.LURE_CLASSES:
        if cls != "L3":
            assert a["lures"][cls]["bought_by_the_lure"] == 0


def test_a_lure_that_makes_the_validator_more_careful_is_counted_as_lost(small):
    class Careful(Oracle):
        def assess(self, *, query):
            item = self.expect[query]
            if item.group == pc.MISMATCHED:
                return GoalFitAssessment("careful", "plausible")
            return GoalFitAssessment("careful", "implausible")

    a = pb.analyse(run(Careful(small), small), small)
    row = a["lures"]["L1"]
    assert row["control_plausible"]["k"] == 6 and row["lured_plausible"]["k"] == 0
    assert row["lost_by_the_lure"] == 6 and row["bought_by_the_lure"] == 0
    assert row["delta_points"] == -100.0


def test_a_false_positive_and_insufficient_context_are_told_apart(small):
    class Picky(Oracle):
        asked = 0

        def assess(self, *, query):
            item = self.expect[query]
            if item.group == pc.MATCHED:
                n = self.asked % 3
                self.asked += 1
                return GoalFitAssessment(
                    "picky", ("plausible", "implausible", "insufficient_context")[n])
            return GoalFitAssessment("picky", "insufficient_context")

    a = pb.analyse(run(Picky(small), small), small)
    assert a["groups"]["matched"]["n"] == 6
    assert a["false_positive_on_matched"]["k"] == 2
    assert a["insufficient_on_matched"]["k"] == 2
    assert a["detection_on_mismatched"]["k"] == 6


def test_a_flip_across_runs_is_counted_per_item(small):
    class Flipper(Oracle):
        def __init__(self, items):
            super().__init__(items)
            self.seen = {}

        def assess(self, *, query):
            n = self.seen[query] = self.seen.get(query, 0) + 1
            return GoalFitAssessment("flip", "plausible" if n % 2 else "implausible")

    a = pb.analyse(run(Flipper(small), small, repeat=2), small)
    assert a["flip_rate"]["k"] == a["flip_rate"]["n"] == len(small)
    stable = pb.analyse(run(Oracle(small), small, repeat=3), small)
    assert stable["flip_rate"]["k"] == 0 and stable["flip_rate"]["n"] == len(small)
    assert pb.analyse(run(Oracle(small), small, repeat=1), small)["flip_rate"]["n"] == 0


def test_an_unavailable_validator_is_all_failures_and_none_of_them_plausible(small):
    a = pb.analyse(run(UnavailableFakePlanFit(), small), small)
    assert a["failed_calls"]["k"] == a["failed_calls"]["n"] == len(small)
    assert a["groups"]["matched"]["plausible"]["k"] == 0
    assert a["groups"]["matched"]["failed"]["k"] == 6
    assert a["lures"]["L1"]["lured_failed"]["k"] == 6


def test_a_validator_that_raises_is_recorded_and_the_run_goes_on(small):
    class Raising:
        validator_id = "raising"

        def assess(self, *, query):
            raise KeyError("boom")

    records = run(Raising(), small)
    assert len(records) == len(small)
    assert {r["goal_fit"] for r in records} == {"failed"}
    assert {r["error_type"] for r in records} == {"KeyError"}
    assert pb.analyse(records, small)["error_types"] == {"KeyError": len(small)}


def test_the_call_records_become_latency_and_tokens(small):
    class Timed(Oracle):
        def assess(self, *, query):
            self.calls.append(SimpleNamespace(
                latency_seconds=2.0 + len(self.calls), input_tokens=100, output_tokens=5,
                failed=False, failure=None))
            return super().assess(query=query)

    a = pb.analyse(run(Timed(small), small), small)
    assert a["latency_seconds"]["calls"] == len(small)
    assert a["latency_seconds"]["median"] == pytest.approx(2.0 + (len(small) - 1) / 2)
    assert a["tokens"] == {"input": 100 * len(small), "output": 5 * len(small)}


def test_records_for_items_the_corpus_does_not_have_are_counted_not_used(small):
    records = run(Oracle(small), small) + [{"item_id": "nope-001", "run": 0,
                                            "goal_fit": "plausible", "cause": None}]
    a = pb.analyse(records, small)
    assert a["unknown_items"] == 1 and a["calls"] == len(small)


def test_the_bounds():
    assert upper95(0, 60) == pytest.approx(0.05)
    assert upper95(0, 0) == 1.0
    assert upper95(0, 300) == pytest.approx(0.01)
    for n in (10, 60, 300):
        last = 0.0
        for k in range(n + 1):
            got = upper95(k, n)
            assert k / n <= got <= 1.0 and got >= last
            last = got
    assert upper95(60, 60) == 1.0


def test_select_keeps_every_group_under_a_limit_and_brings_the_controls_of_the_lures(corpus):
    chosen = pb.select(corpus, group=None, lure=None, limit=24)
    assert {i.group for i in chosen} == set(pc.GROUPS)
    assert {i.lure for i in chosen if i.lure} == set(pc.LURE_CLASSES)
    ids = {i.item_id for i in chosen}
    assert all(i.base_id in ids for i in chosen if i.base_id)
    only = pb.select(corpus, group=["lure"], lure=["L3"], limit=None)
    assert {i.lure for i in only if i.lure} == {"L3"}
    assert {i.group for i in only} == {"lure", "mismatched"}, "L3 and its controls, nothing else"
    assert len([i for i in only if i.lure]) == 60 and len([i for i in only if not i.lure]) == 60


def test_the_report_names_backend_model_cli_and_prompt_together(small, monkeypatch):
    monkeypatch.setattr(pb, "cli_version", lambda: "9.9.9 (Claude Code)")
    validator = Oracle(small)
    report = pb.make_report(
        backend="claude_code", model="sonnet", validator=validator, items=small,
        records=run(validator, small), repeat=1, seed=pc.SEED, per_class=6,
        started="2026-10-21T00:00:00Z")
    meta = report["meta"]
    assert (meta["backend"], meta["model"], meta["cli_version"], meta["prompt_sha256"]) == (
        "claude_code", "sonnet", "9.9.9 (Claude Code)", "p" * 64)
    assert meta["corpus_digest"] == pc.corpus_digest(small) and meta["items"] == len(small)
    text = pb.render(report)
    for needle in ("claude_code", "sonnet", "9.9.9", "pppppppppppp", "Lures against their controls",
                   "No threshold is applied here"):
        assert needle in text
    json.dumps(report, default=str)


# ---------------------------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------------------------

def test_it_refuses_to_run_without_a_backend(capsys):
    with pytest.raises(SystemExit) as stop:
        pb.main([])
    assert stop.value.code == 2
    assert "--backend" in capsys.readouterr().err


def test_the_fake_is_not_a_backend_you_can_measure():
    with pytest.raises(SystemExit) as stop:
        pb.main(["--backend", "fake"])
    assert stop.value.code == 2


def test_a_dry_run_makes_no_validator_and_no_call(monkeypatch, capsys):
    from agents.llm import selection

    def boom(*a, **k):
        raise AssertionError("a dry run built a validator")

    monkeypatch.setattr(selection, "build_plan_fit_validator", boom)
    assert pb.main(["--backend", "local", "--dry-run", "--repeat", "2"]) == 0
    out = capsys.readouterr().out
    assert "480 items" in out and "calls: 960" in out and "no call made" in out


def test_a_run_above_the_call_limit_is_refused_before_anything_is_built(monkeypatch, capsys):
    from agents.llm import selection

    def boom(*a, **k):
        raise AssertionError("built a validator for a refused run")

    monkeypatch.setattr(selection, "build_plan_fit_validator", boom)
    assert pb.main(["--backend", "api", "--repeat", "2"]) == 2          # 960 calls, limit 600
    assert "--max-calls" in capsys.readouterr().err
    assert pb.main(["--backend", "api", "--repeat", "2", "--dry-run"]) == 0   # a plan is not a run


def test_a_run_writes_its_record_and_report(monkeypatch, tmp_path, capsys):
    from agents.llm import selection

    holder = {}

    def build(backend, model=None, **kw):
        holder["validator"] = Oracle(pc.build_corpus(per_class=6))
        return holder["validator"]

    monkeypatch.setattr(selection, "build_plan_fit_validator", build)
    monkeypatch.setattr(pb, "cli_version", lambda: "test-cli")
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    code = pb.main(["--backend", "local", "--per-class", "6", "--json", str(out_json),
                    "--report", str(out_md)])
    assert code == 0
    saved = json.loads(out_json.read_text())
    assert saved["meta"]["backend"] == "local" and saved["analysis"]["calls"] == 48
    assert len(saved["records"]) == 48
    assert "# Plan-fit baseline" in out_md.read_text()
    capsys.readouterr()


def test_nothing_in_ci_runs_the_baseline():
    """It reaches a real model: never in a push gate (ADR_REVIEWER_BILLING)."""
    for path in (REPO / ".github" / "workflows").glob("*.y*ml"):
        assert not re.search(r"plan_fit_baseline", path.read_text()), path.name
    makefile = (REPO / "Makefile").read_text()
    assert "plan_fit_baseline" not in makefile


def test_the_baseline_script_is_the_only_caller_of_a_validator_outside_the_control_plane():
    """Pins where a real validator can be called from at all: the control plane's one guarded
    place, and this manual script."""
    callers = []
    for top in ("agents", "control_plane", "tool_gateway", "scripts"):
        for path in (REPO / top).rglob("*.py"):
            if re.search(r"\.assess\(\s*query=", path.read_text()):
                callers.append(path.relative_to(REPO).as_posix())
    assert sorted(callers) == ["control_plane/plan_fit/goal_fit.py", "scripts/plan_fit_baseline.py"]


# ---------------------------------------------------------------------------------------------
# S7 additions: what the CLI says about each call, the stop after repeated failure, the checkpoint
# ---------------------------------------------------------------------------------------------

def test_the_envelope_recorder_keeps_what_the_cli_said_and_hands_the_process_back_unchanged():
    envelope = {"total_cost_usd": 0.012, "is_error": False, "terminal_reason": "completed",
                "modelUsage": {"claude-sonnet-5-5": {}, "claude-haiku-5-5": {}},
                "usage": {"cache_read_input_tokens": 5, "cache_creation_input_tokens": 7}}
    done = SimpleNamespace(returncode=0, stdout=json.dumps(envelope), stderr="")
    recorder = pb.EnvelopeRecorder(inner=lambda *a, **k: done)
    assert recorder(["claude"], cwd="x") is done
    assert recorder.envelopes == [{
        "returncode": 0, "cost_usd": 0.012, "models": ["claude-haiku-5-5", "claude-sonnet-5-5"],
        "is_error": False, "api_error_status": None, "terminal_reason": "completed",
        "cache_read_tokens": 5, "cache_creation_tokens": 7}]


def test_an_unreadable_envelope_is_recorded_as_such_and_never_raises():
    for stdout in ("", "not json", "[]", None):
        done = SimpleNamespace(returncode=1, stdout=stdout, stderr="boom")
        recorder = pb.EnvelopeRecorder(inner=lambda *a, done=done, **k: done)
        recorder([])
        assert recorder.envelopes[0].get("unparsed") is True


def test_the_per_call_cost_and_the_model_that_answered_reach_the_analysis(small):
    envelopes = []

    class Billed(Oracle):
        def assess(self, *, query):
            envelopes.append({"cost_usd": 0.01, "models": ["claude-sonnet-5-5", "claude-haiku-5-5"],
                              "cache_read_tokens": 3})
            return super().assess(query=query)

    records = run(Billed(small), small, envelopes=envelopes)
    a = pb.analyse(records, small)
    assert a["cost_usd_list_price"] == pytest.approx(0.01 * len(small))
    assert a["models_that_answered"] == {"claude-sonnet-5-5": len(small),
                                         "claude-haiku-5-5": len(small)}
    assert "claude-sonnet-5-5" in pb.render(pb.make_report(
        backend="claude_code", model="sonnet", validator=Oracle(small), items=small,
        records=records, repeat=1, seed=pc.SEED, per_class=6, started="t"))


def test_a_run_stops_after_failures_in_a_row_and_keeps_what_it_had(small):
    class Dies(Oracle):
        def __init__(self, items):
            super().__init__(items)
            self.n = 0

        def assess(self, *, query):
            self.n += 1
            if self.n > 3:
                return GoalFitAssessment("dies", "not_assessed", "failed")
            return super().assess(query=query)

    with pytest.raises(pb.RunAborted) as stop:
        run(Dies(small), small, stop_after_failures=5)
    assert len(stop.value.records) == 3 + 5
    assert "5 calls failed in a row" in str(stop.value)


def test_one_success_resets_the_streak(small):
    class Alternates(Oracle):
        n = 0

        def assess(self, *, query):
            self.n += 1
            if self.n % 3:
                return GoalFitAssessment("alt", "not_assessed", "failed")
            return super().assess(query=query)

    assert len(run(Alternates(small), small, stop_after_failures=3)) == len(small)


def test_the_checkpoint_holds_every_record_as_it_is_made(small, tmp_path):
    path = tmp_path / "cp.jsonl"
    records = run(Oracle(small), small, checkpoint=path)
    lines = [json.loads(x) for x in path.read_text().splitlines()]
    assert lines == records


def test_an_aborted_run_writes_its_partial_record_and_exits_nonzero(monkeypatch, tmp_path, capsys):
    from agents.llm import selection

    monkeypatch.setattr(pb, "cli_version", lambda: "test-cli")
    monkeypatch.setattr(selection, "build_plan_fit_validator",
                        lambda backend, model=None, **kw: UnavailableFakePlanFit())
    out = tmp_path / "r.json"
    code = pb.main(["--backend", "local", "--per-class", "6", "--stop-after-failures", "4",
                    "--json", str(out)])
    assert code == 3
    saved = json.loads(out.read_text())
    assert saved["meta"]["aborted"].startswith("4 calls failed in a row")
    assert len(saved["records"]) == 4
    assert "ABORTED" in capsys.readouterr().err


def test_the_claude_code_backend_is_given_the_recorder_as_its_runner(monkeypatch, tmp_path):
    from agents.llm import selection

    seen = {}

    def build(backend, model=None, **kw):
        seen.update(kw)
        return Oracle(pc.build_corpus(per_class=6))

    monkeypatch.setattr(selection, "build_plan_fit_validator", build)
    monkeypatch.setattr(pb, "cli_version", lambda: "test-cli")
    assert pb.main(["--backend", "claude_code", "--per-class", "6", "--limit", "6"]) == 0
    assert isinstance(seen.get("runner"), pb.EnvelopeRecorder)
