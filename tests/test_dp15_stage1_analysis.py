"""The one analysis of DP-15 stage 1 (C1): the statistics, the marking rule, the verdict, the two
rows, and the one look.

The records here are synthetic. ``docs/D68_DP15_RECORD_MODE/ENABLE_DECISION_PLAN.md`` (5.1, 5.3, 9)
says what the numbers mean.
"""

from __future__ import annotations

import json
from math import ceil

import pytest

from scripts import dp15_stage1_analysis as an

P, I, S = "plausible", "implausible", "insufficient_context"       # noqa: E741
REF, UNC, TRA = ("failed", "refusal"), ("failed", "unclassified"), ("failed", "transport")


def header(real: int = 28, hand: int = 32) -> dict:
    words = [{"i": i, "source": "real" if i < real else "hand"} for i in range(real + hand)]
    return {"type": "header", "wordings": words, "wordings_sha256": "w" * 64,
            "prompt_digest": "5e2357979fb3", "backend": "claude_code", "model_alias": "sonnet",
            "cli_version": "2.1.310", "fallback": "off", "database": "cyberorch_dp15b",
            "migration": "0030", "started_at": "2026-10-26T00:00:00Z", "plan_commit": "c" * 40,
            "seed": 20261025}


def call(wording: int, repeat: int, answer, leg: str = "A") -> dict:
    """``answer``: a goal_fit value, or ``("failed", kind)``."""
    entry = {"type": "call", "leg": leg, "wording": wording, "repeat": repeat,
             "target": f"10.0.{wording}.{repeat + 2}"}
    if isinstance(answer, tuple):
        entry.update(goal_fit=answer[0], failure_kind=answer[1])
    else:
        entry.update(goal_fit=answer, failure_kind=None)
    return entry


def record(answers: dict | None = None, wordings: int = 60) -> list[dict]:
    """``answers``: wording -> a list of three answers (default plausible x3)."""
    answers = answers or {}
    out = []
    for i in range(wordings):
        for r, a in enumerate(answers.get(i, [P, P, P])):
            out.append(call(i, r, a))
    return out


def footer(stopped=None, **usage) -> dict:
    return {"type": "footer", "stopped": stopped, "issued": 190, "finished": 190, "seconds": 60.0,
            "usage": {"cli_runs": 190, "cost_usd": 1.6, "input_tokens": 10, "output_tokens": 20,
                      "cache_read_tokens": 30, "cache_creation_tokens": 40, **usage},
            "models": ["claude-sonnet-x"]}


def marked_wordings(k: int, first: int = 0) -> dict:
    return {first + j: [I, I, I] for j in range(k)}


def verdict_of(calls, head=None):
    return an.analyse(head or header(), calls, footer())


# -- the intervals --------------------------------------------------------------

def test_wilson_matches_the_known_values():
    lo, hi = an.wilson(3, 60)
    assert lo == pytest.approx(0.0171, abs=1e-4) and hi == pytest.approx(0.1370, abs=1e-4)
    assert an.wilson(0, 28)[1] == pytest.approx(0.1206, abs=1e-4)
    assert an.wilson(0, 0) == (0.0, 1.0)


def test_the_exact_interval_matches_the_known_values():
    lo, hi = an.exact(3, 60)
    assert lo == pytest.approx(0.0104, abs=1e-4) and hi == pytest.approx(0.1392, abs=1e-4)
    assert an.exact(0, 28) == (0.0, pytest.approx(0.1234, abs=1e-4))
    assert an.exact(60, 60)[1] == 1.0 and an.exact(0, 0) == (0.0, 1.0)
    assert an.exact(10, 60)[0] == pytest.approx(0.0829, abs=1e-4)


def test_the_most_marked_wordings_a_given_n_allows_at_fifteen_percent():
    assert an.allowed_marked(60) == 3 and an.allowed_marked(57) == 3
    assert an.allowed_marked(54) == 2 and an.allowed_marked(28) == 0
    assert an.allowed_marked(1) == -1                     # not even none can be shown
    # where the two bounds part: at 55 Wilson would allow 3, the exact bound only 2; at 64, 4 and 3
    assert an.wilson(3, 55)[1] <= 0.15 < an.exact(3, 55)[1]
    assert an.allowed_marked(55) == 2 and an.allowed_marked(64) == 3
    assert an.C1_THRESHOLD == 0.15


# -- the mark of a wording ------------------------------------------------------

def test_a_wording_is_marked_when_at_least_half_of_its_counted_calls_are_marked():
    table = an.wording_table(header(), record({
        0: [I, P, P],              # 1 of 3: not marked
        1: [I, I, P],              # 2 of 3: marked
        2: [S, S, S],              # insufficient_context counts as marked
        3: [REF, P, P],            # a refusal is a marked call
        4: [UNC, UNC, P],          # unclassified too
        5: [I, TRA, P],            # a tie of 1 in 2 (one lost to transport): marked
        6: [TRA, TRA, P],          # 0 of 1: not marked
        7: [TRA, TRA, I],          # 1 of 1: marked
        8: [TRA, TRA, TRA],        # nothing counts: undecided
    }))
    assert [table[i]["mark"] for i in range(9)] == [
        False, True, True, False, True, True, False, True, None]
    assert table[5]["transport"] == 1 and table[8]["transport"] == 3 and table[8]["calls"] == 0


def test_transport_losses_are_in_no_denominator():
    result = verdict_of(record({0: [TRA, TRA, TRA], 1: [TRA, I, I]}))
    assert result["pooled"]["decided"] == 59 and result["pooled"]["transport"] == 4
    assert result["pooled"]["counted_calls"] == 58 * 3 + 2          # wording 1 kept two calls
    assert result["undecided"] == [0]


def test_leg_b_calls_do_not_count_in_c1():
    calls = record({0: [I, P, P]})                      # 1 of 3: not marked
    calls += [call(0, 0, I, leg="B"), call(0, 1, I, leg="B")]       # would make it 3 of 5
    assert verdict_of(calls)["pooled"]["marked"] == 0


def test_a_transport_loss_is_not_a_marked_call():
    assert an.is_marked(an.TRANSPORT) is False and an.is_marked(P) is False
    assert an.is_marked(I) and an.is_marked(S) and an.is_marked("failed:refusal")


# -- the verdict ----------------------------------------------------------------

def test_three_marked_wordings_of_sixty_meet_c1_and_four_do_not():
    met = verdict_of(record(marked_wordings(3)))
    assert met["c1"] == an.MET and met["pooled"]["marked"] == 3
    assert "3 of 60 decided wordings marked" in met["reason"] and "at most 3" in met["reason"]
    assert verdict_of(record(marked_wordings(4)))["c1"] == an.NOT_MET


def test_fewer_than_ninety_percent_decided_is_not_evaluable():
    planned = 60
    assert ceil(an.EVALUABLE_SHARE * planned) == 54
    at_edge = {i: [TRA, TRA, TRA] for i in range(6)}            # 54 decided
    assert verdict_of(record(at_edge))["c1"] == an.MET
    below = {i: [TRA, TRA, TRA] for i in range(7)}              # 53 decided
    result = verdict_of(record(below))
    assert result["c1"] == an.NOT_EVALUABLE and "53 of 60" in result["reason"]


def test_a_wording_with_no_call_at_all_is_undecided():
    calls = record(wordings=50)                                  # a run stopped after 50 wordings
    result = verdict_of(calls)
    assert result["c1"] == an.NOT_EVALUABLE and result["pooled"]["decided"] == 50
    assert result["undecided"] == list(range(50, 60))


def test_both_upper_bounds_must_be_within_the_threshold(monkeypatch):
    calls = record(marked_wordings(2))
    assert verdict_of(calls)["c1"] == an.MET
    monkeypatch.setattr(an, "exact", lambda k, n, alpha=0.05: (0.0, 0.2))
    assert verdict_of(calls)["c1"] == an.NOT_MET                 # Wilson alone would pass
    monkeypatch.undo()
    monkeypatch.setattr(an, "wilson", lambda k, n, z=an.Z95: (0.0, 0.2))
    assert verdict_of(calls)["c1"] == an.NOT_MET                 # exact alone would pass


def test_the_exact_bound_can_refuse_where_wilson_would_not():
    undecided = {i: [TRA, TRA, TRA] for i in range(5)}          # 55 decided wordings
    result = verdict_of(record({**undecided, **marked_wordings(3, first=10)}))
    assert result["pooled"]["decided"] == 55 and result["pooled"]["marked"] == 3
    assert result["pooled"]["wilson"][1] <= 0.15 < result["pooled"]["exact"][1]
    assert result["c1"] == an.NOT_MET and "at most 2 may be marked" in result["reason"]


def test_the_bounds_are_computed_on_the_decided_wordings():
    undecided = {i: [TRA, TRA, TRA] for i in range(3)}
    result = verdict_of(record({**undecided, **marked_wordings(3, first=10)}))
    assert result["pooled"]["decided"] == 57 and result["pooled"]["marked"] == 3
    assert result["c1"] == an.MET


# -- the two rows ---------------------------------------------------------------

def test_the_two_sources_are_reported_apart_and_the_pooled_row_decides():
    answers = {**marked_wordings(2, first=0), **marked_wordings(1, first=28)}
    result = verdict_of(record(answers))
    assert (result["real"]["planned"], result["real"]["marked"]) == (28, 2)
    assert (result["hand"]["planned"], result["hand"]["marked"]) == (32, 1)
    assert (result["pooled"]["planned"], result["pooled"]["marked"]) == (60, 3)
    assert result["c1"] == an.MET


def test_a_large_difference_is_a_label_only_when_the_wilson_intervals_do_not_overlap():
    real_ok_hand_bad = marked_wordings(8, first=28)              # 0 of 28 against 8 of 32
    result = verdict_of(record(real_ok_hand_bad))
    assert result["difference"].startswith("LARGE: the hand-written row is above the real row")
    seven = verdict_of(record(marked_wordings(7, first=28)))     # 7 of 32: lower bound 11.0%
    assert seven["difference"].startswith("not large")
    real_bad = verdict_of(record(marked_wordings(7, first=0)))   # 7 of 28 against 0 of 32
    assert real_bad["difference"].startswith("LARGE: the real row is above the hand-written row")
    assert real_bad["c1"] == an.NOT_MET                          # the verdict is the pooled one


def test_the_difference_is_not_assessable_without_decided_wordings_in_a_row():
    calls = [c for c in record() if c["wording"] >= 28]          # no real wording was called
    assert verdict_of(calls)["difference"].startswith("not assessable")


# -- what is reported -----------------------------------------------------------

def test_the_reported_numbers_are_there_and_none_of_them_decides():
    answers = {0: [I, I, P], 1: [S, P, P], 2: [REF, REF, REF], 3: [UNC, P, P], 4: [P, TRA, I]}
    result = verdict_of(record(answers))
    assert result["split_calls"] == {"failed:refusal": 3, "transport": 1,
                                     "failed:unclassified": 1, "implausible": 3,
                                     "insufficient_context": 1, "plausible": 171}
    assert result["split_wordings"] == 4                          # wordings 0, 1, 3 and 4 disagree
    low, high = result["bootstrap"]
    assert 0.0 <= low <= high <= 1.0
    assert an.bootstrap_call_share(an.wording_table(header(), record(answers))) == (low, high)
    assert result["usage"]["cli_runs"] == 190 and result["models"] == ["claude-sonnet-x"]


def test_leg_b_agreement_compares_with_leg_a_first_repeat_and_skips_transport():
    calls = record({0: [P, I, I], 1: [I, P, P], 2: [P, P, P], 3: [REF, P, P], 4: [TRA, P, P]})
    calls += [call(0, 0, P, leg="B"),          # agrees with A's first repeat (plausible)
              call(1, 0, P, leg="B"),          # A's first was implausible: disagree
              call(2, 0, TRA, leg="B"),        # transport in B: not compared
              call(3, 0, UNC, leg="B"),        # a failure is a failure whatever the kind: agree
              call(4, 0, P, leg="B")]          # A's first was a transport loss: not compared
    got = an.agreement(calls)
    assert got == {"pairs": 3, "agree": 2, "not_compared": 2, "leg_b_calls": 5}


# -- the report -----------------------------------------------------------------

def test_the_report_names_the_verdict_both_rows_and_the_reading_rule():
    result = verdict_of(record(marked_wordings(2)))
    text = "\n".join(an.render(result, header(), "r" * 64))
    for needle in ("C1: MET", "real (model Supervisor)", "hand-written",
                   "network.scan pooled (C1)", "difference between the two rows",
                   "not used to resample, drop or reweight a row", "r" * 64, "w" * 64,
                   "5e2357979fb3", "sonnet", "2.1.310", "cyberorch_dp15b", "the run completed",
                   "does not say whether goal_fit_enforce may be turned on"):
        assert needle in text, needle


def test_a_run_that_stopped_says_so_and_so_does_a_record_without_footer():
    result = an.analyse(header(), record(), footer(stopped="the cost cap was reached"))
    assert not result["complete"] and "the cost cap was reached" in "\n".join(
        an.render(result, header(), "r" * 64))
    result = an.analyse(header(), record(), None)
    assert not result["complete"] and "did not end cleanly" in result["stopped"]


# -- the record and the one look ------------------------------------------------

def write_record(path, calls, head=None, end=True):
    lines = [head or header(), *calls] + ([footer()] if end else [])
    path.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    return path


def test_the_record_is_read_back_whole(tmp_path):
    path = write_record(tmp_path / "r.jsonl", record())
    head, calls, end, sha = an.read_record(path)
    assert head["prompt_digest"] == "5e2357979fb3" and len(calls) == 180 and end is not None
    assert len(sha) == 64
    with pytest.raises(ValueError):
        an.read_record(write_record(tmp_path / "x.jsonl", [], head={"type": "call"}))


def test_the_first_look_needs_no_reason_and_prints_the_verdict(tmp_path, capsys):
    path = write_record(tmp_path / "r.jsonl", record(marked_wordings(1)))
    assert an.look(path) == an.EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("look 1 of this record") and "C1: MET" in out
    ledger = an.read_ledger(path)
    assert len(ledger) == 1 and ledger[0]["verdict"] == an.MET and ledger[0]["look"] == 1
    assert ledger[0]["record_sha256"] == an.read_record(path)[3]


def test_a_second_look_is_refused_without_a_reason_and_kept_with_one(tmp_path, capsys):
    path = write_record(tmp_path / "r.jsonl", record())
    assert an.look(path) == an.EXIT_OK
    capsys.readouterr()
    assert an.look(path) == an.EXIT_USAGE
    err = capsys.readouterr().err
    assert "already looked at 1 time(s)" in err and "--reason" in err
    assert an.look(path, reason="   ") == an.EXIT_USAGE                  # a blank reason is none
    assert len(an.read_ledger(path)) == 1                       # nothing was added by the refusals
    assert an.look(path, reason="the analysis script had a typo in its table") == an.EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("look 2 of this record (reason: the analysis script had a typo")
    ledger = an.read_ledger(path)
    assert [e["look"] for e in ledger] == [1, 2] and ledger[1]["reason"].startswith("the analysis")
    assert ledger[0]["reason"] is None


def test_a_record_that_changed_between_looks_is_noted(tmp_path, capsys):
    path = write_record(tmp_path / "r.jsonl", record())
    an.look(path)
    write_record(path, record(marked_wordings(1)))
    capsys.readouterr()
    assert an.look(path, reason="the record was rewritten") == an.EXIT_OK
    assert "NOTE: the record has changed since an earlier look" in capsys.readouterr().out


def test_an_unreadable_record_is_a_usage_error_and_leaves_no_ledger(tmp_path, capsys):
    assert an.look(tmp_path / "missing.jsonl") == an.EXIT_USAGE
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n")
    assert an.look(bad) == an.EXIT_USAGE
    assert "the record cannot be read" in capsys.readouterr().err
    assert not an.ledger_path(bad).exists()


def test_the_command_line_takes_a_record_and_an_optional_reason(tmp_path, capsys):
    path = write_record(tmp_path / "r.jsonl", record())
    assert an.main(["--record", str(path)]) == an.EXIT_OK
    assert an.main(["--record", str(path)]) == an.EXIT_USAGE
    assert an.main(["--record", str(path), "--reason", "again"]) == an.EXIT_OK


def test_the_analysis_calls_no_model_and_reads_no_database():
    import ast
    from pathlib import Path

    tree = ast.parse(Path(an.__file__).read_text())
    imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    names = {a.name for n in imports for a in n.names}
    names |= {n.module for n in imports if isinstance(n, ast.ImportFrom) and n.module}
    for forbidden in ("subprocess", "sqlalchemy", "build_plan_fit_validator", "psycopg",
                      "control_plane", "agents"):
        assert not any(forbidden in str(n) for n in names), forbidden
