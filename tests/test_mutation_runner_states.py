"""The mutation runner's two states of plan item 156: ``retired`` (not run, ``RETIRED: <why>``,
not a failure) and ``accepted_survivor`` (run; INVALID is ``ACCEPTED SURVIVOR: <why>`` and not a
failure; valid is ``ACCEPTED SURVIVOR NOW VALID`` and a failure), beside an ordinary mutation.

``mutation_check.run`` -- which edits files and runs pytest -- is replaced by a stand-in that only
returns a verdict, and the start-up's journal and database checks by nothing: no file is edited,
no test is run, no database is read.
"""

from __future__ import annotations

import sys

import pytest

from scripts import mutation_check as mc
from scripts import mutations_d69


@pytest.fixture
def runner(monkeypatch):
    ran = []

    def fake_run(mutation, baselines):
        ran.append(mutation.id)
        verdict = mutation.summary              # the stand-in's verdict is the summary
        return mc.Result(mutation.id, mutation.summary, verdict=verdict, tests=mutation.tests,
                         problems=[] if verdict == "valid" else ["no test failed on an assertion"])

    monkeypatch.setattr(mc, "run", fake_run)
    monkeypatch.setattr(mc, "_load_env", lambda: None)
    monkeypatch.setattr(mc, "recover", lambda: [])
    monkeypatch.setattr(mc, "hygiene", lambda: [])

    def main(*mutations):
        monkeypatch.setattr(sys, "argv", ["mutation_check.py"])
        with pytest.raises(SystemExit) as ended:
            mc.main({m.id: m for m in mutations})
        return ended.value.code

    main.ran = ran
    return main


def _m(id, verdict, **kwargs):
    return mc.Mutation(id, verdict, ("tests/none.py",), **kwargs)


def test_a_retired_mutation_is_not_run_and_is_not_a_failure(runner, capsys):
    code = runner(_m("R", "INVALID", retired="equivalent since item 154"), _m("V", "valid"))
    out = capsys.readouterr().out
    assert code == 0 and runner.ran == ["V"]
    assert "## R: RETIRED" in out and "   RETIRED: equivalent since item 154" in out
    assert "1 valid, 0 not: []; retired, not run: ['R']" in out


def test_an_accepted_survivor_that_survives_is_reported_and_is_not_a_failure(runner, capsys):
    code = runner(_m("S", "INVALID", accepted_survivor="over-escalation only"))
    out = capsys.readouterr().out
    assert code == 0 and runner.ran == ["S"]
    assert "## S: ACCEPTED SURVIVOR " in out and "   ACCEPTED SURVIVOR: over-escalation only" in out
    assert "0 valid, 0 not: []; accepted survivors: ['S']" in out


def test_an_accepted_survivor_that_is_caught_now_is_a_failure(runner, capsys):
    code = runner(_m("S", "valid", accepted_survivor="over-escalation only"))
    out = capsys.readouterr().out
    assert code == 1
    assert "## S: ACCEPTED SURVIVOR NOW VALID" in out
    assert "the acceptance (over-escalation only) is to be taken back" in out
    assert "0 valid, 1 not: ['S']" in out


def test_an_ordinary_invalid_mutation_is_still_a_failure(runner, capsys):
    code = runner(_m("V", "valid"), _m("I", "INVALID"))
    out = capsys.readouterr().out
    assert code == 1 and "## I: INVALID" in out and "   PROBLEM: no test failed" in out
    assert "1 valid, 1 not: ['I']" in out


def test_e8_is_retired_and_sl2_an_accepted_survivor_with_their_summaries_kept():
    by_id = {m.id: m for m in mutations_d69.CATALOGUE}
    e8, sl2 = by_id["D69-SR-E8"], by_id["D69-SL-2"]
    assert e8.retired and e8.retired in e8.summary and e8.accepted_survivor is None
    assert sl2.accepted_survivor and sl2.accepted_survivor in sl2.summary and sl2.retired is None
    assert [m.id for m in mutations_d69.CATALOGUE if m.retired] == ["D69-SR-E8"]
    assert [m.id for m in mutations_d69.CATALOGUE if m.accepted_survivor] == ["D69-SL-2"]
