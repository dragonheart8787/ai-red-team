"""The dry run of stage 1 of the enable-decision plan (DRAFT): the plan, the checks, the caps and
the guards -- and that it calls no model, writes nothing and refuses to execute.

``docs/D68_DP15_RECORD_MODE/ENABLE_DECISION_PLAN.md`` says what the numbers mean. The wording lists
here are synthetic (a different vocabulary for each wording); the real lists are drafts that are
not in the repository.
"""

from __future__ import annotations

import ast
import hashlib
import itertools
import json
import re
import subprocess
from pathlib import Path

import pytest

from scripts import dp15_enable_stage1 as st

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "dp15_enable_stage1.py"

# distinct made-up words, so that no two synthetic wordings are near-duplicates
VOCAB = ["".join(p) for p in itertools.product("abcdefghjkmnpqrstuvwxyz", repeat=4)]


def wordings(cls_index: int, n: int = st.WORDINGS_PER_CLASS, kinds=("fqdn",)):
    out = []
    for i in range(n):
        base = (cls_index * 100 + i) * 5
        text = " ".join(VOCAB[base + k] for k in range(5)) + " on {t}"
        out.append(st.Wording(text, tuple(kinds), "hand"))
    return out


def lists(classes=st.CLASSES):
    kinds = {"network.scan": ("ip", "cidr"), "code.scan": ("fqdn",), "code.secrets": ("fqdn",)}
    return {c: wordings(i, kinds=kinds[c]) for i, c in enumerate(classes)}


def write_dir(tmp_path, per_class):
    for cls, ws in per_class.items():
        document = {"class": cls, "wordings": [
            {"text": w.text, "kinds": list(w.kinds), "source": w.source} for w in ws]}
        (tmp_path / f"{cls}.json").write_text(json.dumps(document))
    return tmp_path


def clean_world(monkeypatch, *, guards=(), banner=("database: stub",)):
    from scripts import dp15_record_mode as rm

    seen = []

    def check(**kw):
        seen.append(kw)
        return list(banner), list(guards)

    monkeypatch.setattr(rm, "check_startup", check)
    return seen


# -- the registered numbers -----------------------------------------------------

def test_the_registered_numbers():
    assert st.CLASSES == ("network.scan", "code.scan", "code.secrets")
    assert (st.WORDINGS_PER_CLASS, st.REPEATS, st.LEG_B_PER_CLASS) == (60, 3, 10)
    assert st.JACCARD_LIMIT == 0.6 and st.SEED == 20261025


@pytest.mark.parametrize("calls, runs, usd, minutes", [(570, 630, 7.5, 45), (190, 210, 2.5, 15),
                                                      (300, 330, 4.0, 25), (630, 700, 8.5, 50)])
def test_the_hard_caps_follow_from_the_planned_calls(calls, runs, usd, minutes):
    cap = st.caps(calls)
    assert (cap["runs"], cap["usd"], cap["minutes"]) == (runs, usd, minutes)
    assert cap["runs"] > calls and cap["usd"] > calls * st.COST_PER_CALL_USD


def test_the_estimates():
    assert st.estimate(570)["usd"] == 5.02 and st.estimate(190)["usd"] == 1.67
    low, high = st.estimate(570)["minutes_low"], st.estimate(570)["minutes_high"]
    assert 15 <= low < high <= 18


# -- the plan -------------------------------------------------------------------

def test_with_code_classes_the_plan_is_540_calls_and_30_for_leg_b():
    calls = st.build_plan(lists())
    assert sum(c.leg == "A" for c in calls) == 3 * 60 * 3 == 540
    assert sum(c.leg == "B" for c in calls) == 30 and len(calls) == 570


def test_with_network_scan_alone_the_plan_is_180_calls_and_10_for_leg_b():
    calls = st.build_plan(lists(("network.scan",)))
    assert sum(c.leg == "A" for c in calls) == 180 and sum(c.leg == "B" for c in calls) == 10
    assert {c.cls for c in calls} == {"network.scan"}


def test_every_wording_meets_three_different_targets_and_no_target_is_used_twice():
    calls = [c for c in st.build_plan(lists()) if c.leg == "A"]
    assert len({c.target for c in calls}) == len(calls) == 540
    for cls in st.CLASSES:
        for i in range(60):
            mine = [c for c in calls if c.cls == cls and c.wording == i]
            assert sorted(c.repeat for c in mine) == [0, 1, 2]
            assert len({c.target for c in mine}) == 3


def test_a_wording_meets_only_the_kinds_of_target_it_allows():
    per_class = {"network.scan": [st.Wording("a b {t}", ("ip",), "real"),
                                  st.Wording("c d {t}", ("cidr",), "real"),
                                  st.Wording("e f {t}", ("ip", "cidr"), "real")],
                 "code.scan": [st.Wording("g h {t}", ("fqdn",), "hand")]}
    calls = [c for c in st.build_plan(per_class) if c.leg == "A"]
    for c in calls:
        if c.cls == "code.scan":
            assert c.target.endswith(".example") and re.search(r"[a-z]", c.target)
        elif c.wording == 0:
            assert re.fullmatch(r"10\.\d+\.\d+\.\d+", c.target)
        elif c.wording == 1:
            assert re.fullmatch(r"10\.\d+\.\d+\.0/24", c.target)
    both = {("/" in c.target) for c in calls if c.cls == "network.scan" and c.wording == 2}
    assert both == {True, False}                     # the third wording meets both kinds


def test_the_plan_is_reproducible_from_the_seed_and_changes_with_it():
    a, b = st.build_plan(lists()), st.build_plan(lists())
    assert a == b
    other = st.build_plan(lists(), seed=1)
    assert other != a
    assert [c.target for c in other if c.leg == "A"] != [c.target for c in a if c.leg == "A"]


def test_leg_b_is_the_first_repeat_of_ten_wordings_per_class_on_the_same_target_as_leg_a():
    calls = st.build_plan(lists())
    leg_a = {(c.cls, c.wording, c.repeat): c.target for c in calls if c.leg == "A"}
    leg_b = [c for c in calls if c.leg == "B"]
    for cls in st.CLASSES:
        mine = [c for c in leg_b if c.cls == cls]
        assert len(mine) == 10 and len({c.wording for c in mine}) == 10
        assert all(c.repeat == 0 and c.target == leg_a[(cls, c.wording, 0)] for c in mine)
    other = st.build_plan(lists(), seed=7)
    assert {(c.cls, c.wording) for c in other if c.leg == "B"} != {
        (c.cls, c.wording) for c in leg_b}


def test_the_order_is_repeat_by_repeat_and_class_by_class_with_leg_b_last():
    calls = st.build_plan(lists())
    first = [(c.cls, c.wording, c.repeat) for c in calls[:6]]
    assert first == [("network.scan", 0, 0), ("code.scan", 0, 0), ("code.secrets", 0, 0),
                     ("network.scan", 1, 0), ("code.scan", 1, 0), ("code.secrets", 1, 0)]
    assert [c.leg for c in calls] == ["A"] * 540 + ["B"] * 30
    assert all(c.repeat == 0 for c in calls[:180]) and all(c.repeat == 1 for c in calls[180:360])


# -- the wording rules ----------------------------------------------------------

def test_sound_lists_pass_every_check():
    assert st.check_wordings(lists(), seen=[]) == []


def test_a_list_of_the_wrong_length_is_refused():
    per_class = lists()
    per_class["code.scan"] = per_class["code.scan"][:59]
    problems = st.check_wordings(per_class, seen=[])
    assert len(problems) == 1 and "code.scan: 59 wordings" in problems[0]


@pytest.mark.parametrize("text, n", [("no token here", 0), ("two {t} and {t}", 2)])
def test_a_wording_needs_the_target_token_exactly_once(text, n):
    per_class = lists(("code.scan",))
    per_class["code.scan"][5] = st.Wording(text, ("fqdn",), "hand")
    problems = st.check_wordings(per_class, seen=[])
    assert len(problems) == 1 and f"it occurs {n} times" in problems[0]


@pytest.mark.parametrize("kinds", [(), ("url",), ("fqdn", "url")])
def test_a_wording_needs_a_non_empty_set_of_known_target_kinds(kinds):
    per_class = lists(("code.scan",))
    per_class["code.scan"][0] = st.Wording(per_class["code.scan"][0].text, kinds, "hand")
    problems = st.check_wordings(per_class, seen=[])
    assert len(problems) == 1 and "target kinds" in problems[0]


def test_the_same_wording_twice_is_refused_in_a_class_and_across_classes():
    per_class = lists()
    shouted = per_class["code.scan"][0].text.upper()
    per_class["code.scan"][1] = st.Wording(shouted, ("fqdn",), "hand")
    problems = st.check_wordings(per_class, seen=[])
    assert any("are the same wording" in p for p in problems)
    per_class = lists()
    per_class["code.secrets"][3] = per_class["network.scan"][2]
    assert any("are the same wording" in p and "network.scan#2" in p
               for p in st.check_wordings(per_class, seen=[]))


def test_near_duplicates_are_refused_at_the_limit_and_not_below_it():
    per_class = lists(("code.scan",))
    base = per_class["code.scan"][0].text                    # five words and {t}
    close = " ".join(base.split()[:4]) + " zzzz on {t}"       # 5 shared of 7 tokens: 0.71
    per_class["code.scan"][1] = st.Wording(close, ("fqdn",), "hand")
    assert any("near-duplicates" in p for p in st.check_wordings(per_class, seen=[]))
    assert st.jaccard("a b c d e f", "a b c d e g") == pytest.approx(5 / 7)
    assert st.jaccard("a b c d {t}", "a b x y {t}") == pytest.approx(3 / 7)   # below the limit
    third = " ".join(base.split()[:2]) + " yyyy xxxx on {t}"  # 3 shared of 7 tokens: 0.43
    per_class = lists(("code.scan",))
    per_class["code.scan"][1] = st.Wording(third, ("fqdn",), "hand")
    assert not any("near-duplicates" in p for p in st.check_wordings(per_class, seen=[]))


def test_exactly_at_the_limit_two_wordings_are_one_wording():
    """3 shared tokens of 5 is exactly 0.6, which is "at or above"."""
    assert st.jaccard("a b {t}", "a b {t} c d") == 0.6
    per_class = {"code.scan": [st.Wording("a b {t}", ("fqdn",), "hand"),
                               st.Wording("a b {t} c d", ("fqdn",), "hand")]}
    problems = st.check_wordings(per_class, expected=2, seen=[])
    assert len(problems) == 1 and "near-duplicates" in problems[0]
    per_class["code.scan"][1] = st.Wording("a b {t} c d e", ("fqdn",), "hand")        # 3 of 6
    assert st.check_wordings(per_class, expected=2, seen=[]) == []


def test_a_target_already_used_is_never_used_again(monkeypatch):
    """Whatever the draws give, no two calls share a target: the generator is made to repeat."""
    drawn = iter(["10.1.1.1", "10.1.1.1", "10.1.1.1", "10.1.1.2", "10.1.1.2", "10.1.1.3"] + [
        f"10.2.{i // 250}.{i % 250 + 2}" for i in range(50)])
    monkeypatch.setattr(st, "make_target", lambda kind, rng: next(drawn))
    per_class = {"network.scan": [st.Wording("a b {t}", ("ip",), "real"),
                                  st.Wording("c d {t}", ("ip",), "real")]}
    targets = st.allocate_targets(per_class)
    assert len(targets) == 6 and len(set(targets.values())) == 6


def test_a_wording_close_to_one_the_validator_was_already_measured_on_is_refused():
    seen = st.seen_wordings()
    assert "Scan {t} for open ports and the services behind them" in seen       # S7 and run 1
    assert "Find which TCP services {t} exposes and what versions they report" in seen    # S7 only
    assert "Scan the source at {t} for insecure patterns" in seen               # run 1
    assert "Scan the repository at {t} for committed secrets" in seen
    per_class = lists(("code.scan",))
    per_class["code.scan"][0] = st.Wording("Scan the source at {t} for insecure patterns, please",
                                           ("fqdn",), "hand")
    problems = st.check_wordings(per_class)
    assert len(problems) == 1 and "already measured on" in problems[0]
    assert st.check_wordings(lists(("code.scan",))) == []                        # synthetic: far


def test_the_file_hash_is_the_sha256_of_its_bytes(tmp_path):
    write_dir(tmp_path, lists(("code.scan",)))
    ws, digest = st.read_wordings(tmp_path / "code.scan.json")
    assert digest == hashlib.sha256((tmp_path / "code.scan.json").read_bytes()).hexdigest()
    assert len(ws) == 60 and ws[0].kinds == ("fqdn",) and ws[0].source == "hand"


# -- the dry run ----------------------------------------------------------------

def test_the_dry_run_prints_the_plan_the_hashes_the_caps_and_exits_zero(
        tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    seen = clean_world(monkeypatch, banner=("database: stub_db", "migration revision: 0030"))
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert st.main(["--wordings-dir", str(tmp_path)]) == st.EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("DRY RUN (stage 1, registration 1: DRAFT, not pre-registered)")
    for needle in ("no model is called", "database: stub_db", "migration revision: 0030",
                   "startup guards: ok -- goal_fit_enforce is off",
                   "calls: Leg A 540", "Leg B 30", "total 570",
                   "hard caps: 630 CLI runs, US$7.50, 45 minutes", "estimate: US$5.02",
                   "plan checks: ok", "execution: not built"):
        assert needle in out, needle
    for cls in st.CLASSES:
        digest = hashlib.sha256((tmp_path / f"{cls}.json").read_bytes()).hexdigest()
        assert digest in out
    assert seen == [{"allow_nonempty": True, "rehearsal": False}]


def test_the_case_without_the_code_classes_is_190_calls(tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists(("network.scan",)))
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert st.main(["--wordings-dir", str(tmp_path), "--classes", "network.scan"]) == st.EXIT_OK
    out = capsys.readouterr().out
    assert "calls: Leg A 180" in out and "Leg B 10" in out and "total 190" in out
    assert "hard caps: 210 CLI runs, US$2.50, 15 minutes" in out and "estimate: US$1.67" in out


def test_a_guard_that_refuses_makes_the_dry_run_exit_one(tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    clean_world(monkeypatch, guards=["goal_fit_enforce is not off in the effective policy (...)"])
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert st.main(["--wordings-dir", str(tmp_path)]) == st.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "startup guards: REFUSED" in captured.out
    assert "REFUSED: goal_fit_enforce is not off" in captured.err


def test_a_database_that_cannot_be_read_makes_the_dry_run_exit_one(tmp_path, capsys, monkeypatch):
    from scripts import dp15_record_mode as rm

    write_dir(tmp_path, lists())

    def unreadable(**kw):
        raise OSError("connection refused")

    monkeypatch.setattr(rm, "check_startup", unreadable)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert st.main(["--wordings-dir", str(tmp_path)]) == st.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "database: NOT READ (OSError)" in captured.out
    assert "REFUSED: the database could not be read" in captured.err
    assert "calls: Leg A 540" in captured.out                  # the plan is still shown


def test_a_missing_or_unsound_wording_file_is_a_plan_problem(tmp_path, capsys, monkeypatch):
    per_class = lists()
    del per_class["code.secrets"]
    write_dir(tmp_path, per_class)
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert st.main(["--wordings-dir", str(tmp_path)]) == st.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "PLAN PROBLEM: code.secrets: no wording file at" in captured.err
    assert "calls: Leg A 0" in captured.out and "total 0" in captured.out       # no plan is built
    assert "plan checks: 1 problem(s)" in captured.out


def test_an_unsound_wording_file_is_a_plan_problem_and_no_plan_is_built(
        tmp_path, capsys, monkeypatch):
    per_class = lists()
    per_class["code.scan"] = per_class["code.scan"][:59]
    write_dir(tmp_path, per_class)
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert st.main(["--wordings-dir", str(tmp_path)]) == st.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "PLAN PROBLEM: code.scan: 59 wordings, the plan needs exactly 60" in captured.err
    assert "total 0" in captured.out


def test_an_unknown_class_is_a_usage_error(tmp_path, capsys, monkeypatch):
    clean_world(monkeypatch)
    assert st.main(["--wordings-dir", str(tmp_path), "--classes", "web.get"]) == st.EXIT_USAGE
    assert "unknown class" in capsys.readouterr().err


def test_execute_is_refused_and_nothing_else_happens(tmp_path, capsys, monkeypatch):
    called = clean_world(monkeypatch)
    assert st.main(["--wordings-dir", str(tmp_path), "--execute"]) == st.EXIT_USAGE
    captured = capsys.readouterr()
    assert "the stage-1 run is not built" in captured.err and captured.out == ""
    assert called == []                                        # not even the database was read


# -- no model, nothing written --------------------------------------------------

def test_the_dry_run_calls_no_model_and_starts_no_process(tmp_path, capsys, monkeypatch):
    import agents.llm.selection as selection

    def boom(*a, **k):
        raise AssertionError("the dry run reached for a model or a process")

    monkeypatch.setattr(selection, "build_plan_fit_validator", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    write_dir(tmp_path, lists())
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert st.main(["--wordings-dir", str(tmp_path)]) == st.EXIT_OK


def test_the_script_names_no_validator_no_process_and_no_write():
    tree = ast.parse(SCRIPT.read_text())
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
              for a in n.names}
    for forbidden in ("build_plan_fit_validator", "subprocess", "propose_action",
                      "create_engagement", "publish_policy_layer", "publish_engagement_policy",
                      "record_and_review", "record_views", "clear_suspension", "Popen"):
        assert forbidden not in names, forbidden
    source = SCRIPT.read_text()
    for write in ("INSERT", "UPDATE ", "DELETE", "open(", "write_text", "write_bytes"):
        assert write not in source, write


@pytest.mark.usefixtures("db_available")
def test_against_the_real_database_the_banner_comes_first_and_the_switch_reads_off(
        tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    code = st.main(["--wordings-dir", str(tmp_path)])
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0].startswith("DRY RUN (stage 1")
    assert lines[1].startswith("database: ") and lines[2].startswith("migration revision: ")
    assert "goal_fit_enforce: off" in out
    assert code == st.EXIT_OK
