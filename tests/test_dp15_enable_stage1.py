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


def plan_text(hashes):
    """A plan whose wording-hashes block registers ``hashes`` (class -> sha256)."""
    lines = "\n".join(f"{cls} {digest}" for cls, digest in hashes.items())
    return f"# plan\n\nprose\n\n```{st.HASH_BLOCK}\n# class sha256\n{lines}\n```\n\nmore prose\n"


def write_dir(tmp_path, per_class):
    """The wording files, and next to them ``plan.md`` registering exactly those files."""
    hashes = {}
    for cls, ws in per_class.items():
        document = {"class": cls, "wordings": [
            {"text": w.text, "kinds": list(w.kinds), "source": w.source} for w in ws]}
        (tmp_path / f"{cls}.json").write_text(json.dumps(document))
        hashes[cls] = hashlib.sha256((tmp_path / f"{cls}.json").read_bytes()).hexdigest()
    (tmp_path / "plan.md").write_text(plan_text(hashes))
    return tmp_path


def run(tmp_path, *extra):
    return st.main(["--wordings-dir", str(tmp_path), "--plan", str(tmp_path / "plan.md"), *extra])


def clean_world(monkeypatch, *, guards=(), banner=("database: stub",),
                leg_b=("cyberorch_dp15b", 0, 0)):
    from scripts import dp15_record_mode as rm

    seen = []

    def check(**kw):
        seen.append(kw)
        return list(banner), list(guards)

    monkeypatch.setattr(rm, "check_startup", check)
    monkeypatch.setattr(st, "read_leg_b_facts", lambda: st.LegBFacts(*leg_b))
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
    assert run(tmp_path) == st.EXIT_OK
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
    assert run(tmp_path, "--classes", "network.scan") == st.EXIT_OK
    out = capsys.readouterr().out
    assert "calls: Leg A 180" in out and "Leg B 10" in out and "total 190" in out
    assert "hard caps: 210 CLI runs, US$2.50, 15 minutes" in out and "estimate: US$1.67" in out


def test_a_guard_that_refuses_makes_the_dry_run_exit_one(tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    clean_world(monkeypatch, guards=["goal_fit_enforce is not off in the effective policy (...)"])
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_REFUSED
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
    assert run(tmp_path) == st.EXIT_REFUSED
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
    assert run(tmp_path) == st.EXIT_REFUSED
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
    assert run(tmp_path) == st.EXIT_REFUSED
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
    assert run(tmp_path) == st.EXIT_OK


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
    code = run(tmp_path)
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0].startswith("DRY RUN (stage 1")
    assert lines[1].startswith("database: ") and lines[2].startswith("migration revision: ")
    assert "goal_fit_enforce: off" in out
    leg_b = next(line for line in lines if line.startswith("Leg B database: "))
    if leg_b.startswith(f"Leg B database: {st.LEG_B_DATABASE} --"):
        assert code in (st.EXIT_OK, st.EXIT_REFUSED)       # refused only if that database is dirty
    else:
        assert code == st.EXIT_REFUSED and leg_b.endswith("REFUSED")   # any other database


@pytest.mark.usefixtures("db_available")
def test_the_real_leg_b_facts_are_read_in_a_read_only_transaction():
    facts = st.read_leg_b_facts()
    assert isinstance(facts.database, str) and facts.database
    assert isinstance(facts.calls, int) and isinstance(facts.suspensions, int)
    import inspect

    assert "SET TRANSACTION READ ONLY" in inspect.getsource(st.read_leg_b_facts)


# -- the registered hashes ------------------------------------------------------

GOOD = "a" * 64
OTHER = "b" * 64


def test_the_registration_is_read_from_exactly_one_block():
    text = plan_text({"network.scan": GOOD, "code.scan": OTHER})
    assert st.registered_hashes(text) == ({"network.scan": GOOD, "code.scan": OTHER}, [])


@pytest.mark.parametrize("text", [
    "no block at all",
    plan_text({"code.scan": GOOD}) + plan_text({"code.scan": GOOD}),                # two blocks
])
def test_a_plan_without_exactly_one_block_registers_nothing(text):
    registered, problems = st.registered_hashes(text)
    assert registered == {} and len(problems) == 1 and "exactly one" in problems[0]


@pytest.mark.parametrize("line", [
    "code.scan " + "A" * 64,                       # upper case
    "code.scan " + "a" * 63,                       # short
    "code.scan " + "a" * 65,                       # long
    "code.scan " + "g" * 64,                       # not hex
    "web.get " + GOOD,                             # a class the plan does not have
    "code.scan",                                   # no hash
    "code.scan " + GOOD + " extra",                # a third column
])
def test_a_malformed_line_makes_the_whole_registration_void(line):
    registered, problems = st.registered_hashes(
        f"```{st.HASH_BLOCK}\nnetwork.scan {GOOD}\n{line}\n```\n")
    assert registered == {}                        # the good line is not trusted either
    assert len(problems) == 1 and "malformed line" in problems[0]


def test_a_class_registered_twice_makes_the_whole_registration_void():
    registered, problems = st.registered_hashes(
        f"```{st.HASH_BLOCK}\ncode.scan {GOOD}\ncode.scan {OTHER}\n```\n")
    assert registered == {} and problems == [
        f"code.scan is registered twice in the {st.HASH_BLOCK} block"]


def test_blank_and_comment_lines_in_the_block_are_ignored():
    text = f"```{st.HASH_BLOCK}\n\n# a comment\ncode.scan {GOOD}\n   \n```\n"
    assert st.registered_hashes(text) == ({"code.scan": GOOD}, [])


def test_a_file_that_is_not_the_registered_one_is_named_with_both_hashes():
    problems = st.hash_problems({"code.scan": GOOD}, {"code.scan": OTHER}, ("code.scan",))
    assert len(problems) == 1
    assert GOOD in problems[0] and OTHER in problems[0] and "not the registered one" in problems[0]
    assert st.hash_problems({"code.scan": GOOD}, {"code.scan": GOOD}, ("code.scan",)) == []


def test_a_file_the_plan_does_not_register_is_refused_and_an_unread_class_is_not_judged():
    problems = st.hash_problems({}, {"code.scan": GOOD}, ("code.scan",))
    assert len(problems) == 1 and "registers no sha256" in problems[0]
    assert st.hash_problems({}, {}, ("code.scan",)) == []        # a missing file is reported apart


def test_the_dry_run_refuses_a_wording_file_changed_after_registration(
        tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    registered = hashlib.sha256((tmp_path / "code.scan.json").read_bytes()).hexdigest()
    path = tmp_path / "code.scan.json"
    path.write_bytes(path.read_bytes() + b"\n")                  # one byte; the JSON is still sound
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "PLAN PROBLEM: code.scan: the wording file is not the registered one" in captured.err
    assert registered in captured.err and actual in captured.err
    assert "total 0" in captured.out                              # no plan is built
    assert "network.scan: the wording file" not in captured.err   # the other files are fine


def test_the_dry_run_compares_each_file_with_its_own_class_registration(
        tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    hashes = {c: hashlib.sha256((tmp_path / f"{c}.json").read_bytes()).hexdigest()
              for c in st.CLASSES}
    swapped = dict(hashes, **{"code.scan": hashes["code.secrets"],
                              "code.secrets": hashes["code.scan"]})
    (tmp_path / "plan.md").write_text(plan_text(swapped))
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "code.scan: the wording file is not the registered one" in err
    assert "code.secrets: the wording file is not the registered one" in err


def test_the_dry_run_refuses_a_class_the_plan_does_not_register(tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    hashes = {c: hashlib.sha256((tmp_path / f"{c}.json").read_bytes()).hexdigest()
              for c in st.CLASSES if c != "code.secrets"}
    (tmp_path / "plan.md").write_text(plan_text(hashes))
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "code.secrets: the plan registers no sha256" in captured.err
    assert "total 0" in captured.out


@pytest.mark.parametrize("plan", ["missing", "no block", "bad line"])
def test_the_dry_run_refuses_when_the_registration_cannot_be_trusted(
        plan, tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    if plan == "missing":
        (tmp_path / "plan.md").unlink()
    elif plan == "no block":
        (tmp_path / "plan.md").write_text("nothing registered here")
    else:
        (tmp_path / "plan.md").write_text(f"```{st.HASH_BLOCK}\ncode.scan nothex\n```\n")
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "PLAN PROBLEM:" in captured.err and "total 0" in captured.out


def test_the_unreadable_plan_does_not_also_report_every_file_as_unregistered(
        tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    (tmp_path / "plan.md").unlink()
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    run(tmp_path)
    err = capsys.readouterr().err
    assert "the plan could not be read" in err and "registers no sha256" not in err


def test_a_sound_registered_set_passes_and_the_hash_is_of_the_bytes_as_they_are(
        tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    clean_world(monkeypatch)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_OK
    assert "not the registered one" not in capsys.readouterr().err


# -- the database of Leg B ------------------------------------------------------

def test_leg_b_wants_its_own_clean_database():
    assert st.LEG_B_DATABASE == "cyberorch_dp15b"
    assert st.leg_b_problems(st.LegBFacts("cyberorch_dp15b", 0, 0)) == []


@pytest.mark.parametrize("facts, needle", [
    (("cyberorch_dp15", 0, 0), "Leg B runs in database 'cyberorch_dp15b', this one is "
                               "'cyberorch_dp15'"),
    (("cyberorch", 0, 0), "this one is 'cyberorch'"),
    (("cyberorch_dp15b", 1, 0), "goal_fit_calls in database 'cyberorch_dp15b' holds 1 row(s)"),
    (("cyberorch_dp15b", 0, 2), "goal_fit_suspensions in database 'cyberorch_dp15b' holds 2"),
])
def test_leg_b_refuses_another_database_and_a_database_that_is_not_empty(facts, needle):
    problems = st.leg_b_problems(st.LegBFacts(*facts))
    assert len(problems) == 1 and needle in problems[0]


def test_leg_b_reports_every_reason_at_once_and_the_expected_name_can_be_chosen():
    assert len(st.leg_b_problems(st.LegBFacts("x", 3, 4))) == 3
    assert st.leg_b_problems(st.LegBFacts("x", 0, 0), "x") == []


def test_the_dry_run_shows_the_leg_b_database_and_passes_when_it_is_clean(
        tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    clean_world(monkeypatch, leg_b=("cyberorch_dp15b", 0, 0))
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_OK
    assert ("Leg B database: cyberorch_dp15b -- goal_fit_calls 0 row(s), goal_fit_suspensions 0 "
            "row(s); clean, as Leg B needs") in capsys.readouterr().out


@pytest.mark.parametrize("leg_b, needle", [
    (("cyberorch_dp15", 0, 0), "Leg B runs in database 'cyberorch_dp15b'"),
    (("cyberorch_dp15b", 150, 0), "holds 150 row(s): Leg B needs it empty"),
    (("cyberorch_dp15b", 0, 1), "goal_fit_suspensions in database 'cyberorch_dp15b' holds 1"),
])
def test_the_dry_run_refuses_a_leg_b_database_that_is_wrong_or_dirty(
        leg_b, needle, tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    clean_world(monkeypatch, leg_b=leg_b)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_REFUSED
    captured = capsys.readouterr()
    assert needle in captured.err and captured.err.count("REFUSED: ") == 1
    assert "; REFUSED" in captured.out
    assert "startup guards: ok" in captured.out       # the enforce guard is a separate line


def test_the_dry_run_accepts_another_expected_leg_b_database_by_flag(
        tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    clean_world(monkeypatch, leg_b=("elsewhere", 0, 0))
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_REFUSED
    capsys.readouterr()
    assert run(tmp_path, "--leg-b-database", "elsewhere") == st.EXIT_OK


def test_the_leg_b_facts_that_cannot_be_read_refuse_the_dry_run(tmp_path, capsys, monkeypatch):
    write_dir(tmp_path, lists())
    clean_world(monkeypatch)

    def unreadable():
        raise OSError("connection refused")

    monkeypatch.setattr(st, "read_leg_b_facts", unreadable)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    assert run(tmp_path) == st.EXIT_REFUSED
    assert "the database could not be read" in capsys.readouterr().err
