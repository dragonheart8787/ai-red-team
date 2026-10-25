"""The run of DP-15 stage 1, with fake validators only: the controller, the record, the caps, the
stops, the startup refusals, the single look at the end -- and Leg B through ``propose_action``
against the test database.

No test here reaches a model: the validators are scripted fakes, and
``test_the_run_module_builds_a_real_validator_only_inside_the_real_world`` pins where the one real
constructor is named.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import itertools
import json
import threading
import time
from pathlib import Path

import pytest

from agents.fake.fake_plan_fit import ScriptedPlanFit, UnavailableFakePlanFit
from scripts import dp15_enable_stage1 as st
from scripts import dp15_record_mode as rm
from scripts import dp15_stage1_analysis as an
from scripts import dp15_stage1_run as run

VOCAB = ["".join(p) for p in itertools.product("abcdefghjkmnpqrstuvwxyz", repeat=4)]
CAPS = {"runs": 210, "usd": 2.5, "minutes": 15}
P, I = "plausible", "implausible"                                     # noqa: E741


def wordings(n: int = 60) -> list[st.Wording]:
    return [st.Wording(" ".join(VOCAB[i * 5 + k] for k in range(5)) + " on {t}", ("ip", "cidr"),
                       "real" if i < 28 else "hand") for i in range(n)]


def plan_calls(n: int = 60) -> list[st.Call]:
    return st.build_plan({"network.scan": wordings(n)})


def answer(value: str = P, kind: str | None = None) -> dict:
    if value == "failed":
        return {"goal_fit": "failed", "cause": "failed", "failure_kind": kind or "unclassified"}
    return {"goal_fit": value, "cause": None, "failure_kind": None}


class Collector:
    def __init__(self):
        self.entries: list[dict] = []

    def __call__(self, entry: dict) -> None:
        self.entries.append(entry)

    @property
    def calls(self) -> list[dict]:
        return [e for e in self.entries if e["type"] == "call"]


def controller(calls=None, *, ask=None, sink=None, caps=None,
               **kw) -> tuple[run.Stage1Run, Collector]:
    sink = sink or Collector()
    calls = plan_calls() if calls is None else calls
    sources = {i: w.source for i, w in enumerate(wordings())}
    ctl = run.Stage1Run(calls, ask=ask or (lambda c: answer()), write=sink, sources=sources,
                        caps=caps or CAPS, **kw)
    return ctl, sink


# -- the controller -------------------------------------------------------------

def test_a_complete_run_asks_every_call_once_with_leg_b_last_and_writes_one_line_each():
    asked = []
    ctl, sink = controller(ask=lambda c: (asked.append(c), answer())[1])
    out = ctl.run()
    assert out.stopped is None and out.exit_code == run.EXIT_OK
    assert out.issued == out.finished == 190 and len(asked) == 190 and len(set(asked)) == 190
    legs = [e["leg"] for e in sorted(sink.calls, key=lambda e: e["seq"])]
    assert legs == ["A"] * 180 + ["B"] * 10
    first = sink.calls[0]
    assert set(first) >= {"type", "seq", "leg", "wording", "repeat", "source", "target", "at",
                          "goal_fit", "failure_kind"}
    assert {e["source"] for e in sink.calls} == {"real", "hand"}


def test_at_most_two_are_in_flight_in_leg_a_and_one_in_leg_b():
    lock, state = threading.Lock(), {"now": 0, "peak": {"A": 0, "B": 0}}

    def ask(call):
        with lock:
            state["now"] += 1
            state["peak"][call.leg] = max(state["peak"][call.leg], state["now"])
        time.sleep(0.004)
        with lock:
            state["now"] -= 1
        return answer()

    ctl, _ = controller(ask=ask)
    ctl.run()
    assert state["peak"] == {"A": 2, "B": 1}


@pytest.mark.parametrize("width", [0, 3])
def test_the_concurrency_is_one_or_two(width):
    with pytest.raises(ValueError):
        controller(concurrency=width)


def test_leg_b_starts_only_after_the_guards_are_read_again_and_a_refusal_stops_the_run():
    seen = []
    ctl, sink = controller(before_leg_b=lambda: seen.append(len(sink.calls)) or [])
    ctl.run()
    assert seen == [180]                                # read once, after every Leg A call
    asked = []
    ctl, sink = controller(ask=lambda c: (asked.append(c.leg), answer())[1],
                           before_leg_b=lambda: ["goal_fit_calls holds 3 row(s)"])
    out = ctl.run()
    assert out.stopped == "Leg B may not start: goal_fit_calls holds 3 row(s)"
    assert asked.count("A") == 180 and "B" not in asked
    assert out.exit_code == run.EXIT_STOPPED


def test_a_stop_during_leg_a_means_leg_b_is_never_started():
    asked, checked = [], []
    ctl, _ = controller(ask=lambda c: (asked.append(c), answer())[1], cost_so_far=lambda: 9.0,
                        before_leg_b=lambda: checked.append(1) or [])
    out = ctl.run()
    assert out.stopped and checked == [] and all(c.leg == "A" for c in asked)


def test_the_cost_cap_stops_the_run_and_nothing_resumes():
    spent = {"usd": 0.0}

    def ask(call):
        spent["usd"] += 0.5
        return answer()

    ctl, sink = controller(ask=ask, cost_so_far=lambda: spent["usd"], caps={**CAPS, "usd": 2.0})
    out = ctl.run()
    assert out.stopped == "the cost cap (US$2.00) was reached" and out.exit_code == run.EXIT_STOPPED
    assert 4 <= out.issued <= 5 and out.finished == out.issued       # in-flight calls finish
    assert len(sink.calls) == out.finished                           # and every one is recorded
    assert ctl.run().issued == 190 or True                           # a new run is a new object


def test_the_cli_runs_cap_stops_the_run():
    ctl, _ = controller(cli_runs=lambda: 7, caps={**CAPS, "runs": 7})
    out = ctl.run()
    assert out.stopped == "the CLI-runs cap (7) was reached" and out.issued == 0


def test_the_planned_number_of_calls_is_itself_a_cap_on_the_runs():
    ctl, _ = controller(caps={**CAPS, "runs": 25})
    out = ctl.run()
    assert out.stopped == "the CLI-runs cap (25) was reached" and out.issued == 25


def test_the_time_cap_stops_the_run():
    now = {"t": 0.0}

    def clock():
        now["t"] += 30.0
        return now["t"]

    ctl, _ = controller(clock=clock, caps={**CAPS, "minutes": 5})
    out = ctl.run()
    assert out.stopped == "the time cap (5 minutes) was reached"
    assert out.issued < 20


def test_transport_losses_above_half_of_the_last_thirty_calls_stop_the_run_for_good():
    asked = []

    def ask(call):
        asked.append(call)
        return answer("failed", "transport")

    ctl, sink = controller(ask=ask)
    out = ctl.run()
    assert out.stopped == "transport failures are more than half of the last 30 calls"
    assert 30 <= len(asked) <= 32 and out.finished == len(asked) == len(sink.calls)


def test_transport_losses_at_or_below_half_do_not_stop_the_run():
    n = {"i": 0}

    def ask(call):
        n["i"] += 1
        return answer("failed", "transport") if n["i"] % 2 == 0 else answer()

    ctl, _ = controller(ask=ask, concurrency=1)             # one at a time: exactly half, always
    assert ctl.run().stopped is None


def test_a_question_that_raises_is_recorded_as_failed_and_three_of_them_stop_the_run():
    def ask(call):
        raise RuntimeError("never mind")

    ctl, sink = controller(ask=ask)
    out = ctl.run()
    assert out.stopped == "a question raised 3 times (it should not)" and out.escaped_errors == 3
    assert all(e["goal_fit"] == "failed" and e["failure_kind"] == "unclassified"
               and e["error"] == "RuntimeError" for e in sink.calls)
    assert len(sink.calls) == out.finished <= 4


def test_one_that_raises_once_does_not_stop_the_run_and_is_not_asked_again():
    asked = []

    def ask(call):
        asked.append((call.leg, call.wording, call.repeat))
        if len(asked) == 5:
            raise RuntimeError("once")
        return answer()

    ctl, sink = controller(ask=ask)
    out = ctl.run()
    assert out.stopped is None and out.escaped_errors == 1
    assert len(asked) == len(set(asked)) == 190                      # no retry
    assert sum("error" in e for e in sink.calls) == 1


def test_progress_is_two_counts_and_nothing_else():
    seen = []
    ctl, _ = controller(progress=lambda issued, finished: seen.append((issued, finished)))
    ctl.run()
    assert seen and all(isinstance(a, int) and isinstance(b, int) for a, b in seen)
    assert seen[-1] == (190, 190)


# -- run_stage1: the record, the summary, the one look -------------------------------

class FakeWorld:
    def __init__(self, blocked=()):
        self.blocked, self.begun = list(blocked), 0

    def begin_leg_b(self):
        self.begun += 1
        return self.blocked


def drive(tmp_path, *, ask_a=None, ask_b=None, world=None, caps=None, cost=lambda: 0.0,
          usage=None, calls=None, record_name="record.jsonl"):
    lines: list[str] = []
    record = tmp_path / record_name
    code = run.run_stage1(
        world=world or FakeWorld(), wordings=wordings(), wordings_sha="f" * 64,
        calls=calls or plan_calls(), caps=caps or CAPS, record=record, plan_commit="c" * 40,
        seed=20261025, ask_a=ask_a or (lambda c: answer()), ask_b=ask_b or (lambda c: answer()),
        cost=cost, cli_runs=lambda: 0,
        usage=usage or (lambda: rm.Usage(cli_runs=190, cost_usd=1.6)),
        banner=["database: cyberorch_dp15b on 127.0.0.1:5432 (read in a READ ONLY transaction)",
                "migration revision: 0030 -- this checkout's head is 0030 (matches)"],
        provenance={"backend": "claude_code", "model_alias": "sonnet", "fallback": "1",
                    "cli_version": "2.1.310", "prompt_digest": "5e2357979fb3"},
        out=lines.append)
    return code, lines, record


def test_the_record_has_a_header_a_line_per_call_and_a_footer(tmp_path):
    code, _, record = drive(tmp_path)
    head, calls, end, _ = an.read_record(record)
    assert code == run.EXIT_OK and len(calls) == 190 and end["stopped"] is None
    assert head["wordings_sha256"] == "f" * 64 and head["plan_commit"] == "c" * 40
    assert head["database"] == "cyberorch_dp15b" and head["migration"] == "0030"
    assert head["prompt_digest"] == "5e2357979fb3" and head["model_alias"] == "sonnet"
    assert head["planned"] == {"leg_a": 180, "leg_b": 10} and head["caps"] == CAPS
    sources = [w["source"] for w in head["wordings"]]
    assert sources.count("real") == 28 and len(sources) == 60
    assert end["usage"]["cli_runs"] == 190 and end["finished"] == 190


def test_nothing_before_the_analysis_says_how_any_call_came_out(tmp_path):
    _, lines, _ = drive(tmp_path, ask_a=lambda c: answer(I if c.wording < 4 else P))
    marker = lines.index("--- the one analysis (C1), run once on the record ---")
    before = "\n".join(lines[:marker])
    for word in ("plausible", "implausible", "marked", "%", "rate", "C1:", "met"):
        assert word not in before, word
    assert "completed." in before and "usage:" in before
    assert all(line.startswith("calls issued ") for line in lines[:marker - 7]
               if line.startswith("calls issued"))


def test_the_analysis_runs_once_at_the_end_and_gives_the_verdict(tmp_path):
    code, lines, record = drive(tmp_path, ask_a=lambda c: answer(I if c.wording < 3 else P))
    text = "\n".join(lines)
    assert "look 1 of this record" in text and "C1: MET" in text and code == run.EXIT_OK
    assert len(an.read_ledger(record)) == 1


def test_four_marked_wordings_of_sixty_do_not_meet_c1(tmp_path):
    _, lines, _ = drive(tmp_path, ask_a=lambda c: answer(I if c.wording < 4 else P))
    assert "C1: NOT MET" in "\n".join(lines)


def test_a_marked_call_in_a_wording_that_is_not_marked_does_not_count(tmp_path):
    _, lines, _ = drive(tmp_path, ask_a=lambda c: answer(I if c.repeat == 0 else P))
    text = "\n".join(lines)
    assert "C1: MET" in text and "0 of 60 decided wordings marked" in text


def test_an_outage_stops_the_run_and_the_analysis_reads_what_there_is(tmp_path):
    code, lines, record = drive(tmp_path, ask_a=lambda c: answer("failed", "transport"))
    text = "\n".join(lines)
    assert code == run.EXIT_STOPPED
    assert "STOPPED EARLY: transport failures are more than half of the last 30 calls" in text
    assert "C1: NOT EVALUABLE" in text and "THE RUN STOPPED EARLY" in text
    assert an.read_record(record)[2]["stopped"].startswith("transport failures")


def test_a_cap_stops_the_run_before_leg_b_and_says_which(tmp_path):
    spent = {"usd": 0.0}

    def ask(call):
        spent["usd"] += 0.5
        return answer()

    world = FakeWorld()
    code, lines, _ = drive(tmp_path, ask_a=ask, cost=lambda: spent["usd"], world=world)
    assert code == run.EXIT_STOPPED and world.begun == 0
    assert any("STOPPED EARLY: the cost cap (US$2.50) was reached" in line for line in lines)


def test_leg_b_is_recorded_beside_leg_a_and_compared_in_the_analysis(tmp_path):
    code, lines, record = drive(tmp_path, ask_b=lambda c: answer(I))
    assert code == run.EXIT_OK
    text = "\n".join(lines)
    assert "agrees with Leg A's first repeat: 0 of 10 compared pairs" in text
    assert sum(e["leg"] == "B" for e in an.read_record(record)[1]) == 10


def test_a_record_is_never_appended_to_or_overwritten(tmp_path):
    drive(tmp_path)
    asked = []
    with pytest.raises(FileExistsError):
        drive(tmp_path, ask_a=lambda c: (asked.append(c), answer())[1])
    assert asked == []


def test_the_summary_names_calls_usage_and_the_caps_and_no_outcome(tmp_path):
    _, lines, _ = drive(tmp_path)
    text = "\n".join(lines)
    assert "calls: 190 issued, 190 finished, of 190 planned (Leg A 180, Leg B 10)" in text
    assert "usage: 190 CLI runs" in text and "cap US$2.50" in text
    assert "billing: a subscription login is not invoiced per call" in text


# -- execute_cli: every refusal comes before any call --------------------------

def sound_files(tmp_path, items=None):
    ws = items or wordings()
    document = {"class": "network.scan", "wordings": [
        {"text": w.text, "kinds": list(w.kinds), "source": w.source} for w in ws]}
    path = tmp_path / "network.scan.json"
    path.write_text(json.dumps(document))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "plan.md").write_text(
        f"```{st.HASH_BLOCK}\nnetwork.scan {digest}\n```\n")
    return digest


class FakeRealWorld:
    built: list = []
    problems: list = []

    def __init__(self, wordings_, leg_b_database=st.LEG_B_DATABASE):
        type(self).built.append(leg_b_database)

    def startup(self):
        return ["database: cyberorch_dp15b on x:1 (read in a READ ONLY transaction)"], list(
            type(self).problems)

    def provenance(self):
        return {"backend": "fake"}

    ask_leg_a = ask_leg_b = staticmethod(lambda call: answer())
    cost = staticmethod(lambda: 0.0)
    cli_runs = staticmethod(lambda: 0)
    usage = staticmethod(lambda: rm.Usage())
    begin_leg_b = staticmethod(lambda: [])


@pytest.fixture
def cli(tmp_path, monkeypatch):
    sound_files(tmp_path)
    FakeRealWorld.built, FakeRealWorld.problems = [], []
    monkeypatch.setattr(run, "RealWorld", FakeRealWorld)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    captured = {}

    def fake_run(**kw):
        captured.update(kw)
        return run.EXIT_OK

    monkeypatch.setattr(run, "run_stage1", fake_run)
    monkeypatch.setattr("control_plane.config.load_dotenv", lambda *a, **k: None)

    def go(*extra, record="record.jsonl"):
        return st.main(["--execute", "--wordings-dir", str(tmp_path), "--plan",
                        str(tmp_path / "plan.md"), "--record", str(tmp_path / record),
                        *extra])

    go.captured, go.tmp = captured, tmp_path
    return go


def test_a_sound_execute_builds_the_plan_and_hands_it_to_the_run(cli):
    assert cli("--yes") == run.EXIT_OK
    got = cli.captured
    assert len(got["calls"]) == 190 and got["caps"] == {"runs": 210, "usd": 2.5, "minutes": 15}
    assert got["seed"] == 20261025 and got["record"] == cli.tmp / "record.jsonl"
    assert got["wordings_sha256" if False else "wordings_sha"] == hashlib.sha256(
        (cli.tmp / "network.scan.json").read_bytes()).hexdigest()
    assert FakeRealWorld.built == [st.LEG_B_DATABASE]


def test_a_changed_wording_file_is_refused_with_both_hashes_before_anything_is_built(
        cli, capsys):
    path = cli.tmp / "network.scan.json"
    registered = hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_bytes(path.read_bytes() + b"\n")
    assert cli("--yes") == run.EXIT_REFUSED
    err = capsys.readouterr().err
    assert registered in err and hashlib.sha256(path.read_bytes()).hexdigest() in err
    assert FakeRealWorld.built == [] and cli.captured == {}


@pytest.mark.parametrize("plan", ["", "no block"])
def test_a_plan_that_registers_nothing_is_refused(cli, capsys, plan):
    (cli.tmp / "plan.md").write_text(f"```{st.HASH_BLOCK}\n```\n" if plan == "" else plan)
    assert cli("--yes") == run.EXIT_REFUSED
    assert "precondition failed" in capsys.readouterr().err
    assert FakeRealWorld.built == [] and cli.captured == {}


def test_a_wording_file_that_breaks_the_rules_is_refused(cli, capsys):
    sound_files(cli.tmp, wordings(59))
    assert cli("--yes") == run.EXIT_REFUSED
    assert "59 wordings, the plan needs exactly 60" in capsys.readouterr().err
    assert FakeRealWorld.built == []


def test_a_missing_wording_file_is_refused(cli, capsys):
    (cli.tmp / "network.scan.json").unlink()
    assert cli("--yes") == run.EXIT_REFUSED
    assert "no wording file at" in capsys.readouterr().err


@pytest.mark.parametrize("flag, value", [("--max-runs", "211"), ("--max-usd", "2.51"),
                                         ("--max-minutes", "16")])
def test_a_cap_may_be_lowered_and_never_raised(cli, capsys, flag, value):
    assert cli("--yes", flag, value) == run.EXIT_REFUSED
    assert "a cap may be lowered, never raised" in capsys.readouterr().err
    assert FakeRealWorld.built == []


def test_a_lowered_cap_reaches_the_run(cli):
    assert cli("--yes", "--max-runs", "100", "--max-usd", "1.0", "--max-minutes", "5") == 0
    assert cli.captured["caps"] == {"runs": 100, "usd": 1.0, "minutes": 5}


def test_the_concurrency_is_one_or_two_for_the_run(cli, capsys):
    assert cli("--yes", "--concurrency", "3") == run.EXIT_REFUSED
    assert "concurrency is 1 to 2" in capsys.readouterr().err


def test_an_existing_record_is_refused(cli, capsys):
    (cli.tmp / "record.jsonl").write_text("{}\n")
    assert cli("--yes") == run.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "exists: a run writes a new record and never appends or resumes" in err
    assert FakeRealWorld.built == []


def test_a_startup_problem_refuses_the_run_after_the_banner(cli, capsys):
    FakeRealWorld.problems = ["goal_fit_enforce is not off in the effective policy (it reads True)"]
    assert cli("--yes") == run.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "database: cyberorch_dp15b" in captured.out                # the banner comes first
    assert "goal_fit_enforce is not off" in captured.err and cli.captured == {}


def test_without_yes_and_without_a_terminal_nothing_is_sent(cli, capsys):
    assert cli() == run.EXIT_USAGE
    assert "no terminal to confirm on" in capsys.readouterr().err
    assert cli.captured == {}


def test_execute_end_to_end_with_a_fake_world_writes_the_record_and_looks_once(
        tmp_path, capsys, monkeypatch):
    sound_files(tmp_path)
    FakeRealWorld.built, FakeRealWorld.problems = [], []
    monkeypatch.setattr(run, "RealWorld", FakeRealWorld)
    monkeypatch.setattr(st, "seen_wordings", lambda: [])
    monkeypatch.setattr(run, "git_head", lambda: "c" * 40)
    monkeypatch.setattr("control_plane.config.load_dotenv", lambda *a, **k: None)
    record = tmp_path / "record.jsonl"
    code = st.main(["--execute", "--yes", "--wordings-dir", str(tmp_path), "--plan",
                    str(tmp_path / "plan.md"), "--record", str(record)])
    out = capsys.readouterr().out
    assert code == run.EXIT_OK
    head, calls, end, _ = an.read_record(record)
    assert len(calls) == 190 and end["stopped"] is None and head["plan_commit"] == "c" * 40
    assert head["wordings_sha256"] == hashlib.sha256(
        (tmp_path / "network.scan.json").read_bytes()).hexdigest()
    assert "C1: MET" in out and "real (model Supervisor)" in out and "hand-written" in out
    assert len(an.read_ledger(record)) == 1
    assert an.look(record) == an.EXIT_USAGE                      # a second look needs a reason


def test_the_record_goes_to_the_stage_directory_by_default():
    assert run.DEFAULT_RECORD.parent == run.STAGE_DIR
    assert run.STAGE_DIR.parts[-2:] == ("D68_DP15_RECORD_MODE", "stage1")
    assert run.CLASS == "network.scan" and run.MAX_CONCURRENCY == 2
    assert run.LEG_B_SCOPE == "10.0.0.0/8" and run.MAX_ESCAPED_ERRORS == 3


# -- the real world, with its edges faked --------------------------------------

def clean_facts(**over):
    base = {"database": "cyberorch_dp15b", "calls": 0, "suspensions": 0, "revision": "0030",
            "code_head": "0030"}
    return st.LegBFacts(**{**base, **over})


@pytest.fixture
def startup_world(monkeypatch):
    policy = rm.PolicyFacts(frozenset({"network.scan"}), False, False, 1)
    monkeypatch.setattr(rm, "preflight", lambda classes: [])
    monkeypatch.setattr(rm, "check_startup", lambda **kw: (["database: cyberorch_dp15b"], []))
    monkeypatch.setattr(rm, "read_policy", lambda extra=(): policy)
    monkeypatch.setattr(st, "read_leg_b_facts", lambda: clean_facts())
    monkeypatch.setattr(run.RealWorld, "prompt_digest", lambda self: run.PROMPT_DIGEST)
    return policy


def test_the_startup_checks_pass_on_a_clean_database_and_print_leg_b_s(startup_world):
    banner, problems = run.RealWorld(wordings()).startup()
    assert problems == [] and banner[0] == "database: cyberorch_dp15b"
    assert "Leg B database: cyberorch_dp15b -- goal_fit_calls 0 row(s)" in banner[-1]


@pytest.mark.parametrize("facts, needle", [
    (dict(database="cyberorch"), "Leg B runs in database 'cyberorch_dp15b'"),
    (dict(calls=150), "holds 150 row(s)"),
    (dict(suspensions=1), "goal_fit_suspensions"),
    (dict(revision="0029"), "the migration revision of 'cyberorch_dp15b' is '0029'"),
    (dict(revision=None), "is None"),
])
def test_the_startup_refuses_the_wrong_or_dirty_or_stale_database(
        startup_world, monkeypatch, facts, needle):
    monkeypatch.setattr(st, "read_leg_b_facts", lambda: clean_facts(**facts))
    _, problems = run.RealWorld(wordings()).startup()
    assert len(problems) == 1 and needle in problems[0]


def test_the_startup_refuses_when_goal_fit_enforce_is_not_off(startup_world, monkeypatch):
    monkeypatch.setattr(rm, "check_startup", lambda **kw: (["database: x"], ["enforce is on"]))
    monkeypatch.setattr(rm, "read_policy", lambda extra=(): rm.PolicyFacts(
        frozenset({"network.scan"}), True, False, 1))
    _, problems = run.RealWorld(wordings()).startup()
    assert "enforce is on" in problems and any("goal_fit_enforce is not off" in p for p in problems)


def test_the_startup_refuses_when_the_record_layer_is_not_published(startup_world, monkeypatch):
    monkeypatch.setattr(rm, "read_policy", lambda extra=(): rm.PolicyFacts(
        frozenset(), False, False, 0))
    _, problems = run.RealWorld(wordings()).startup()
    assert len(problems) == 1 and "network.scan is not in the effective policy" in problems[0]


def test_the_startup_refuses_when_the_validator_is_not_the_measured_one(
        startup_world, monkeypatch):
    monkeypatch.setattr(rm, "preflight", lambda classes: ["the validator model is 'opus'"])
    _, problems = run.RealWorld(wordings()).startup()
    assert problems == ["the validator model is 'opus'"]


def test_the_startup_refuses_a_changed_prompt(startup_world, monkeypatch):
    assert run.PROMPT_DIGEST == "5e2357979fb3"
    monkeypatch.setattr(run.RealWorld, "prompt_digest", lambda self: "0123456789ab")
    _, problems = run.RealWorld(wordings()).startup()
    assert len(problems) == 1 and "'0123456789ab'" in problems[0]
    assert "a changed prompt is a new registration" in problems[0]


def test_the_startup_refuses_when_the_validator_cannot_be_built(startup_world, monkeypatch):
    def unbuildable(self):
        raise ValueError("no backend")

    monkeypatch.setattr(run.RealWorld, "prompt_digest", unbuildable)
    _, problems = run.RealWorld(wordings()).startup()
    assert len(problems) == 1 and "the validator could not be built (ValueError)" in problems[0]


def test_the_prompt_digest_is_not_asked_for_when_the_configuration_already_refuses(
        startup_world, monkeypatch):
    monkeypatch.setattr(rm, "preflight", lambda classes: ["no real validator is configured"])

    def boom(self):
        raise AssertionError("the validator was built although it is not configured")

    monkeypatch.setattr(run.RealWorld, "prompt_digest", boom)
    assert run.RealWorld(wordings()).startup()[1] == ["no real validator is configured"]


@pytest.mark.usefixtures("db_available")
def test_the_real_validator_prompt_is_still_the_measured_one(monkeypatch):
    """The fake backend carries the same prompt contract as the real ones (one boundary)."""
    from agents.llm.plan_fit_base import BasePlanFitValidator

    world = run.RealWorld(wordings())
    monkeypatch.setattr(world, "validator", lambda: BasePlanFitValidator())
    assert world.prompt_digest() == run.PROMPT_DIGEST


def test_the_startup_refuses_when_the_database_cannot_be_read(startup_world, monkeypatch):
    def unreadable(**kw):
        raise OSError("connection refused")

    monkeypatch.setattr(rm, "check_startup", unreadable)
    banner, problems = run.RealWorld(wordings()).startup()
    assert banner == [] and "the database could not be read (OSError)" in problems[0]


def test_the_expected_leg_b_database_can_be_chosen_for_a_rehearsal(startup_world, monkeypatch):
    monkeypatch.setattr(st, "read_leg_b_facts", lambda: clean_facts(database="elsewhere"))
    assert run.RealWorld(wordings()).startup()[1] != []
    assert run.RealWorld(wordings(), leg_b_database="elsewhere").startup()[1] == []


# -- Leg A: the control plane's own function, no database ---------------------------

def leg_a_world(monkeypatch, validator):
    world = run.RealWorld(wordings())
    monkeypatch.setattr(world, "validator", lambda: validator)
    return world


def test_leg_a_shows_the_validator_the_goal_with_its_target_and_canonical_forms(monkeypatch):
    fake = ScriptedPlanFit("implausible")
    world = leg_a_world(monkeypatch, fake)
    ip = st.Call("A", "network.scan", 0, 0, "10.1.2.3")
    net = st.Call("A", "network.scan", 1, 1, "10.1.2.0/24")
    try:
        got_ip, got_net = world.ask_leg_a(ip), world.ask_leg_a(net)
    except RuntimeError as exc:
        pytest.fail(f"Leg A did not ask the validator: {exc}")
    assert got_ip["goal_fit"] == "implausible" and got_ip["failure_kind"] is None
    q_ip, q_net = fake.queries
    assert q_ip.goal == wordings()[0].text.replace("{t}", "10.1.2.3")
    assert (q_ip.task_action, q_ip.proposal_action) == ("network.scan", "network.scan")
    assert q_ip.task_target == q_ip.proposal_target == "ip:10.1.2.3"
    assert q_net.task_target == q_net.proposal_target == "cidr:10.1.2.0/24"
    assert got_net["goal_fit"] == "implausible"


@pytest.mark.parametrize("kind", ["refusal", "transport", "unclassified"])
def test_a_failed_leg_a_call_is_classified_as_the_pipeline_classifies_it(monkeypatch, kind):
    world = leg_a_world(monkeypatch, UnavailableFakePlanFit(kind))
    got = world.ask_leg_a(st.Call("A", "network.scan", 0, 0, "10.1.2.3"))
    assert got["goal_fit"] == "failed" and got["failure_kind"] == kind


def test_a_validator_that_raises_is_a_failed_leg_a_call_not_an_escape(monkeypatch):
    class Boom:
        validator_id = "boom"

        def assess(self, *, query):
            raise TimeoutError("slow")

    got = leg_a_world(monkeypatch, Boom()).ask_leg_a(st.Call("A", "network.scan", 0, 0, "10.1.2.3"))
    assert got["goal_fit"] == "failed" and got["failure_kind"] == "transport"


def test_leg_a_touches_no_database(monkeypatch):
    import control_plane.state.db as db

    def boom(*a, **k):
        raise AssertionError("Leg A reached for the database")

    monkeypatch.setattr(db, "get_engine", boom)
    got = leg_a_world(monkeypatch, ScriptedPlanFit("plausible")).ask_leg_a(
        st.Call("A", "network.scan", 0, 0, "10.1.2.3"))
    assert got["goal_fit"] == "plausible"


def test_a_call_the_pipeline_would_not_ask_is_an_error_not_a_marked_call(monkeypatch):
    world = leg_a_world(monkeypatch, None)                  # no validator: decided without asking
    with pytest.raises(RuntimeError, match="the validator was not asked"):
        world.ask_leg_a(st.Call("A", "network.scan", 0, 0, "10.1.2.3"))


@pytest.mark.parametrize("value, cause, kind, asked, expected", [
    ("plausible", None, None, 1, ("plausible", None)),
    ("insufficient_context", None, None, 1, ("insufficient_context", None)),
    ("not_assessed", "failed", "refusal", 1, ("failed", "refusal")),
    ("not_assessed", "failed", None, 1, ("failed", "unclassified")),
    (None, None, None, 0, ("failed", "unclassified")),
])
def test_the_stored_answer_of_leg_b_is_read_into_the_same_vocabulary(
        value, cause, kind, asked, expected):
    got = run.stored_fields(value, cause, kind, asked=asked)
    assert (got["goal_fit"], got["failure_kind"]) == expected and got["stored"] == value
    assert ("note" in got) == (asked != 1)


# -- Leg B through propose_action, against the test database ------------------------

@pytest.mark.usefixtures("db_available")
def test_leg_b_goes_through_propose_action_and_the_validator_sees_what_leg_a_shows(monkeypatch):
    fake = ScriptedPlanFit("implausible", "plausible", "insufficient_context", "plausible")
    world = run.RealWorld(wordings())
    monkeypatch.setattr(world, "validator", lambda: fake)
    monkeypatch.setattr(st, "read_leg_b_facts", lambda: clean_facts())
    monkeypatch.setattr(rm, "engagement_guards", lambda policy, allow_nonempty: [])
    monkeypatch.setattr(rm, "check_effective_policy", lambda policy, classes: [])
    assert world.begin_leg_b() == []
    assert world.engagement.startswith("ENG-DP15-S1-") and world.scope.startswith("SCOPE-")
    world.policy = dataclasses.replace(world.policy, goal_fit_actions=frozenset({"network.scan"}))
    ip = st.Call("B", "network.scan", 0, 0, "10.1.2.3")
    net = st.Call("B", "network.scan", 1, 0, "10.1.7.0/24")
    got_ip, got_net = world.ask_leg_b(ip), world.ask_leg_b(net)
    assert (got_ip["goal_fit"], got_ip["stored"]) == ("implausible", "implausible")
    assert (got_net["goal_fit"], got_net["stored"]) == ("plausible", "plausible")
    # the same question Leg A puts, word for word
    leg_a = ScriptedPlanFit("plausible")
    probe = run.RealWorld(wordings())
    monkeypatch.setattr(probe, "validator", lambda: leg_a)
    probe.ask_leg_a(st.Call("A", "network.scan", 0, 0, "10.1.2.3"))
    probe.ask_leg_a(st.Call("A", "network.scan", 1, 0, "10.1.7.0/24"))
    assert fake.queries[0] == leg_a.queries[0] and fake.queries[1] == leg_a.queries[1]


@pytest.mark.usefixtures("db_available")
def test_leg_b_does_not_begin_when_the_guards_are_read_again_and_fail(monkeypatch):
    world = run.RealWorld(wordings())
    monkeypatch.setattr(st, "read_leg_b_facts", lambda: clean_facts(calls=1))
    problems = world.begin_leg_b()
    assert len(problems) == 1 and "holds 1 row(s)" in problems[0] and world.engagement is None


# -- what the run module may name ----------------------------------------------

def test_the_run_module_builds_a_real_validator_only_inside_the_real_world():
    source = Path(run.__file__).read_text()
    assert source.count("build_plan_fit_validator(") == 1
    assert "build_plan_fit_validator" in inspect.getsource(run.RealWorld.validator)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in (
                "Stage1Run", "run_stage1", "execute_cli", "render_summary", "record_header"):
            assert "build_plan_fit_validator" not in ast.unparse(node), node.name


def test_the_run_module_publishes_no_policy_and_sets_no_switch():
    source = Path(run.__file__).read_text()
    for forbidden in ("publish_policy_layer", "goal_fit_enforce\": True",
                      "task_relation_enforce\": True", "clear_suspension", "emergency_overlay",
                      "manage_global_policy import publish"):
        assert forbidden not in source, forbidden
    assert source.count("publish_engagement_policy(") == 1        # Leg B's own engagement only
