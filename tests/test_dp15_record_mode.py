"""The record-mode measurement's traffic generator (D68 DP-15): prepared and tested, not run.

No test here calls a model, publishes a layer or sends the real traffic. The controller is given
fake calls and a fake world; the plan is pure; the dry run is run as a process with the database
and the validator made to explode if touched; the one test that reads the real tables does so with
class names of its own.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

from scripts import dp15_record_mode as rm

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "dp15_record_mode.py"
SENSITIVE_ROLES = ("payroll-db", "hr-files", "vault", "backup", "dc", "finance-sql", "crm-db",
                   "customer-archive", "idp", "secrets-store", "ledger", "build-signing")


# -- the plan ------------------------------------------------------------------

def test_the_registered_numbers():
    assert (rm.N, rm.PER_CLASS_MAX, rm.MAX_PROPOSALS, rm.MAX_CONCURRENCY) == (50, 60, 180, 2)
    assert (rm.MAX_COST_USD, rm.MAX_SECONDS) == (3.00, 3600.0)
    assert rm.CLASSES == ("network.scan", "code.scan", "code.secrets")
    assert rm.MAX_PROPOSALS == len(rm.CLASSES) * rm.PER_CLASS_MAX


def test_the_plan_is_sixty_distinct_proposals_per_class_interleaved():
    plan = rm.build_plan()
    assert len(plan) == 180 and rm.check_plan(plan) == []
    assert len({p.host for p in plan}) == 180                       # no host twice, in any class
    assert len({p.goal for p in plan}) == 180                       # and so no goal twice
    for action in rm.CLASSES:
        mine = [p for p in plan if p.action == action]
        assert [p.index for p in mine] == list(range(60))
    assert [p.action for p in plan[:6]] == list(rm.CLASSES) * 2     # a bad hour falls on all three
    assert [p.seq for p in plan] == list(range(180))


def test_the_goal_sentences_are_the_registered_ones_and_differ_only_in_the_host():
    from tests.task_support import GOALS

    for action in rm.CLASSES:
        assert rm.GOALS[action] == GOALS[action]    # the sentences every existing test uses
    for p in rm.build_plan():
        assert p.goal == rm.GOALS[p.action].format(host=p.host)
        assert "Active Directory" not in p.goal and "credential" not in p.goal.lower()


def test_the_targets_are_addresses_in_one_slash_sixteen_and_plain_host_names():
    plan = rm.build_plan()
    for p in plan:
        if p.action == "network.scan":
            a, b, c, d = (int(x) for x in p.host.split("."))
            assert (a, b) == (10, 77) and 1 <= c <= 255 and 1 <= d <= 200 and p.target_type == "ip"
        else:
            assert p.target_type == "fqdn" and p.host.endswith(".example")
            role = p.host.split(".")[0].rstrip("0123456789")
            assert role in rm.ROLES and role not in SENSITIVE_ROLES
            assert p.host.split(".")[1] in rm.ZONES


def test_a_plan_with_a_repeated_host_or_a_wrong_count_or_sentence_is_refused():
    plan = rm.build_plan()
    assert rm.check_plan(plan[:-1]) != []                                       # 59 for one class
    repeated = list(plan)
    repeated[3] = repeated[3].__class__(**{**repeated[3].__dict__, "host": plan[0].host})
    assert any("more than one" in p for p in rm.check_plan(repeated))
    reworded = list(plan)
    reworded[0] = reworded[0].__class__(**{**reworded[0].__dict__, "goal": "Scan everything"})
    assert any("sentence" in p for p in rm.check_plan(reworded))
    assert rm.check_plan(plan, per_class=40, n=50) != []                        # 40 cannot give 50
    outside = list(plan)
    outside[0] = outside[0].__class__(**{**outside[0].__dict__, "host": "192.168.0.1"})
    assert any("scope" in p for p in rm.check_plan(outside))


def test_the_estimate_is_calls_times_the_unit_cost_with_the_cap_above_the_worst_case():
    est = rm.estimate()
    assert est["planned_calls"] == 150 and est["worst_case_calls"] == 180
    assert est["cost_planned_usd"] == pytest.approx(150 * 0.0088, abs=0.01)
    assert est["cost_planned_usd"] == pytest.approx(1.32, abs=0.01)
    assert est["cost_worst_usd"] == pytest.approx(1.58, abs=0.01)
    assert est["cost_worst_usd"] < est["cost_cap_usd"] == 3.0
    assert est["minutes_planned"] < est["minutes_worst"] < est["minutes_cap"]


# -- the controller, with a fake world -----------------------------------------

class World:
    """A fake of the tables: ``issue`` records a call of the kind the test scripted for that
    proposal's position in its class (answered unless told otherwise)."""

    def __init__(self, kinds=None, *, delay=0.0, suspend_at=None, raises=()):
        self.kinds = kinds or {}                    # (action, index) -> failure kind | "answered"
        self.delay = delay
        self.suspend_at = suspend_at or {}          # action -> judgements at which it is suspended
        self.raises = set(raises)
        self.calls: list[tuple[str, int, str | None]] = []   # (action, index, kind)
        self.lock = threading.Lock()
        self.live = 0
        self.max_live = 0
        self.issued: list[rm.Planned] = []

    def issue(self, p: rm.Planned) -> None:
        with self.lock:
            self.live += 1
            self.max_live = max(self.max_live, self.live)
            self.issued.append(p)
        try:
            if self.delay:
                time.sleep(self.delay)
            if p.seq in self.raises:
                raise RuntimeError("the pipeline raised")
            kind = self.kinds.get((p.action, p.index), "answered")
            with self.lock:
                self.calls.append((p.action, p.index, None if kind == "answered" else kind))
        finally:
            with self.lock:
                self.live -= 1

    def state(self) -> rm.State:
        with self.lock:
            calls = list(self.calls)
        judged = {c: 0 for c in rm.CLASSES}
        asked = {c: 0 for c in rm.CLASSES}
        for action, _i, kind in calls:
            asked[action] += 1
            if kind != "transport":
                judged[action] += 1
        suspended = {a: n for a, n in self.suspend_at.items() if judged[a] >= n}
        return rm.State(judged, asked, suspended, [k for _a, _i, k in reversed(calls)][:30])


def measure(world, **kw):
    return rm.Measurement(rm.build_plan(), issue=world.issue, read_state=world.state, **kw).run()


def test_a_clean_run_makes_exactly_fifty_judgements_per_class_two_at_a_time():
    world = World(delay=0.002)
    result = measure(world)
    assert result.stopped is None and result.exit_code == 0
    assert result.state.judged == {c: 50 for c in rm.CLASSES}
    assert result.issued == {c: 50 for c in rm.CLASSES}                  # none spare was needed
    assert world.max_live == 2                                           # concurrency, and no more
    assert len({p.host for p in world.issued}) == 150                    # no proposal repeated


def test_a_transport_loss_is_replaced_by_a_new_proposal_and_never_retried():
    world = World(kinds={("code.scan", 3): "transport", ("code.scan", 4): "transport",
                         ("network.scan", 0): "transport"})
    result = measure(world)
    assert result.stopped is None
    assert result.state.judged == {c: 50 for c in rm.CLASSES}            # still exactly 50
    assert result.issued == {"network.scan": 51, "code.scan": 52, "code.secrets": 50}
    hosts = [p.host for p in world.issued]
    assert len(hosts) == len(set(hosts))                  # a replacement is a new host


def test_a_class_that_cannot_reach_fifty_in_sixty_proposals_ends_with_what_it_has():
    kinds = {("code.secrets", i): "transport" for i in range(0, 60, 3)}  # 20 of 60 lost
    result = measure(World(kinds=kinds))
    assert result.issued["code.secrets"] == 60                           # the cap, not more
    assert result.state.judged["code.secrets"] == 40 and result.stopped is None


def test_a_suspended_class_is_censored_where_it_stands_and_the_others_go_on():
    world = World(suspend_at={"code.scan": 31})
    result = measure(world)
    assert result.state.suspended == {"code.scan": 31}
    assert result.state.judged["code.scan"] in (31, 32)                  # at most one in flight
    assert result.state.judged["network.scan"] == result.state.judged["code.secrets"] == 50
    assert "censored at n=31" in rm.render_result(result)


def test_more_than_half_of_the_last_thirty_in_transport_stops_the_run_without_a_retry():
    kinds = {(a, i): "transport" for a in rm.CLASSES for i in range(60)}
    world = World(kinds=kinds)
    result = measure(world)
    assert result.stopped and "more than half of the last 30" in result.stopped
    assert result.exit_code == 3
    # it noticed once thirty calls were in, and let only the calls already in flight finish
    assert 30 <= len(world.calls) <= 32
    assert sum(result.issued.values()) == len(world.issued) == len(world.calls)
    assert len({(p.action, p.index) for p in world.issued}) == len(world.issued)   # no retry
    assert "STOPPED EARLY" in rm.render_result(result)


def test_half_exactly_in_transport_does_not_stop_the_run():
    kinds = {(a, i): "transport" for a in rm.CLASSES for i in range(0, 60, 2)}
    result = measure(World(kinds=kinds))
    assert result.stopped is None                                        # 15 of 30 is not over half
    assert result.issued == {c: 60 for c in rm.CLASSES}                  # all sixty used, then done
    assert result.state.judged == {c: 30 for c in rm.CLASSES}     # the half that were not lost


def test_other_failures_do_not_stop_the_run_only_transport_does():
    kinds = {(a, i): "refusal" for a in rm.CLASSES for i in range(60)}
    result = measure(World(kinds=kinds))
    assert result.stopped is None


def test_the_cost_the_time_and_the_proposal_caps_each_end_the_run():
    world = World()
    result = measure(world, cost_so_far=lambda: 3.01)
    assert result.stopped and "cost cap" in result.stopped and sum(result.issued.values()) == 0
    ticks = iter(range(10_000))
    result = measure(World(), clock=lambda: float(next(ticks)) * 100.0)
    assert result.stopped and "time cap" in result.stopped
    result = measure(World(), max_proposals=20)
    assert result.stopped and "proposal cap" in result.stopped
    assert sum(result.issued.values()) == 20


def test_a_pipeline_that_raises_stops_the_run_after_three():
    world = World(raises={0, 1, 2, 3, 4})
    result = measure(world)
    assert result.stopped and "raised" in result.stopped and result.escaped_errors >= 3


def test_a_cap_may_be_lowered_and_never_raised_and_two_is_the_most_in_flight():
    plan = rm.build_plan()
    world = World()
    for kw in ({"concurrency": 3}, {"concurrency": 0}, {"max_proposals": 181},
               {"max_cost": 3.01}, {"max_seconds": 3601.0}):
        with pytest.raises(ValueError):
            rm.Measurement(plan, issue=world.issue, read_state=world.state, **kw)
    rm.Measurement(plan, issue=world.issue, read_state=world.state, concurrency=1,
                   max_proposals=10, max_cost=1.0, max_seconds=60.0)


def test_the_end_of_run_summary_has_calls_and_suspension_and_no_failure_count_or_rate():
    kinds = {("code.scan", i): "refusal" for i in range(10)}
    kinds.update({("network.scan", i): "transport" for i in range(3)})
    result = measure(World(kinds=kinds))
    text = rm.render_result(result)
    assert "network.scan" in text and "validator calls" in text and "judgements" in text
    assert "suspended" in text
    for word in ("fail", "refus", "transport", "unclassified", "%", "rate", "upper"):
        assert word not in text.lower().replace("stopped early", ""), word
    # a stopped run says why, but still not how often anything failed
    stopped = rm.render_result(measure(World(kinds={(a, i): "transport" for a in rm.CLASSES
                                                   for i in range(60)})))
    assert "STOPPED EARLY" in stopped and "%" not in stopped


def test_progress_lines_count_proposals_and_say_nothing_about_outcomes():
    seen = []
    measure(World(kinds={("code.scan", 0): "refusal"}), progress=lambda a, b: seen.append((a, b)))
    assert seen and all(isinstance(a, int) and isinstance(b, int) for a, b in seen)


# -- reading the real tables (class names of its own) --------------------------

@pytest.mark.usefixtures("q1_class_store_live", "db_available")
def test_the_state_read_from_the_tables_counts_judgements_apart_from_transport_losses():
    from control_plane.plan_fit import class_store as store
    from control_plane.state.db import get_engine

    mine = tuple(f"dp15x.c{uuid.uuid4().hex[:10]}" for _ in range(2))
    with get_engine().begin() as conn:
        from sqlalchemy import text
        start = int(conn.execute(text(
            "SELECT coalesce(max(call_id), 0) FROM goal_fit_calls")).scalar())

    def put(action, outcome, kind=None):
        with get_engine().begin() as conn:
            store.record_and_review(conn, action, outcome, kind)

    for _ in range(31):
        put(mine[0], "answered")
    put(mine[0], "failed", "transport")
    put(mine[0], "failed", "refusal")
    put(mine[1], "failed", "transport")
    state = rm.read_state_from_tables(mine, start)
    assert state.judged == {mine[0]: 32, mine[1]: 0}                # transport is not one
    assert state.asked == {mine[0]: 33, mine[1]: 1}                    # but it is a call
    assert state.suspended == {}
    assert state.kinds_newest_first[0] == "transport" and len(state.kinds_newest_first) == 30
    for _ in range(30):
        put(mine[1], "failed", "refusal")                              # the exit rule suspends it
    state = rm.read_state_from_tables(mine, start)
    assert mine[1] in state.suspended and state.suspended[mine[1]] == 30


# -- the dry run, the guards, and what the script does not do ------------------

def clean_world(monkeypatch, *, guards=(), banner=("database: stub",)):
    """Replace the reading of the database by a fixed answer, so what is tested is what the dry run
    and the run do with it."""
    seen = []

    def check(**kw):
        seen.append(kw)
        return list(banner), list(guards)

    monkeypatch.setattr(rm, "check_startup", check)
    return seen


def test_the_dry_run_prints_the_plan_and_calls_no_model_and_publishes_nothing(
        capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a dry run reached for something")

    import agents.llm.selection as selection
    import control_plane.orchestrator.engagement as engagement
    import control_plane.state.db as db

    monkeypatch.setattr(db, "global_policy_admin_scope", boom)
    monkeypatch.setattr(db, "registry_admin_scope", boom)
    monkeypatch.setattr(engagement, "create_engagement", boom)
    monkeypatch.setattr(selection, "build_plan_fit_validator", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    seen = clean_world(monkeypatch)
    assert rm.main([]) == 0
    out = capsys.readouterr().out
    assert out.startswith("DRY RUN -- nothing was sent, no model was called")
    for needle in ("180 distinct hosts", "US$1.32 planned", "US$1.58 worst case",
                   "plan checks: ok", "network.scan", "code.scan", "code.secrets",
                   "database: stub", "startup guards: ok"):
        assert needle in out, needle
    assert seen == [{"allow_nonempty": False, "rehearsal": True}]


def test_the_dry_run_as_a_process_with_no_reachable_database_prints_the_plan_and_exits_one():
    """The guards cannot be checked, so the dry run does not say the run would be allowed."""
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO),
           "DATABASE_URL": "postgresql+psycopg://nobody:nothing@127.0.0.1:1/none"}
    done = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True,
                          cwd=REPO, env=env, timeout=120)
    assert done.returncode == rm.EXIT_PRECONDITION, done.stderr
    assert "DRY RUN" in done.stdout and "no model was called" in done.stdout
    assert "database: NOT READ" in done.stdout and "180 distinct hosts" in done.stdout
    assert "WOULD REFUSE: the database could not be read" in done.stderr
    assert "plan checks: ok" not in done.stdout


def test_a_dry_run_the_guards_would_refuse_lists_the_reasons_and_exits_one(capsys, monkeypatch):
    clean_world(monkeypatch, guards=["code.scan already has 3 row(s)", "goal_fit_enforce is on"],
                banner=("database: d",))
    assert rm.main([]) == rm.EXIT_PRECONDITION
    captured = capsys.readouterr()
    assert "startup guards: WOULD REFUSE TO START" in captured.out
    assert "180 distinct hosts" in captured.out                  # the plan is still shown
    assert "plan checks: ok" not in captured.out
    assert "WOULD REFUSE: code.scan already has 3 row(s)" in captured.err
    assert "WOULD REFUSE: goal_fit_enforce is on" in captured.err


def test_the_flag_reaches_the_guards_with_a_warning_and_is_off_by_default(capsys, monkeypatch):
    seen = clean_world(monkeypatch)
    assert rm.main([]) == 0 and rm.main(["--allow-nonempty"]) == 0
    assert [kw["allow_nonempty"] for kw in seen] == [False, True]
    out = capsys.readouterr().out
    assert out.count("WARNING: --allow-nonempty is set") == 1
    assert "For tests only" in out


def test_without_the_flag_nothing_is_sent_and_the_flag_hands_over_to_execute(monkeypatch):
    sent = []
    clean_world(monkeypatch)
    monkeypatch.setattr(rm, "execute", lambda args, plan: sent.append(args) or 0)
    assert rm.main([]) == 0 and sent == []
    assert rm.main(["--execute"]) == 0 and len(sent) == 1
    assert sent[0].allow_nonempty is False and sent[0].yes is False


@pytest.mark.parametrize("flags", [["--concurrency", "3"], ["--concurrency", "0"],
                                   ["--max-proposals", "181"], ["--max-cost", "3.5"]])
def test_the_command_line_refuses_to_raise_a_cap(flags, capsys):
    assert rm.main(flags) == rm.EXIT_USAGE
    assert "refused" in capsys.readouterr().err


# -- usage: what the run used, as totals --------------------------------------

ENVELOPE = ('{"total_cost_usd": 0.0125, "usage": {"input_tokens": 3, "output_tokens": 60, '
            '"cache_read_input_tokens": 1000, "cache_creation_input_tokens": 200}, '
            '"modelUsage": {"claude-haiku-5-5": {}, "claude-sonnet-5-5": {}}}')


class FakeDone:
    def __init__(self, stdout):
        self.stdout = stdout


def test_an_envelope_adds_its_cost_tokens_and_models():
    usage = rm.Usage()
    usage.add_envelope(ENVELOPE)
    usage.add_envelope(ENVELOPE)
    assert round(usage.cost_usd, 4) == 0.025
    assert (usage.input_tokens, usage.output_tokens) == (6, 120)
    assert (usage.cache_read_tokens, usage.cache_creation_tokens) == (2000, 400)
    assert usage.models == {"claude-haiku-5-5", "claude-sonnet-5-5"}


@pytest.mark.parametrize("stdout", [None, "", "not json", "[1, 2]", "3", 5,
                                    '{"total_cost_usd": "free", "usage": 5, "modelUsage": []}',
                                    '{"total_cost_usd": "x", "usage": {"input_tokens": "many"}}',
                                    '{"total_cost_usd": [1]}',
                                    '{"usage": {"output_tokens": [1]}}'])
def test_a_reply_that_is_not_an_envelope_adds_nothing_and_never_raises(stdout):
    usage = rm.Usage()
    try:
        usage.add_envelope(stdout)
    except Exception as exc:                       # noqa: BLE001 - the point is that none escapes
        pytest.fail(f"metering raised {exc!r}")
    assert usage == rm.Usage()


STORED = REPO / "docs" / "D68_S7_BASELINE"


def test_the_envelope_keys_are_the_ones_in_responses_of_the_real_cli_that_are_stored():
    """The field names are not guessed: three of them appear verbatim in the text of real CLI result
    envelopes kept in the S7 records (the stored text is cut at 200 characters, so it ends inside
    the usage block). ``cache_read_input_tokens``, ``output_tokens`` and ``modelUsage`` are cut off
    in what is stored; they are the names ``scripts/plan_fit_baseline.py`` read to produce S7's
    non-zero ``cache_read_tokens``, ``output_tokens`` and ``models`` (verified by use, not text)."""
    creation = (STORED / "p1_scale" / "sonnet" / "run_26.json").read_text()
    assert '\\"cache_creation_input_tokens\\":' in creation
    assert '\\"usage\\":{\\"input_tokens\\":' in creation
    cost = (STORED / "goal_class_probe" / "probe.json").read_text()
    assert '\\"total_cost_usd\\":' in cost
    source = SCRIPT.read_text()
    for key in ("total_cost_usd", "cache_creation_input_tokens", "cache_read_input_tokens",
                "modelUsage"):
        assert f'"{key}"' in source, key
    baseline = (REPO / "scripts" / "plan_fit_baseline.py").read_text()
    for key in ("cache_read_input_tokens", "modelUsage", "total_cost_usd"):
        assert f'"{key}"' in baseline, key               # the runner that produced S7's records


def test_the_runner_counts_every_run_and_what_the_envelope_reports(monkeypatch):
    seen = []

    def run(*args, **kwargs):
        seen.append(kwargs)
        return FakeDone(ENVELOPE)

    runner = rm.MeteredRunner(
        run=run, environ={"HOME": "/h", "CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK": "0"})
    first = runner(["claude"], env={"X": "1"}, timeout=5)
    runner(["claude"])
    assert isinstance(first, FakeDone)
    assert runner.usage.cli_runs == 2 and round(runner.cost, 4) == 0.025
    # the DP-14 configuration is forced over what the environment said; nothing else is lost
    assert seen[0]["env"].get("CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK") == "1"
    assert seen[0]["env"].get("HOME") == "/h" and seen[0]["env"].get("X") == "1"
    assert seen[0]["timeout"] == 5


def test_a_run_that_raises_is_a_run_and_adds_no_cost():
    def run(*args, **kwargs):
        raise TimeoutError("30 s")

    runner = rm.MeteredRunner(run=run, environ={})
    with pytest.raises(TimeoutError):
        runner(["claude"])
    assert runner.usage.cli_runs == 1 and runner.usage.cost_usd == 0.0


def test_the_totals_of_the_validator_threads_add_up():
    a = rm.Usage(cli_runs=3, cost_usd=0.5, input_tokens=1, output_tokens=2, cache_read_tokens=3,
                 cache_creation_tokens=4, models={"m1"})
    b = rm.Usage(cli_runs=4, cost_usd=0.25, input_tokens=9, output_tokens=8, cache_read_tokens=7,
                 cache_creation_tokens=6, models={"m2"})
    total = rm.Usage.total([a, b])
    assert (total.cli_runs, total.cost_usd) == (7, 0.75)
    assert (total.input_tokens, total.output_tokens) == (10, 10)
    assert (total.cache_read_tokens, total.cache_creation_tokens) == (10, 10)
    assert total.models == {"m1", "m2"}
    assert rm.Usage.total([]) == rm.Usage()


def test_the_end_of_run_summary_ends_with_the_usage_and_how_it_is_to_be_read():
    usage = rm.Usage(cli_runs=150, cost_usd=1.3151, input_tokens=450, output_tokens=9000,
                     cache_read_tokens=150000, cache_creation_tokens=30000,
                     models={"claude-sonnet-5-5"})
    state = rm.State(judged={c: 50 for c in rm.CLASSES}, asked={c: 51 for c in rm.CLASSES},
                     suspended={}, kinds_newest_first=[])
    out = rm.render_result(rm.Result(issued={c: 51 for c in rm.CLASSES}, state=state, seconds=246,
                                     usage=usage))
    lines = out.splitlines()
    assert any(line.startswith("usage:") for line in lines), out
    block = "\n".join(lines[next(i for i, line in enumerate(lines) if line.startswith("usage:")):])
    assert "usage: 150 CLI runs (validator calls recorded in the tables: 153)" in block
    assert "list-price-equivalent cost: US$1.32 (cap US$3.00; planned estimate" in block
    assert "tokens: input 450, output 9000, cache read 150000, cache creation 30000" in block
    assert "models named in the envelopes: claude-sonnet-5-5" in block
    assert "not invoiced per call" in block and "it is not an invoice" in block
    assert "usage window, which the CLI does not report" in block
    assert "adds none" in block
    # totals only: nothing about outcomes, in the usage block or beside it
    import re
    assert not re.search(r"fail|refus|transport|safety|suspend|rate\b", block, re.IGNORECASE)


def test_without_usage_the_summary_is_what_it_was():
    out = rm.render_result(rm.Result(issued={}, state=None, seconds=60))
    assert "usage:" not in out


def test_the_run_attaches_the_totals_of_its_validators_to_the_result():
    source = SCRIPT.read_text()
    assert "result.usage = Usage.total(m.usage for m in list(meters))" in source
    assert "MeteredRunner(environ=dict(os.environ), no_fallback_env=NO_FALLBACK_ENV)" in source


# -- the startup guards ---------------------------------------------------------

def facts(*, calls=None, suspended=None, database="clean_db", revision="0030", head="0030"):
    return rm.DbFacts(host="127.0.0.1", port=5432, database=database, revision=revision,
                      code_head=head, calls=dict(calls or {}), transport={},
                      live_suspensions=dict(suspended or {}))


def policy(*, enforce=False, relation=False, listed=()):
    return rm.PolicyFacts(frozenset(listed), enforce, relation, 0)


def guards(db=None, pol=None, classes=rm.CLASSES, **kw):
    return rm.guard_problems(db or facts(), pol or policy(), classes, **kw)


def test_a_clean_database_with_the_switch_off_passes_every_guard():
    assert guards() == []
    assert guards(allow_nonempty=True) == []


@pytest.mark.parametrize("cls", rm.CLASSES)
def test_rows_in_goal_fit_calls_for_any_one_class_refuse_the_start_and_name_it(cls):
    problems = guards(facts(calls={cls: 7}, database="somewhere"))
    assert len(problems) == 1
    assert cls in problems[0] and "7 row(s) in goal_fit_calls" in problems[0]
    assert "'somewhere'" in problems[0] and "clean database" in problems[0]


@pytest.mark.parametrize("cls", rm.CLASSES)
def test_an_uncleared_suspension_for_any_one_class_refuses_the_start_and_names_it(cls):
    problems = guards(facts(suspended={cls: 1}))
    assert len(problems) == 1
    assert cls in problems[0] and "uncleared suspension" in problems[0]
    assert "goal_fit_suspensions" in problems[0]


def test_every_reason_is_listed_not_only_the_first():
    dirty = facts(calls={"network.scan": 2, "code.scan": 3}, suspended={"code.secrets": 1})
    problems = guards(dirty, policy(enforce=True))
    assert len(problems) == 4
    text = "\n".join(problems)
    for needle in ("network.scan already has 2", "code.scan already has 3", "code.secrets has 1",
                   "goal_fit_enforce is not off"):
        assert needle in text, needle


def test_a_class_outside_the_three_that_the_database_has_rows_for_also_refuses():
    problems = guards(facts(calls={"code.extra": 4}), classes=rm.CLASSES + ("code.extra",))
    assert len(problems) == 1 and "code.extra" in problems[0]
    # and rows for a class nobody is looking at do not
    assert guards(facts(calls={"code.unlisted": 4})) == []


@pytest.mark.parametrize("value", [True, None, "false", 0, 1, "off"])
def test_the_switch_must_be_exactly_off_anything_else_refuses(value):
    problems = guards(pol=policy(enforce=value))
    assert len(problems) == 1 and "goal_fit_enforce is not off" in problems[0]
    assert repr(value) in problems[0]


def test_the_allow_flag_lifts_the_two_data_refusals_and_nothing_else():
    dirty = facts(calls={"network.scan": 5}, suspended={"code.scan": 1})
    assert len(guards(dirty)) == 2
    assert guards(dirty, allow_nonempty=True) == []
    # the switch refusal is not lifted by it, alone or beside the data refusals
    only = guards(pol=policy(enforce=True), allow_nonempty=True)
    assert len(only) == 1 and "goal_fit_enforce is not off" in only[0]
    both = guards(dirty, policy(enforce=True), allow_nonempty=True)
    assert both == only
    assert len(guards(dirty, policy(enforce=True))) == 3


def test_task_relation_enforce_is_shown_but_does_not_refuse():
    assert guards(pol=policy(relation=True)) == []


def test_the_classes_looked_at_are_the_layer_files_the_three_and_the_policys(monkeypatch):
    assert set(rm.guard_classes(policy())) == set(rm.CLASSES)
    assert set(rm.guard_classes(policy(listed=["code.extra"]))) == set(rm.CLASSES) | {"code.extra"}
    monkeypatch.setattr(rm, "layer_document", lambda: {"goal_fit_actions": ["code.layer"]})
    assert set(rm.guard_classes(policy())) == set(rm.CLASSES) | {"code.layer"}
    assert rm.guard_classes(policy()) == tuple(sorted(rm.guard_classes(policy())))


def test_the_layer_file_lists_the_three_measured_classes():
    assert set(rm.layer_document()["goal_fit_actions"]) == set(rm.CLASSES)
    assert "goal_fit_enforce" not in rm.layer_document()


# -- what is printed first ------------------------------------------------------

def banner(db=None, now=None, after=None, control=None, classes=rm.CLASSES):
    return "\n".join(rm.render_banner(db or facts(), now or policy(), after, classes, control))


def test_the_banner_names_the_database_the_revision_the_counts_and_both_switches():
    text = banner(facts(calls={"network.scan": 12}, suspended={"code.scan": 2},
                        database="dp15_clean"),
                  now=policy(enforce=False, relation=True))
    assert "database: dp15_clean on 127.0.0.1:5432" in text
    assert "migration revision: 0030 -- this checkout's head is 0030 (matches)" in text
    assert "network.scan 12, code.scan 0, code.secrets 0" in text
    assert "uncleared suspensions (goal_fit_suspensions): code.scan 2" in text
    assert "goal_fit_enforce: off; task_relation_enforce: ON" in text


def test_the_banner_says_when_the_revision_is_not_the_head_or_unknown():
    assert "DOES NOT MATCH" in banner(facts(revision="0029"))
    assert "migration revision: None" in banner(facts(revision=None))
    assert "UNKNOWN (None)" in banner(now=policy(enforce=None))


def test_the_banner_of_a_rehearsal_shows_the_policy_after_publication_and_the_control():
    after = policy(listed=rm.CLASSES)
    text = banner(now=policy(), after=after, control=policy(enforce=True, listed=rm.CLASSES))
    assert "effective policy now (0 layer(s) in force): goal_fit_actions: (none); " in text
    assert ("effective policy AFTER publishing layer_record_mode.json (0 layer(s)): "
            "goal_fit_actions: code.scan, code.secrets, network.scan; "
            "goal_fit_enforce: off") in text
    assert "computed by the policy code" in text and "not inferred" in text
    assert "turns the switch on reads goal_fit_enforce: ON" in text
    live = banner(now=policy(listed=rm.CLASSES))                  # the layer is live: no "after"
    assert "AFTER" not in live and "control" not in live
    assert "what a new engagement is given" in live


# -- reading the database (READ ONLY, class names of its own) -------------------

@pytest.fixture
def statements():
    from sqlalchemy import event

    from control_plane.state.db import get_engine

    engine, seen = get_engine(), []

    def record(conn, cursor, statement, params, context, executemany):
        seen.append(" ".join(statement.split()))

    event.listen(engine, "before_cursor_execute", record)
    yield seen
    event.remove(engine, "before_cursor_execute", record)


@pytest.mark.usefixtures("q1_class_store_live", "db_available")
def test_the_facts_read_from_the_database_count_rows_and_only_uncleared_suspensions(statements):
    from sqlalchemy import text

    from control_plane.plan_fit import class_store as store
    from control_plane.state.db import get_engine

    mine = tuple(f"dp15x.c{uuid.uuid4().hex[:10]}" for _ in range(3))

    def put(action, outcome, kind=None):
        with get_engine().begin() as conn:
            store.record_and_review(conn, action, outcome, kind)

    for _ in range(3):
        put(mine[0], "answered")
    put(mine[0], "failed", "transport")
    for _ in range(30):
        put(mine[1], "failed", "refusal")                          # suspended by the exit rule
    statements.clear()
    got = rm.read_db_facts(mine)
    assert got.calls == {mine[0]: 4, mine[1]: 30} and mine[2] not in got.calls
    assert got.transport == {mine[0]: 1, mine[1]: 0}
    assert got.live_suspensions == {mine[1]: 1}
    with get_engine().begin() as conn:
        assert got.database == conn.execute(text("SELECT current_database()")).scalar_one()
    assert got.revision == got.code_head and got.code_head
    assert statements[0] == "SET TRANSACTION READ ONLY"
    assert not [st for st in statements
                if st.split()[0].upper() in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "DROP")]
    # an operator clears the suspension: the class has no live one any more, its rows remain
    from control_plane.state.db import global_policy_admin_scope
    with global_policy_admin_scope() as conn:
        assert store.clear_suspension(conn, mine[1], "operator-test",
                                      "wording of the goal template changed; 30 test calls")
    after = rm.read_db_facts(mine)
    assert after.live_suspensions == {} and after.calls[mine[1]] == 30


@pytest.mark.usefixtures("q1_class_store_live", "db_available")
def test_check_startup_refuses_on_rows_and_on_a_suspension_and_the_flag_lifts_only_those(
        monkeypatch):
    from control_plane.plan_fit import class_store as store
    from control_plane.state.db import get_engine

    mine = tuple(f"dp15x.c{uuid.uuid4().hex[:10]}" for _ in range(3))
    monkeypatch.setattr(rm, "layer_document", lambda: {"goal_fit_actions": [mine[0], mine[1]]})
    monkeypatch.setattr(rm, "CLASSES", (mine[2],))

    def put(action, outcome, kind=None):
        with get_engine().begin() as conn:
            store.record_and_review(conn, action, outcome, kind)

    lines, problems = rm.check_startup(allow_nonempty=False, rehearsal=True)
    assert [p for p in problems if "dp15x." in p] == []                   # clean for these classes
    assert any(f"{mine[0]} 0" in line for line in lines)
    put(mine[0], "answered")
    for _ in range(30):
        put(mine[1], "failed", "refusal")
    lines, problems = rm.check_startup(allow_nonempty=False, rehearsal=True)
    mine_problems = [p for p in problems if "dp15x." in p]
    assert any(mine[0] in p and "1 row(s)" in p for p in mine_problems)
    assert any(mine[1] in p and "30 row(s)" in p for p in mine_problems)
    assert any(mine[1] in p and "uncleared suspension" in p for p in mine_problems)
    assert not any(mine[2] in p for p in mine_problems)
    assert any(f"{mine[0]} 1" in line for line in lines)
    _, lifted = rm.check_startup(allow_nonempty=True, rehearsal=True)
    assert [p for p in lifted if "dp15x." in p] == []
    # the same in a live (not rehearsed) start
    _, live = rm.check_startup(allow_nonempty=False, rehearsal=False)
    assert any(mine[0] in p for p in live)


@pytest.mark.usefixtures("db_available")
def test_check_startup_refuses_a_switch_that_is_on_whatever_the_flag_says(monkeypatch):
    on = rm.PolicyFacts(frozenset(), True, False, 3)
    monkeypatch.setattr(rm, "read_policy", lambda extra=(): on)
    for allow in (False, True):
        for rehearsal in (False, True):
            _, problems = rm.check_startup(allow_nonempty=allow, rehearsal=rehearsal)
            assert any("goal_fit_enforce is not off" in p for p in problems), (allow, rehearsal)


@pytest.mark.usefixtures("db_available")
def test_a_rehearsal_reads_the_policy_with_the_draft_added_and_a_live_start_does_not(monkeypatch):
    reads = []

    def read(extra=()):
        reads.append(list(extra))
        draft_in = any("goal_fit_actions" in doc for _, doc in extra)
        return rm.PolicyFacts(frozenset(rm.CLASSES) if draft_in else frozenset(),
                              draft_in and len(extra) == 1, False, len(extra))

    monkeypatch.setattr(rm, "read_policy", read)
    monkeypatch.setattr(rm, "read_db_facts", lambda classes: facts())
    lines, problems = rm.check_startup(allow_nonempty=False, rehearsal=True)
    draft = ("emergency_overlay", rm.layer_document())
    assert reads == [[], [draft], [draft, ("emergency_overlay", {"goal_fit_enforce": True})]]
    # the verdict is over the policy AFTER publication: here the draft would turn the switch on
    assert any("goal_fit_enforce is not off" in p for p in problems)
    assert any(line.startswith("effective policy AFTER") for line in lines)
    reads.clear()
    lines, problems = rm.check_startup(allow_nonempty=False, rehearsal=False)
    assert reads == [[]] and problems == []
    assert not any("AFTER" in line or "control" in line for line in lines)


@pytest.mark.usefixtures("db_available")
def test_the_policy_read_is_read_only_and_leaves_the_layers_as_they_were(statements):
    from sqlalchemy import text

    from control_plane.state.db import get_engine

    def layers():
        with get_engine().begin() as conn:
            return conn.execute(text(
                "SELECT count(*), coalesce(max(id), 0) FROM policy_layers "
                "WHERE engagement_id IS NULL")).one()

    before = layers()
    rm.read_policy()
    rm.read_policy(extra=[("emergency_overlay", {"goal_fit_actions": ["dp15x.nothing"]})])
    statements.clear()
    rm.read_policy(extra=[("emergency_overlay", {"goal_fit_enforce": True})])
    assert layers() == before
    assert statements[1] == "SET TRANSACTION READ ONLY"             # after the scope's set_config
    assert not [st for st in statements
                if st.split()[0].upper() in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "DROP")]


@pytest.mark.usefixtures("db_available")
def test_the_policy_after_publication_is_what_a_real_publication_then_gives():
    """The evidence is computed, so it is compared with the real thing: publish a layer of the
    same kind (a class name of its own), read the policy a new engagement gets, take it back."""
    from tests.helpers import deactivate_global_layer, publish_global_layer

    doc = {"goal_fit_actions": [f"dp15x.c{uuid.uuid4().hex[:10]}"]}
    before = rm.read_policy()
    rehearsed = rm.read_policy(extra=[("emergency_overlay", doc)])
    assert rehearsed.goal_fit_actions == before.goal_fit_actions | set(doc["goal_fit_actions"])
    layer_id = publish_global_layer(layer="emergency_overlay", version=uuid.uuid4().int % 10**9,
                                    document=doc, actor="dp15-parity-test")
    try:
        real = rm.read_policy()
    finally:
        deactivate_global_layer(layer_id, actor="dp15-parity-test")
    assert real == rehearsed
    assert rm.read_policy() == before


@pytest.mark.usefixtures("db_available")
def test_the_rehearsal_can_see_a_switch_that_is_on_and_refuses_what_a_publication_would():
    from control_plane.policy.layers import load_effective_policy_with
    from control_plane.policy.merge import EmergencyOverlayError
    from control_plane.state.db import engagement_scope

    assert rm.read_policy(extra=[("emergency_overlay", {"goal_fit_enforce": True})]
                          ).goal_fit_enforce is True
    assert rm.read_policy(extra=[("emergency_overlay", {"task_relation_enforce": True})]
                          ).task_relation_enforce is True
    with engagement_scope("ENG-DP15-PROBE") as conn:
        with pytest.raises(EmergencyOverlayError):                  # an overlay may only tighten
            load_effective_policy_with(conn, "ENG-DP15-PROBE",
                                       [("emergency_overlay", {"goal_fit_enforce": False})])


# -- execute: what it does with a refusal ---------------------------------------

def run_args(**kw):
    values = dict(concurrency=2, max_proposals=180, max_cost=3.0, yes=False, allow_nonempty=False)
    values.update(kw)
    return rm.argparse.Namespace(**values)


@pytest.fixture
def nothing_may_be_made(monkeypatch):
    """execute must stop before it makes an engagement, asks to send, or runs the measurement."""
    import control_plane.orchestrator.engagement as engagement
    from scripts import manage_global_policy

    called = []

    def boom(*a, **k):
        called.append("made")
        raise AssertionError("execute went on past a refusal")

    monkeypatch.setattr(engagement, "create_engagement", boom)
    monkeypatch.setattr(manage_global_policy, "_confirm",
                        lambda *a, **k: called.append("asked") or True)
    monkeypatch.setattr(rm.Measurement, "run", lambda self: called.append("ran"))
    monkeypatch.setattr(rm, "preflight", lambda classes: [])
    return called


def test_execute_refuses_on_a_guard_prints_the_banner_first_and_goes_no_further(
        capsys, monkeypatch, nothing_may_be_made):
    clean_world(monkeypatch, guards=["network.scan already has 9 row(s)"],
                banner=("database: the_database", "migration revision: 0030"))
    assert rm.execute(run_args(), rm.build_plan()) == rm.EXIT_PRECONDITION
    captured = capsys.readouterr()
    assert "database: the_database" in captured.out
    assert "precondition failed: network.scan already has 9 row(s)" in captured.err
    assert nothing_may_be_made == []                                       # not even asked


def test_execute_lists_the_validator_problem_and_the_guards_together(
        capsys, monkeypatch, nothing_may_be_made):
    monkeypatch.setattr(rm, "preflight", lambda classes: ["a thing is wrong"])
    clean_world(monkeypatch, guards=["a guard said no"])
    assert rm.execute(run_args(), rm.build_plan()) == rm.EXIT_PRECONDITION
    err = capsys.readouterr().err
    assert "precondition failed: a thing is wrong" in err and "a guard said no" in err
    # and the flag does not reach the validator check
    clean_world(monkeypatch)
    assert rm.execute(run_args(allow_nonempty=True), rm.build_plan()) == rm.EXIT_PRECONDITION
    assert nothing_may_be_made == []


def test_execute_does_not_start_when_the_database_cannot_be_read(
        capsys, monkeypatch, nothing_may_be_made):
    def unreadable(**kw):
        raise OSError("connection refused")

    monkeypatch.setattr(rm, "check_startup", unreadable)
    assert rm.execute(run_args(), rm.build_plan()) == rm.EXIT_PRECONDITION
    err = capsys.readouterr().err
    assert "database could not be read (OSError)" in err and "guards cannot be checked" in err
    assert nothing_may_be_made == []


@pytest.mark.parametrize("allow", [False, True])
def test_execute_refuses_a_switch_that_is_on_with_or_without_the_flag(
        allow, capsys, monkeypatch, nothing_may_be_made):
    """The real guards, over a stubbed read: the policy has the switch on and the database is clean
    (the flag has nothing to lift) or dirty (it lifts the data refusals, not this one)."""
    monkeypatch.setattr(rm, "read_policy", lambda extra=(): rm.PolicyFacts(
        frozenset(rm.CLASSES), True, False, 1))
    monkeypatch.setattr(rm, "read_db_facts", lambda classes: facts(calls={"code.scan": 4}))
    assert rm.execute(run_args(allow_nonempty=allow), rm.build_plan()) == rm.EXIT_PRECONDITION
    err = capsys.readouterr().err
    assert "goal_fit_enforce is not off" in err
    assert ("already has 4 row(s)" in err) is (not allow)
    assert nothing_may_be_made == []


def test_execute_with_the_flag_prints_the_warning_before_anything_else(
        capsys, monkeypatch, nothing_may_be_made):
    clean_world(monkeypatch, guards=["x"])
    rm.execute(run_args(allow_nonempty=True), rm.build_plan())
    assert capsys.readouterr().out.startswith("WARNING: --allow-nonempty is set")


def test_execute_asks_after_showing_the_banner_and_stops_on_a_no(
        capsys, monkeypatch, nothing_may_be_made):
    from scripts import manage_global_policy

    asked = []
    monkeypatch.setattr(manage_global_policy, "_confirm",
                        lambda prompt, word, default: asked.append(prompt) or False)
    clean_world(monkeypatch, banner=("database: the_database",))
    assert rm.execute(run_args(), rm.build_plan()) == rm.EXIT_USAGE
    assert "database: the_database" in capsys.readouterr().out
    assert len(asked) == 1 and "into the database above" in asked[0]
    assert nothing_may_be_made == []


def test_the_guards_are_read_again_over_the_engagements_own_policy(monkeypatch):
    effective = type("P", (), {"goal_fit_actions": frozenset(rm.CLASSES),
                               "goal_fit_enforce": False, "task_relation_enforce": False})()
    monkeypatch.setattr(rm, "read_db_facts", lambda classes: facts())
    assert rm.engagement_guards(effective, allow_nonempty=False) == []
    monkeypatch.setattr(rm, "read_db_facts", lambda classes: facts(calls={"code.secrets": 2}))
    again = rm.engagement_guards(effective, allow_nonempty=False)
    assert len(again) == 1 and "code.secrets already has 2" in again[0]
    assert rm.engagement_guards(effective, allow_nonempty=True) == []
    effective.goal_fit_enforce = True
    assert "goal_fit_enforce is not off" in "\n".join(
        rm.engagement_guards(effective, allow_nonempty=True))
    effective.goal_fit_enforce = False
    effective.goal_fit_actions = frozenset(rm.CLASSES[:2])
    assert "is not in the effective policy's goal_fit_actions" in "\n".join(
        rm.engagement_guards(effective, allow_nonempty=True))


def test_the_effective_policy_must_list_the_three_classes_and_have_the_switch_off():
    from control_plane.policy.merge import PolicyLayer, merge_policy

    empty = PolicyLayer(name="x")

    def policy(*layers):
        return merge_policy(empty, empty, empty, *layers) if layers else merge_policy(
            empty, empty, empty, empty)

    listed = PolicyLayer(name="engagement", goal_fit_actions=frozenset(rm.CLASSES))
    assert rm.check_effective_policy(policy(listed)) == []
    none = rm.check_effective_policy(policy())
    assert len(none) == 3 and all("not in the effective policy" in p for p in none)
    two = PolicyLayer(name="engagement", goal_fit_actions=frozenset(rm.CLASSES[:2]))
    assert len(rm.check_effective_policy(policy(two))) == 1
    on = PolicyLayer(name="engagement", goal_fit_actions=frozenset(rm.CLASSES),
                     goal_fit_enforce=True)
    wrong = rm.check_effective_policy(policy(on))
    assert len(wrong) == 1 and "goal_fit_enforce is not off" in wrong[0]


def test_the_script_publishes_no_global_policy_and_never_takes_the_one_look():
    """Read from the source: it names none of the functions that publish a global layer, a
    baseline included, and none that write a look or run the report."""
    tree = ast.parse(SCRIPT.read_text())
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
              for a in n.names}
    for forbidden in ("publish_policy_layer", "publish_global_layer", "ensure_test_baseline",
                      "record_views", "record_looks", "_report", "view_counts",
                      "clear_suspension"):
        assert forbidden not in names, forbidden
    source = SCRIPT.read_text()
    # it reads the global layers (to refuse to start without the list); it writes none
    for write in ("INSERT INTO policy_layers", "UPDATE policy_layers", "DELETE FROM policy_layers"):
        assert write not in source, write
    # it turns no switch on: no keyword or assignment gives either one a constant. The one place
    # that names a switch with a value is the control of a dry run (a further overlay added to a
    # read-only rehearsal, never published), and it is exactly one literal.
    switches = ("goal_fit_enforce", "task_relation_enforce")
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in switches:
            assert not isinstance(node.value, ast.Constant), ast.dump(node)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                assert not (isinstance(target, ast.Attribute) and target.attr in switches)
    literals = [n for n in ast.walk(tree) if isinstance(n, ast.Dict)
                and any(isinstance(k, ast.Constant) and k.value in switches for k in n.keys)]
    assert len(literals) == 1
    assert source.count('("emergency_overlay", {"goal_fit_enforce": True})') == 1
    # the one engagement-scoped layer it writes is its own engagement's, through the helper
    assert source.count("publish_engagement_policy(") == 1


# -- the documents that go with the guards ---------------------------------------

DOCS = REPO / "docs" / "D68_DP15_RECORD_MODE"


def test_the_publish_document_says_how_to_make_the_clean_database_and_that_it_is_where_to_run():
    text = (DOCS / "PUBLISH_AND_ROLLBACK.md").read_text()
    section = text[text.index("## 0."):text.index("## 1.")]
    for needle in ("DB_NAME=cyberorch_dp15 bash scripts/init_db.sh", "alembic upgrade head",
                   f"**{rm.code_head()}**", "rewrites `.env`", "Pending approvals must be 0",
                   "SELECT 'pending approvals', count(*) FROM action_proposals",
                   "pipeline_stage = 'awaiting_approval'", "--allow-nonempty",
                   "refuses to start", "baseline_global"):
        assert needle in section, needle
    assert "run in a database made for it" in section
    assert text.count("## ") >= 6 and "## 0." in text.split("## 1.")[0]


def test_the_committed_dry_run_shows_the_policy_after_publication_with_the_switch_off():
    out = (DOCS / "dry_run_output.txt").read_text()
    lines = out.splitlines()
    assert lines[0].startswith("DRY RUN -- nothing was sent, no model was called")
    after = next(line for line in lines if line.startswith("effective policy AFTER publishing"))
    assert "goal_fit_actions: code.scan, code.secrets, network.scan" in after
    assert "goal_fit_enforce: off" in after
    assert any("computed by the policy code" in line for line in lines)
    assert any("turns the switch on reads goal_fit_enforce: ON" in line for line in lines)
    head = rm.code_head()
    assert f"migration revision: {head} -- this checkout's head is {head}" in out
    assert ("calls already recorded (goal_fit_calls): "
            "code.scan 0, code.secrets 0, network.scan 0") in out
    assert "startup guards: ok" in out
    refused = (DOCS / "dry_run_refused_on_dev_db.txt").read_text()
    assert "WOULD REFUSE: network.scan already has" in refused
    assert refused.rstrip().endswith("(exit status 1)")
