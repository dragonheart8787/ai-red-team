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

def test_the_dry_run_prints_the_plan_and_touches_neither_the_database_nor_a_model(
        capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a dry run reached for something")

    import agents.llm.selection as selection
    import control_plane.state.db as db

    monkeypatch.setattr(db, "get_engine", boom)
    monkeypatch.setattr(db, "global_policy_admin_scope", boom)
    monkeypatch.setattr(selection, "build_plan_fit_validator", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    assert rm.main([]) == 0
    out = capsys.readouterr().out
    assert out.startswith("DRY RUN -- nothing was sent, no model was called")
    for needle in ("180 distinct hosts", "US$1.32 planned", "US$1.58 worst case",
                   "plan checks: ok", "network.scan", "code.scan", "code.secrets"):
        assert needle in out, needle


def test_the_dry_run_as_a_process_needs_no_credentials_and_exits_zero():
    done = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True,
                          cwd=REPO, env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO)},
                          timeout=60)
    assert done.returncode == 0, done.stderr
    assert "DRY RUN" in done.stdout and "no model was called" in done.stdout


def test_without_the_flag_nothing_is_sent_and_the_flag_alone_asks_first(capsys, monkeypatch):
    sent = []
    monkeypatch.setattr(rm, "execute", lambda *a, **k: sent.append(1) or 0)
    assert rm.main([]) == 0 and sent == []
    from scripts import manage_global_policy

    monkeypatch.setattr(manage_global_policy, "_confirm", lambda *a, **k: False)
    assert rm.main(["--execute"]) == rm.EXIT_USAGE and sent == []        # declined: still nothing
    monkeypatch.setattr(manage_global_policy, "_confirm", lambda *a, **k: True)
    assert rm.main(["--execute"]) == 0 and sent == [1]


@pytest.mark.parametrize("flags", [["--concurrency", "3"], ["--concurrency", "0"],
                                   ["--max-proposals", "181"], ["--max-cost", "3.5"]])
def test_the_command_line_refuses_to_raise_a_cap(flags, capsys):
    assert rm.main(flags) == rm.EXIT_USAGE
    assert "refused" in capsys.readouterr().err


@pytest.mark.usefixtures("db_available")
def test_a_failed_precondition_sends_nothing(capsys, monkeypatch):
    """The real preflight, on the development database: no real validator is configured here and
    the classes are not listed by an active global layer, so it refuses -- and nothing was sent."""
    monkeypatch.delenv("CYBERORCH_PLANFIT_BACKEND", raising=False)
    problems, facts = rm.preflight(rm.CLASSES)
    text = "\n".join(problems)
    assert "no real validator is configured" in text
    assert set(facts["start_counts"]) == set(rm.CLASSES)
    issued = []
    monkeypatch.setattr(rm, "preflight", lambda classes: (["a thing is wrong"], {}))
    import scripts.dp15_record_mode as mod
    monkeypatch.setattr(mod.Measurement, "run", lambda self: issued.append(1))
    args = mod.argparse.Namespace(concurrency=2, max_proposals=180, max_cost=3.0)
    assert mod.execute(args, rm.build_plan()) == rm.EXIT_PRECONDITION
    assert issued == []
    assert "precondition failed: a thing is wrong" in capsys.readouterr().err


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
    assert "goal_fit_enforce=" not in source and "task_relation_enforce=" not in source
    # the one engagement-scoped layer it writes is its own engagement's, through the helper
    assert source.count("publish_engagement_policy(") == 1
