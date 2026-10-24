#!/usr/bin/env python
"""D68 DP-15 record mode: the traffic generator for the pre-registered measurement.

    PYTHONPATH=. python scripts/dp15_record_mode.py              # a dry run: the plan, no model
    PYTHONPATH=. python scripts/dp15_record_mode.py --execute    # the measurement (not run yet)

**Read ``docs/D68_DP15_RECORD_MODE/MEASUREMENT_PLAN.md`` first: it was written before this file
and this file follows it.** Nothing here has been run against a model.

What it does, with ``--execute``: after an operator has published ``layer_record_mode.json`` (this
script never publishes a policy), it makes one engagement of its own, then issues proposals for
``network.scan``, ``code.scan`` and ``code.secrets`` through the real ``propose_action`` -- each
with a task of its own, a goal sentence fixed in the plan and a target host used by no other
proposal -- until each class has 50 *judgements* (a call that ended answered, refusal or
unclassified; a transport failure is not one). At most two calls are in flight; no proposal is
repeated and no call retried (a transport loss is replaced by a new proposal, at most 60 per
class); the run stops at 180 proposals, US$3.00 or 60 minutes, and **stops, does not retry and
does not resume** when transport failures are more than half of the last 30 calls. A class that
the exit rule suspends is censored where it stands.

The Reviewer is the scripted honest one and the sandbox a recording fake: no tool runs and no
target is touched; the one model call per proposal is the validator's. The goal-fit switch is not
read, set or changed here, and neither is ``task_relation_enforce``.

**What it prints.** While running, progress counts. At the end, per class: proposals issued,
validator calls made, judgements counted, suspended or not -- and no failure count and no rate. It
never runs ``manage_goal_fit_classes.py report``: the one look at the result is the operator's,
after the run (plan, rule 5).

Exit status: 0 the run completed, 1 a precondition failed (nothing was sent), 2 usage,
3 stopped early (outage, a cap, or the pipeline raising) with what it had.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# -- the registered numbers (MEASUREMENT_PLAN.md, section 2) --------------------------------------
CLASSES = ("network.scan", "code.scan", "code.secrets")
N = 50                      # judgements per class
PER_CLASS_MAX = 60          # proposals per class, N plus ten spare for transport losses
MAX_PROPOSALS = 180
MAX_CONCURRENCY = 2
MAX_COST_USD = 3.00
MAX_SECONDS = 3600.0
COST_PER_CALL_USD = 0.0088  # S7 fixed-model baseline: $4.23 for 480 calls
MEDIAN_SECONDS, P95_SECONDS = 3.2, 5.7
MAX_ESCAPED_ERRORS = 3      # propose_action raising (it should not): stop after this many

#: One sentence per class, differing only in the host. The sentences of tests/task_support.py.
GOALS = {
    "network.scan": "Scan {host} for open ports and the services behind them",
    "code.scan": "Scan the source at {host} for insecure patterns",
    "code.secrets": "Scan the repository at {host} for committed secrets",
}
NETWORK_SCOPE = "10.77.0.0/16"
#: the plain roles and the zones of the S7 corpus (tests/plan_fit_corpus.py); never the
#: sensitive roles
ROLES = ("www", "blog", "docs", "status", "shop", "events", "careers", "press", "help",
         "intranet-wiki", "portal", "kb", "downloads", "support", "partners")
ZONES = ("corp", "eu", "us", "lab", "ops", "dmz")
LAYER_FILE = REPO_ROOT / "docs" / "D68_DP15_RECORD_MODE" / "layer_record_mode.json"

EXIT_OK, EXIT_PRECONDITION, EXIT_USAGE, EXIT_STOPPED = 0, 1, 2, 3


# -- the plan: pure, no database, no model ---------------------------------------------------------

@dataclass(frozen=True)
class Planned:
    seq: int            # position in the interleaved order
    action: str
    index: int          # position within its class
    target_type: str    # "ip" or "fqdn"
    host: str
    goal: str


def host_for(action: str, index: int, code_offset: int = 0) -> tuple[str, str]:
    """``(target type, host)`` for the ``index``-th proposal of a class. Every host of the whole
    plan is different: the addresses by construction, the names because
    ``(role, number)`` determines the running number they come from."""
    if action == "network.scan":
        return "ip", f"10.77.{1 + index // 200}.{1 + index % 200}"
    g = code_offset + index
    role, number, zone = ROLES[g % len(ROLES)], 1 + g // len(ROLES), ZONES[g % len(ZONES)]
    return "fqdn", f"{role}{number:02d}.{zone}.example"


def build_plan(classes: tuple[str, ...] = CLASSES, per_class: int = PER_CLASS_MAX) -> list[Planned]:
    """Every proposal of the run, interleaved class by class (so a bad hour falls on all three)."""
    code_classes = [c for c in classes if c.startswith("code.")]
    offsets = {c: i * per_class for i, c in enumerate(code_classes)}
    plan: list[Planned] = []
    for index in range(per_class):
        for action in classes:
            target_type, host = host_for(action, index, offsets.get(action, 0))
            plan.append(Planned(len(plan), action, index, target_type, host,
                                GOALS[action].format(host=host)))
    return plan


def check_plan(plan: list[Planned], classes: tuple[str, ...] = CLASSES,
               per_class: int = PER_CLASS_MAX, n: int = N) -> list[str]:
    """What is wrong with a plan (empty: nothing). Run before anything is sent."""
    problems: list[str] = []
    hosts = [p.host for p in plan]
    if len(set(hosts)) != len(hosts):
        problems.append("a target host is used by more than one proposal")
    if len({p.goal for p in plan}) != len(plan):
        problems.append("two proposals have the same goal sentence")
    for action in classes:
        mine = [p for p in plan if p.action == action]
        if len(mine) != per_class:
            problems.append(f"{action}: {len(mine)} proposals planned, {per_class} registered")
        if [p.index for p in mine] != list(range(per_class)):
            problems.append(f"{action}: the proposals are not numbered 0..{per_class - 1} in order")
        for p in mine:
            if p.goal != GOALS[action].format(host=p.host):
                problems.append(f"{action}: a goal sentence differs from the registered one")
                break
    if per_class < n:
        problems.append(f"{per_class} proposals per class cannot give {n} judgements")
    if len(plan) > MAX_PROPOSALS:
        problems.append(f"{len(plan)} proposals planned, the cap is {MAX_PROPOSALS}")
    if any(p.target_type == "ip" and not p.host.startswith("10.77.") for p in plan):
        problems.append("an address is outside the registered scope")
    if any(p.target_type == "fqdn" and not p.host.endswith(".example") for p in plan):
        problems.append("a host name is outside the registered zones")
    return problems


def estimate(classes: tuple[str, ...] = CLASSES, n: int = N,
             per_class: int = PER_CLASS_MAX) -> dict[str, float]:
    """Cost and time, from the S7 fixed-model figures. Estimates, not promises."""
    planned, worst = len(classes) * n, len(classes) * per_class
    return {
        "planned_calls": planned, "worst_case_calls": worst,
        "cost_planned_usd": round(planned * COST_PER_CALL_USD, 2),
        "cost_worst_usd": round(worst * COST_PER_CALL_USD, 2),
        "cost_cap_usd": MAX_COST_USD,
        "minutes_planned": round(planned * MEDIAN_SECONDS / MAX_CONCURRENCY / 60, 1),
        "minutes_worst": round(worst * P95_SECONDS / MAX_CONCURRENCY / 60, 1),
        "minutes_cap": MAX_SECONDS / 60,
    }


# -- the run: the controller takes its world as arguments, so it is tested without one -------------

@dataclass(frozen=True)
class State:
    """What the tables say, read between calls. Counts and kinds only; nothing here is printed
    while the run is on."""

    judged: dict[str, int]                 # judgements since the start, per class
    asked: dict[str, int]                  # validator calls since the start (incl. transport)
    suspended: dict[str, int]              # class -> the judgements it had when it was suspended
    kinds_newest_first: list[str | None]   # failure kinds of the last calls of any class


@dataclass
class Result:
    issued: dict[str, int] = field(default_factory=dict)
    state: State | None = None
    stopped: str | None = None             # None: completed; else why it stopped early
    escaped_errors: int = 0
    seconds: float = 0.0

    @property
    def exit_code(self) -> int:
        return EXIT_OK if self.stopped is None else EXIT_STOPPED


class Measurement:
    def __init__(
        self, plan: list[Planned], *, issue: Callable[[Planned], None],
        read_state: Callable[[], State], cost_so_far: Callable[[], float] = lambda: 0.0,
        classes: tuple[str, ...] = CLASSES, n: int = N, per_class: int = PER_CLASS_MAX,
        concurrency: int = MAX_CONCURRENCY, max_proposals: int = MAX_PROPOSALS,
        max_cost: float = MAX_COST_USD, max_seconds: float = MAX_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        progress: Callable[[int, int], None] | None = None,
    ) -> None:
        if not 1 <= concurrency <= MAX_CONCURRENCY:
            raise ValueError(f"concurrency is 1 to {MAX_CONCURRENCY}, not {concurrency}")
        if max_proposals > MAX_PROPOSALS or max_cost > MAX_COST_USD or max_seconds > MAX_SECONDS:
            raise ValueError("a cap may be lowered, never raised")
        self.plan, self.issue, self.read_state = plan, issue, read_state
        self.cost_so_far = cost_so_far
        self.classes, self.n, self.per_class = classes, n, per_class
        self.concurrency, self.max_proposals = concurrency, max_proposals
        self.max_cost, self.max_seconds = max_cost, max_seconds
        self.clock, self.progress = clock, progress
        self._by_class = {c: [p for p in plan if p.action == c][:per_class] for c in classes}

    def stop_reason(self, state: State, started: float, errors: int) -> str | None:
        """Why no further proposal may be issued, or ``None``. Checked after every call. (The
        proposal cap is checked where a proposal is about to be issued: reaching it with nothing
        left to issue is a completed run, not a stopped one.)"""
        from control_plane.plan_fit.classes import review_outage

        if review_outage(state.kinds_newest_first).suspected:
            return "transport failures are more than half of the last 30 calls"
        if self.cost_so_far() >= self.max_cost:
            return f"the cost cap (US${self.max_cost:.2f}) was reached"
        if self.clock() - started >= self.max_seconds:
            return f"the time cap ({self.max_seconds / 60:.0f} minutes) was reached"
        if errors >= MAX_ESCAPED_ERRORS:
            return f"propose_action raised {errors} times (it should not)"
        return None

    def run(self) -> Result:
        started = self.clock()
        result = Result(issued={c: 0 for c in self.classes})
        inflight = {c: 0 for c in self.classes}
        cursor = {c: 0 for c in self.classes}
        pending: dict = {}
        state = self.read_state()
        turn = 0
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            while True:
                done, _ = wait(list(pending), timeout=0.02 if pending else 0,
                               return_when=FIRST_COMPLETED)
                for future in done:
                    planned = pending.pop(future)
                    inflight[planned.action] -= 1
                    if future.exception() is not None:
                        result.escaped_errors += 1
                    state = self.read_state()
                    if self.progress:
                        self.progress(sum(result.issued.values()),
                                      sum(result.issued.values()) - len(pending))
                if result.stopped is None:
                    result.stopped = self.stop_reason(state, started, result.escaped_errors)
                while result.stopped is None and len(pending) < self.concurrency:
                    chosen = None
                    for step in range(len(self.classes)):
                        c = self.classes[(turn + step) % len(self.classes)]
                        if (c not in state.suspended
                                and state.judged.get(c, 0) + inflight[c] < self.n
                                and cursor[c] < len(self._by_class[c])):
                            chosen, turn = c, (turn + step + 1) % len(self.classes)
                            break
                    if chosen is None:
                        break
                    if sum(result.issued.values()) >= self.max_proposals:
                        result.stopped = f"the proposal cap ({self.max_proposals}) was reached"
                        break
                    planned = self._by_class[chosen][cursor[chosen]]
                    cursor[chosen] += 1
                    inflight[chosen] += 1
                    result.issued[chosen] += 1
                    pending[pool.submit(self.issue, planned)] = planned
                if not pending:
                    break
        result.state = self.read_state()
        result.seconds = self.clock() - started
        return result


def render_result(result: Result, classes: tuple[str, ...] = CLASSES, n: int = N) -> str:
    """The end-of-run summary: calls made and suspension status. No failure count, no rate."""
    state = result.state
    lines = [f"{'class':<14}{'proposals':>10}{'validator calls':>17}{'judgements':>12}  suspended"]
    for c in classes:
        suspended = (f"yes, censored at n={state.suspended[c]}" if state and c in state.suspended
                     else "no")
        asked = state.asked.get(c, 0) if state else 0
        judged = state.judged.get(c, 0) if state else 0
        lines.append(f"{c:<14}{result.issued.get(c, 0):>10}{asked:>17}{judged:>12}  {suspended}")
    lines.append(f"registered judgements per class: {n}; run time {result.seconds / 60:.1f} min")
    if result.stopped:
        lines.append(f"STOPPED EARLY: {result.stopped}. Nothing was retried and nothing resumes.")
    else:
        lines.append("completed. Run `manage_goal_fit_classes.py report` once, now, and not "
                     "before.")
    return "\n".join(lines)


# -- the real world: only reached with --execute ---------------------------------------------------

def read_state_from_tables(classes: tuple[str, ...], start_call_id: int) -> State:
    """Counts from ``goal_fit_calls`` and ``goal_fit_suspensions`` since the run began (over the
    runtime connection, which can read both)."""
    from sqlalchemy import text

    from control_plane.state.db import get_engine

    with get_engine().begin() as conn:
        rows = conn.execute(text(
            "SELECT action, count(*) FILTER (WHERE failure_kind IS DISTINCT FROM 'transport'), "
            "count(*) FROM goal_fit_calls WHERE call_id > :s AND action = ANY(:c) "
            "GROUP BY action"), {"s": start_call_id, "c": list(classes)}).all()
        kinds = [r[0] for r in conn.execute(text(
            "SELECT failure_kind FROM goal_fit_calls WHERE call_id > :s "
            "ORDER BY call_id DESC LIMIT 30"), {"s": start_call_id})]
        suspended = {a: int(n) for a, n in conn.execute(text(
            "SELECT action, window_n FROM goal_fit_suspensions "
            "WHERE cleared_at IS NULL AND action = ANY(:c)"), {"c": list(classes)})}
    return State(judged={a: int(j) for a, j, _ in rows}, asked={a: int(t) for a, _, t in rows},
                 suspended=suspended, kinds_newest_first=kinds)


def check_effective_policy(policy, classes: tuple[str, ...] = CLASSES) -> list[str]:
    """What is wrong with the policy this run would govern (empty: nothing). Read from the
    effective policy of the run's own engagement, so what is checked is what the pipeline will
    use, and not a guess from the layer table."""
    problems = []
    for c in classes:
        if c not in policy.goal_fit_actions:
            problems.append(f"{c} is not in the effective policy's goal_fit_actions: publish "
                            "layer_record_mode.json first (this script publishes nothing)")
    if policy.goal_fit_enforce:
        problems.append("goal_fit_enforce is on in the effective policy: this is the record-mode "
                        "measurement, with the switch off")
    return problems


def preflight(classes: tuple[str, ...]) -> tuple[list[str], dict]:
    """What must be true before the run's engagement is made. ``(problems, facts)``. The policy is
    checked after the engagement exists (:func:`check_effective_policy`); a missing baseline stops
    the engagement's creation, and this script will not publish one."""
    import os

    from sqlalchemy import text

    from control_plane.plan_fit import class_store
    from control_plane.state.db import get_engine
    from scripts.s8_enablement_check import (
        NO_FALLBACK_ENV,
        PLANFIT_BACKEND_ENV,
        PLANFIT_MODEL_ENV,
        config_problems,
    )

    problems: list[str] = []
    backend = os.environ.get(PLANFIT_BACKEND_ENV)
    if not (backend or "").strip() or backend.strip().lower() == "fake":
        problems.append(f"no real validator is configured ({PLANFIT_BACKEND_ENV}={backend!r})")
    else:
        problems += config_problems(backend=backend, model=os.environ.get(PLANFIT_MODEL_ENV),
                                    fallback_off=os.environ.get(NO_FALLBACK_ENV))
    with get_engine().begin() as conn:
        table = {r["action"]: r for r in class_store.class_table(conn, ())}
        live = {a for (a,) in conn.execute(text(
            "SELECT action FROM goal_fit_suspensions WHERE cleared_at IS NULL"))}
    for c in classes:
        if c in live:
            problems.append(f"{c} is already suspended")
    facts = {"start_counts": {c: (table.get(c, {}).get("n_total", 0),
                                  table.get(c, {}).get("transport_total", 0)) for c in classes}}
    return problems, facts


def execute(args: argparse.Namespace, plan: list[Planned]) -> int:
    import json
    import os
    import subprocess

    from sqlalchemy import text

    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from agents.llm.selection import build_plan_fit_validator
    from control_plane.api.function_api import propose_action
    from control_plane.config import load_dotenv
    from control_plane.orchestrator.engagement import create_engagement
    from control_plane.policy.layers import load_effective_policy
    from control_plane.state.db import engagement_scope, get_engine
    from scripts.s8_enablement_check import NO_FALLBACK_ENV
    from tests.helpers import EngagementManager
    from tests.scheduler_support import proposal_for, publish_engagement_policy, register_scope
    from tests.task_support import attach_task
    from tool_gateway.sandbox import SandboxResult

    load_dotenv()
    problems, facts = preflight(CLASSES)
    if problems:
        for p in problems:
            print(f"precondition failed: {p}", file=sys.stderr)
        return EXIT_PRECONDITION
    print("starting state (counts only): " + ", ".join(
        f"{c}: {a} calls recorded, {b} of them transport" for c, (a, b) in
        facts["start_counts"].items()))

    from control_plane.state.db import registry_admin_scope

    eid = f"ENG-DP15-RM-{time.strftime('%m%d%H%M%S', time.gmtime())}"
    with registry_admin_scope(eid) as conn:
        create_engagement(conn, engagement_id=eid, customer_id="CUST-DP15",
                          actor="dp15-record-mode")
    publish_engagement_policy(eid, actions=CLASSES)     # an engagement's own layer; nothing global
    manager = EngagementManager(eid)
    scopes = {"network.scan": register_scope(manager, type="cidr", value=NETWORK_SCOPE,
                                             actions=CLASSES)}
    for zone in ZONES:
        scopes[zone] = register_scope(manager, type="fqdn", value=f"{zone}.example",
                                      actions=CLASSES)
    with engagement_scope(eid) as conn:
        policy = load_effective_policy(conn, eid)
    wrong = check_effective_policy(policy)
    if wrong:
        for p in wrong:
            print(f"precondition failed: {p}", file=sys.stderr)
        print("nothing was sent (an empty engagement was made)", file=sys.stderr)
        return EXIT_PRECONDITION
    with get_engine().begin() as conn:
        start_call_id = int(conn.execute(text(
            "SELECT coalesce(max(call_id), 0) FROM goal_fit_calls")).scalar_one())

    local = threading.local()
    meters: list = []
    lock = threading.Lock()

    class Metered:
        """subprocess.run, with the refusal fallback off (the DP-14 configuration) and the cost
        of each call read from the CLI's own envelope."""

        def __init__(self):
            self.cost = 0.0

        def __call__(self, *a, **kw):
            kw["env"] = {**os.environ, **kw.get("env", {}), NO_FALLBACK_ENV: "1"}
            done = subprocess.run(*a, **kw)
            try:
                self.cost += float(json.loads(done.stdout or "{}").get("total_cost_usd") or 0.0)
            except (ValueError, TypeError, AttributeError):
                pass
            return done

    def validator():
        if not hasattr(local, "v"):
            local.meter = Metered()
            with lock:
                meters.append(local.meter)
            local.v = build_plan_fit_validator(runner=local.meter)
        return local.v

    class Sandbox:
        def run(self, **kwargs):
            return SandboxResult(0, "recorded, not run", "", False, 0.0, (NETWORK_SCOPE,), "fake")

    def issue(p: Planned) -> None:
        zone = None if p.action == "network.scan" else p.host.split(".")[1]
        scope = scopes["network.scan"] if zone is None else scopes[zone]
        proposal = proposal_for(scope, host=p.host, action=p.action, target_type=p.target_type)
        proposal = attach_task(eid, proposal, goal=p.goal)
        propose_action(
            engagement_id=eid, proposal=proposal, reviewer=HonestFakeReviewer(), policy=policy,
            agent_id="dp15-record-mode", sandbox=Sandbox(), network_allowlist=[NETWORK_SCOPE],
            plan_fit_validator=validator(), idempotency_key=f"dp15-rm-{eid}-{p.seq}")

    def progress(issued: int, finished: int) -> None:
        print(f"proposals issued {issued}, finished {finished}", flush=True)

    run = Measurement(
        plan, issue=issue, read_state=lambda: read_state_from_tables(CLASSES, start_call_id),
        cost_so_far=lambda: sum(m.cost for m in list(meters)), concurrency=args.concurrency,
        max_proposals=min(args.max_proposals, MAX_PROPOSALS),
        max_cost=min(args.max_cost, MAX_COST_USD), progress=progress)
    result = run.run()
    print(render_result(result))
    return result.exit_code


def dry_run(plan: list[Planned], args: argparse.Namespace) -> int:
    """The plan and its checks. No database, no model, no network, no file written."""
    problems = check_plan(plan)
    est = estimate()
    print("DRY RUN -- nothing was sent, no model was called, no database was opened.")
    print(f"classes: {', '.join(CLASSES)}   registered judgements per class: {N}")
    print(f"proposals planned: {len(plan)} ({PER_CLASS_MAX} per class: {N} + {PER_CLASS_MAX - N} "
          f"spare targets, used only to replace a transport loss)")
    print(f"bounds: at most {args.concurrency} in flight, {args.max_proposals} proposals, "
          f"US${args.max_cost:.2f}, {MAX_SECONDS / 60:.0f} minutes; stops (no retry, no resume) "
          "when transport failures are more than half of the last 30 calls")
    print(f"cost estimate: {est['planned_calls']} calls x US${COST_PER_CALL_USD} = "
          f"US${est['cost_planned_usd']} planned, US${est['cost_worst_usd']} worst case "
          f"({est['worst_case_calls']} calls), cap US${est['cost_cap_usd']}")
    print(f"time estimate: about {est['minutes_planned']} min planned, "
          f"{est['minutes_worst']} min worst case at two in flight")
    print("goal sentences (fixed):")
    for action, sentence in GOALS.items():
        first = next(p for p in plan if p.action == action)
        print(f"  {action:<13}{sentence}   e.g. {first.host}")
    distinct = len({p.host for p in plan})
    print(f"targets: {distinct} distinct hosts for {len(plan)} proposals "
          f"({sum(p.target_type == 'ip' for p in plan)} addresses, "
          f"{sum(p.target_type == 'fqdn' for p in plan)} host names)")
    print("order (first twelve): " + ", ".join(f"{p.action}#{p.index}" for p in plan[:12]))
    if problems:
        for problem in problems:
            print(f"PLAN PROBLEM: {problem}", file=sys.stderr)
        return EXIT_PRECONDITION
    print("plan checks: ok (no host repeated, 60 per class in order, sentences as registered)")
    print("preflight (not run in a dry run): validator configured as DP-14 measured it; no class "
          "suspended; a baseline in force (the engagement cannot be made without one); and, in the "
          "run's own engagement, the three classes in the effective policy's goal_fit_actions with "
          "goal_fit_enforce off.")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--execute", action="store_true",
                        help="send the traffic (default: a dry run that sends nothing)")
    parser.add_argument("--concurrency", type=int, default=MAX_CONCURRENCY)
    parser.add_argument("--max-proposals", type=int, default=MAX_PROPOSALS)
    parser.add_argument("--max-cost", type=float, default=MAX_COST_USD)
    parser.add_argument("--yes", action="store_true", help="do not ask before --execute")
    args = parser.parse_args(argv)
    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        print(f"refused: concurrency is 1 to {MAX_CONCURRENCY}", file=sys.stderr)
        return EXIT_USAGE
    if args.max_proposals > MAX_PROPOSALS or args.max_cost > MAX_COST_USD:
        print("refused: a cap may be lowered, never raised", file=sys.stderr)
        return EXIT_USAGE
    plan = build_plan()
    if not args.execute:
        return dry_run(plan, args)
    problems = check_plan(plan)
    if problems:
        for problem in problems:
            print(f"PLAN PROBLEM: {problem}", file=sys.stderr)
        return EXIT_PRECONDITION
    if not args.yes:
        from scripts.manage_global_policy import _confirm

        if not _confirm("SEND the DP-15 record-mode measurement: up to "
                        f"{args.max_proposals} proposals, US${args.max_cost:.2f}, real model "
                        "calls.", "SEND", False):
            return EXIT_USAGE
    return execute(args, plan)


if __name__ == "__main__":
    raise SystemExit(main())
