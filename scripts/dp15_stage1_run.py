"""D68 DP-15 enable-decision, stage 1: the run (``dp15_enable_stage1.py --execute`` calls this).

**Built, not run.** Read ``docs/D68_DP15_RECORD_MODE/ENABLE_DECISION_PLAN.md`` first (sections 3, 5,
9, 10, 13). The run needs the owner's separate authorization; until then it is exercised only with
fake validators, in tests.

What a run is. After the startup checks below, 180 questions (Leg A: 60 wordings x 3 repeats, each
repeat with a different target) are put to the validator directly -- through the control plane's own
``assess_goal_fit``, so a failure is classified exactly as the pipeline classifies it -- and nothing
is written to a database. Then 10 more (Leg B: the first repeat of 10 wordings, on the same target)
go through ``propose_action`` in the clean database ``cyberorch_dp15b``. At most two are in flight
in Leg A and one in Leg B.

**Startup checks (they run first; any one refuses and nothing is sent).**
the wording file's sha256 equals the one the plan registers; the wording rules hold; the database is
``cyberorch_dp15b``, at the code's migration head, with ``goal_fit_calls`` and
``goal_fit_suspensions`` empty and ``goal_fit_enforce`` off in the effective policy (and
``network.scan`` among its ``goal_fit_actions``: the record layer is published); the validator is
the one DP-14 measured (backend, model alias ``sonnet``, refusal fallback off); the record file does
not exist yet. Before Leg B starts the database guards are read again.

**While it runs** only a progress count is printed: no rate, no outcome. **It stops, finally,
with no retry and no resume,** when a hard cap is reached (CLI runs, list-price US$, minutes:
the caps of the plan, lowerable by flag, never raisable), when transport failures are more than
half of the last 30 calls, or when a question raised three times. A stopped run is analysed as
it stands.

**At the end** the item-level record (``--record``, JSONL; one header, one line per call, one
footer) is complete, the summary of calls and usage is printed, and the one analysis
(``dp15_stage1_analysis.py``) is run once on the record: C1 met / not met / not evaluable.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts import dp15_enable_stage1 as st  # noqa: E402
from scripts import dp15_record_mode as rm  # noqa: E402
from scripts import dp15_stage1_analysis as an  # noqa: E402

CLASS = "network.scan"
PROMPT_DIGEST = "5e2357979fb3"   # the prompt DP-14 and S7 measured (12 hex of its sha256)
STAGE_DIR = REPO_ROOT / "docs" / "D68_DP15_RECORD_MODE" / "stage1"
DEFAULT_RECORD = STAGE_DIR / "record.jsonl"
MAX_CONCURRENCY = 2             # Leg A; Leg B is one at a time
MAX_ESCAPED_ERRORS = 3          # a question raising (it should not): stop after this many
LEG_B_SCOPE = "10.0.0.0/8"      # the scope object of Leg B's engagement: covers every target
EXIT_OK, EXIT_REFUSED, EXIT_USAGE, EXIT_STOPPED = 0, 1, 2, 3


# -- the controller: its world is passed in, so it is tested without one ---------------------------

@dataclass
class Outcome:
    issued: int = 0
    finished: int = 0
    stopped: str | None = None          # None: every planned call was made
    escaped_errors: int = 0
    seconds: float = 0.0
    kinds_newest_first: list = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return EXIT_OK if self.stopped is None else EXIT_STOPPED


class Stage1Run:
    """Issues the planned calls in their order and writes one record line per finished call.

    ``ask(call)`` returns the fields of the answer (``goal_fit``, ``failure_kind``, ...); the
    controller adds the plan's own fields. Whatever ``ask`` raises is recorded as a failed call and
    counted. ``before_leg_b()`` returns the reasons Leg B may not start (empty: it may)."""

    def __init__(self, calls: list[st.Call], *, ask: Callable[[st.Call], dict],
                 write: Callable[[dict], None], sources: dict[int, str],
                 caps: dict[str, float], cost_so_far: Callable[[], float] = lambda: 0.0,
                 cli_runs: Callable[[], int] = lambda: 0,
                 before_leg_b: Callable[[], list[str]] = lambda: [],
                 progress: Callable[[int, int], None] | None = None,
                 concurrency: int = MAX_CONCURRENCY,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if not 1 <= concurrency <= MAX_CONCURRENCY:
            raise ValueError(f"concurrency is 1 to {MAX_CONCURRENCY}, not {concurrency}")
        self.calls, self.ask, self.write, self.sources = calls, ask, write, sources
        self.caps, self.cost_so_far, self.cli_runs = caps, cost_so_far, cli_runs
        self.before_leg_b, self.progress = before_leg_b, progress
        self.concurrency, self.clock = concurrency, clock

    def stop_reason(self, out: Outcome, started: float) -> str | None:
        """Why nothing further may be issued, or ``None``. Checked before every call and after
        every finished one."""
        from control_plane.plan_fit.classes import review_outage

        if review_outage(out.kinds_newest_first).suspected:
            return "transport failures are more than half of the last 30 calls"
        if max(self.cli_runs(), out.issued) >= self.caps["runs"]:
            return f"the CLI-runs cap ({int(self.caps['runs'])}) was reached"
        if self.cost_so_far() >= self.caps["usd"]:
            return f"the cost cap (US${self.caps['usd']:.2f}) was reached"
        if self.clock() - started >= self.caps["minutes"] * 60:
            return f"the time cap ({int(self.caps['minutes'])} minutes) was reached"
        if out.escaped_errors >= MAX_ESCAPED_ERRORS:
            return f"a question raised {out.escaped_errors} times (it should not)"
        return None

    def _entry(self, seq: int, call: st.Call, answer: dict | None, error: str | None) -> dict:
        entry = {"type": "call", "seq": seq, "leg": call.leg, "wording": call.wording,
                 "repeat": call.repeat, "source": self.sources.get(call.wording),
                 "target": call.target, "at": time.strftime("%H:%M:%S", time.gmtime())}
        if error is not None:                  # what escaped is the validator's failure, unnamed
            entry.update(goal_fit="failed", failure_kind="unclassified", error=error)
        else:
            entry.update(answer or {})
        return entry

    def run(self) -> Outcome:
        out = Outcome()
        started = self.clock()
        leg_a = [c for c in self.calls if c.leg == "A"]
        leg_b = [c for c in self.calls if c.leg == "B"]
        self._leg(leg_a, self.concurrency, out, started)
        if out.stopped is None and leg_b:
            blocked = self.before_leg_b()
            if blocked:
                out.stopped = "Leg B may not start: " + "; ".join(blocked)
            else:
                self._leg(leg_b, 1, out, started)
        out.seconds = self.clock() - started
        return out

    def _leg(self, todo: list[st.Call], width: int, out: Outcome, started: float) -> None:
        pending: dict = {}
        cursor = 0
        with ThreadPoolExecutor(max_workers=width) as pool:
            while True:
                done, _ = wait(list(pending), timeout=0.02 if pending else 0,
                               return_when=FIRST_COMPLETED)
                for future in done:
                    seq, call = pending.pop(future)
                    error = type(future.exception()).__name__ if future.exception() else None
                    entry = self._entry(seq, call, None if error else future.result(), error)
                    out.escaped_errors += error is not None
                    out.finished += 1
                    out.kinds_newest_first.insert(0, entry.get("failure_kind"))
                    self.write(entry)
                    if self.progress:
                        self.progress(out.issued, out.finished)
                if out.stopped is None:
                    out.stopped = self.stop_reason(out, started)
                while out.stopped is None and len(pending) < width and cursor < len(todo):
                    call = todo[cursor]
                    cursor += 1
                    out.issued += 1
                    pending[pool.submit(self.ask, call)] = (out.issued, call)
                    out.stopped = self.stop_reason(out, started)
                if not pending:
                    break


# -- the world -------------------------------------------------------------------------------------

def canonical_target(target: str) -> str:
    """The form the control plane writes a target in (``ip:`` / ``cidr:``)."""
    return ("cidr:" if "/" in target else "ip:") + target


def query_text(wording: str, target: str) -> str:
    return wording.replace(st.TARGET_TOKEN, target)


class RealWorld:
    """The database, the validator and the engagement of Leg B. Only built by ``execute_cli``."""

    def __init__(self, wordings: list[st.Wording], *, leg_b_database: str = st.LEG_B_DATABASE):
        self.wordings = wordings
        self.leg_b_database = leg_b_database
        self.meters: list = []
        self._local = threading.local()
        self._lock = threading.Lock()
        self.engagement: str | None = None
        self.policy = None
        self.scope: str | None = None

    # startup ---------------------------------------------------------------------------------
    def startup(self) -> tuple[list[str], list[str]]:
        """``(banner lines, reasons to refuse)``. A database that cannot be read is a reason."""
        problems = list(rm.preflight((CLASS,)))
        configured = not problems
        try:
            banner, guards = rm.check_startup(allow_nonempty=False, rehearsal=False)
            problems += guards
            problems += rm.check_effective_policy(rm.read_policy(), (CLASS,))
            facts = st.read_leg_b_facts()
            problems += st.leg_b_problems(facts, self.leg_b_database)
            banner = list(banner) + [
                f"Leg B database: {facts.database} -- goal_fit_calls {facts.calls} row(s), "
                f"goal_fit_suspensions {facts.suspensions} row(s)"]
        except Exception as exc:  # the guards cannot be checked: do not start
            return [], problems + [f"the database could not be read ({type(exc).__name__}): the "
                                   "startup guards cannot be checked"]
        if configured:
            try:
                digest = self.prompt_digest()
            except Exception as exc:  # the validator cannot be built: nothing could be asked
                problems.append(f"the validator could not be built ({type(exc).__name__}): its "
                                "prompt cannot be checked")
            else:
                if digest != PROMPT_DIGEST:
                    problems.append(f"the validator's prompt digest is {digest!r}, the measured "
                                    f"one is {PROMPT_DIGEST!r}: a changed prompt is a new "
                                    "registration")
        return banner, problems

    def prompt_digest(self) -> str:
        """The first 12 hex of the sha256 of the validator's prompt contract, as it is built now."""
        validator = self.validator()
        prov = validator.provenance() if hasattr(validator, "provenance") else {}
        return str(prov.get("prompt_sha256", ""))[:12]

    def provenance(self) -> dict:
        import os

        from scripts.plan_fit_baseline import cli_version
        from scripts.s8_enablement_check import (
            NO_FALLBACK_ENV,
            PLANFIT_BACKEND_ENV,
            PLANFIT_MODEL_ENV,
        )

        validator = self.validator()
        prov = validator.provenance() if hasattr(validator, "provenance") else {}
        return {"backend": os.environ.get(PLANFIT_BACKEND_ENV),
                "model_alias": os.environ.get(PLANFIT_MODEL_ENV),
                "fallback": f"{NO_FALLBACK_ENV}={os.environ.get(NO_FALLBACK_ENV)}",
                "cli_version": cli_version(),
                "prompt_digest": str(prov.get("prompt_sha256", ""))[:12]}

    # the validator ---------------------------------------------------------------------------
    def validator(self):
        """One validator, and one meter, per thread."""
        import os

        from agents.llm.selection import build_plan_fit_validator
        from scripts.s8_enablement_check import NO_FALLBACK_ENV

        if not hasattr(self._local, "v"):
            self._local.meter = rm.MeteredRunner(environ=dict(os.environ),
                                                 no_fallback_env=NO_FALLBACK_ENV)
            with self._lock:
                self.meters.append(self._local.meter)
            self._local.v = build_plan_fit_validator(runner=self._local.meter)
        return self._local.v

    def cost(self) -> float:
        return sum(m.cost for m in list(self.meters))

    def cli_runs(self) -> int:
        return sum(m.usage.cli_runs for m in list(self.meters))

    def usage(self) -> rm.Usage:
        return rm.Usage.total(m.usage for m in list(self.meters))

    # Leg A -----------------------------------------------------------------------------------
    def ask_leg_a(self, call: st.Call) -> dict:
        from control_plane.plan_fit import goal_fit as plan_goal
        from control_plane.plan_fit import relation as r

        wording = self.wordings[call.wording]
        canonical = canonical_target(call.target)
        got = plan_goal.assess_goal_fit(
            validator=self.validator(), relation=r.TaskRelation(r.MATCHES_TASK),
            task_context={"goal": query_text(wording.text, call.target), "action": CLASS,
                          "canonical_target": canonical},
            proposal_action=CLASS, proposal_target=canonical,
            enabled_actions=frozenset({CLASS}), suspended_actions=frozenset())
        if not got.asked:       # decided without asking: no question reached the validator
            raise RuntimeError(f"the validator was not asked ({got.cause})")
        return answer_fields(got)

    # Leg B -----------------------------------------------------------------------------------
    def begin_leg_b(self) -> list[str]:
        """Read the guards again, then make Leg B's engagement. Nothing is published globally."""
        from control_plane.orchestrator.engagement import create_engagement
        from control_plane.policy.layers import load_effective_policy
        from control_plane.state.db import engagement_scope, registry_admin_scope
        from tests.helpers import EngagementManager
        from tests.scheduler_support import publish_engagement_policy, register_scope

        again = st.leg_b_problems(st.read_leg_b_facts(), self.leg_b_database)
        if again:
            return again
        eid = (f"ENG-DP15-S1-{time.strftime('%m%d%H%M%S', time.gmtime())}"
               f"-{uuid.uuid4().hex[:6].upper()}")
        with registry_admin_scope(eid) as conn:
            create_engagement(conn, engagement_id=eid, customer_id="CUST-DP15",
                              actor="dp15-stage1")
        publish_engagement_policy(eid, actions=(CLASS,))
        manager = EngagementManager(eid)
        self.scope = register_scope(manager, type="cidr", value=LEG_B_SCOPE, actions=(CLASS,))
        with engagement_scope(eid) as conn:
            policy = load_effective_policy(conn, eid)
        wrong = rm.engagement_guards(policy, allow_nonempty=False)
        wrong += rm.check_effective_policy(policy, (CLASS,))
        if wrong:
            return wrong
        self.engagement, self.policy = eid, policy
        return []

    def ask_leg_b(self, call: st.Call) -> dict:
        from sqlalchemy import text

        from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
        from control_plane.api.function_api import propose_action
        from control_plane.state.db import engagement_scope, get_engine
        from tests.scheduler_support import proposal_for
        from tests.task_support import attach_task
        from tool_gateway.sandbox import SandboxResult

        class Sandbox:
            def run(self, **kwargs):
                return SandboxResult(0, "recorded, not run", "", False, 0.0, (LEG_B_SCOPE,), "fake")

        wording = self.wordings[call.wording]
        proposal = proposal_for(self.scope, host=call.target, action=CLASS,
                                target_type="cidr" if "/" in call.target else "ip")
        proposal = attach_task(self.engagement, proposal,
                               goal=query_text(wording.text, call.target))
        with get_engine().begin() as conn:
            before = int(conn.execute(text(
                "SELECT coalesce(max(call_id), 0) FROM goal_fit_calls")).scalar_one())
        done = propose_action(
            engagement_id=self.engagement, proposal=proposal, reviewer=HonestFakeReviewer(),
            policy=self.policy, agent_id="dp15-stage1", sandbox=Sandbox(),
            network_allowlist=[LEG_B_SCOPE], plan_fit_validator=self.validator(),
            idempotency_key=f"dp15-s1-{self.engagement}-{call.wording}-{call.repeat}")
        with engagement_scope(self.engagement) as conn:
            stored = conn.execute(text(
                "SELECT reviewer_hints->'plan_fit'->>'goal_fit', "
                "reviewer_hints->'plan_fit'->>'goal_fit_cause' FROM action_proposals "
                "WHERE proposal_id = :p"), {"p": done.proposal_id}).first()
        with get_engine().begin() as conn:
            rows = conn.execute(text(
                "SELECT outcome, failure_kind FROM goal_fit_calls WHERE call_id > :b "
                "ORDER BY call_id DESC"), {"b": before}).all()
        value, cause = (stored or (None, None))
        kind = rows[0][1] if rows and rows[0][0] == "failed" else None
        return stored_fields(value, cause, kind, asked=len(rows))


def answer_fields(got) -> dict:
    """The record fields of one control-plane ``GoalFit``."""
    value = got.value if got.outcome == "answered" else "failed"
    fields = {"goal_fit": value, "cause": got.cause, "failure_kind": got.failure_kind}
    call = got.detail.get("call") or {}
    for key in ("latency_seconds", "input_tokens", "output_tokens"):
        if key in call:
            fields[key] = call[key]
    return fields


def stored_fields(value: str | None, cause: str | None, kind: str | None, *,
                  asked: int) -> dict:
    """The record fields of what ``propose_action`` stored for one Leg B proposal."""
    answered = value in ("plausible", "implausible", "insufficient_context")
    fields = {"goal_fit": value if answered else "failed", "cause": cause,
              "failure_kind": None if answered else (kind or "unclassified"), "stored": value,
              "validator_calls_recorded": asked}
    if asked != 1:                     # one proposal is one question; anything else is named
        fields["note"] = f"{asked} goal_fit_calls rows for this proposal, expected 1"
    return fields


# -- the run, from the plan to the analysis --------------------------------------------------------

def record_header(wordings: list[st.Wording], *, wordings_sha: str, plan_commit: str,
                  banner: list[str], provenance: dict, calls: list[st.Call], caps: dict,
                  seed: int) -> dict:
    database = next((line.split(" on ")[0].removeprefix("database: ") for line in banner
                     if line.startswith("database: ")), None)
    migration = next((line.split(" -- ")[0].removeprefix("migration revision: ")
                      for line in banner if line.startswith("migration revision: ")), None)
    return {"type": "header", "registration": "stage 1",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "wordings_sha256": wordings_sha, "plan_commit": plan_commit, "seed": seed,
            "database": database, "migration": migration, **provenance,
            "planned": {"leg_a": sum(c.leg == "A" for c in calls),
                        "leg_b": sum(c.leg == "B" for c in calls)},
            "caps": caps,
            "wordings": [{"i": i, "source": w.source} for i, w in enumerate(wordings)]}


def render_summary(out: Outcome, calls: list[st.Call], usage: rm.Usage, caps: dict,
                   recorded: int) -> list[str]:
    """What is printed when the run ends, before the analysis: calls made, why it stopped, usage.
    No outcome and no rate."""
    leg_a = sum(c.leg == "A" for c in calls)
    leg_b = sum(c.leg == "B" for c in calls)
    lines = [f"calls: {out.issued} issued, {out.finished} finished, of {len(calls)} planned "
             f"(Leg A {leg_a}, Leg B {leg_b}); run time {out.seconds / 60:.1f} min"]
    lines += rm.render_usage(usage, recorded_calls=recorded, cap=caps["usd"], estimate_={
        "cost_planned_usd": st.estimate(len(calls))["usd"], "planned_calls": len(calls)})
    lines.append(f"STOPPED EARLY: {out.stopped}. Nothing was retried and nothing resumes."
                 if out.stopped else "completed.")
    return lines


def git_head() -> str:
    import subprocess

    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              cwd=REPO_ROOT, timeout=10).stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001 - a record field
        return "unknown"


def run_stage1(*, world, wordings: list[st.Wording], wordings_sha: str, calls: list[st.Call],
               caps: dict, record: Path, plan_commit: str, seed: int, ask_a: Callable,
               ask_b: Callable, cost: Callable[[], float], cli_runs: Callable[[], int],
               usage: Callable[[], rm.Usage], banner: list[str], provenance: dict,
               out=print) -> int:
    """The run, with a world passed in. Writes the record, prints the summary and then the one
    analysis. The record file is created here and must not exist."""
    handle = record.open("x")                       # an existing record is never appended to
    try:
        def write(entry: dict) -> None:
            handle.write(json.dumps(entry) + "\n")
            handle.flush()

        write(record_header(wordings, wordings_sha=wordings_sha, plan_commit=plan_commit,
                            banner=banner, provenance=provenance, calls=calls, caps=caps,
                            seed=seed))
        controller = Stage1Run(
            calls, ask=lambda c: ask_a(c) if c.leg == "A" else ask_b(c), write=write,
            sources={i: w.source for i, w in enumerate(wordings)}, caps=caps,
            cost_so_far=cost, cli_runs=cli_runs, before_leg_b=world.begin_leg_b,
            progress=lambda issued, finished: out(
                f"calls issued {issued}, finished {finished}"))
        result = controller.run()
        used = usage()
        write({"type": "footer", "stopped": result.stopped, "issued": result.issued,
               "finished": result.finished, "seconds": round(result.seconds, 1),
               "usage": {"cli_runs": used.cli_runs, "cost_usd": round(used.cost_usd, 4),
                         "input_tokens": used.input_tokens, "output_tokens": used.output_tokens,
                         "cache_read_tokens": used.cache_read_tokens,
                         "cache_creation_tokens": used.cache_creation_tokens},
               "models": sorted(used.models)})
    finally:
        handle.close()
    for line in render_summary(result, calls, usage(), caps, result.finished):
        out(line)
    out("--- the one analysis (C1), run once on the record ---")
    an.look(record, out=out)
    return result.exit_code


def execute_cli(args) -> int:
    """``dp15_enable_stage1.py --execute``: every refusal comes before any call."""
    problems: list[str] = []
    classes = (CLASS,)
    wordings_path = Path(args.wordings_dir) / f"{CLASS}.json"
    if not wordings_path.exists():
        problems.append(f"no wording file at {wordings_path}")
        return refuse(problems)
    wordings, sha = st.read_wordings(wordings_path)
    try:
        registered, wrong = st.registered_hashes(Path(args.plan).read_text())
    except OSError as exc:
        registered, wrong = {}, [f"the plan could not be read at {args.plan} "
                                 f"({type(exc).__name__}): no hash is registered"]
    problems += wrong
    if not wrong:
        problems += st.hash_problems(registered, {CLASS: sha}, classes)
    problems += st.check_wordings({CLASS: wordings})
    calls = st.build_plan({CLASS: wordings}, args.seed) if not problems else []
    planned = st.caps(len(calls)) if calls else {"runs": 0, "usd": 0.0, "minutes": 0}
    caps = dict(planned)
    for flag, key in (("max_runs", "runs"), ("max_usd", "usd"), ("max_minutes", "minutes")):
        asked = getattr(args, flag, None)
        if asked is not None:
            if asked > planned[key]:
                problems.append(f"--{flag.replace('_', '-')} {asked} is above the plan's "
                                f"{planned[key]}: a cap may be lowered, never raised")
            else:
                caps[key] = asked
    if args.concurrency > MAX_CONCURRENCY or args.concurrency < 1:
        problems.append(f"concurrency is 1 to {MAX_CONCURRENCY}")
    if Path(args.record).exists():
        problems.append(f"the record {args.record} exists: a run writes a new record and never "
                        "appends or resumes")
    if problems:
        return refuse(problems)
    from control_plane.config import load_dotenv

    load_dotenv()
    world = RealWorld(wordings, leg_b_database=args.leg_b_database)
    banner, problems = world.startup()
    print("\n".join(banner))
    if problems:
        return refuse(problems)
    if not args.yes:
        from scripts.manage_global_policy import _confirm

        if not _confirm(f"SEND the DP-15 stage-1 measurement into the database above: "
                        f"{len(calls)} calls, caps {int(caps['runs'])} CLI runs / "
                        f"US${caps['usd']:.2f} / {int(caps['minutes'])} minutes, real model calls.",
                        "SEND", False):
            return EXIT_USAGE
    return run_stage1(
        world=world, wordings=wordings, wordings_sha=sha, calls=calls, caps=caps,
        record=Path(args.record), plan_commit=git_head(), seed=args.seed,
        ask_a=world.ask_leg_a, ask_b=world.ask_leg_b, cost=world.cost, cli_runs=world.cli_runs,
        usage=world.usage, banner=banner, provenance=world.provenance())


def refuse(problems: list[str]) -> int:
    for p in problems:
        print(f"precondition failed: {p}", file=sys.stderr)
    return EXIT_REFUSED
