"""Run the production harness's loop, or list what a run left behind (D69 H5c2).

    python scripts/run_harness.py run --role-factory module:function \\
        --objective TEXT --window-limit N --max-rounds N --max-model-calls N \\
        --no-progress-limit N --live-task-limit N [--once] [--lock-watchdog-interval S]
    python scripts/run_harness.py residue --live-task-limit N

``run`` works on the engagements listed by ``scripts/manage_harness_enrolment.py`` (purpose
``harness_lab``) and on nothing else: the list is read **once at the start**, it is the banner's
list, and the loop visits those of them that are still enrolled (``harness/frozen_enrolment.py``),
so an engagement enrolled after the start waits for a restart. **Every bound is required and has
no default**: the round cap, the model-call cap, the number of rounds without progress that stops
the run, the evidence window and the limit of live tasks one engagement may hold. They are the
owner's numbers and are written down before a run that is not a test.

Two caps are optional on this script (S3, plan item 143): ``--max-tokens N`` (the input and output
tokens of the three roles' calls, cache reads not counted) and ``--max-minutes N`` (from the moment
the bounds are built). They are optional here only because the factory gate admits two scripted
factories and nothing else (plan item 131); ``scripts/run_shadow.py`` requires both. A cap reached
ends the run with 13, and the stop line then ends with ``cap=`` and the cap's name.
The banner shows both under their own names, ``not set`` for one not given (plan item 148).

The roles come from ``--role-factory``, the dotted path of a function that returns an object with
``supervisor``, ``worker``, ``reviewer`` and ``sandbox``. **This script builds no model role and no
real sandbox**: it is the stage of the lock, the signals and the banner, and H5c2's tests give it
scripted roles and a fake sandbox. A factory of real roles is a later decision.

What a run does, in order: take the harness lock (``harness/lock.py``; a second instance exits with
2 before it reads anything), collect and print the banner (``harness/banner_facts.py``; to standard
output), install the handlers for SIGINT and SIGTERM (``harness.signals.install``: they set a flag,
the loop finishes the task it is on and stops at its next safe point), and run the loop. It does not
restart itself or reconnect.

Exit status: 0 stopped by a signal or ``--once``; 1 unexpected (the role factory failed); 2 another
instance holds the lock; 4 the database cannot be reached (the lock cannot be asked for); 6 the lock
was lost; 10 the role factory is not in ``APPROVED_ROLE_FACTORIES`` (refused before the lock and
before any import), or the start-up check refused an engagement (it
holds a live task), or the banner cannot be stated (no engagement enrolled, or the enrolled
engagements disagree on a switch); 11 a task that is not the loop's own was claimed; 12 a fault
outside the closed list; 13 a round or model-call cap was reached; 14 no progress.
(``harness/exit_codes.py``.)

``residue`` only reads: it lists the queued, claimed and running tasks of the enrolled engagements
and changes nothing; no command clears them.
"""

from __future__ import annotations

import argparse
import importlib
import signal
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from control_plane.config import load_dotenv  # noqa: E402
from harness.banner import NOT_SET, format_banner  # noqa: E402
from harness.banner_facts import BannerFactsUnavailable, collect_banner_facts  # noqa: E402
from harness.bounds import Bounds, RunCounters  # noqa: E402
from harness.enrolment_db import EnrolledFromDatabase  # noqa: E402
from harness.exit_codes import (  # noqa: E402
    EXIT_AUDIT_FAILED,
    EXIT_CODE,
    EXIT_DB_LOST,
    EXIT_LOCK_HELD,
    EXIT_LOCK_LOST,
    EXIT_STARTUP_REFUSED,
    EXIT_UNEXPECTED,
    StopReason,
)
from harness.frozen_enrolment import FrozenEnrolment  # noqa: E402
from harness.lock import HarnessLock, LockGuardedPorts  # noqa: E402
from harness.loop import run_loop  # noqa: E402
from harness.loop_adapter import LoopAdapter  # noqa: E402
from harness.residue_listing import format_residue, list_residue  # noqa: E402
from harness.signals import SignalFlag, install  # noqa: E402

#: Seconds between the watchdog's looks at the lock. Not a cap of the run; the scheduler's value.
WATCHDOG_INTERVAL = 2.0

#: The only role factories ``run`` accepts: the tests' two scripted factories (no model, no real
#: sandbox). ``--role-factory`` is compared with this tuple, as a string, before the lock is taken
#: and before the factory's module is imported; any other is refused with exit 10. Adding a factory
#: of real roles is a numbered change the owner authorizes (plan items 98 (a), 101 (b), 110 and
#: 131), not an argument of this script.
APPROVED_ROLE_FACTORIES = ("tests.harness_h5c2_roles:build", "tests.harness_h7_roles:build")


# -- the observer (plan item 140): only when one is given; with none, nothing below is used --------

class _Observation:
    """Hands an observer what happened, as it happens: ``on_banner(facts)``, ``on_refusal(side,
    reason)`` for each new entry of the adapter's ``RefusalCounter``, ``on_call(role, call)`` for
    each new entry of a role's ``calls``, ``on_round(number, progress)``, ``on_stop(reason, code)``.
    An exception of the observer's is kept and re-raised, never swallowed: the loop then stops (as
    it does for any exception), and the run ends with exit 3. Since S3 (plan item 143) ``on_stop``
    also gets the cap reached (``None`` unless the reason is ``cap_reached``) and ``token_use``."""

    ROLES = ("supervisor", "worker", "reviewer")

    def __init__(self, observer, roles) -> None:
        self.observer, self.roles = observer, roles
        self.refusals = None
        self.failure: Exception | None = None
        self._refusals_seen = 0
        self._calls_seen = dict.fromkeys(self.ROLES, 0)

    def emit(self, method: str, *args) -> None:
        try:
            getattr(self.observer, method)(*args)
        except Exception as exc:
            if self.failure is None:
                self.failure = exc
            raise

    def catch_up(self) -> None:
        entries = self.refusals.entries() if self.refusals is not None else ()
        for side, reason in entries[self._refusals_seen:]:
            self._refusals_seen += 1
            self.emit("on_refusal", side, reason)
        for role in self.ROLES:
            calls = list(getattr(getattr(self.roles, role, None), "calls", None) or ())
            for call in calls[self._calls_seen[role]:]:
                self._calls_seen[role] += 1
                self.emit("on_call", role, call)


class _ObservedBounds(Bounds):
    """``Bounds``, telling the observer when a round ends (after what the round produced)."""

    def __init__(self, max_rounds, max_model_calls, no_progress_limit, *, observation,
                 **caps) -> None:
        super().__init__(max_rounds, max_model_calls, no_progress_limit, **caps)
        self._observation = observation
        self._round = 0

    def start_round(self) -> None:
        super().start_round()
        self._round += 1

    def end_round(self, progress: bool) -> None:
        super().end_round(progress)
        self._observation.catch_up()
        self._observation.emit("on_round", self._round, progress)


class _ObservedPorts:
    """The loop's ports, unchanged, with the observer caught up after every port call."""

    def __init__(self, ports, observation) -> None:
        self._ports, self._observation = ports, observation

    def __getattr__(self, name):
        attr = getattr(self._ports, name)
        if not callable(attr):
            return attr

        def call(*args, **kwargs):
            try:
                return attr(*args, **kwargs)
            finally:
                self._observation.catch_up()
        return call


#: The roles whose ``calls`` the token cap reads.
TOKEN_ROLES = ("supervisor", "worker", "reviewer")


def token_use(roles) -> dict[str, int]:
    """``input_tokens``, ``output_tokens`` and ``cache_read_tokens`` over the three roles'
    ``calls``. The token cap counts the first two; cache reads are kept apart (plan item 143)."""
    totals = dict.fromkeys(("input_tokens", "output_tokens", "cache_read_tokens"), 0)
    for role in TOKEN_ROLES:
        for call in list(getattr(getattr(roles, role, None), "calls", None) or ()):
            for key in totals:
                totals[key] += int(getattr(call, key, 0) or 0)
    return totals


def tokens_spent(roles) -> int:
    """What the token cap is compared with: input plus output tokens, no cache reads."""
    use = token_use(roles)
    return use["input_tokens"] + use["output_tokens"]


def _positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("at least 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the loop")
    run.add_argument("--role-factory", required=True, help="module:function giving the roles")
    run.add_argument("--objective", required=True, help="the engagement objective the Supervisor "
                     "is shown")
    for name in ("window-limit", "max-rounds", "max-model-calls", "no-progress-limit",
                 "live-task-limit"):
        run.add_argument(f"--{name}", required=True, type=_positive, help="required, no default")
    for name in ("max-tokens", "max-minutes"):
        run.add_argument(f"--{name}", type=_positive, default=None,
                         help="optional here (plan item 131's gate); required by run_shadow.py")
    run.add_argument("--once", action="store_true", help="one round, then stop")
    run.add_argument("--lock-watchdog-interval", type=float, default=WATCHDOG_INTERVAL,
                     help=f"seconds between looks at the lock (default {WATCHDOG_INTERVAL})")
    residue = sub.add_parser("residue", help="list the live tasks of the enrolled engagements")
    residue.add_argument("--live-task-limit", required=True, type=_positive,
                         help="at most this many tasks per engagement; required, no default")
    return parser


def _roles(spec: str):
    module_name, _, function = spec.partition(":")
    if not module_name or not function:
        raise ValueError("--role-factory is module:function")
    return getattr(importlib.import_module(module_name), function)()


def _run(args: argparse.Namespace, lock: HarnessLock, register, roles=None,
         observer=None) -> int:
    # ``roles`` (plan item 137): the roles the shadow runner has already built from the approved
    # factory and checked, so that the instances checked are the instances that run. None: the
    # factory is called here, as before. The factory string is compared first either way.
    if args.role_factory not in APPROVED_ROLE_FACTORIES:
        print("refused: the role factory is not an approved one", file=sys.stderr)
        return EXIT_STARTUP_REFUSED
    try:
        taken = lock.acquire()
    except Exception as exc:  # noqa: BLE001 - what the driver raised is not printed
        print(f"refused: the database cannot be reached ({type(exc).__name__})", file=sys.stderr)
        return EXIT_DB_LOST
    if not taken:
        print("refused: another instance holds the harness lock", file=sys.stderr)
        return EXIT_LOCK_HELD
    try:
        try:
            if roles is None:
                roles = _roles(args.role_factory)
        except Exception as exc:  # noqa: BLE001 - what a factory raised is not printed
            print(f"refused: the role factory failed ({type(exc).__name__})", file=sys.stderr)
            return EXIT_UNEXPECTED
        reader = EnrolledFromDatabase()
        engagements = reader.enrolled()           # the one read: the banner's list and the loop's
        frozen = FrozenEnrolment(engagements, reader)
        try:
            facts = collect_banner_facts(
                engagements=engagements, supervisor=roles.supervisor, worker=roles.worker,
                reviewer=roles.reviewer, window_limit=args.window_limit,
                max_rounds=args.max_rounds, max_model_calls=args.max_model_calls,
                no_progress_limit=args.no_progress_limit,
                max_tokens=NOT_SET if args.max_tokens is None else args.max_tokens,
                max_minutes=NOT_SET if args.max_minutes is None else args.max_minutes)
        except BannerFactsUnavailable as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_STARTUP_REFUSED
        print(format_banner(facts), flush=True)
        observation = None if observer is None else _Observation(observer, roles)
        if observation is not None:
            try:
                observation.emit("on_banner", facts)
            except Exception:  # noqa: BLE001 - kept in observation.failure, ends the run as 3
                return _record_failed(observation)

        flag = SignalFlag()
        install(register, flag, (signal.SIGINT, signal.SIGTERM))
        lock.start_watchdog(args.lock_watchdog_interval)
        adapter = LoopAdapter(
            enrolment=frozen, supervisor=roles.supervisor, worker=roles.worker,
            reviewer=roles.reviewer, sandbox=roles.sandbox, objective=args.objective,
            window_limit=args.window_limit, live_task_limit=args.live_task_limit)
        ports = LockGuardedPorts(adapter, lock)
        caps = {"max_tokens": args.max_tokens, "max_minutes": args.max_minutes,
                "tokens_spent": lambda: tokens_spent(roles)}
        if observation is None:
            bounds = Bounds(args.max_rounds, args.max_model_calls, args.no_progress_limit, **caps)
        else:
            observation.refusals = adapter.refusals
            ports = _ObservedPorts(ports, observation)
            bounds = _ObservedBounds(args.max_rounds, args.max_model_calls,
                                     args.no_progress_limit, observation=observation, **caps)
        result = run_loop(
            ports, bounds,
            RunCounters(), adapter.refusals, window_limit=args.window_limit, stop_event=flag,
            once=args.once)
        code = EXIT_LOCK_LOST if lock.lost.is_set() else EXIT_CODE[result.reason]
        cap = bounds.cap_hit if result.reason is StopReason.CAP_REACHED else None
        if observation is not None:
            try:
                if observation.failure is None:
                    observation.catch_up()
                    observation.emit("on_stop", result.reason.value, code, cap, token_use(roles))
            except Exception:  # noqa: BLE001 - kept in observation.failure, ends the run as 3
                pass
            if observation.failure is not None:
                return _record_failed(observation)
        print(f"harness stopped (exit {code}): reason={result.reason.value} "
              f"rounds={result.rounds} counters={result.counters}"
              + (f" cap={cap}" if cap is not None else ""), file=sys.stderr, flush=True)
        return code
    finally:
        lock.close()


def _record_failed(observation: _Observation) -> int:
    """The observer could not take an event: the run stops, and the code is 3, "an audit record
    could not be written" (``harness/exit_codes.py``), the one reason that names a lost record."""
    print(f"harness stopped (exit {EXIT_AUDIT_FAILED}): the run record could not be written "
          f"({type(observation.failure).__name__})", file=sys.stderr, flush=True)
    return EXIT_AUDIT_FAILED


def _residue(args: argparse.Namespace) -> int:
    tasks = list_residue(EnrolledFromDatabase().enrolled(), limit=args.live_task_limit)
    print(format_residue(tasks))
    return 0


def main(argv: list[str] | None = None, *, lock: HarnessLock | None = None,
         register=signal.signal, roles=None, observer=None) -> int:
    args = build_parser().parse_args(argv)
    load_dotenv()
    if args.command == "residue":
        return _residue(args)
    return _run(args, lock if lock is not None else HarnessLock(), register, roles=roles,
                observer=observer)


if __name__ == "__main__":
    raise SystemExit(main())
