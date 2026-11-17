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
was lost; 10 the start-up check refused an engagement (it
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
from harness.banner import format_banner  # noqa: E402
from harness.banner_facts import BannerFactsUnavailable, collect_banner_facts  # noqa: E402
from harness.bounds import Bounds, RunCounters  # noqa: E402
from harness.enrolment_db import EnrolledFromDatabase  # noqa: E402
from harness.exit_codes import (  # noqa: E402
    EXIT_CODE,
    EXIT_DB_LOST,
    EXIT_LOCK_HELD,
    EXIT_LOCK_LOST,
    EXIT_STARTUP_REFUSED,
    EXIT_UNEXPECTED,
)
from harness.frozen_enrolment import FrozenEnrolment  # noqa: E402
from harness.lock import HarnessLock, LockGuardedPorts  # noqa: E402
from harness.loop import run_loop  # noqa: E402
from harness.loop_adapter import LoopAdapter  # noqa: E402
from harness.residue_listing import format_residue, list_residue  # noqa: E402
from harness.signals import SignalFlag, install  # noqa: E402

#: Seconds between the watchdog's looks at the lock. Not a cap of the run; the scheduler's value.
WATCHDOG_INTERVAL = 2.0


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


def _run(args: argparse.Namespace, lock: HarnessLock, register) -> int:
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
                no_progress_limit=args.no_progress_limit)
        except BannerFactsUnavailable as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_STARTUP_REFUSED
        print(format_banner(facts), flush=True)

        flag = SignalFlag()
        install(register, flag, (signal.SIGINT, signal.SIGTERM))
        lock.start_watchdog(args.lock_watchdog_interval)
        adapter = LoopAdapter(
            enrolment=frozen, supervisor=roles.supervisor, worker=roles.worker,
            reviewer=roles.reviewer, sandbox=roles.sandbox, objective=args.objective,
            window_limit=args.window_limit, live_task_limit=args.live_task_limit)
        result = run_loop(
            LockGuardedPorts(adapter, lock),
            Bounds(args.max_rounds, args.max_model_calls, args.no_progress_limit),
            RunCounters(), adapter.refusals, window_limit=args.window_limit, stop_event=flag,
            once=args.once)
        code = EXIT_LOCK_LOST if lock.lost.is_set() else EXIT_CODE[result.reason]
        print(f"harness stopped (exit {code}): reason={result.reason.value} "
              f"rounds={result.rounds} counters={result.counters}", file=sys.stderr, flush=True)
        return code
    finally:
        lock.close()


def _residue(args: argparse.Namespace) -> int:
    tasks = list_residue(EnrolledFromDatabase().enrolled(), limit=args.live_task_limit)
    print(format_residue(tasks))
    return 0


def main(argv: list[str] | None = None, *, lock: HarnessLock | None = None,
         register=signal.signal) -> int:
    args = build_parser().parse_args(argv)
    load_dotenv()
    if args.command == "residue":
        return _residue(args)
    return _run(args, lock if lock is not None else HarnessLock(), register)


if __name__ == "__main__":
    raise SystemExit(main())
