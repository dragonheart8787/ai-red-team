"""Run the reconciler (D64): find what a crash or a lapse left behind and put it right.

    python scripts/run_reconciler.py --mode dry-run|state-only [--once] [--interval 60]
                                     [--enable kill] [--enable container] [--enable proxy]

There is no default mode, and only two:

* ``dry-run``    reads everything, plans, and prints what it *would* do as JSON lines. It changes
                 nothing -- no stage, no container, no file, not even an audit record -- and takes
                 no lock, so it may run beside the real thing.
* ``state-only`` moves proposals out of the stages a crash left them in (``received`` past the grace
                 -> ``abandoned``; ``decided`` / ``capability_issued`` / ``approved`` that can never
                 proceed -> ``closed``; ``dispatching`` past ``B + P + Q`` -> ``unknown_outcome``),
                 each by one compare-and-set, each audited after it was seen to have happened.
                 Killing and removing Docker objects and deleting files are **off** unless a
                 category is named with ``--enable`` (below).

**Irreversible actions** (ACCEPTANCE 5.92) are five categories, each off: ``kill``, ``container``,
``proxy``, ``network``, ``file``. Only the command line turns one on -- ``--enable kill``, repeated
for more -- only with ``state-only``, and only after a person at a terminal types back the phrase
the program shows (``enable`` and the sorted names). There is no ``--yes``: a pipe, a cron job or a
service manager cannot answer. In this version ``network`` and ``file`` are refused (exit 7) before
the configuration is read; so is any other word, and so is a run that cannot be confirmed. What was
enabled is written to ``reconciler.started``.

Every threshold comes from the ``RECONCILER_*`` settings (see ``.env.example``); with one missing or
unusable the reconciler refuses to start (exit 8), naming the keys.

**Start order.** Run ``--once`` before the scheduler starts. That is a convention, not a check:
nothing here or in the scheduler makes either wait for the other, and they hold different locks.

Exit status: 0 stopped by signal / ``--once`` done, 1 unexpected error, 2 another instance holds the
lock, 3 an audit record could not be written, 4 database connection lost, 5 Docker unreachable,
6 lock lost, 7 a switch refused (a word that is not available, a dry run asked to enable, nothing
confirmed at a terminal), 8 configuration refused.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.reconciler import act, emit, flags  # noqa: E402
from control_plane.reconciler.config import ConfigError, load  # noqa: E402
from control_plane.reconciler.service import (  # noqa: E402
    EXIT_CONFIG_REFUSED,
    PassReport,
    Reconciler,
)


def _print(report: PassReport) -> None:
    """Every result, then -- uncapped -- every planned action this pass did not carry out (the cap
    ``RECONCILER_MAX_ACTIONS_PER_PASS`` or a hold-back) and every report (what was seen and left
    alone), then one summary line. Ids and closed codes only; nothing else is ever in a plan."""
    for result in report.results:
        print(json.dumps({"kind": result.action.kind, "reason_code": result.action.reason_code,
                          "subject_id": result.action.subject_id,
                          "engagement_id": result.action.engagement_id, "outcome": result.outcome,
                          "detail": result.detail}, sort_keys=True))
    if report.plan is not None:
        carried = {(r.action.kind, r.action.subject_id) for r in report.results}
        for a in report.plan.actions:
            if (a.kind, a.subject_id) not in carried:
                print(json.dumps({"kind": a.kind, "reason_code": a.reason_code,
                                  "subject_id": a.subject_id, "engagement_id": a.engagement_id,
                                  "outcome": "planned_not_carried_out_this_pass", "detail": None},
                                 sort_keys=True))
        for r in report.plan.reports:
            print(json.dumps({"report": r.reason_code, "subject": r.subject,
                              "subject_id": r.subject_id, "engagement_id": r.engagement_id},
                             sort_keys=True))
    print(json.dumps({"summary": report.planned, "outcomes": dict(report.outcomes),
                      "reports": report.reports, "limited": report.limited,
                      "held_back": report.held_back, "truncated": report.truncated},
                     sort_keys=True))


EXIT_FLAG_REFUSED = 7

#: one line each, for the person who is about to confirm
EFFECT = {
    flags.KILL: "KILL a tool container still running past its run's budget plus the margin",
    flags.CONTAINER: "REMOVE a tool container at rest whose run is over and whose retention passed",
    flags.PROXY: "REMOVE an egress proxy whose run is over or whose bound has passed",
    flags.NETWORK: "REMOVE a sandbox network",
    flags.FILE: "REMOVE a credential or TLS file from the temporary directory",
}


def _is_terminal(stream) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def confirm(categories, *, stdin, stdout) -> bool:
    """Ask a person, at a terminal, whether these categories may act. ``True`` only if both ends
    are terminals and the exact phrase is typed back; anything else -- a pipe, a file, end of input,
    another phrase, an empty line -- is ``False`` and nothing was enabled. Read once."""
    categories = frozenset(categories)
    if not categories:
        return True
    if not (_is_terminal(stdin) and _is_terminal(stdout)):
        stdout.write("refused: irreversible actions are confirmed by a person at a terminal, and "
                     "this is not one (no --yes exists)\n")
        stdout.flush()
        return False
    lines = ["This run may carry out, on real Docker objects and for real:"]
    lines += [f"  {category:<10} {EFFECT[category]}" for category in sorted(categories)]
    lines += ["It will do nothing else, and everything else stays off.",
              f"Type exactly:  {flags.phrase(categories)}"]
    stdout.write("\n".join(lines) + "\n> ")
    stdout.flush()
    try:
        answer = stdin.readline()
    except (OSError, ValueError):
        return False
    return answer.rstrip("\r\n") == flags.phrase(categories)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", required=True, choices=sorted(act.MODE_NAMES))
    parser.add_argument("--interval", type=float, default=60.0, help="seconds between passes")
    parser.add_argument("--once", action="store_true", help="run one pass and exit")
    parser.add_argument("--enable", action="append", metavar="CATEGORY",
                        help="let this category of irreversible action be carried out "
                             f"({', '.join(flags.OPERATOR_MAY_ENABLE)} in this version; repeat for "
                             "more; state-only only; confirmed by typing a phrase at a terminal)")
    parser.add_argument("--engagement", action="append", metavar="ID",
                        help="limit the pass to this engagement (repeatable): its proposals and "
                             "the containers it owns; networks and files are then left alone")
    parser.add_argument("--directory", default=tempfile.gettempdir(),
                        help="where the credential and TLS files are (default: the temp dir)")
    args = parser.parse_args(argv)
    try:                                   # before the configuration, the database and Docker
        settings = act.settings_for(args.mode, args.enable or ())
    except flags.FlagRefused as refused:
        print(f"refused: {refused}", file=sys.stderr)
        return EXIT_FLAG_REFUSED
    except ValueError as refused:          # a dry run asked to enable something
        print(f"refused: {refused}", file=sys.stderr)
        return EXIT_FLAG_REFUSED
    load_dotenv()

    try:
        thresholds = load(os.environ)
    except ConfigError as refused:
        print(str(refused), file=sys.stderr)
        _audit_refusal(args.mode)
        return EXIT_CONFIG_REFUSED
    if not confirm(settings.enabled, stdin=sys.stdin, stdout=sys.stdout):
        print("refused: nothing was confirmed, so nothing was started", file=sys.stderr)
        return EXIT_FLAG_REFUSED

    import docker
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    only = frozenset(args.engagement) if args.engagement else None
    reconciler = Reconciler(settings=settings, th=thresholds,
                            client=docker.from_env(), directory=args.directory,
                            expected_uid=os.getuid(), only_engagements=only)
    code = reconciler.serve(interval=args.interval, max_passes=1 if args.once else None,
                          stop_event=stop, on_pass=_print)
    print(f"reconciler stopped (exit {code})", file=sys.stderr)
    return code


def _audit_refusal(mode: str) -> None:
    """A refused start is recorded when the database can say so (a dry run records nothing)."""
    if mode != "state-only":
        return
    try:
        emit.emit(emit.START_REFUSED, {"instance_id": "RECON-config-refused",
                                       "reason_code": emit.CONFIG_REFUSED},
                  subject_type="reconciler", subject_id="RECON-config-refused")
    except Exception:  # noqa: BLE001 - the refusal itself is the outcome
        pass


if __name__ == "__main__":
    raise SystemExit(main())
