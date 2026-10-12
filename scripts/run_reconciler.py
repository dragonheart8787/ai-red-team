"""Run the reconciler (D64): find what a crash or a lapse left behind and put it right.

    python scripts/run_reconciler.py --mode dry-run|state-only [--once] [--interval 60]

There is no default mode, and only two:

* ``dry-run``    reads everything, plans, and prints what it *would* do as JSON lines. It changes
                 nothing -- no stage, no container, no file, not even an audit record -- and takes
                 no lock, so it may run beside the real thing.
* ``state-only`` moves proposals out of the stages a crash left them in (``received`` past the grace
                 -> ``abandoned``; ``decided`` / ``capability_issued`` / ``approved`` that can never
                 proceed -> ``closed``; ``dispatching`` past ``B + P + Q`` -> ``unknown_outcome``),
                 each by one compare-and-set, each audited after it was seen to have happened.
                 Killing and removing Docker objects and deleting files are **off** in this version
                 and there is no option that turns them on.

Every threshold comes from the ``RECONCILER_*`` settings (see ``.env.example``); with one missing or
unusable the reconciler refuses to start (exit 8), naming the keys.

**Start order.** Run ``--once`` before the scheduler starts. That is a convention, not a check:
nothing here or in the scheduler makes either wait for the other, and they hold different locks.

Exit status: 0 stopped by signal / ``--once`` done, 1 unexpected error, 2 another instance holds the
lock, 3 an audit record could not be written, 4 database connection lost, 5 Docker unreachable,
6 lock lost, 8 configuration refused.
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
from control_plane.reconciler import act, emit  # noqa: E402
from control_plane.reconciler.config import ConfigError, load  # noqa: E402
from control_plane.reconciler.service import (  # noqa: E402
    EXIT_CONFIG_REFUSED,
    PassReport,
    Reconciler,
)


def _print(report: PassReport) -> None:
    for result in report.results:
        print(json.dumps({"kind": result.action.kind, "reason_code": result.action.reason_code,
                          "subject_id": result.action.subject_id, "outcome": result.outcome,
                          "detail": result.detail}, sort_keys=True))
    print(json.dumps({"summary": report.planned, "outcomes": dict(report.outcomes),
                      "reports": report.reports}, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", required=True, choices=sorted(act.MODE_NAMES))
    parser.add_argument("--interval", type=float, default=60.0, help="seconds between passes")
    parser.add_argument("--once", action="store_true", help="run one pass and exit")
    parser.add_argument("--engagement", action="append", metavar="ID",
                        help="limit the pass to this engagement (repeatable): its proposals and "
                             "the containers it owns; networks and files are then left alone")
    parser.add_argument("--directory", default=tempfile.gettempdir(),
                        help="where the credential and TLS files are (default: the temp dir)")
    args = parser.parse_args(argv)
    load_dotenv()

    try:
        thresholds = load(os.environ)
    except ConfigError as refused:
        print(str(refused), file=sys.stderr)
        _audit_refusal(args.mode)
        return EXIT_CONFIG_REFUSED

    import docker
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    only = frozenset(args.engagement) if args.engagement else None
    reconciler = Reconciler(settings=act.settings_for(args.mode), th=thresholds,
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
