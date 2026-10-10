"""Run the scheduler, v0 (D62).

    python scripts/run_scheduler.py [--interval 5] [--once]

Finds approved, not-yet-dispatched proposals in *enrolled* engagements (see
``scripts/manage_scheduler_enrollment.py``) and dispatches them one at a time. It holds the
singleton lock for as long as it runs; a second instance exits at once.

It does **not** restart itself or reconnect: any lost connection, lost lock, unreachable Docker,
unwritable audit record or unexpected error stops it with a distinct exit code, and a supervisor
should not restart it blindly (a deterministic fault would repeat once per restart).

Exit status: 0 stopped by signal / ``--once`` done, 1 unexpected error, 2 another instance holds the
lock, 3 audit record could not be written, 4 database connection lost, 5 Docker unreachable,
6 lock lost, 7 a dispatched proposal was still ``approved`` afterwards.
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.scheduler.service import Scheduler  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between ticks")
    parser.add_argument("--once", action="store_true", help="run one tick and exit")
    args = parser.parse_args(argv)
    load_dotenv()

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    code = Scheduler().run(interval=args.interval, max_ticks=1 if args.once else None,
                           stop_event=stop)
    print(f"scheduler stopped (exit {code})", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
