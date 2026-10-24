"""Q1 per action class: what the numbers say, who is suspended, and re-including one (DP-15).

    python scripts/manage_goal_fit_classes.py report [--since 2026-10-01] [--json]
    python scripts/manage_goal_fit_classes.py suspensions
    python scripts/manage_goal_fit_classes.py clear --action network.scan \\
        --reason "classifier wording fixed in the goal template, checked on 30 calls"

**This tool recommends and never admits.** ``report`` prints, for each action class, the calls
Q1 has made on the real ``propose_action`` path (since the class was last cleared), how many failed,
the Wilson 95% upper bound of the failure rate, and whether the admission rule would recommend the
class: at least 40 calls and an upper bound of at most 15% -- **judged over a fixed window, the
class's last 50 calls** (the exit rule's window), so a long run of good calls long ago cannot
carry a class whose recent calls fail. The total since clearing is shown beside it. ``report``
ends with the **classes suspended this period** (``--since``; all time without it). A class is
*admitted* only by a person publishing the layer that lists it
(``scripts/manage_global_policy.py publish ... --document
'{"goal_fit_actions": ["network.scan"]}'``); nothing here writes a list.

**Exit is automatic, re-inclusion is not.** The control plane suspends a class when its last 50
calls (at least 30) failed above 30% (``control_plane/plan_fit/classes.py``). ``clear`` lifts a
suspension -- that is all re-inclusion is: the class is asked about again if the policy still lists
it, and its rates start from nothing. It is an operator's act over the ``global_policy_admin``
connection, which no automated component holds; the runtime role has no grant to do it. Like the
other operator tools it asks for a person on a terminal; ``--yes`` is the caller's statement
that one already decided.

**A clearing says why and who, and the tool checks who.** ``--reason`` is required (10 to 500
printable characters on one line) and is stored with the clearing; the database refuses a clearing
without one. The person is not taken from a flag: it is the login that runs the tool (``SUDO_USER``
if there is one, else the OS user), and a ``--actor`` that differs is refused, as is a shared
account (``root``) that names no one. What this checks is the operator host's login and nothing
more: someone holding the ``global_policy_admin`` credential can still clear with SQL, which is
why the row is write-once and records who, when and why.

The list this reads is the **global** layers' ``goal_fit_actions``; a class listed only in a layer
of one engagement shows as "not in the list" here.

Exit status: 0 done, 1 refused or nothing to do, 2 not confirmed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text  # noqa: E402

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.plan_fit import class_store, classes  # noqa: E402
from control_plane.policy.merge import goal_fit_actions_of  # noqa: E402
from control_plane.state.db import global_policy_admin_scope  # noqa: E402
from scripts.manage_global_policy import _confirm  # noqa: E402


def global_list(conn) -> list[str]:
    """The classes the active global layers list (union, as the policy merges them)."""
    rows = conn.execute(text(
        "SELECT document FROM policy_layers WHERE active IS TRUE AND engagement_id IS NULL"
    )).all()
    listed: set[str] = set()
    for (document,) in rows:
        listed |= goal_fit_actions_of((document or {}).get("goal_fit_actions"))
    return sorted(listed)


def render(rows: list[dict], suspensions: list[dict] | None = None,
           since: str | None = None) -> str:
    lines = [f"admission: at least {classes.ADMIT_MIN} of the class's last {classes.ADMIT_WINDOW} "
             f"calls on the real path and a Wilson 95% upper bound of at most "
             f"{classes.ADMIT_UPPER:.0%} over that window; exit: last {classes.EXIT_WINDOW} "
             f"calls (at least {classes.EXIT_MIN}) failing above {classes.EXIT_RATE:.0%}. This is "
             "advice: a class is admitted only by publishing the layer that lists it.", ""]
    if not rows:
        lines.append("no call has been made and no class is listed: nothing to report")
    lines.append(f"{'class':<16}{'window':>7}{'failed':>8}{'upper95':>9}{'total':>7}{'tot.fail':>9}"
                 f"  {'state':<16}advice")
    for r in rows:
        advice = "RECOMMEND ADMISSION" if r["recommend_admission"] else r["reason"]
        lines.append(f"{r['action']:<16}{r['n']:>7}{r['failed']:>8}{r['upper95']:>9.1%}"
                     f"{r['n_total']:>7}{r['failed_total']:>9}  {r['state']:<16}{advice}")
    if suspensions is not None:
        lines += ["", *classes.suspension_lines(suspensions, since)]
    return "\n".join(lines)


def _report(as_json: bool, since: str | None) -> int:
    with global_policy_admin_scope() as conn:
        rows = class_store.class_table(conn, global_list(conn))
        suspended = class_store.suspensions_in_period(conn, since)
    if as_json:
        print(json.dumps({"classes": rows, "suspended_this_period": suspended, "since": since},
                         indent=1, default=str))
    else:
        print(render(rows, suspended, since))
    return 0


def _suspensions() -> int:
    with global_policy_admin_scope() as conn:
        rows = class_store.suspensions_in_period(conn)
    for line in classes.suspension_lines(rows):
        print(line)
    return 0


def login_identity() -> str:
    """Who is running this: the login behind ``sudo`` if there is one, else the OS user."""
    return os.environ.get("SUDO_USER") or getpass.getuser()


def identity_problem(actor: str | None, identity: str) -> str | None:
    """Why the person at the terminal cannot clear a suspension as ``actor``, or ``None``.

    ``root`` is a shared account that names no one; a differing ``--actor`` is somebody else's
    name on this person's act."""
    if not identity or identity == "root":
        return ("the login running this is a shared account (root) and names no one: log in "
                "as yourself (or use sudo from your own login)")
    if actor is not None and actor != identity:
        return f"--actor {actor!r} is not the login running this ({identity!r})"
    return None


def _clear(action: str, actor: str | None, reason: str | None, assume_yes: bool) -> int:
    if not classes.valid_action_name(action):
        print(f"refused: {action!r} is not an action class name", file=sys.stderr)
        return 1
    problem = identity_problem(actor, login_identity())
    if problem:
        print(f"refused: {problem}", file=sys.stderr)
        return 1
    if not classes.valid_reason(reason):
        print(f"refused: --reason is required, {classes.REASON_MIN} to {classes.REASON_MAX} "
              "printable characters on one line: why is this class safe to ask again?",
              file=sys.stderr)
        return 1
    who = login_identity()
    summary = (f"RE-INCLUDE {action} as {who}\n  reason: {reason.strip()}\n  lifts its live "
               "suspension; the class is asked about again if the policy lists it, and its "
               "rates start from nothing")
    if not _confirm(summary, "CLEAR", assume_yes):
        return 2
    with global_policy_admin_scope() as conn:
        done = class_store.clear_suspension(conn, action, who, reason)
    print("cleared" if done else f"{action} has no live suspension")
    return 0 if done else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    rep = sub.add_parser("report", help="calls, failures, upper bound and advice per class")
    rep.add_argument("--since", default=None,
                     help="the period for 'classes suspended this period' (default: all time)")
    rep.add_argument("--json", action="store_true")
    sub.add_parser("suspensions", help="every suspension, live and cleared")
    clr = sub.add_parser("clear", help="re-include a suspended class (an operator's act)")
    clr.add_argument("--action", required=True)
    clr.add_argument("--actor", default=None,
                     help="optional; if given it must be the login running this (it is checked)")
    clr.add_argument("--reason", default=None, help="why the class is safe to ask again (stored)")
    clr.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    load_dotenv()
    if args.command == "report":
        return _report(args.json, args.since)
    if args.command == "suspensions":
        return _suspensions()
    return _clear(args.action, args.actor, args.reason, args.yes)


if __name__ == "__main__":
    raise SystemExit(main())
