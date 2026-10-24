"""Q1 per action class: what the numbers say, who is suspended, and re-including one (DP-15).

    python scripts/manage_goal_fit_classes.py report [--json]
    python scripts/manage_goal_fit_classes.py suspensions
    python scripts/manage_goal_fit_classes.py clear --action network.scan --actor alice

**This tool recommends and never admits.** ``report`` prints, for each action class, the calls
Q1 has made on the real ``propose_action`` path (since the class was last cleared), how many failed,
the Wilson 95% upper bound of the failure rate, and whether the admission rule would recommend the
class: at least 40 calls and an upper bound of at most 15%. A class is *admitted* only by a person
publishing the layer that lists it (``scripts/manage_global_policy.py publish ... --document
'{"goal_fit_actions": ["network.scan"]}'``); nothing here writes a list.

**Exit is automatic, re-inclusion is not.** The control plane suspends a class when its last 50
calls (at least 30) failed above 30% (``control_plane/plan_fit/classes.py``). ``clear`` lifts a
suspension -- that is all re-inclusion is: the class is asked about again if the policy still lists
it, and its rates start from nothing. It is an operator's act over the ``global_policy_admin``
connection, which no automated component holds; the runtime role has no grant to do it. Like the
other operator tools it asks for a person on a terminal; ``--yes`` is the caller's statement
that one already decided.

The list this reads is the **global** layers' ``goal_fit_actions``; a class listed only in a layer
of one engagement shows as "not in the list" here.

Exit status: 0 done, 1 refused or nothing to do, 2 not confirmed.
"""

from __future__ import annotations

import argparse
import json
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


def render(rows: list[dict]) -> str:
    lines = [f"admission: at least {classes.ADMIT_MIN} calls on the real path and a Wilson 95% "
             f"upper bound of at most {classes.ADMIT_UPPER:.0%}; exit: last {classes.EXIT_WINDOW} "
             f"calls (at least {classes.EXIT_MIN}) failing above {classes.EXIT_RATE:.0%}. This is "
             "advice: a class is admitted only by publishing the layer that lists it.", ""]
    if not rows:
        lines.append("no call has been made and no class is listed: nothing to report")
    lines.append(f"{'class':<16}{'calls':>7}{'failed':>8}{'upper95':>9}  {'state':<16}advice")
    for r in rows:
        advice = "RECOMMEND ADMISSION" if r["recommend_admission"] else r["reason"]
        lines.append(f"{r['action']:<16}{r['n']:>7}{r['failed']:>8}{r['upper95']:>9.1%}  "
                     f"{r['state']:<16}{advice}")
    return "\n".join(lines)


def _report(as_json: bool) -> int:
    with global_policy_admin_scope() as conn:
        rows = class_store.class_table(conn, global_list(conn))
    print(json.dumps(rows, indent=1) if as_json else render(rows))
    return 0


def _suspensions() -> int:
    with global_policy_admin_scope() as conn:
        rows = conn.execute(text(
            "SELECT suspension_id, action, suspended_at, window_n, window_failed, cleared_at, "
            "cleared_by FROM goal_fit_suspensions ORDER BY suspension_id")).mappings().all()
    if not rows:
        print("no class has been suspended")
    for r in rows:
        state = f"cleared {r['cleared_at']:%Y-%m-%d %H:%M} by {r['cleared_by']}" if r[
            "cleared_at"] else "LIVE"
        print(f"#{r['suspension_id']} {r['action']}  suspended {r['suspended_at']:%Y-%m-%d %H:%M} "
              f"on {r['window_failed']}/{r['window_n']} failed  {state}")
    return 0


def _clear(action: str, actor: str, assume_yes: bool) -> int:
    if not classes.valid_action_name(action):
        print(f"refused: {action!r} is not an action class name", file=sys.stderr)
        return 1
    summary = (f"RE-INCLUDE {action} as {actor}\n  lifts its live suspension; the class is asked "
               "about again if the policy lists it, and its rates start from nothing")
    if not _confirm(summary, "CLEAR", assume_yes):
        return 2
    with global_policy_admin_scope() as conn:
        done = class_store.clear_suspension(conn, action, actor)
    print("cleared" if done else f"{action} has no live suspension")
    return 0 if done else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    rep = sub.add_parser("report", help="calls, failures, upper bound and advice per class")
    rep.add_argument("--json", action="store_true")
    sub.add_parser("suspensions", help="every suspension, live and cleared")
    clr = sub.add_parser("clear", help="re-include a suspended class (an operator's act)")
    clr.add_argument("--action", required=True)
    clr.add_argument("--actor", required=True, help="who is re-including it (recorded)")
    clr.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    load_dotenv()
    if args.command == "report":
        return _report(args.json)
    if args.command == "suspensions":
        return _suspensions()
    return _clear(args.action, args.actor, args.yes)


if __name__ == "__main__":
    raise SystemExit(main())
