"""Q1 per action class: what the numbers say, who is suspended, and re-including one (DP-15).

    python scripts/manage_goal_fit_classes.py report [--since 2026-10-01] [--json]
    python scripts/manage_goal_fit_classes.py suspensions
    python scripts/manage_goal_fit_classes.py clear --action network.scan \\
        --reason "classifier wording fixed in the goal template, checked on 30 calls"

**This tool recommends and never admits.** ``report`` prints, for each action class, the calls
Q1 has made on the real ``propose_action`` path (since the class was last cleared), how many failed,
the Wilson 95% upper bound of the failure rate, and whether the admission rule would recommend the
class: at least 40 calls and an upper bound of at most 15% -- **judged over a rolling window, the
class's last 50 calls** (the exit rule's window), so a long run of good calls long ago cannot
carry a class whose recent calls fail. It is **not a pre-fixed sample**: the more often this report
is read, the more likely a class is to be seen in a good stretch
(``docs/D68_DP15_ADMISSION_LOOKS.md``). The total since clearing is shown beside it. ``report``
ends with the **classes suspended this period** (``--since``; all time without it). A class is
*admitted* only by a person publishing the layer that lists it
(``scripts/manage_global_policy.py publish ... --document
'{"goal_fit_actions": ["network.scan"]}'``); nothing here writes a list.

**What counts, and every look is counted.** A failed call has a kind: ``refusal`` (the service's
safety classifier stopped it), ``transport`` (timeout, connection, 5xx, authentication, usage) or
``unclassified``. The window, the admission rule and the exit rule read judgements -- answered,
``refusal`` and ``unclassified`` -- and never ``transport`` (an outage says nothing about a class;
the check still fails closed). ``report`` shows each kind per class, and ends with the classes
suspended this period and the **validator outages suspected this period** (more than half of the
last 30 calls, of any class, failed in transport; nothing is suspended by it). **Every run of
``report`` is recorded as a look at each class** (when, the window's ``n``, failures, bound, who);
the report shows ``looks`` and the ``n`` at the first look. Read it once, at a number of calls
decided beforehand, and do not keep reading it: looking again and again overstates how often a
class passes, and the count is how that is checked afterwards. The record is never an input to
anything, and a report whose look cannot be written is still printed, marked as not recorded.

**Exit is automatic, re-inclusion is not.** The control plane suspends a class when its last 50
calls (at least 30) failed above 30% (``control_plane/plan_fit/classes.py``). ``clear`` lifts a
suspension -- that is all re-inclusion is: the class is asked about again if the policy still lists
it, and its rates start from nothing. It is an operator's act over the ``global_policy_admin``
connection, which no automated component holds; the runtime role has no grant to do it. Like the
other operator tools it asks for a person on a terminal; ``--yes`` is the caller's statement
that one already decided.

**A clearing says why and who, and the tool checks who.** ``--reason`` is required (10 to 500
printable characters on one line) and is stored with the clearing; the database refuses a clearing
without one. The person is not taken from a flag. The tool reads the kernel's audit login uid
(``/proc/self/loginuid``: set once at login, inherited through ``sudo`` and ``su``, and not
changeable by an environment variable) and turns it into an account name; that path cannot be
forged with ``SUDO_USER=somebody python ...``. Where the file cannot be read, or holds the "unset"
value (4294967295 -- containers, some services), the tool falls back to ``SUDO_USER`` or the OS
user, which **can** be forged, and the clearing's audit event (``plan_fit.class_cleared``) says
``identity_unverified: true``. In both paths a shared account (``root``) and an ``--actor`` that
differs from the identity found are refused. What is not stopped: whoever holds the
``global_policy_admin`` credential can still clear with SQL under any name, which is why the row
is write-once and records who, when and why.

Exit status: 0 done, 1 refused or nothing to do, 2 not confirmed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import pwd
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text  # noqa: E402

from control_plane.audit.logger import record_audit  # noqa: E402
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.plan_fit import class_store, classes  # noqa: E402
from control_plane.policy.merge import goal_fit_actions_of  # noqa: E402
from control_plane.state.db import get_engine, global_policy_admin_scope  # noqa: E402
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
           since: str | None = None, outages: list[dict] | None = None,
           views: dict[str, tuple[int, int]] | None = None,
           recorded: bool | None = None) -> str:
    lines = [f"admission: at least {classes.ADMIT_MIN} of the class's last {classes.ADMIT_WINDOW} "
             f"judgements on the real path and a Wilson 95% upper bound of at most "
             f"{classes.ADMIT_UPPER:.0%} over that window; exit: last {classes.EXIT_WINDOW} "
             f"judgements (at least {classes.EXIT_MIN}) failing above {classes.EXIT_RATE:.0%}. "
             "A transport failure (timeout, connection, 5xx, authentication, usage) is shown and "
             "is neither a failure nor a success for either rule. This is advice: a class is "
             "admitted only by publishing the layer that lists it. Read it once, at a number of "
             "calls decided beforehand; every run is recorded and counted in 'looks'.", ""]
    if recorded is True:
        lines += ["this run is recorded as a look at each class below", ""]
    elif recorded is False:
        lines += ["THIS RUN WAS NOT RECORDED: the look could not be written; the 'looks' below "
                  "do not include it", ""]
    if not rows:
        lines.append("no call has been made and no class is listed: nothing to report")
    lines.append(f"{'class':<16}{'window':>7}{'failed':>8}{'upper95':>9}{'total':>7}{'tot.fail':>9}"
                 f"{'refusal':>8}{'unclass':>8}{'transp':>7}{'transp%':>8}{'looks':>7}"
                 f"{'n@first':>8}  "
                 f"{'state':<16}advice")
    for r in rows:
        advice = "RECOMMEND ADMISSION" if r["recommend_admission"] else r["reason"]
        if views is None:
            looks, first = "?", "?"
        else:
            count, first_n = views.get(r["action"], (0, 0))
            looks, first = str(count), (str(first_n) if count else "-")
        lines.append(f"{r['action']:<16}{r['n']:>7}{r['failed']:>8}{r['upper95']:>9.1%}"
                     f"{r['n_total']:>7}{r['failed_total']:>9}{r['refusal_total']:>8}"
                     f"{r['unclassified_total']:>8}{r['transport_total']:>7}"
                     f"{r['transport_share']:>8.1%}{looks:>7}{first:>8}  "
                     f"{r['state']:<16}{advice}")
    if suspensions is not None:
        lines += ["", *classes.suspension_lines(suspensions, since)]
    if outages is not None:
        lines += ["", *classes.outage_lines(outages, since)]
    return "\n".join(lines)


def record_looks(
    rows: list[dict], who: Identity,
) -> tuple[bool, dict[str, tuple[int, int]] | None]:
    """Write this run as a look at every class shown, and read the counts back.

    ``(recorded, counts)``. Never raises and never decides anything: if the look cannot be written
    the report is printed all the same and says so; if the counts cannot be read they are shown
    as unknown. Over the runtime connection -- the one the tool already uses to write the audit
    event of a clearing -- so that the operator role is given no new write."""
    recorded = False
    try:
        with get_engine().begin() as conn:
            class_store.record_views(conn, rows, who.name, who.unverified)
            counts = class_store.view_counts(conn)
        return True, counts
    except Exception:  # noqa: BLE001 - a report that cannot be recorded is still a report
        pass
    try:
        with get_engine().begin() as conn:
            return recorded, class_store.view_counts(conn)
    except Exception:  # noqa: BLE001
        return recorded, None


def _report(as_json: bool, since: str | None) -> int:
    with global_policy_admin_scope() as conn:
        rows = class_store.class_table(conn, global_list(conn))
        suspended = class_store.suspensions_in_period(conn, since)
        outages = class_store.outages_in_period(conn, since)
    recorded, views = record_looks(rows, login_identity())
    if as_json:
        for r in rows:
            count, first_n = (views or {}).get(r["action"], (0, 0))
            r["looks"] = count if views is not None else None
            r["n_at_first_look"] = first_n if count else None
        print(json.dumps({"classes": rows, "suspended_this_period": suspended,
                          "validator_outage_suspected_this_period": outages, "since": since,
                          "this_run_recorded": recorded}, indent=1, default=str))
    else:
        print(render(rows, suspended, since, outages, views, recorded))
    return 0


def _suspensions() -> int:
    with global_policy_admin_scope() as conn:
        rows = class_store.suspensions_in_period(conn)
    for line in classes.suspension_lines(rows):
        print(line)
    return 0


LOGINUID_PATH = "/proc/self/loginuid"
#: what the kernel holds when no login set the audit uid (``(uid_t)-1``)
LOGINUID_UNSET = 4294967295


@dataclass(frozen=True)
class Identity:
    """Who is running this tool, and how much that is worth."""

    name: str
    #: ``loginuid`` (the kernel's audit uid; an environment variable cannot change it) or
    #: ``environment`` (``SUDO_USER`` / the OS user, which can be forged)
    source: str

    @property
    def unverified(self) -> bool:
        return self.source != "loginuid"


def read_loginuid(path: str = LOGINUID_PATH) -> int | None:
    """The audit login uid, or ``None`` if it cannot be read, is not a number, or is unset."""
    try:
        with open(path) as handle:
            value = int(handle.read().strip())
    except (OSError, ValueError):
        return None
    return None if value == LOGINUID_UNSET or value < 0 else value


def resolve_identity(*, loginuid_path: str = LOGINUID_PATH,
                     environ: dict[str, str] | None = None) -> Identity:
    """The kernel's login uid as an account name when it is there; otherwise the environment's
    answer, marked as the weaker thing it is. The environment is not consulted at all when the
    kernel has an answer."""
    uid = read_loginuid(loginuid_path)
    if uid is not None:
        try:
            return Identity(pwd.getpwuid(uid).pw_name, "loginuid")
        except KeyError:        # a login uid with no account entry is still the kernel's answer
            return Identity(f"uid:{uid}", "loginuid")
    env = os.environ if environ is None else environ
    return Identity(env.get("SUDO_USER") or getpass.getuser(), "environment")


def login_identity() -> Identity:
    return resolve_identity()


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
    who = login_identity()
    problem = identity_problem(actor, who.name)
    if problem:
        print(f"refused: {problem}", file=sys.stderr)
        return 1
    if not classes.valid_reason(reason):
        print(f"refused: --reason is required, {classes.REASON_MIN} to {classes.REASON_MAX} "
              "printable characters on one line: why is this class safe to ask again?",
              file=sys.stderr)
        return 1
    weak = ("" if not who.unverified else
            "\n  IDENTITY NOT VERIFIED: the kernel has no login uid here, so this name is the "
            "environment's and can be forged; the audit event will say so")
    summary = (f"RE-INCLUDE {action} as {who.name}\n  reason: {reason.strip()}\n  lifts its live "
               "suspension; the class is asked about again if the policy lists it, and its "
               f"rates start from nothing{weak}")
    if not _confirm(summary, "CLEAR", assume_yes):
        return 2
    with global_policy_admin_scope() as conn:
        done = class_store.clear_suspension(conn, action, who.name, reason)
        if done:
            # Inside the operator's transaction: an audit write that fails rolls the clearing back
            # (a re-inclusion with no record is the failure to avoid).
            record_audit(
                engagement_id=None, scope="global", actor=who.name,
                event_type="plan_fit.class_cleared", subject_type="goal_fit_class",
                subject_id=action,
                payload={"action": action, "reason": reason.strip(),
                         "identity_source": who.source,
                         "identity_unverified": who.unverified})
    print("cleared" if done else f"{action} has no live suspension")
    if done and who.unverified:
        print("note: identity_unverified (recorded in the audit event)")
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
