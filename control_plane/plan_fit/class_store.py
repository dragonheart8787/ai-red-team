"""The memory behind Q1's per-class rules (D68 DP-15): reads and writes of the two global tables.

* The pipeline (``cyberorch_app``) reads which classes are suspended, appends one row per call the
  validator was asked, and -- after a call -- runs the exit rule over the class's last calls and may
  insert a suspension. It cannot clear one: the database gives it no grant.
* The operator (``global_policy_admin``) reads the calls for the admission report and clears a
  suspension. Re-inclusion is only that.

Nothing here reads or stores a goal, a target, an engagement or an answer: an action class, an
outcome and a time.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import Connection, text

from control_plane.plan_fit import classes


def suspended_actions(conn: Connection) -> frozenset[str]:
    """The classes with a live suspension."""
    rows = conn.execute(text(
        "SELECT action FROM goal_fit_suspensions WHERE cleared_at IS NULL")).all()
    return frozenset(r[0] for r in rows)


def record_call(conn: Connection, action: str, outcome: str) -> None:
    if outcome not in classes.OUTCOMES:
        raise ValueError(f"not an outcome: {outcome!r}")
    conn.execute(text("INSERT INTO goal_fit_calls (action, outcome) VALUES (:a, :o)"),
                 {"a": action, "o": outcome})


def recent_outcomes(conn: Connection, action: str) -> list[str]:
    """The outcomes of the class's last calls, newest first, since the last time an operator
    cleared a suspension of it (a class let back in starts a new window: its old failures are the
    reason it was out)."""
    rows = conn.execute(text(
        "SELECT outcome FROM goal_fit_calls WHERE action = :a AND called_at > COALESCE("
        "(SELECT max(cleared_at) FROM goal_fit_suspensions WHERE action = :a), '-infinity') "
        "ORDER BY call_id DESC LIMIT :n"), {"a": action, "n": classes.EXIT_WINDOW}).all()
    return [r[0] for r in rows]


def suspend(conn: Connection, action: str, verdict: classes.ExitVerdict) -> bool:
    """Insert the suspension; ``False`` if the class already has a live one."""
    done = conn.execute(text(
        "INSERT INTO goal_fit_suspensions (action, window_n, window_failed) "
        "VALUES (:a, :n, :f) ON CONFLICT (action) WHERE cleared_at IS NULL DO NOTHING"),
        {"a": action, "n": verdict.n, "f": verdict.failed})
    return done.rowcount == 1


def record_and_review(conn: Connection, action: str, outcome: str) -> classes.ExitVerdict | None:
    """After a call: append it, run the exit rule over the class's window, and suspend the class if
    the rule says so. Returns the verdict when this call *caused* a suspension, else ``None``."""
    record_call(conn, action, outcome)
    verdict = classes.review_exit(recent_outcomes(conn, action))
    if verdict.take_out and suspend(conn, action, verdict):
        return verdict
    return None


# -- the operator's side ------------------------------------------------------------------------

def clear_suspension(conn: Connection, action: str, actor: str, reason: str) -> bool:
    """Re-include a class: clear its live suspension, saying who and why. ``False`` if there was
    none. A clearing without a name or without a reason (see :func:`classes.valid_reason`) is
    refused here and again by the database."""
    if not actor:
        raise ValueError("clearing a suspension must name who does it")
    if not classes.valid_reason(reason):
        raise ValueError(
            f"clearing a suspension must say why: {classes.REASON_MIN} to {classes.REASON_MAX} "
            "printable characters on one line")
    done = conn.execute(text(
        "UPDATE goal_fit_suspensions SET cleared_at = now(), cleared_by = :who, "
        "cleared_reason = :why WHERE action = :a AND cleared_at IS NULL"),
        {"a": action, "who": actor, "why": reason.strip()})
    return done.rowcount == 1


def suspensions_in_period(conn: Connection, since: str | None = None) -> list[dict[str, Any]]:
    """The suspensions written at or after ``since`` (all of them without it), oldest first, with
    how each ended: still live, or cleared by whom, when and why. A suspension is listed by when it
    was written, whether or not it has been cleared since."""
    when = " WHERE suspended_at >= CAST(:since AS timestamptz)" if since else ""
    rows = conn.execute(text(
        "SELECT suspension_id, action, suspended_at, window_n, window_failed, cleared_at, "
        "cleared_by, cleared_reason FROM goal_fit_suspensions" + when
        + " ORDER BY suspension_id"), {"since": since} if since else {}).mappings().all()
    return [{**dict(r), "live": r["cleared_at"] is None} for r in rows]


def class_table(conn: Connection, listed: Sequence[str] = ()) -> list[dict[str, Any]]:
    """Per class: the failures among its last :data:`classes.ADMIT_WINDOW` calls (since it was last
    cleared), the Wilson bound of that, whether the admission rule would recommend it, and its
    state; and, beside them, how many calls the class has had in all since then. ``listed`` is the
    effective list, read by the caller from policy; this reads only the two tables."""
    live = {r[0] for r in conn.execute(text(
        "SELECT action FROM goal_fit_suspensions WHERE cleared_at IS NULL")).all()}
    since = ("c.called_at > COALESCE((SELECT max(s.cleared_at) FROM goal_fit_suspensions s "
             "WHERE s.action = c.action), '-infinity')")
    recent: dict[str, list[str]] = {}
    for action, outcome in conn.execute(text(
            "SELECT action, outcome FROM (SELECT c.action, c.outcome, row_number() OVER "
            "(PARTITION BY c.action ORDER BY c.call_id DESC) AS rn FROM goal_fit_calls c WHERE "
            + since + ") t WHERE rn <= :w ORDER BY action, rn"), {"w": classes.ADMIT_WINDOW}):
        recent.setdefault(action, []).append(outcome)
    totals = {a: (int(n), int(f)) for a, n, f in conn.execute(text(
        "SELECT c.action, count(*), count(*) FILTER (WHERE c.outcome = 'failed') "
        "FROM goal_fit_calls c WHERE " + since + " GROUP BY c.action"))}
    out = []
    for action in sorted(set(recent) | set(listed) | live):
        adm = classes.admission_over_window(action, recent.get(action, []))
        total_n, total_failed = totals.get(action, (0, 0))
        out.append({**_row(adm, action in listed, action in live),
                    "n_total": total_n, "failed_total": total_failed})
    return out


def _row(adm: classes.Admission, listed: bool, suspended: bool) -> dict[str, Any]:
    state = "suspended" if suspended else ("in the list" if listed else "not in the list")
    return {"action": adm.action, "n": adm.n, "failed": adm.failed,
            "upper95": round(adm.upper, 4), "recommend_admission": adm.recommend and not (
                listed or suspended),
            "state": state, "reason": adm.reason}
