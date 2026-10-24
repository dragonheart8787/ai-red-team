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

from agents.failure_kind import FAILURE_KINDS, TRANSPORT, UNCLASSIFIED
from control_plane.plan_fit import classes


def suspended_actions(conn: Connection) -> frozenset[str]:
    """The classes with a live suspension."""
    rows = conn.execute(text(
        "SELECT action FROM goal_fit_suspensions WHERE cleared_at IS NULL")).all()
    return frozenset(r[0] for r in rows)


def record_call(conn: Connection, action: str, outcome: str,
                failure_kind: str | None = None) -> None:
    """Append one call. A failed call has a kind (``unclassified`` if none is given, which is how
    every failure was counted before kinds existed); an answered one has none."""
    if outcome not in classes.OUTCOMES:
        raise ValueError(f"not an outcome: {outcome!r}")
    if outcome == classes.FAILED:
        failure_kind = failure_kind or UNCLASSIFIED
        if failure_kind not in FAILURE_KINDS:
            raise ValueError(f"not a failure kind: {failure_kind!r}")
    else:
        failure_kind = None
    conn.execute(text("INSERT INTO goal_fit_calls (action, outcome, failure_kind) "
                      "VALUES (:a, :o, :k)"), {"a": action, "o": outcome, "k": failure_kind})


def recent_outcomes(conn: Connection, action: str) -> list[str]:
    """The outcomes of the class's last calls that say something about the class, newest first,
    since the last time an operator cleared a suspension of it (a class let back in starts a new
    window: its old failures are the reason it was out). **A ``transport`` failure is not in it:**
    a timeout or an outage says nothing about the class, so it is neither a failure nor a success
    for the window."""
    rows = conn.execute(text(
        "SELECT outcome FROM goal_fit_calls WHERE action = :a "
        "AND failure_kind IS DISTINCT FROM 'transport' AND called_at > COALESCE("
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


def record_and_review(conn: Connection, action: str, outcome: str,
                      failure_kind: str | None = None) -> classes.ExitVerdict | None:
    """After a call: append it, run the exit rule over the class's window, and suspend the class if
    the rule says so. Returns the verdict when this call *caused* a suspension, else ``None``. A
    ``transport`` failure is recorded and does not reach the rule (see :func:`recent_outcomes`)."""
    record_call(conn, action, outcome, failure_kind)
    if outcome == classes.FAILED and (failure_kind or UNCLASSIFIED) == TRANSPORT:
        return None
    verdict = classes.review_exit(recent_outcomes(conn, action))
    if verdict.take_out and suspend(conn, action, verdict):
        return verdict
    return None


def check_outage(conn: Connection) -> classes.OutageVerdict | None:
    """After a call was recorded: whether it raised the suspicion that the validator service is
    down. If so, one row is written (and the caller audits it); the verdict is returned. Nothing
    is suspended and no decision depends on this."""
    kinds = [r[0] for r in conn.execute(text(
        "SELECT failure_kind FROM goal_fit_calls ORDER BY call_id DESC LIMIT :n"),
        {"n": classes.OUTAGE_WINDOW + 1})]
    if not classes.outage_started(kinds):
        return None
    verdict = classes.review_outage(kinds)
    conn.execute(text("INSERT INTO goal_fit_outage_suspicions (window_n, window_transport) "
                      "VALUES (:n, :t)"), {"n": verdict.n, "t": verdict.transport})
    return verdict


def outages_in_period(conn: Connection, since: str | None = None) -> list[dict[str, Any]]:
    """The suspected outages written at or after ``since`` (all without it), oldest first."""
    when = " WHERE detected_at >= CAST(:since AS timestamptz)" if since else ""
    return [dict(r) for r in conn.execute(text(
        "SELECT suspicion_id, detected_at, window_n, window_transport "
        "FROM goal_fit_outage_suspicions" + when + " ORDER BY suspicion_id"),
        {"since": since} if since else {}).mappings()]


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
    """Per class: the failures among its last :data:`classes.ADMIT_WINDOW` calls that say
    something about the class (since it was last cleared), the Wilson bound of that, whether the
    admission rule would recommend it, and its state; beside them, the totals since then by kind
    -- calls that answered, ``refusal``, ``unclassified`` and ``transport`` failures. A
    ``transport`` failure is shown and is not in the window or in the judgements: it is not
    evidence about the class. ``listed`` is the effective list, read by the caller from policy;
    this reads only the two tables."""
    live = {r[0] for r in conn.execute(text(
        "SELECT action FROM goal_fit_suspensions WHERE cleared_at IS NULL")).all()}
    since = ("c.called_at > COALESCE((SELECT max(s.cleared_at) FROM goal_fit_suspensions s "
             "WHERE s.action = c.action), '-infinity')")
    recent: dict[str, list[str]] = {}
    for action, outcome in conn.execute(text(
            "SELECT action, outcome FROM (SELECT c.action, c.outcome, row_number() OVER "
            "(PARTITION BY c.action ORDER BY c.call_id DESC) AS rn FROM goal_fit_calls c WHERE "
            "c.failure_kind IS DISTINCT FROM 'transport' AND "
            + since + ") t WHERE rn <= :w ORDER BY action, rn"), {"w": classes.ADMIT_WINDOW}):
        recent.setdefault(action, []).append(outcome)
    totals = {a: (int(n), int(f), int(rf), int(un), int(tr)) for a, n, f, rf, un, tr in
              conn.execute(text(
                  "SELECT c.action, "
                  "count(*) FILTER (WHERE c.failure_kind IS DISTINCT FROM 'transport'), "
                  "count(*) FILTER (WHERE c.outcome = 'failed' AND "
                  "c.failure_kind IS DISTINCT FROM 'transport'), "
                  "count(*) FILTER (WHERE c.failure_kind = 'refusal'), "
                  "count(*) FILTER (WHERE c.failure_kind = 'unclassified'), "
                  "count(*) FILTER (WHERE c.failure_kind = 'transport') "
                  "FROM goal_fit_calls c WHERE " + since + " GROUP BY c.action"))}
    out = []
    for action in sorted(set(recent) | set(totals) | set(listed) | live):
        adm = classes.admission_over_window(action, recent.get(action, []))
        total_n, total_failed, refusal, unclassified, transport = totals.get(
            action, (0, 0, 0, 0, 0))
        out.append({**_row(adm, action in listed, action in live),
                    "n_total": total_n, "failed_total": total_failed,
                    "refusal_total": refusal, "unclassified_total": unclassified,
                    "transport_total": transport})
    return out


def _row(adm: classes.Admission, listed: bool, suspended: bool) -> dict[str, Any]:
    state = "suspended" if suspended else ("in the list" if listed else "not in the list")
    return {"action": adm.action, "n": adm.n, "failed": adm.failed,
            "upper95": round(adm.upper, 4), "recommend_admission": adm.recommend and not (
                listed or suspended),
            "state": state, "reason": adm.reason}


# -- looks at the admission report (0030) -------------------------------------------------------

def record_views(conn: Connection, rows: Sequence[dict[str, Any]], viewer: str,
                 identity_unverified: bool) -> int:
    """One row per class the report showed: when (the database's clock), the window's ``n``,
    failures and upper bound, and who looked. A record about reading and nothing else: no
    decision, no list, no suspension reads this table. Returns the number written."""
    if not viewer:
        raise ValueError("a view must name who looked")
    if rows:
        conn.execute(text(
            "INSERT INTO goal_fit_report_views "
            "(action, window_n, window_failed, upper95, viewer, identity_unverified) "
            "VALUES (:a, :n, :f, :u, :v, :x)"),
            [{"a": r["action"], "n": r["n"], "f": r["failed"], "u": r["upper95"],
              "v": viewer, "x": bool(identity_unverified)} for r in rows])
    return len(rows)


def view_counts(conn: Connection) -> dict[str, tuple[int, int]]:
    """Per class: how many times the report has shown it, and the window's ``n`` the first time."""
    return {a: (int(count), int(first_n)) for a, count, first_n in conn.execute(text(
        "SELECT action, count(*), (array_agg(window_n ORDER BY view_id))[1] "
        "FROM goal_fit_report_views GROUP BY action"))}
