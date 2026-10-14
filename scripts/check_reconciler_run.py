"""Check what a ``state-only`` run did against what it said it did (completion 3, item 1).

    python scripts/check_reconciler_run.py before --state STATE.json
    python scripts/run_reconciler.py --mode state-only --once > PASS1.jsonl   # as many as needed
    python scripts/check_reconciler_run.py after  --state STATE.json PASS1.jsonl [PASS2.jsonl ...]

``before`` records what must not change: the schema (``snapshot_schema``: columns, constraints,
policies, functions, grants, comments ...) and the database's own insert / update / delete counters
(``pg_stat_user_tables``), which count every row written to a table whoever wrote it and are not
subject to row-level security -- an independent count, not the reconciler's own.

``after`` reads the passes' output and fails (exit 1) unless **all** of these hold:

1. every ``done`` result's proposal is in the stage and detail the transition table promises;
2. ``assert_coherent`` (the suite's own function) holds for every transitioned proposal, with the
   rest of its engagement's rows around it;
3. each transition has exactly one reconciler audit event of the right type, naming it, written
   after ``before`` -- and no other proposal in those engagements has one;
4. the database's counters agree with the output: ``audit_log`` took exactly
   ``transitions + 2 * passes + failure events`` rows (a failure is audited once per object, kind
   and reason per process), ``action_proposals`` was updated exactly ``transitions`` times, and
   **no table had a row deleted**;
5. the schema is identical to the one recorded by ``before``.

Ids and counts are printed; nothing else. The database role is the table owner for the schema and
counters (it reads no row), the runtime role bound to one engagement at a time for the rows.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine, text  # noqa: E402

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.reconciler import emit, vocab  # noqa: E402
from control_plane.state.db import engagement_scope  # noqa: E402
from control_plane.state.schema_snapshot import diff, snapshot_schema  # noqa: E402

EVENT_OF = {vocab.ABANDON: emit.PROPOSAL_ABANDONED, vocab.CLOSE: emit.PROPOSAL_CLOSED,
            vocab.MARK_UNKNOWN_OUTCOME: emit.DISPATCH_UNKNOWN_OUTCOME}
COUNTERS = """
    SELECT relname, n_tup_ins, n_tup_upd, n_tup_del FROM pg_stat_user_tables
    WHERE schemaname = 'public' ORDER BY relname
"""
#: the statistics reach other sessions after a short delay; wait until two reads agree
SETTLE_S = 0.6


def _owner():
    return create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)


def _counters(conn) -> dict[str, list[int]]:
    previous = None
    for _ in range(20):
        now = {r[0]: [int(r[1]), int(r[2]), int(r[3])] for r in conn.execute(text(COUNTERS))}
        if now == previous:
            return now
        previous = now
        time.sleep(SETTLE_S)
    return previous


def before(path: Path) -> int:
    engine = _owner()
    with engine.connect() as conn:
        state = {"schema": snapshot_schema(conn), "counters": _counters(conn),
                 "db_now": str(conn.execute(text("SELECT now()")).scalar_one())}
    path.write_text(json.dumps(state, sort_keys=True))
    print(f"recorded {len(state['schema'])} schema facts and the counters of "
          f"{len(state['counters'])} tables at {state['db_now']}")
    return 0


def _passes(files: list[Path]):
    """``(done transitions, failed results, number of passes, failure events expected)`` from the
    runs' output. A failure is audited once per object, kind and reason per *process*, and each
    file is one process."""
    done, failed, passes, failure_events = [], [], 0, 0
    for file in files:
        saw_summary = False
        distinct = set()
        for line in file.read_text().splitlines():
            if not line.startswith("{"):
                continue
            item = json.loads(line)
            if "summary" in item:
                saw_summary = True
            elif item.get("outcome") == "done":
                done.append(item)
            elif item.get("outcome") == "failed":
                failed.append(item)
                distinct.add((item["subject_id"], item["kind"], item["reason_code"]))
        passes += 1 if saw_summary else 0
        failure_events += len(distinct)
    return done, failed, passes, failure_events


def _only(snap: dict, mine: set[str], eid: str) -> dict:
    """The snapshot of an engagement cut down to the proposals that were moved and what hangs off
    them, so that ``assert_coherent`` judges those and not a hand-made row beside them."""
    with engagement_scope(eid) as conn:
        runs = [r[0] for r in conn.execute(text(
            "SELECT status FROM tool_runs WHERE proposal_id = ANY(:p)"), {"p": sorted(mine)})]
    keep = {k: snap[k] & mine for k in ("approved", "with_capability", "with_run", "any_approval",
                                         "decided_audit")}
    return dict(snap, proposals=[p for p in snap["proposals"] if p["proposal_id"] in mine],
                capabilities=len(keep["with_capability"]), runs=runs,
                evidence=snap["evidence"] if runs else 0, **keep)


def after(state_path: Path, files: list[Path]) -> int:
    from tests.test_pipeline_stages import assert_coherent, snapshot

    state = json.loads(state_path.read_text())
    done, failed, passes, failure_events = _passes(files)
    problems: list[str] = []
    note = problems.append

    # 1 + 2: the stage each transition promised, and the suite's own coherence rules
    by_engagement: dict[str, list[dict]] = {}
    for item in done:
        by_engagement.setdefault(item["engagement_id"], []).append(item)
    wrong_stage = incoherent = unaffected_incoherent = 0
    for eid, items in sorted(by_engagement.items()):
        snap = snapshot(eid)
        stage_of = {p["proposal_id"]: p for p in snap["proposals"]}
        mine = set()
        for item in items:
            _expected, new, detail = vocab.PROPOSAL_TRANSITIONS[(item["kind"], item["reason_code"])]
            row = stage_of.get(item["subject_id"])
            mine.add(item["subject_id"])
            if row is None or (row["stage"], row["detail"]) != (new, detail):
                wrong_stage += 1
                note(f"{item['subject_id']}: expected {new}/{detail}, found "
                     f"{None if row is None else (row['stage'], row['detail'])}")
        scoped = _only(snap, mine, eid)
        try:
            assert_coherent(scoped)
        except AssertionError as exc:
            incoherent += 1
            note(f"{eid}: not coherent: {str(exc)[:160]}")
        try:
            assert_coherent(snap)
        except AssertionError:
            unaffected_incoherent += 1       # a row nobody moved (a hand-made one), only counted

    # 3: one audit event per transition, none for anything else
    wrong_events = 0
    expected_events = Counter()
    for item in done:
        expected_events[(item["engagement_id"], EVENT_OF[item["kind"]], item["subject_id"])] += 1
    for eid in sorted(by_engagement):
        with engagement_scope(eid) as conn:
            rows = conn.execute(text(
                "SELECT event_type, subject_id FROM audit_log WHERE event_type = ANY(:t) "
                "AND ts > CAST(:since AS timestamptz)"),
                {"t": list(EVENT_OF.values()), "since": state["db_now"]}).all()
        seen = Counter((eid, event_type, subject) for event_type, subject in rows)
        if seen != Counter({k: v for k, v in expected_events.items() if k[0] == eid}):
            wrong_events += 1
            note(f"{eid}: audit events do not match the transitions "
                 f"({sum(seen.values())} events, "
                 f"{sum(v for k, v in expected_events.items() if k[0] == eid)} transitions)")

    # 4: the database's own counters
    engine = _owner()
    with engine.connect() as conn:
        now = _counters(conn)
        schema_now = snapshot_schema(conn)
    delta = {t: [now[t][i] - state["counters"].get(t, [0, 0, 0])[i] for i in range(3)]
             for t in now}
    deleted = {t: d[2] for t, d in delta.items() if d[2]}
    want_audit = len(done) + 2 * passes + failure_events
    if deleted:
        note(f"rows were deleted: {deleted}")
    if delta["audit_log"][0] != want_audit:
        note(f"audit_log took {delta['audit_log'][0]} rows, expected {want_audit} "
             f"({len(done)} transitions + 2 x {passes} passes + {failure_events} failures)")
    if delta["action_proposals"][1] != len(done):
        note(f"action_proposals was updated {delta['action_proposals'][1]} times, expected "
             f"{len(done)}")
    if delta["action_proposals"][0] or delta["action_proposals"][2]:
        note(f"action_proposals rows inserted/deleted: {delta['action_proposals']}")

    # 5: the schema
    changes = diff(state["schema"], schema_now)
    for line in changes[:20]:
        note(f"schema: {line}")

    report = {
        "passes": passes, "transitions_done": len(done), "failed": len(failed),
        "failed_by_detail": dict(sorted(Counter(
            f"{f['kind']}:{f['detail']}" for f in failed).items())),
        "by_kind": dict(sorted(Counter(f"{i['kind']}:{i['reason_code']}" for i in done).items())),
        "engagements": len(by_engagement), "wrong_stage": wrong_stage,
        "engagements_incoherent_in_moved_rows": incoherent,
        "engagements_with_an_unmoved_incoherent_row": unaffected_incoherent,
        "engagements_with_wrong_audit_events": wrong_events,
        "audit_log_rows_inserted": delta["audit_log"][0], "audit_log_rows_expected": want_audit,
        "action_proposals_updates": delta["action_proposals"][1],
        "tool_runs_updates": delta["tool_runs"][1],
        "rows_deleted_in_any_table": sum(deleted.values()), "schema_differences": len(changes),
        "ok": not problems,
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    for line in problems:
        print("PROBLEM:", line, file=sys.stderr)
    return 0 if not problems else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="step", required=True)
    one = sub.add_parser("before")
    one.add_argument("--state", type=Path, required=True)
    two = sub.add_parser("after")
    two.add_argument("--state", type=Path, required=True)
    two.add_argument("results", nargs="+", type=Path)
    args = parser.parse_args(argv)
    load_dotenv()
    return before(args.state) if args.step == "before" else after(args.state, args.results)


if __name__ == "__main__":
    raise SystemExit(main())
