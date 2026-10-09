"""The operator's side of the scheduler (D62): enrollment, and what ``awaiting-dispatch`` shows.

Enrollment is the operator's act, so the script asks for a person (as ``manage_global_policy.py``
does) and every change is audited on the global trail. ``awaiting-dispatch`` tells an operator why
an approved proposal has not run -- the scheduler's skip reason, in the closed vocabulary.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import text

from control_plane.audit.query import list_global_audit
from control_plane.scheduler import vocab
from control_plane.state.db import global_auditor_scope, scheduler_admin_scope
from tests import scheduler_support as sup

REPO = Path(__file__).resolve().parents[1]
ENROLL = REPO / "scripts" / "manage_scheduler_enrollment.py"
APPROVALS = REPO / "scripts" / "approvals.py"


def _run(script, *args, stdin=subprocess.DEVNULL):
    return subprocess.run([sys.executable, str(script), *args], cwd=REPO, env=os.environ.copy(),
                          capture_output=True, text=True, stdin=stdin, timeout=60)


def _live(engagement_id) -> bool:
    with scheduler_admin_scope() as conn:
        return bool(conn.execute(text(
            "SELECT 1 FROM scheduler_enrollment WHERE engagement_id = :e AND withdrawn_at IS NULL"),
            {"e": engagement_id}).first())


def test_the_enrollment_script_will_not_act_without_a_person_to_confirm(engagement_id):
    done = _run(ENROLL, "enroll", engagement_id, "--by", "alice")
    assert done.returncode == 2 and "no terminal" in done.stderr
    assert not _live(engagement_id)


def test_enroll_and_withdraw_are_audited_on_the_global_trail(engagement_id):
    try:
        done = _run(ENROLL, "enroll", engagement_id, "--by", "alice", "--yes")
        assert done.returncode == 0, done.stderr
        assert _live(engagement_id)
        assert _run(ENROLL, "list").stdout.count(engagement_id) == 1

        again = _run(ENROLL, "enroll", engagement_id, "--by", "alice", "--yes")
        assert again.returncode == 1 and "already enrolled" in again.stderr

        gone = _run(ENROLL, "withdraw", engagement_id, "--by", "bob", "--yes")
        assert gone.returncode == 0, gone.stderr
        assert not _live(engagement_id)
        nothing = _run(ENROLL, "withdraw", engagement_id, "--by", "bob", "--yes")
        assert nothing.returncode == 1 and "not currently enrolled" in nothing.stderr
    finally:
        sup.withdraw(engagement_id)

    with global_auditor_scope() as conn:
        events = [e for e in list_global_audit(conn, event_types=[vocab.ENROLLED, vocab.WITHDRAWN],
                                               limit=50)
                  if e.payload.get("engagement_id") == engagement_id]
    assert {(e.event_type, e.actor) for e in events} == {
        (vocab.ENROLLED, "alice"), (vocab.WITHDRAWN, "bob")}


def test_enrolling_an_engagement_that_does_not_exist_is_refused_by_the_database():
    done = _run(ENROLL, "enroll", "ENG-DOES-NOT-EXIST", "--by", "alice", "--yes")
    assert done.returncode == 1 and "no such engagement" in done.stderr


def test_an_enrollment_whose_audit_record_cannot_be_written_is_not_made(engagement_id):
    """The record is written inside the enrollment's own transaction: a --by that the audit
    whitelist refuses leaves no enrollment behind."""
    done = _run(ENROLL, "enroll", engagement_id, "--by", "alice; DROP TABLE x", "--yes")
    assert done.returncode == 1 and "plain identifier" in done.stderr
    assert not _live(engagement_id)


def test_awaiting_dispatch_says_why_a_skipped_proposal_has_not_run(engagement_id, registry):
    import json

    from tests.test_scheduler_skips import RecordingSandbox

    sup.publish_engagement_policy(engagement_id)
    narrow = sup.register_scope(registry, type="cidr", value="10.96.73.0/30")
    fine = sup.register_scope(registry, type="cidr", value="10.96.73.64/26")
    stuck = sup.approved_proposal(engagement_id, narrow, host="10.96.73.2")
    ran = sup.approved_proposal(engagement_id, fine, host="10.96.73.70")

    before = _run(APPROVALS, "--engagement", engagement_id, "awaiting-dispatch")
    assert before.returncode == 0 and "SKIPPED" not in before.stdout   # nobody has looked yet

    sup.enroll(engagement_id)
    try:
        with sup.running(RecordingSandbox()) as sched:
            assert sched.tick().dispatched == [ran]
    finally:
        sup.withdraw(engagement_id)

    shown = _run(APPROVALS, "--engagement", engagement_id, "awaiting-dispatch")
    assert shown.returncode == 0, shown.stderr
    assert stuck in shown.stdout and ran not in shown.stdout
    assert f"[SKIPPED by the scheduler: {vocab.SCOPE_TOO_NARROW}]" in shown.stdout

    as_json = json.loads(_run(APPROVALS, "--engagement", engagement_id, "--json",
                              "awaiting-dispatch").stdout)
    (row,) = as_json
    assert (row["proposal_id"], row["skip_reason"]) == (stuck, vocab.SCOPE_TOO_NARROW)
