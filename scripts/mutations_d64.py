# ruff: noqa: E501  -- the edits quote source lines verbatim; they must match exactly
"""The mutations of the D64 implementation steps, as runnable checks (see ``mutation_check.py``).

``python scripts/mutations_d64.py --list`` names them. Ids: ``D64-1-*`` for step 1 (ACCEPTANCE 5.74,
the late-result transition), and so on for the steps that follow.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_check import Edit, Mutation, main  # noqa: E402

DISPATCH = "control_plane/orchestrator/dispatch.py"
LATE = ("tests/test_dispatch_late_result.py",)

CATALOGUE = [
    Mutation(
        "D64-1-a", "the stage transition's result is ignored again (the original 5.74)", LATE,
        edits=(Edit(DISPATCH, "    if stages.advance(conn, proposal_id, expected=stages.DISPATCHING, new=stages.RECORDED,\n"
                    "                      detail=detail):\n        return False\n",
                    "    stages.advance(conn, proposal_id, expected=stages.DISPATCHING, new=stages.RECORDED,\n"
                    "                   detail=detail)\n    return False\n"),),
        targets=("test_the_reconciler_first_then_the_result_arrives_late",
                 "test_a_proposal_someone_else_closed_gets_no_result_and_nothing_is_written")),
    Mutation(
        "D64-1-b", "a late result no longer needs the proposal's detail to be unknown_outcome", LATE,
        edits=(Edit(DISPATCH, "              AND stage_detail = :unknown AND dispatch_state = :unknown\n",
                    "              AND dispatch_state = :unknown\n"),),
        targets=("test_which_states_a_result_may_be_recorded_over",)),
    Mutation(
        "D64-1-c", "a late result no longer needs the dispatch state to be unknown_outcome", LATE,
        edits=(Edit(DISPATCH, "              AND stage_detail = :unknown AND dispatch_state = :unknown\n",
                    "              AND stage_detail = :unknown\n"),),
        targets=("test_which_states_a_result_may_be_recorded_over",)),
    Mutation(
        "D64-1-d", "a late result may also overwrite a `closed` proposal", LATE,
        edits=(Edit(DISPATCH, "            WHERE proposal_id = :pid AND pipeline_stage = :recorded\n              AND stage_detail = :unknown",
                    "            WHERE proposal_id = :pid AND pipeline_stage IN (:recorded, 'closed')\n              AND stage_detail = :unknown"),),
        targets=("test_which_states_a_result_may_be_recorded_over",)),
    Mutation(
        "D64-1-e", "the run row is no longer required to be unknown_outcome for a late result", LATE,
        edits=(Edit(DISPATCH, "                only_if_status=UNKNOWN_OUTCOME if late else None,\n",
                    "                only_if_status=None,\n"),),
        targets=("test_a_late_result_needs_the_run_to_be_unknown_too",)),
    Mutation(
        "D64-1-f", "the late result is not audited", LATE,
        edits=(Edit(DISPATCH, "            if late:\n                record_audit(\n                    engagement_id=engagement_id, actor=actor, event_type=LATE_RESULT_EVENT,",
                    "            if False:\n                record_audit(\n                    engagement_id=engagement_id, actor=actor, event_type=LATE_RESULT_EVENT,"),),
        targets=("test_the_reconciler_first_then_the_result_arrives_late",)),
    Mutation(
        "D64-1-g", "a refusal before start is recorded over a proposal someone else moved", LATE,
        edits=(Edit(DISPATCH, "                stages.take(conn, proposal_id, expected=stages.DISPATCHING,\n"
                    "                            new=stages.CLOSED, detail=exc.reason)\n",
                    "                stages.advance(conn, proposal_id, expected=stages.DISPATCHING,\n"
                    "                               new=stages.CLOSED, detail=exc.reason)\n"),),
        targets=("test_a_refusal_before_start_does_not_overwrite_a_proposal_someone_moved",)),
    Mutation(
        "D64-1-h", "a sandbox failure after the reconciler marked the run is treated as a conflict", LATE,
        edits=(Edit(DISPATCH, "                    if stages.stage_of(conn, proposal_id) != (stages.RECORDED, UNKNOWN_OUTCOME):\n",
                    "                    if True:\n"),),
        targets=("test_a_sandbox_failure_after_the_reconciler_marked_the_run_is_not_a_conflict",)),
    Mutation(
        "D64-1-i", "the record forgets to set the dispatch state (stage and state tell two stories)", LATE,
        edits=(Edit(DISPATCH, "            _set_state(conn, proposal_id, status)\n            record_audit(\n"
                    "                engagement_id=engagement_id, actor=actor,\n                event_type=f\"tool_run.{status}\"",
                    "            record_audit(\n"
                    "                engagement_id=engagement_id, actor=actor,\n                event_type=f\"tool_run.{status}\""),),
        targets=("test_the_reconciler_first_then_the_result_arrives_late",)),
]


if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
