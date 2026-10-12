"""The reconciler's closed vocabularies: what it can decide to do, and why (D64 §1.6, §4).

One place, so that the plan, the act half (6c) and the audit vocabulary (6d) cannot drift apart. The
stage names are written out here and **not** imported from ``control_plane.orchestrator.stages``:
the plan side imports nothing of the orchestrator (D64 §2.2a, pinned by an AST test), and a test
holds these literals equal to ``stages.py`` and the transitions to the database's CHECK constraints.
"""

from __future__ import annotations

STAGE_RECEIVED = "received"
STAGE_DECIDED = "decided"
STAGE_APPROVED = "approved"
STAGE_CAPABILITY_ISSUED = "capability_issued"
STAGE_DISPATCHING = "dispatching"
STAGE_RECORDED = "recorded"
STAGE_CLOSED = "closed"
STAGE_ABANDONED = "abandoned"

#: the stages the reconciler looks at -- the stage list of migration 0023's function and policy
STUCK_STAGES = (STAGE_RECEIVED, STAGE_DECIDED, STAGE_APPROVED, STAGE_CAPABILITY_ISSUED,
                STAGE_DISPATCHING)

# --- what the plan can ask the act half to do
# ------------------------------------------------------
#: a proposal's stage moves, by one conditional UPDATE
ABANDON = "abandon"                       # received -> abandoned
CLOSE = "close"                           # decided/approved/capability_issued -> closed
MARK_UNKNOWN_OUTCOME = "mark_unknown_outcome"   # dispatching -> recorded / unknown_outcome
#: Docker
KILL_CONTAINER = "kill_container"
REMOVE_CONTAINER = "remove_container"
REMOVE_PROXY = "remove_proxy"
REMOVE_NETWORK = "remove_network"
#: host files
UNLINK_FILE = "unlink_file"

PROPOSAL_ACTIONS = (ABANDON, CLOSE, MARK_UNKNOWN_OUTCOME)
DOCKER_ACTIONS = (KILL_CONTAINER, REMOVE_CONTAINER, REMOVE_PROXY, REMOVE_NETWORK)
ACTION_KINDS = (*PROPOSAL_ACTIONS, *DOCKER_ACTIONS, UNLINK_FILE)

# --- reason codes, per kind --------------------------------------------------------------------
UNDECIDED_PAST_GRACE = "undecided_past_grace"
ABANDONED_AFTER_DECISION = "abandoned_after_decision"
CAPABILITY_NOT_LIVE = "capability_not_live"
APPROVAL_EXPIRED = "approval_expired"
APPROVAL_REVOKED = "approval_revoked"
ENGAGEMENT_KILLED = "engagement_killed"
UNKNOWN_OUTCOME = "unknown_outcome"
OVERRAN_DEADLINE = "overran_deadline"
RUN_FINISHED = "run_finished"
NO_RUN_ROW_PAST_GRACE = "no_run_row_past_grace"
OWNER_RUN_ENDED = "owner_run_ended"
IDLE_SWEEP = "idle_sweep"

REASONS: dict[str, tuple[str, ...]] = {
    ABANDON: (UNDECIDED_PAST_GRACE,),
    CLOSE: (ABANDONED_AFTER_DECISION, CAPABILITY_NOT_LIVE, APPROVAL_EXPIRED, APPROVAL_REVOKED,
            ENGAGEMENT_KILLED),
    MARK_UNKNOWN_OUTCOME: (UNKNOWN_OUTCOME,),
    KILL_CONTAINER: (OVERRAN_DEADLINE,),
    REMOVE_CONTAINER: (RUN_FINISHED, NO_RUN_ROW_PAST_GRACE),
    REMOVE_PROXY: (OWNER_RUN_ENDED, OVERRAN_DEADLINE),
    REMOVE_NETWORK: (IDLE_SWEEP,),
    UNLINK_FILE: ("credential_mount", "tls_leaf"),
}

#: the stage each proposal action starts from and ends in (the act half's compare-and-set)
PROPOSAL_TRANSITIONS: dict[tuple[str, str], tuple[str, str, str]] = {
    # (kind, reason) -> (expected stage, new stage, stage_detail)
    (ABANDON, UNDECIDED_PAST_GRACE): (STAGE_RECEIVED, STAGE_ABANDONED, UNDECIDED_PAST_GRACE),
    (CLOSE, ABANDONED_AFTER_DECISION): (STAGE_DECIDED, STAGE_CLOSED, ABANDONED_AFTER_DECISION),
    (CLOSE, CAPABILITY_NOT_LIVE): (STAGE_CAPABILITY_ISSUED, STAGE_CLOSED, CAPABILITY_NOT_LIVE),
    (CLOSE, APPROVAL_EXPIRED): (STAGE_APPROVED, STAGE_CLOSED, APPROVAL_EXPIRED),
    (CLOSE, APPROVAL_REVOKED): (STAGE_APPROVED, STAGE_CLOSED, APPROVAL_REVOKED),
    (CLOSE, ENGAGEMENT_KILLED): (STAGE_APPROVED, STAGE_CLOSED, ENGAGEMENT_KILLED),
    (MARK_UNKNOWN_OUTCOME, UNKNOWN_OUTCOME): (STAGE_DISPATCHING, STAGE_RECORDED, UNKNOWN_OUTCOME),
}

# --- reports: things seen and deliberately left alone
# ------------------------------------------------
BUDGET_UNREADABLE = "budget_unreadable"
CAPABILITY_MISSING = "capability_missing"
APPROVAL_MISSING = "approval_missing"
NO_OWNER_LABEL = "no_owner_label"
NO_RUN_ID_LABEL = "no_run_id_label"
RUN_UNKNOWN = "run_unknown"
UNEXPECTED_STATE = "unexpected_state"
NOT_A_REGULAR_FILE = "not_a_regular_file"
FOREIGN_OWNER = "foreign_owner"
NAME_MISMATCH = "name_mismatch"
RESULT_TRUNCATED = "result_truncated"

REPORT_REASONS = (BUDGET_UNREADABLE, CAPABILITY_MISSING, APPROVAL_MISSING, NO_OWNER_LABEL,
                  NO_RUN_ID_LABEL, RUN_UNKNOWN, UNEXPECTED_STATE, NOT_A_REGULAR_FILE,
                  FOREIGN_OWNER, NAME_MISMATCH, RESULT_TRUNCATED)

#: what a report is about
SUBJECTS = ("proposal", "container", "network", "file", "result")
