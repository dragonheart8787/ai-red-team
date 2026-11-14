"""D69 H5a1 (a2): what the loop writes as a task's ``result_summary``, and nothing else.

``complete_task`` stores any string. The harness therefore builds the string itself, from a
closed vocabulary, and never copies anything a model, a tool or an exception wrote: not
``ActionOutcome.failure`` (which can carry free text -- ``function_api.py:589`` puts the Worker's
target string into it, ``:606`` an adapter's message, ``dispatch.py:482`` an exception's text),
not ``deny_reasons`` text, nothing (plan items 55 and 56).

Three states say whether an action ran, judged by the two ids and **not** by ``decision``:

* both ``run_id`` and ``evidence_id`` -> ``executed``;
* only ``run_id`` -> ``unknown_outcome``: a run row exists and no evidence was recorded, so the
  tool may have run. It is not "not executed" and v0 does not retry it (plan item 65);
* neither -> ``not_executed``.

:func:`build_summary` turns an outcome into one closed string:

* executed or unknown_outcome: that word, whatever the decision and the failure;
* not executed and ``ALLOW``: ``not_executed``;
* not executed and ``DENY`` or ``HUMAN_APPROVAL``: the decision, and ``:<token>`` when there is
  a failure; a failure that is in the vocabulary is that token, one that is not is ``other``.

The vocabulary is :data:`VOCABULARY`. Its 16 refusal codes are copied from
``control_plane.orchestrator.dispatch.REFUSAL_CODES``; this module does not import that one (the
harness takes the loop's inputs from the outcome, not from the dispatcher), and a test compares
the two so that a code added there and not here fails.
"""

from __future__ import annotations

from typing import Any

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_HUMAN_APPROVAL = "HUMAN_APPROVAL"
DECISIONS = (DECISION_ALLOW, DECISION_DENY, DECISION_HUMAN_APPROVAL)

STATE_EXECUTED = "executed"
STATE_UNKNOWN_OUTCOME = "unknown_outcome"
STATE_NOT_EXECUTED = "not_executed"

TOKEN_NOT_RUN = "not_run"
TOKEN_OTHER = "other"

#: The codes the pipeline itself puts in ``ActionOutcome.failure`` (``function_api.py``,
#: ``approved_dispatch.py`` and the reasons of ``dispatch.py``), plus ``unknown_outcome`` and
#: ``budget_exhausted`` (plan item 66).
FIXED_CODES = (
    "capability_refused", "approval_revalidation_failed", "capability_missing", "abandoned",
    "dispatch_in_progress_or_unknown_outcome", "dedup_hit", "tool_run_timed_out",
    "not_claimable", "capability_not_live", "engagement_not_active", "unbuildable_plan",
    "no_adapter_for_action", "egress_proxy_required", "repo_fetch_failed",
    "stage_moved_before_record", "unknown_proposal", "not_approved", "approval_missing",
    "unknown_outcome", "budget_exhausted",
)

#: ``dispatch.REFUSAL_CODES``, copied.
REFUSAL_CODES = (
    "sandbox_not_started", "docker_unreachable", "tool_image_missing", "container_start_refused",
    "network_unavailable", "network_in_use_by_another_engagement",
    "network_range_conflicts_with_another_network", "tool_command_not_executable",
    "deadline_helper_unavailable", "deadline_helper_unsupported_architecture",
    "deadline_helper_unpinned", "deadline_helper_unreadable", "deadline_helper_missing",
    "deadline_helper_hash_mismatch", "deadline_helper_not_executable",
    "deadline_helper_path_in_use",
)

LOOP_TOKENS = (TOKEN_NOT_RUN, STATE_NOT_EXECUTED, TOKEN_OTHER)

VOCABULARY = DECISIONS + FIXED_CODES + REFUSAL_CODES + LOOP_TOKENS

#: Every string :func:`is_valid_summary` accepts: each token of the vocabulary alone,
#: ``executed``, and ``<DENY|HUMAN_APPROVAL>:<token>``.
VALID_SUMMARIES = frozenset(
    {STATE_EXECUTED}
    | set(VOCABULARY)
    | {f"{d}:{t}" for d in (DECISION_DENY, DECISION_HUMAN_APPROVAL) for t in VOCABULARY}
)

KEY_CONFLICT_REASON = "idempotency_key_reused_with_a_different_request"


def _present(value: object, name: str) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, str):
        return True
    raise ValueError(f"{name} is a string or empty, not {type(value).__name__}")


def executed_state(run_id: str | None, evidence_id: str | None) -> str:
    """``executed``, ``unknown_outcome`` or ``not_executed``, from the two ids only."""
    has_run = _present(run_id, "run_id")
    has_evidence = _present(evidence_id, "evidence_id")
    if has_run and has_evidence:
        return STATE_EXECUTED
    if has_run:
        return STATE_UNKNOWN_OUTCOME
    if has_evidence:
        raise ValueError("an evidence id without a run id is not a state the pipeline produces")
    return STATE_NOT_EXECUTED


def failure_token(failure: object) -> str | None:
    """``None`` for no failure, the failure itself when it is in the vocabulary, else ``other``."""
    if failure is None or failure == "":
        return None
    if isinstance(failure, str) and failure in VOCABULARY:
        return failure
    return TOKEN_OTHER


def build_summary(outcome: Any) -> str:
    """The closed ``result_summary`` of ``outcome`` (``decision``, ``failure``, ``run_id``,
    ``evidence_id`` are read; nothing else is)."""
    decision = outcome.decision
    if decision not in DECISIONS:
        raise ValueError(f"not a decision: {decision!r}")
    state = executed_state(outcome.run_id, outcome.evidence_id)
    if state == STATE_EXECUTED:
        return STATE_EXECUTED
    if state == STATE_UNKNOWN_OUTCOME:
        return STATE_UNKNOWN_OUTCOME
    if decision == DECISION_ALLOW:
        return STATE_NOT_EXECUTED
    token = failure_token(outcome.failure)
    if token is None:
        return decision
    return f"{decision}:{token}"


def is_valid_summary(summary: object) -> bool:
    """Whether ``summary`` is a string of the closed set."""
    return isinstance(summary, str) and summary in VALID_SUMMARIES


def is_key_conflict(outcome: Any) -> bool:
    """Whether the pipeline refused the call because its idempotency key names other work.
    That is a bug in the harness itself (plan item 67): a stop for a fault, code 12."""
    return KEY_CONFLICT_REASON in tuple(outcome.deny_reasons or ())
