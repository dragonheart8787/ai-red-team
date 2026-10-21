"""Q1: asking a plan-fit validator whether a task's goal, action and target fit (D68 S5).

The control plane's one place that calls a validator, and it is written for a validator that cannot
be trusted to behave: **anything it raises, and anything it returns that is not a valid answer, is
``not_assessed`` with cause ``failed``**. A validator is a model behind a network call, and an
exception that escaped from it would interrupt ``propose_action`` -- the proposal would be left
at ``received``, no human asked (the Reviewer's local adapter does exactly that on an empty reply:
ACCEPTANCE 5.120). Here the call is wrapped in ``except Exception`` and the adapters' promise not
to raise is not relied on.

``BaseException`` that is not an ``Exception`` (``KeyboardInterrupt``, ``SystemExit``) is
deliberately not caught: a process asked to stop must stop. The proposal is then left at
``received``, coherent, and is resumed by a retry or abandoned by the reconciler -- the pipeline's
ordinary answer to an interruption.

What is shown to the validator is built here from the task's row and the proposal's own identity --
never from the proposal's words. The goal is read by the control plane from the task, not sent by
the agent. The result carries no text: a failure's detail is the exception's *class name*, in the
audit only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from agents.base_agent import (
    GOAL_FIT_VALUES,
    NOT_ASSESSED,
    GoalFitAssessment,
    PlanFitQuery,
)
from control_plane.plan_fit import relation as r

#: Who the system-set assessments come from (no validator was asked).
SYSTEM = "control-plane"


@dataclass(frozen=True)
class GoalFit:
    """An assessment, and what is kept about how it was obtained (audit only, never policy)."""

    assessment: GoalFitAssessment
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def value(self) -> str:
        return self.assessment.goal_fit

    @property
    def cause(self) -> str | None:
        return self.assessment.cause

    def as_hint(self) -> dict[str, Any]:
        """What is stored with the decision beside the task relation, and replayed."""
        return {"goal_fit": self.assessment.goal_fit, "goal_fit_cause": self.assessment.cause}

    def audit_payload(self) -> dict[str, Any]:
        return {**self.as_hint(), "validator_id": self.assessment.validator_id, **self.detail}


def _system(cause: str, **detail: Any) -> GoalFit:
    return GoalFit(GoalFitAssessment(SYSTEM, NOT_ASSESSED, cause), detail)


def input_digest(query: PlanFitQuery) -> str:
    """A hash of what the validator was shown, so a record can be matched with its input without
    keeping the goal's text (model-authored; it may carry a target's words) in the audit."""
    body = json.dumps(
        [query.goal, query.task_action, query.task_target, query.proposal_action,
         query.proposal_target], ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()


def _valid(result: Any) -> bool:
    """An answer the control plane accepts: a real assessment that a *validator* may give -- one of
    the three values, or ``not_assessed`` / ``failed``. ``disabled`` and ``not_applicable`` are the
    system's to say, never a validator's."""
    if not isinstance(result, GoalFitAssessment):
        return False
    if result.goal_fit in GOAL_FIT_VALUES:
        return result.cause is None
    return result.goal_fit == NOT_ASSESSED and result.cause == "failed"


def assess_goal_fit(
    *, validator: Any, relation: r.TaskRelation, task_context: dict[str, Any] | None,
    proposal_action: str, proposal_target: str | None,
) -> GoalFit:
    """The goal-fit assessment for one proposal. Never raises an ``Exception``."""
    if validator is None:
        return _system("disabled")
    if relation.value != r.MATCHES_TASK:
        # Nothing to judge it by: a goal belongs to the task the proposal names, and this proposal
        # is not that task's. The relation already answers.
        return _system("not_applicable")
    if task_context is None:
        return _system("failed", error_type="task_unreadable")

    try:
        query = PlanFitQuery(
            goal=str(task_context["goal"]), task_action=str(task_context["action"]),
            task_target=str(task_context["canonical_target"] or ""),
            proposal_action=proposal_action, proposal_target=proposal_target or "")
        digest = input_digest(query)
    except Exception as exc:  # noqa: BLE001 - the inputs could not be built: no question was asked
        return _system("failed", error_type=type(exc).__name__)

    detail: dict[str, Any] = {"input_digest": digest}
    try:
        result = _ask(validator, query, detail)
    except Exception as exc:  # noqa: BLE001 - a validator that raises did not answer
        detail["error_type"] = type(exc).__name__
        detail.update(_provenance(validator))
        return GoalFit(GoalFitAssessment(SYSTEM, NOT_ASSESSED, "failed"), detail)
    return GoalFit(result, detail)


def _ask(validator: Any, query: PlanFitQuery, detail: dict[str, Any]) -> GoalFitAssessment:
    """The call itself, and the reading of what it returned. Raises whatever goes wrong; the caller
    turns every ``Exception`` into ``failed``. Kept apart so that nothing about the validator -- its
    answer, its call record, its provenance -- is touched outside that ``try``."""
    calls = getattr(validator, "calls", None)
    before = len(calls) if isinstance(calls, list) else None
    result = validator.assess(query=query)
    detail.update(_provenance(validator))
    if before is not None and isinstance(calls, list) and len(calls) > before:
        call = calls[-1]
        detail["call"] = {
            "latency_seconds": round(float(getattr(call, "latency_seconds", 0.0) or 0.0), 3),
            "input_tokens": int(getattr(call, "input_tokens", 0) or 0),
            "output_tokens": int(getattr(call, "output_tokens", 0) or 0),
            "failed": bool(getattr(call, "failed", False)),
        }
    if not _valid(result):
        detail["error_type"] = "invalid_answer"
        return GoalFitAssessment(SYSTEM, NOT_ASSESSED, "failed")
    return result


def _provenance(validator: Any) -> dict[str, Any]:
    """Which validator, which model, which prompt -- so a drift in the rates is attributable
    (design section 5). Optional on a validator; failing to produce it never matters to the
    decision."""
    try:
        got = validator.provenance()
        return {"validator": {k: str(v)[:120] for k, v in dict(got).items()}}
    except Exception:  # noqa: BLE001 - provenance is a record, not an input
        return {}
