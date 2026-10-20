"""The scripted plan-fit validators (D68 Q1, S4): what CI uses, and what proves the kernel does not
depend on a model being right.

No model is behind any of these. They are the ``fake`` backend of
``selection.build_plan_fit_validator`` and the default, for the reason the Reviewer's is: an
unconfigured checkout must not reach a model.
"""

from __future__ import annotations

from agents.base_agent import (
    GOAL_FIT_VALUES,
    NOT_ASSESSED,
    GoalFitAssessment,
    PlanFitQuery,
)


class ScriptedPlanFit:
    """Answers with the values it is given in order, repeating the last; records its queries."""

    validator_id = "scripted-plan-fit"

    def __init__(self, *values: str) -> None:
        values = values or ("plausible",)
        for value in values:
            if value not in GOAL_FIT_VALUES:
                raise ValueError(
                    f"a scripted validator answers from {GOAL_FIT_VALUES}, not {value!r}")
        self._values = values
        self.queries: list[PlanFitQuery] = []

    def assess(self, *, query: PlanFitQuery) -> GoalFitAssessment:
        self.queries.append(query)
        value = self._values[min(len(self.queries), len(self._values)) - 1]
        return GoalFitAssessment(self.validator_id, value)


class HonestFakePlanFit(ScriptedPlanFit):
    """The default ``fake`` backend: it finds everything plausible, which adds no caution and so
    changes no decision -- an unconfigured checkout behaves as one without the validator."""

    validator_id = "honest-fake-plan-fit"


class AdversarialFakePlanFit(ScriptedPlanFit):
    """A validator that lies: ``plausible`` for every triple, however mismatched.

    The control that makes the kernel's claim testable. A fooled or lying validator can only fail to
    add friction -- ``plausible`` is read by no rule -- so the decision with this validator is the
    decision without one.
    """

    validator_id = "adversarial-fake-plan-fit"

    def __init__(self) -> None:
        super().__init__("plausible")


class UnavailableFakePlanFit:
    """A validator that cannot answer: every call is ``not_assessed`` / ``failed``."""

    validator_id = "unavailable-fake-plan-fit"

    def __init__(self) -> None:
        self.queries: list[PlanFitQuery] = []

    def assess(self, *, query: PlanFitQuery) -> GoalFitAssessment:
        self.queries.append(query)
        return GoalFitAssessment(self.validator_id, NOT_ASSESSED, "failed")
