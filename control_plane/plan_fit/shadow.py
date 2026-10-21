"""What the plan-fit switches *would* ask for, from what was stored (D68 S6).

Shadow mode is the state both switches are in until S8: the relation and the validator's answer are
computed, stored and audited, and no decision moves. The question S7 has to answer before anything
is enabled is how many extra approvals enabling would cause. That is this module: given a stored
``plan_fit`` it says which approval reasons the policy *would* add under a pair of switch settings.

It is a restatement of the rules in ``policy/rego/authz.rego`` (``approval_reasons``) in Python,
because a report cannot start an OPA process per row. A restatement can drift, so a test runs it
against the real policy over every signal and every switch pair
(``tests/test_plan_fit_shadow.py``): a rule changed in rego and not here fails that test. It reads
a stored value through :func:`relation.policy_signal`, the same function the re-derivation uses, so
an unreadable value is judged the way the policy judges it.

The statistics helpers live here too so that the baseline script and the report agree on what
``k/N (<= x% at 95%)`` means.
"""

from __future__ import annotations

import math
from typing import Any

from agents.base_agent import GOAL_FIT_VALUES
from control_plane.plan_fit import relation as r

WITHOUT_TASK = "proposal_without_task"
OUTSIDE_TASK = "proposal_outside_task"
IMPLAUSIBLE = "plan_implausible"
UNVERIFIED = "plan_unverified"
CHECK_FAILED = "plan_check_failed"
ALL_REASONS = (WITHOUT_TASK, OUTSIDE_TASK, IMPLAUSIBLE, UNVERIFIED, CHECK_FAILED)

_QUIET_NOT_ASSESSED = ("disabled", "not_applicable")


def would_ask(stored: Any, *, task_enforce: bool, goal_enforce: bool) -> tuple[str, ...]:
    """The approval reasons the stored ``plan_fit`` would add. ``stored`` is the value of
    ``reviewer_hints["plan_fit"]``, or ``None`` for a decision with none (from before S2): which
    asks for nothing, as in the policy."""
    if stored is None:
        return ()
    signal = r.policy_signal(stored)
    reasons: list[str] = []
    if task_enforce:
        relation = signal["task_relation"]
        if relation == r.NO_TASK:
            reasons.append(WITHOUT_TASK)
        elif relation != r.MATCHES_TASK:
            reasons.append(OUTSIDE_TASK)
    if goal_enforce and "goal_fit" in signal:
        value, cause = signal["goal_fit"], signal["goal_fit_cause"]
        if value == GOAL_FIT_VALUES[0]:                   # plausible
            pass
        elif value == "not_assessed" and cause in _QUIET_NOT_ASSESSED:
            pass
        elif value == GOAL_FIT_VALUES[1]:                 # implausible
            reasons.append(IMPLAUSIBLE)
        elif value == GOAL_FIT_VALUES[2]:                 # insufficient_context
            reasons.append(UNVERIFIED)
        else:
            reasons.append(CHECK_FAILED)
    return tuple(reasons)


def upper95(k: int, n: int) -> float:
    """An upper 95% bound on a rate seen as ``k`` of ``n``: the rule of three for ``k == 0``,
    Wilson's upper end otherwise. A bound, not an estimate."""
    if n <= 0:
        return 1.0
    if k <= 0:
        return min(1.0, 3.0 / n)
    if k >= n:
        return 1.0
    z, p = 1.96, k / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + margin) / (1 + z * z / n))


def rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "upper95": round(upper95(k, n), 4) if n else None}


def fmt(value: dict[str, Any] | None) -> str:
    if not value or not value.get("n"):
        return "0/0"
    return f"{value['k']}/{value['n']} (<= {100 * value['upper95']:.1f}% at 95%)"
