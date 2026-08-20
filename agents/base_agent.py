"""What an agent is allowed to be (§2).

Agents reach the system through the narrow function API in
``control_plane.api.function_api`` and through nothing else. Tool invocation,
shell access, network access and registry writes never appear in an interface
an agent can call — §2 is explicit that an agent able to write the Scope or
Metadata Registry could bypass the Authorization Resolver entirely.

The types here are the contract MVP-0 inherits. When the fakes are replaced by
real models, the model's output has to be parsed into one of these structures
before the control plane sees it, which is what keeps "the AI decided" from
turning into "the AI is trusted": a :class:`ReviewerOpinion` can carry alarm and
nothing else, because those are the only fields it has.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ProposedTask:
    """What a planner produces (§4.2)."""

    goal: str
    target: dict[str, Any]
    action: str
    scope_object_id: str
    priority: int = 0


@dataclass(frozen=True)
class ProposedAction:
    """An Action Proposal as an agent submits it (§4.1).

    ``authorization`` and ``discovery`` are separate fields and stay separate
    all the way down. §8.9/I8: discovery explains how a candidate target was
    found and may at most trigger escalation; authorization must name a scope
    object. Merging them is the v0.2 bug where DNS resolution silently widened
    scope.
    """

    action: str
    target: dict[str, Any]
    authorization: dict[str, Any]
    discovery: dict[str, Any]
    task_id: str | None = None
    resources: tuple[str, ...] = field(default_factory=tuple)
    expected_data: tuple[str, ...] = field(default_factory=tuple)
    writes_data: bool = False
    changes_state: bool = False
    reason: str = ""
    requested_capability_ttl_seconds: int = 60


@dataclass(frozen=True)
class ReviewerOpinion:
    """What a Policy Reviewer may say (§5).

    Every field here is advisory and may only make the outcome stricter. There
    is deliberately no field for "this is safe", no way to name a data class as
    canonical, and no way to assert authorization — an opinion that could say
    those things would be an opinion that could satisfy a prerequisite, which
    is exactly what I6b forbids.

    ``possible_sensitive_data_hint`` keeps the ``_hint`` suffix from §4.1 for
    the same reason: it can raise a concern, never retire one. An empty list
    means the reviewer flagged nothing, not that nothing is sensitive.
    """

    reviewer_id: str
    risk_hint: str = "low"
    possible_sensitive_data_hint: tuple[str, ...] = field(default_factory=tuple)
    semantic_risk_hints: tuple[str, ...] = field(default_factory=tuple)
    recommended_escalation: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "reviewer_id": self.reviewer_id,
            "risk_hint": self.risk_hint,
            "possible_sensitive_data_hint": list(self.possible_sensitive_data_hint),
            "semantic_risk_hints": list(self.semantic_risk_hints),
            "recommended_escalation": self.recommended_escalation,
        }


@runtime_checkable
class PolicyReviewer(Protocol):
    """The seam a real LLM reviewer drops into at MVP-0.

    The control plane calls this and does not care what is behind it. A model
    swapped in here gains no authority it did not already have, because the
    return type is the whole of what it can express.
    """

    def review(
        self, *, proposal: ProposedAction, canonical_target: Any
    ) -> ReviewerOpinion:  # pragma: no cover - protocol
        ...


@runtime_checkable
class Planner(Protocol):
    def plan(self, *, engagement_id: str) -> list[ProposedTask]:  # pragma: no cover
        ...


@runtime_checkable
class Worker(Protocol):
    def propose(self, *, task: ProposedTask) -> ProposedAction:  # pragma: no cover
        ...
