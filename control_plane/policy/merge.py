"""Policy constraint algebra (§4.5).

    Effective Policy =
        Baseline Global Snapshot   (frozen when the engagement was created)
      ∩ Emergency Overlay          (may tighten at any time, globally)
      ∩ Customer Snapshot
      ∩ Engagement Snapshot

The subtlety this module exists for is what "this layer did not set that field"
means. Treating unset as a literal empty set breaks in opposite directions
depending on the constraint: ``intersect(global_allow, [], customer_allow)`` is
empty, so switching on an Emergency Overlay would deny an entire engagement,
while ``actions.get(key, DENY)`` turns "no opinion" into "forbidden". Both are
bugs, and both look reasonable in isolation.

So every constraint carries its own neutral element — the value that means
"this layer adds no restriction" (§4.5):

    ==============  =========================  ==========
    constraint      neutral element            operation
    ==============  =========================  ==========
    scope_allow     UNIVERSE (not [])          ∩
    scope_deny      ∅                          ∪
    data_deny       ∅                          ∪
    rate_limit      ∞                          min
    actions         INHERIT (not a boolean)    see below
    ==============  =========================  ==========

``task_relation_enforce`` (D68 P1) and ``goal_fit_enforce`` (D68 Q1) are not in the table because
they are not constraints on an action: each is a switch that decides whether the policy reads one
signal about a proposal (its relation to its task; whether its task's goal, action and target fit).
Their neutral element is ``False`` and they merge by OR, so a layer that says nothing, or ``false``,
adds no restriction and no layer can turn off what another turned on. Only a layer can turn one
*on*. :data:`ENFORCE_SWITCHES` names them, and every place that handles one handles both.

Action policy resolution is DENY-dominant: any layer that says DENY wins
outright, regardless of position; otherwise any layer saying ALLOW wins; if
every layer is INHERIT the answer is DENY (fail-closed, I10). The §4.5 prose
also describes "the first non-INHERIT value from the outside in", which
contradicts both the code in the same section and I2 — under that reading an
inner Engagement layer could ALLOW something an outer Global layer had DENIED,
which is precisely the permission expansion I2 forbids. DENY-dominant is the
resolved semantics.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

ALLOW = "ALLOW"
DENY = "DENY"

#: The two D68 switches. A new one is added here and in :class:`PolicyLayer`,
#: :class:`EffectivePolicy` and ``merge_policy`` / ``_combine``; a test fails if one is missed.
ENFORCE_SWITCHES = ("task_relation_enforce", "goal_fit_enforce")


class Sentinel:
    """A neutral element. Distinct from every real value, including empty ones."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return self.name

    def __str__(self) -> str:
        return self.name


#: scope_allow when a layer expresses no opinion: everything, not nothing.
UNIVERSE = Sentinel("UNIVERSE")
#: action policy when a layer expresses no opinion. Not a boolean, on purpose.
INHERIT = Sentinel("INHERIT")

#: Outermost to innermost. Order matters for readability and for the audit
#: record; DENY-dominance means it does not decide the outcome.
LAYER_ORDER = ("baseline_global", "emergency_overlay", "customer", "engagement")


class EmergencyOverlayError(ValueError):
    """The Emergency Overlay tried to relax something."""


def goal_fit_actions_of(value: Any) -> frozenset[str]:
    """The action classes a stored document lists for Q1, read strictly (DP-15).

    Anything that is not a list of well-formed class names is read as *no class*: a damaged or
    hand-written value can only mean "ask about nothing", never "ask about something". Publication
    refuses such a document; this refuses to read one that got in another way.
    """
    from control_plane.plan_fit.classes import valid_action_name

    if not isinstance(value, (list, tuple)):
        return frozenset()
    if not all(valid_action_name(item) for item in value):
        return frozenset()
    return frozenset(value)


@dataclass(frozen=True)
class PolicyLayer:
    """One layer of the policy pack.

    Every field defaults to its neutral element, so a layer that mentions only
    what it cares about constrains only that.
    """

    name: str
    scope_allow: frozenset[str] | Sentinel = UNIVERSE
    scope_deny: frozenset[str] = field(default_factory=frozenset)
    data_deny: frozenset[str] = field(default_factory=frozenset)
    rate_limit: float = math.inf
    actions: Mapping[str, str] = field(default_factory=dict)
    task_relation_enforce: bool = False
    goal_fit_enforce: bool = False
    #: DP-15: the action classes Q1 may be asked about. Union across layers; empty by default.
    goal_fit_actions: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_document(cls, name: str, document: Mapping[str, Any] | None) -> PolicyLayer:
        """Build a layer from a stored JSONB policy document.

        An absent key becomes the neutral element. A key present but explicitly
        null is treated the same way: both mean "no opinion", and distinguishing
        them would be a distinction nobody writing a policy intends to draw.
        """
        doc = document or {}

        scope_allow: frozenset[str] | Sentinel = UNIVERSE
        if doc.get("scope_allow") is not None:
            scope_allow = frozenset(doc["scope_allow"])

        rate_limit = doc.get("rate_limit")

        return cls(
            name=name,
            scope_allow=scope_allow,
            scope_deny=frozenset(doc.get("scope_deny") or ()),
            data_deny=frozenset(doc.get("data_deny") or ()),
            rate_limit=math.inf if rate_limit is None else float(rate_limit),
            actions={
                k: v for k, v in (doc.get("actions") or {}).items() if v != str(INHERIT)
            },
            # Only a real ``true`` turns it on. (A string "false" is truthy; publication refuses
            # anything but a boolean, and this refuses to read one.)
            task_relation_enforce=doc.get("task_relation_enforce") is True,
            goal_fit_enforce=doc.get("goal_fit_enforce") is True,
            goal_fit_actions=goal_fit_actions_of(doc.get("goal_fit_actions")),
        )


@dataclass(frozen=True)
class EffectivePolicy:
    """The merged result. This is what OPA is given as ``input.policy``."""

    scope_allow: frozenset[str] | Sentinel
    scope_deny: frozenset[str]
    data_deny: frozenset[str]
    rate_limit: float
    actions: Mapping[str, str]
    task_relation_enforce: bool = False
    goal_fit_enforce: bool = False
    goal_fit_actions: frozenset[str] = field(default_factory=frozenset)

    def action_decision(self, action: str) -> str:
        """Resolve one action, including one never mentioned by any layer.

        An unmentioned action is DENY: fail-closed is the only safe reading of
        silence in an authorization system (I10).
        """
        return self.actions.get(action, DENY)

    def as_dict(self) -> dict[str, Any]:
        return {
            # UNIVERSE is serialized as a marker string rather than a list, so
            # Rego can tell "unconstrained" from "an allow list that happens to
            # be empty" — the same distinction this module exists to preserve.
            "scope_allow": (
                str(UNIVERSE)
                if isinstance(self.scope_allow, Sentinel)
                else sorted(self.scope_allow)
            ),
            "scope_deny": sorted(self.scope_deny),
            "data_deny": sorted(self.data_deny),
            # JSON has no infinity. null means "no limit", which Rego reads as
            # the neutral element rather than as a limit of zero.
            "rate_limit": None if math.isinf(self.rate_limit) else self.rate_limit,
            "actions": dict(self.actions),
            "task_relation_enforce": self.task_relation_enforce,
            "goal_fit_enforce": self.goal_fit_enforce,
            "goal_fit_actions": sorted(self.goal_fit_actions),
        }


def validate_emergency_overlay(document: Mapping[str, Any] | None) -> None:
    """Reject an overlay that would relax anything (§4.5).

    The database enforces this too, as a CHECK constraint. It is repeated here
    because the overlay is the one layer that can be pushed globally, at speed,
    while engagements are already running — the moment when a mistake is least
    likely to be caught by review and most likely to matter.
    """
    doc = document or {}
    if "scope_allow" in doc:
        raise EmergencyOverlayError(
            "emergency overlay may not carry scope_allow: it can only tighten"
        )
    for action, decision in (doc.get("actions") or {}).items():
        if decision == ALLOW:
            raise EmergencyOverlayError(
                f"emergency overlay may not ALLOW {action!r}: it can only tighten"
            )
    for switch in ENFORCE_SWITCHES:
        if switch in doc and doc[switch] is not True:
            # false is a no-op under the OR merge, so it could not relax anything; it is refused all
            # the same, because an overlay that says "false" reads as a relaxation to its reader.
            raise EmergencyOverlayError(
                f"emergency overlay may only turn {switch} on (true): it can only tighten"
            )


def intersect_allow(
    values: Iterable[frozenset[str] | Sentinel],
) -> frozenset[str] | Sentinel:
    """Intersect only the layers that actually set an allow list.

    ``UNIVERSE ∩ A = A``. With every layer at UNIVERSE the result is UNIVERSE —
    unconstrained, not empty. This is the §4.5 bug in one function: folding an
    unset layer in as ``[]`` would deny everything the moment any layer stayed
    silent.
    """
    explicit = [v for v in values if not isinstance(v, Sentinel)]
    if not explicit:
        return UNIVERSE
    result = explicit[0]
    for item in explicit[1:]:
        result = result & item
    return result


def resolve_action(decisions: Sequence[str | Sentinel]) -> str:
    """DENY-dominant resolution over one action across all layers."""
    explicit = [d for d in decisions if not isinstance(d, Sentinel) and d != str(INHERIT)]
    if DENY in explicit:
        return DENY
    if ALLOW in explicit:
        return ALLOW
    return DENY  # every layer INHERIT — fail closed


def merge_policy(
    baseline_global: PolicyLayer,
    emergency_overlay: PolicyLayer,
    customer: PolicyLayer,
    engagement: PolicyLayer,
) -> EffectivePolicy:
    """Merge the four layers into the effective policy.

    Positional, not a list, because the four layers are not interchangeable:
    the overlay has different rules from the rest, and a signature that accepts
    "some layers" invites calling it with the wrong number of them.
    """
    layers = (baseline_global, emergency_overlay, customer, engagement)

    # Every action any layer mentions. Actions nobody mentions are resolved on
    # demand by EffectivePolicy.action_decision, which denies them.
    action_keys: set[str] = set()
    for layer in layers:
        action_keys.update(layer.actions)

    return EffectivePolicy(
        scope_allow=intersect_allow(layer.scope_allow for layer in layers),
        scope_deny=frozenset().union(*(layer.scope_deny for layer in layers)),
        data_deny=frozenset().union(*(layer.data_deny for layer in layers)),
        # min over an iterable, not min(*iterable): the latter raises on a
        # single layer, and rate limits are exactly where one layer is common.
        rate_limit=min(layer.rate_limit for layer in layers),
        actions={
            key: resolve_action([layer.actions.get(key, INHERIT) for layer in layers])
            for key in sorted(action_keys)
        },
        task_relation_enforce=any(layer.task_relation_enforce for layer in layers),
        goal_fit_enforce=any(layer.goal_fit_enforce for layer in layers),
        goal_fit_actions=frozenset().union(*(layer.goal_fit_actions for layer in layers)),
    )
