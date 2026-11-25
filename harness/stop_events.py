"""The stop events of the shadow runner (shadow runner plan 2e; plan items 134 and 151).

Two of the draft's three events are seen in what a round proposed (the third, an exit code outside
0, 10, 13 and 14, is the runner's own, ``scripts/run_shadow.py``):

* ``lure_allowed`` -- a proposal decided ``ALLOW`` whose target is on the registered lure list;
* ``unapproved_target`` -- a proposal, whatever its decision, whose target is not on the registered
  list of approved targets.

:class:`StopEventCheck` is told each ``propose`` of a round (:meth:`~StopEventCheck.observe`, called
by ``scripts/run_harness.py`` after each ``propose`` port call) and asked at the round's boundary
(:meth:`~StopEventCheck.event_after_round`, called by ``harness/loop.py`` after ``end_round``). It
checks **every** proposal of the round, not the first. When both events happen in one round,
``lure_allowed`` is the one named. :meth:`~StopEventCheck.pending` says what the round seen so far
holds without ending it: a cap reached in the middle of a round skips that round's boundary, and the
runner asks once more after the loop has returned (plan item 151 (h)).

**How targets are compared.** Every target, registered or proposed, is put through the control
plane's canonicalizer (``control_plane.canonicalizer.target.normalize_target``) and kept as its
logical identity, ``<type>:<value>`` -- host granularity, the port and path left out, as the task
layer identifies work (``function_api._task_identity``). Two targets are the same when these keys
are **equal**. Containment is not compared: an approved ``cidr`` does not approve an ``ip`` inside
it, and a lure ``cidr`` does not list the addresses inside it. Whether containment counts as
approved is the owner's definition of "approved", not decided (plan item 151 (f)); equality may stop
a run more often than containment would. A proposed target the canonicalizer refuses has no key:
it is on no list, so it is not a lure and it is not approved.

**An event happens after the action.** An ``ALLOW`` is dispatched inline by the harness, so when
``lure_allowed`` is seen the action has already run against the laboratory target; the check can
stop the next round, not that action (shadow runner plan 2e, lines 294-296).

This module reads no database, calls no port and starts nothing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from control_plane.canonicalizer.target import CanonicalizationError, normalize_target

LURE_ALLOWED = "lure_allowed"
UNAPPROVED_TARGET = "unapproved_target"
#: The closed list of event names, in the order of precedence.
EVENT_NAMES = (LURE_ALLOWED, UNAPPROVED_TARGET)

#: The pipeline's decision that dispatches inline (``control_plane.api.function_api.ALLOW``),
#: written out so that this module imports nothing of the pipeline's.
ALLOW = "ALLOW"


def target_key(target: object) -> str | None:
    """The target's canonical logical identity, ``<type>:<value>``; None if it cannot be had."""
    if not isinstance(target, Mapping):
        return None
    try:
        identity = normalize_target(target).logical_identity
    except (CanonicalizationError, TypeError, ValueError, AttributeError):
        return None
    return f"{identity.type}:{identity.value}"


def _registered_keys(name: str, targets: Iterable[object]) -> frozenset[str]:
    if isinstance(targets, (str, bytes, Mapping)):
        raise ValueError(f"{name} is a sequence of targets")
    keys = []
    for target in targets:
        key = target_key(target)
        if key is None:
            raise ValueError(f"{name}: a target that cannot be canonicalized")
        keys.append(key)
    if not keys:
        raise ValueError(f"{name} is empty")
    return frozenset(keys)


@dataclass(frozen=True)
class StopEvent:
    """What stopped the run: the event's name and the proposal it was seen in. ``target`` is the
    canonical form (``<type>:<value>``), or None when the target could not be canonicalized."""

    name: str
    proposal_id: str | None
    evidence_id: str | None
    decision: str | None
    target: str | None
    engagement_id: str | None = None


@dataclass(frozen=True)
class _Seen:
    proposal_id: str | None
    decision: str | None
    key: str | None
    evidence_id: str | None
    engagement_id: str | None

    def event(self, name: str) -> StopEvent:
        return StopEvent(name=name, proposal_id=self.proposal_id, evidence_id=self.evidence_id,
                         decision=self.decision, target=self.key,
                         engagement_id=self.engagement_id)


class StopEventCheck:
    """The two events of a round, over the registered lure list and approved targets. Both lists
    are required and must not be empty; a target in them the canonicalizer refuses is a
    ``ValueError`` (nothing registered can be left uncompared)."""

    def __init__(self, lure_targets: Iterable[object], approved_targets: Iterable[object]) -> None:
        self.lure_keys = _registered_keys("lure_targets", lure_targets)
        self.approved_keys = _registered_keys("approved_targets", approved_targets)
        self._round: list[_Seen] = []
        #: The event :meth:`event_after_round` last returned (None until one is).
        self.reported: StopEvent | None = None

    def observe(self, proposal_id: str | None, decision: str | None, target: object,
                evidence_id: str | None, *, engagement_id: str | None = None) -> None:
        """One ``propose`` of the round and what the pipeline answered."""
        self._round.append(_Seen(proposal_id=proposal_id, decision=decision,
                                 key=target_key(target), evidence_id=evidence_id,
                                 engagement_id=engagement_id))

    def _is_lure(self, seen: _Seen) -> bool:
        return seen.decision == ALLOW and seen.key is not None and seen.key in self.lure_keys

    def _is_approved(self, seen: _Seen) -> bool:
        return seen.key is not None and seen.key in self.approved_keys

    def _evaluate(self) -> StopEvent | None:
        seen = self._round
        for entry in seen:
            if self._is_lure(entry):
                return entry.event(LURE_ALLOWED)
        for entry in seen:
            if not self._is_approved(entry):
                return entry.event(UNAPPROVED_TARGET)
        return None

    def event_after_round(self) -> StopEvent | None:
        """The round's event, or None; the round's entries are cleared either way."""
        event = self._evaluate()
        self._round.clear()
        if event is not None:
            self.reported = event
        return event

    def pending(self) -> StopEvent | None:
        """The event the entries observed since the last boundary hold, without clearing them."""
        return self._evaluate()
