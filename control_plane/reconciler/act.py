"""The act half (D64 §2.2a, §1.7): carry out what the plan asked, verify it, and say what happened.

The plan hands over plain ``Action`` values; nothing here decides whether an action is warranted.
What this half adds is **safety at the moment of acting**:

* **two modes, and five switches that are off.** ``Mode.DRY_RUN`` changes nothing at all -- no
  connection is opened, no Docker call made -- and says what it would have done. ``Mode.STATE_ONLY``
  carries out the proposal transitions and *skips* every action that kills, removes or deletes a
  Docker object or a host file (outcome ``skipped_deletions_off``) unless its category is in
  ``Settings.enabled``: ``kill``, ``container``, ``proxy``, ``network``, ``file`` (``flags.py``,
  ACCEPTANCE 5.92). ``enabled`` is empty by default, no setting or environment variable sets it, and
  the one place that builds it from an operator's words is ``settings_for`` -- from the command
  line's ``--enable``, confirmed by a person at a terminal, and refusing ``network`` and ``file`` in
  this version;
* **a state change is one conditional ``UPDATE``** inside ``engagement_scope(engagement_id)``, a
  compare-and-set on the stage *and* on the ``stage_updated_at`` the plan observed. Zero rows moved
  means someone else got there first: ``lost_race``, nothing is audited, nothing is retried. When
  the caller hands in ``record`` (the service always does), the change's own audit record is
  written **in the same transaction**: both commit or neither does, so there is no state change
  without its record and no record without its change (D64 item 4);
* **verification, independent of the call's own reply** (§1.7): after the commit a new transaction
  re-reads the stage; after a kill the container is inspected; after a removal the object must be
  gone. Only a verified action is ``done``, and only a verified action reaches ``on_verified`` --
  the hook the audit trail is written from (6d). A reply of "done" that did not do it is ``failed``;
* **deletions act by full id, after a fresh inspect** (``act_docker``, ``act_files``): the id, the
  owner and run labels, and the object's kind must still be what the plan saw, or the action is
  ``changed_since_plan`` and nothing is touched. When the caller hands in ``intend``, the intent is
  written **after** that last check and **immediately before** the irreversible call; if it cannot
  be written, no call is made (``failed / audit_failed``).

One action failing never stops the others. The reason a failure is reported is a fixed code, never
the text of an exception (which can carry ids, paths or document content). The module never calls
``propose_action``, ``dispatch_*`` or ``dispatch_approved`` (I7): it re-runs nothing.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from control_plane.orchestrator import stages
from control_plane.reconciler import act_docker, act_files, flags, vocab
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import (
    AUDIT_FAILED,
    DB_ERROR,
    DONE,
    DRY_RUN,
    FAILED,
    INVALID_ACTION,
    LOST_RACE,
    NOT_CHANGED_AFTER_UPDATE,
    SKIPPED_OFF,
    Result,
)
from control_plane.state.db import engagement_scope

log = logging.getLogger("cyberorch.reconciler")


class Mode(StrEnum):
    DRY_RUN = "dry_run"
    STATE_ONLY = "state_only"


#: the names an operator can pass; there is deliberately no third
MODE_NAMES = {"dry-run": Mode.DRY_RUN, "state-only": Mode.STATE_ONLY}


@dataclass(frozen=True)
class Settings:
    """How a pass acts. ``enabled`` is the set of irreversible-action categories switched on
    (``flags.CATEGORIES``); empty unless a person said otherwise at a terminal."""

    mode: Mode
    enabled: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.enabled <= flags.EVERYTHING:
            raise ValueError(f"not categories: {sorted(self.enabled - flags.EVERYTHING)}")
        if self.enabled and self.mode is Mode.DRY_RUN:
            raise ValueError("a dry run changes nothing, so it cannot also enable anything")


def settings_for(name: str, enable: Iterable[str] = ()) -> Settings:
    """The settings an operator's words select: a mode name and, for ``state-only``, the categories
    (``flags.FlagRefused`` for any that is unknown or not available in this version)."""
    try:
        mode = MODE_NAMES[name]
    except KeyError:
        raise ValueError(f"unknown mode {name!r}; the modes are {sorted(MODE_NAMES)}") from None
    chosen = flags.validate(enable)
    return Settings(mode, enabled=chosen)


# --- the three statements that change a proposal -------------------------------------------------
CLOSE_SQL = """
    UPDATE action_proposals
    SET pipeline_stage = :new, stage_detail = :detail, stage_updated_at = now(), updated_at = now()
    WHERE proposal_id = :pid AND pipeline_stage = :expected AND stage_updated_at = :planned
    RETURNING proposal_id
"""
MARK_UNKNOWN_SQL = """
    UPDATE action_proposals
    SET pipeline_stage = :new, stage_detail = :detail, dispatch_state = 'unknown_outcome',
        stage_updated_at = now(), updated_at = now()
    WHERE proposal_id = :pid AND pipeline_stage = :expected AND stage_updated_at = :planned
    RETURNING proposal_id
"""
RUNS_SQL = """
    UPDATE tool_runs SET status = 'unknown_outcome'
    WHERE proposal_id = :pid AND status IN ('dispatching', 'running')
"""
RUNS_LEFT_SQL = """
    SELECT count(*) FROM tool_runs
    WHERE proposal_id = :pid AND status IN ('dispatching', 'running')
"""

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _timestamp(microseconds: int) -> datetime:
    """The exact instant: an integer of microseconds, not a float, so the compare-and-set matches
    the stored value to the last digit."""
    return _EPOCH + timedelta(microseconds=microseconds)


class _RecordFailed(Exception):  # noqa: N818 - internal: the transition's own audit record
    """The audit record of a transition could not be written; the transaction rolls back."""


def carry_out(
    actions: Iterable[Action], settings: Settings, *, th: Thresholds | None = None,
    client: Any = None, directory: str | None = None, expected_uid: int | None = None,
    on_verified: Callable[[Result], None] | None = None,
    record: Callable[[Any, Action], None] | None = None,
    intend: Callable[[Action], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    wall_clock_us: Callable[[], int] = lambda: time.time_ns() // 1000,
) -> list[Result]:
    """Carry out ``actions`` in the order given (the plan put them in execution order).

    ``on_verified`` is called once, after verification, for each ``done`` result and for none
    other; if it raises, the failure is logged by type and the pass goes on.

    ``record(conn, action)`` is called for a proposal transition **inside its transaction**, after
    the conditional ``UPDATE`` moved a row and before the commit; if it raises, the transaction
    rolls back and the result is ``failed / audit_failed`` (the proposal is unchanged).
    ``intend(action)`` is called for a kill, a removal or an unlink right before the call; if it
    raises, no call is made.
    """
    results: list[Result] = []
    for action in actions:
        result = _one(action, settings, th, client, directory, expected_uid, sleep, clock,
                      wall_clock_us, record, intend)
        results.append(result)
        if result.outcome == DONE and on_verified is not None:
            try:
                on_verified(result)
            except Exception as exc:                                  # noqa: BLE001
                log.error("reconciler: audit hook failed (%s) after %s",
                          type(exc).__name__, result.action.kind)
    return results


def _one(action, settings, th, client, directory, expected_uid, sleep, clock, wall_clock_us,
         record=None, intend=None):
    if action.kind not in vocab.ACTION_KINDS or action.reason_code not in vocab.REASONS.get(
            action.kind, ()):
        return Result(action, FAILED, INVALID_ACTION)
    if settings.mode is Mode.DRY_RUN:
        return Result(action, DRY_RUN)
    if action.kind in vocab.PROPOSAL_ACTIONS:
        return _transition(action, record)
    if flags.CATEGORY_OF[action.kind] not in settings.enabled:
        return Result(action, SKIPPED_OFF)
    if th is None:
        return Result(action, FAILED, INVALID_ACTION)
    if action.kind == vocab.UNLINK_FILE:
        return act_files.sweep(action, directory=directory, expected_uid=expected_uid, th=th,
                                client=client, wall_clock_us=wall_clock_us, intend=intend)
    return act_docker.perform(action, client=client, th=th, sleep=sleep, clock=clock,
                              intend=intend)


# --- proposals -----------------------------------------------------------------------------------

def _transition(action: Action, record: Callable[[Any, Action], None] | None = None) -> Result:
    transition = vocab.PROPOSAL_TRANSITIONS.get((action.kind, action.reason_code))
    if (transition is None or action.engagement_id is None
            or action.planned_stage_updated_us is None or action.expected_stage != transition[0]):
        return Result(action, FAILED, INVALID_ACTION)
    expected, new, detail = transition
    planned = _timestamp(action.planned_stage_updated_us)
    try:
        with engagement_scope(action.engagement_id) as conn:
            moved = _move(conn, action, expected, new, detail, planned)
            if moved and record is not None:
                try:
                    record(conn, action)          # the change's own record: same transaction
                except Exception as exc:          # noqa: BLE001
                    log.error("reconciler: audit record failed (%s) before %s",
                              type(exc).__name__, action.kind)
                    raise _RecordFailed from exc
        if not moved:
            return Result(action, LOST_RACE)
        # After the commit, a new transaction: the stage and its reason are what was asked for.
        with engagement_scope(action.engagement_id) as conn:
            if stages.stage_of(conn, action.subject_id) != (new, detail):
                return Result(action, FAILED, NOT_CHANGED_AFTER_UPDATE)
            if action.kind == vocab.MARK_UNKNOWN_OUTCOME and conn.execute(
                    text(RUNS_LEFT_SQL), {"pid": action.subject_id}).scalar_one():
                return Result(action, FAILED, NOT_CHANGED_AFTER_UPDATE)
    except _RecordFailed:
        return Result(action, FAILED, AUDIT_FAILED)       # rolled back: nothing was changed
    except SQLAlchemyError:
        return Result(action, FAILED, DB_ERROR)
    return Result(action, DONE, audited=record is not None)


def _move(conn, action: Action, expected: str, new: str, detail: str, planned: datetime) -> bool:
    pid = action.subject_id
    if action.kind == vocab.ABANDON:
        return stages.abandon(conn, pid, stage_updated_at=planned)
    params = {"pid": pid, "new": new, "detail": detail, "expected": expected, "planned": planned}
    if action.kind == vocab.CLOSE:
        return conn.execute(text(CLOSE_SQL), params).scalar_one_or_none() is not None
    moved = conn.execute(text(MARK_UNKNOWN_SQL), params).scalar_one_or_none() is not None
    if moved:                       # the runs of a proposal declared unknown are unknown too
        conn.execute(text(RUNS_SQL), {"pid": pid})
    return moved

