"""The scheduler loop (D62): wires ``decide``, ``execute``, ``emit``, ``state`` and the lock.

This is the only module that imports both the reader side and the execution side, and it passes
only ids and closed codes between them (``tests/test_scheduler_structure.py`` pins that). Every rule
here is conservative on purpose, as a temporary simplification until D58-6's failure ladder exists:

* an audit record that cannot be written means the decision is **not carried out** and the service
  stops;
* a lost database connection, an unreachable Docker, a lost lock or any unexpected exception stops
  the service with a distinct non-zero exit code -- nothing is retried or reconnected;
* a proposal is dispatched at most once per tick, and a proposal that is *skipped* is never counted
  as dispatched: the "still approved after dispatch" check (exit 7) applies only to a proposal that
  was actually handed to ``dispatch_approved``.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.exc import InterfaceError, OperationalError

from control_plane.audit.logger import AuditWriteError
from control_plane.scheduler import decide, emit, execute, state, vocab
from control_plane.scheduler.lock import SingletonLock


class StopService(Exception):  # noqa: N818 - a control-flow signal, not an error condition
    """The service must stop: ``reason`` is one of ``vocab.STOP_REASONS`` (or ``lock_held``)."""

    def __init__(self, reason: str, exit_code: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.exit_code = exit_code if exit_code is not None else vocab.EXIT_CODE_OF_STOP.get(
            reason, vocab.EXIT_UNEXPECTED)


@dataclass
class TickReport:
    dispatched: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    deferred: list[str] = field(default_factory=list)
    resumed: list[str] = field(default_factory=list)


def _translate(exc: BaseException) -> StopService:
    if isinstance(exc, StopService):
        return exc
    if isinstance(exc, AuditWriteError):
        return StopService(vocab.STOP_AUDIT_FAILED)
    if isinstance(exc, (OperationalError, InterfaceError)):
        return StopService(vocab.STOP_DB_LOST)
    return StopService(vocab.STOP_UNEXPECTED)


class Scheduler:
    def __init__(self, *, sandbox=None, lock: SingletonLock | None = None,
                 watchdog_interval: float = 2.0, instance_id: str | None = None):
        self.sandbox = sandbox
        self.lock = lock or SingletonLock()
        self.watchdog_interval = watchdog_interval
        self.instance_id = instance_id or f"SCHED-{uuid.uuid4().hex[:10]}"
        self.started = False
        self._stopped = False

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Take the lock, observe the enrolled engagements, record ``scheduler.started``."""
        try:
            got = self.lock.acquire()
        except Exception as exc:  # noqa: BLE001
            raise _translate(exc) from exc
        if not got:
            try:
                emit.emit(vocab.START_REFUSED, {"instance_id": self.instance_id,
                                                "reason_code": vocab.LOCK_HELD},
                          subject_type="scheduler", subject_id=self.instance_id)
            except Exception:  # noqa: BLE001 - refusing to start needs no further record
                pass
            raise StopService(vocab.LOCK_HELD, vocab.EXIT_LOCK_HELD)
        try:
            self.lock.start_watchdog(self.watchdog_interval)
            enrolled = decide.read_enrollment()
            seen = [decide.observe(e) for e in enrolled]
            emit.emit(vocab.STARTED, {
                "instance_id": self.instance_id,
                "enrolled": enrolled,
                "missing": [o.engagement_id for o in seen if not o.exists],
                "dispatching": {o.engagement_id: o.dispatching for o in seen if o.exists},
                "capability_issued": {o.engagement_id: o.capability_issued
                                      for o in seen if o.exists},
                "approved_waiting": {o.engagement_id: len(o.waiting) for o in seen if o.exists},
                "approved_redispatch": {
                    o.engagement_id: len({w.proposal_id for w in o.waiting} & o.decided)
                    for o in seen if o.exists},
            }, subject_type="scheduler", subject_id=self.instance_id)
        except BaseException as exc:
            self.lock.close()
            raise _translate(exc) from exc
        self.started = True

    def stop(self, reason: str) -> None:
        """Record ``scheduler.stopped`` (best effort: the audit may be what failed); let go."""
        if self._stopped:
            return
        self._stopped = True
        if self.started and reason in vocab.STOP_REASONS:
            try:
                emit.emit(vocab.STOPPED, {"instance_id": self.instance_id, "reason_code": reason},
                          subject_type="scheduler", subject_id=self.instance_id)
            except Exception:  # noqa: BLE001 - an unclean stop reads as started-without-stopped
                pass
        self.lock.close()

    def run(self, *, interval: float = 5.0, max_ticks: int | None = None,
            stop_event: threading.Event | None = None) -> int:
        """Serve until stopped; returns the process exit code."""
        stop_event = stop_event or threading.Event()
        try:
            self.start()
            ticks = 0
            while not stop_event.is_set() and (max_ticks is None or ticks < max_ticks):
                self.tick()
                ticks += 1
                if max_ticks is None or ticks < max_ticks:
                    stop_event.wait(interval)
        except BaseException as exc:  # noqa: BLE001
            stop = _translate(exc)
            self.stop(stop.reason)
            return stop.exit_code
        self.stop(vocab.STOP_SIGNAL)
        return vocab.EXIT_OK

    # ------------------------------------------------------------------ one tick
    def tick(self) -> TickReport:
        """One level-triggered pass over every enrolled engagement. Raises ``StopService``."""
        report = TickReport()
        try:
            self._assert_lock()
            for engagement_id in decide.read_enrollment():
                self._serve(engagement_id, report)
        except BaseException as exc:
            raise _translate(exc) from exc
        return report

    def _assert_lock(self) -> None:
        if not self.lock.held():
            raise StopService(vocab.STOP_LOCK_LOST)

    def _serve(self, engagement_id: str, report: TickReport) -> None:
        obs = decide.observe(engagement_id)
        plan = decide.plan(obs, now=datetime.now(UTC))

        for transition in plan.transitions:
            self._transition(transition)
            (report.deferred if transition.kind == "deferred" else report.resumed).append(
                engagement_id)
        for skip in plan.skips:
            if self._record_skip(skip.engagement_id, skip.proposal_id, skip.reason_code,
                                 obs.skipped):
                report.skipped.append(skip.proposal_id)

        for candidate in plan.candidates:
            self._assert_lock()
            # Re-read the engagement right before acting, so a pause or kill that landed since the
            # observation is a deferral on the next tick, not a refusal that closes the proposal.
            if not decide.servable_now(engagement_id):
                break
            prepared = execute.prepare(engagement_id, candidate.proposal_id)
            if prepared.skip:
                if self._record_skip(engagement_id, candidate.proposal_id, prepared.skip,
                                     obs.skipped):
                    report.skipped.append(candidate.proposal_id)
                continue                      # a skip is not a dispatch: nothing below applies
            if not execute.docker_reachable():
                raise StopService(vocab.STOP_DOCKER_LOST)
            self._dispatch(candidate, prepared, report)

    def _transition(self, transition: decide.Transition) -> None:
        eid = transition.engagement_id
        if transition.kind == "deferred":
            emit.emit(vocab.DEFERRED, {"reason_code": transition.reason_code,
                                       "waiting_count": transition.waiting_count},
                      engagement_id=eid, subject_type="engagement", subject_id=eid)
            state.record_engagement(eid, vocab.DEFERRED_STATE, transition.reason_code)
        else:
            emit.emit(vocab.RESUMED, {"deferred_seconds": transition.deferred_seconds,
                                      "waiting_count": transition.waiting_count},
                      engagement_id=eid, subject_type="engagement", subject_id=eid)
            state.record_engagement(eid, vocab.SERVED, None)

    def _record_skip(self, eid: str, proposal_id: str, reason: str, known: dict[str, str]) -> bool:
        """A skip is recorded once; the audit event is written before the state row.

        True if this call recorded it (the first time, or with a different reason)."""
        if known.get(proposal_id) == reason:
            return False
        emit.emit(vocab.SKIPPED, {"proposal_id": proposal_id, "reason_code": reason},
                  engagement_id=eid, subject_type="action_proposal", subject_id=proposal_id)
        state.record_proposal(eid, proposal_id, vocab.SKIPPED_STATE, reason)
        return True

    def _dispatch(self, candidate: decide.Candidate, prepared: execute.Prepared,
                  report: TickReport) -> None:
        eid, pid = candidate.engagement_id, candidate.proposal_id
        # The decision is recorded first: if it cannot be, it is not carried out.
        emit.emit(vocab.DISPATCHED, {"proposal_id": pid, "reason_code": vocab.APPROVED_AND_IDLE},
                  engagement_id=eid, subject_type="action_proposal", subject_id=pid)
        state.record_proposal(eid, pid, vocab.DISPATCH_DECIDED, vocab.APPROVED_AND_IDLE)
        execute.dispatch(eid, pid, prepared, sandbox=self.sandbox)
        report.dispatched.append(pid)
        # Only a proposal that was handed over is held to this: it must have left `approved`.
        if decide.stage_of(eid, pid) == "approved":
            raise StopService(vocab.STOP_NOT_ADVANCED)
        self._assert_lock()
