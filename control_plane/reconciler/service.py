"""The reconciler loop (D64): lock, observe, plan, act, audit -- in that order and no other.

This is the only module that imports both halves (the reader's scope on one side, ``act`` on the
other) and it hands one to the other nothing but plain data (``tests/test_reconciler_structure.py``
pins that). The rules are the scheduler's, for the same reason -- conservative until D58-6's failure
ladder exists:

* ``state-only`` takes the singleton lock, audits what it did, and stops on an audit record it
  cannot write, a lost connection, an unreachable Docker, a lost lock or any unexpected exception,
  each with its own exit code; nothing is retried or reconnected. ``dry-run`` takes no lock, writes
  nothing -- not even an audit record -- and only says what it would do;
* **an action is audited after it was verified, never before** (act's ``on_verified`` hook), and an
  audit record that fails to write makes the service stop at the end of the pass: the action it
  describes happened, and the stop is what says so;
* a failed action is audited once per ``(object, kind, reason)`` per process lifetime and counted
  after that; every ``summary_period_s`` a **failure summary** says how many of what failed, if any
  did. A restart reports once more -- stated, not hidden (D64-11);
* a network is judged idle by how long *this process* has seen it idle, so a freshly started
  reconciler removes no network in its first idle period.

**Start order.** Reconciling before scheduling is an operator convention (``--once`` before the
scheduler starts, a ``systemd`` ``After=``). Nothing here or in the scheduler makes one wait for the
other; they hold different locks and may run together (docs/D64_RECONCILER_DESIGN.md §3.3).
"""

from __future__ import annotations

import dataclasses
import logging
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from docker.errors import DockerException
from sqlalchemy.exc import InterfaceError, OperationalError

from control_plane.audit.logger import AuditWriteError
from control_plane.reconciler import act, emit, observe
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.lock import SingletonLock
from control_plane.reconciler.model import Observation
from control_plane.reconciler.outcome import FAILED, Result
from control_plane.reconciler.plan import plan as make_plan
from control_plane.state.db import reconciler_reader_scope

log = logging.getLogger("cyberorch.reconciler")

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_LOCK_HELD = 2
EXIT_AUDIT_FAILED = 3
EXIT_DB_LOST = 4
EXIT_DOCKER_LOST = 5
EXIT_LOCK_LOST = 6
EXIT_CONFIG_REFUSED = 8
EXIT_CODE_OF_STOP = {
    emit.STOP_SIGNAL: EXIT_OK, emit.STOP_UNEXPECTED: EXIT_UNEXPECTED,
    emit.STOP_AUDIT_FAILED: EXIT_AUDIT_FAILED, emit.STOP_DB_LOST: EXIT_DB_LOST,
    emit.STOP_DOCKER_LOST: EXIT_DOCKER_LOST, emit.STOP_LOCK_LOST: EXIT_LOCK_LOST,
}


class StopService(Exception):  # noqa: N818 - a control-flow signal, not an error condition
    """The service must stop: ``reason`` is one of ``emit.STOP_REASONS`` (or ``lock_held``)."""

    def __init__(self, reason: str, exit_code: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.exit_code = exit_code if exit_code is not None else EXIT_CODE_OF_STOP.get(
            reason, EXIT_UNEXPECTED)


def _translate(exc: BaseException) -> StopService:
    if isinstance(exc, StopService):
        return exc
    if isinstance(exc, AuditWriteError | emit.PayloadRejected):
        return StopService(emit.STOP_AUDIT_FAILED)
    if isinstance(exc, OperationalError | InterfaceError):
        return StopService(emit.STOP_DB_LOST)
    if isinstance(exc, FileNotFoundError | PermissionError | NotADirectoryError):
        return StopService(emit.STOP_UNEXPECTED)        # the configured directory, not the daemon
    if isinstance(exc, DockerException | OSError):
        return StopService(emit.STOP_DOCKER_LOST)
    return StopService(emit.STOP_UNEXPECTED)


@dataclass
class PassReport:
    planned: dict[str, int] = field(default_factory=dict)
    outcomes: Counter = field(default_factory=Counter)
    results: list[Result] = field(default_factory=list)
    reports: int = 0
    truncated: bool = False


def _planned(plan) -> dict[str, int]:
    counts: Counter = Counter(f"{a.kind}:{a.reason_code}" for a in plan.actions)
    for report in plan.reports:
        counts[f"report:{report.reason_code}"] += 1
    return dict(sorted(counts.items()))


class Reconciler:
    def __init__(
        self, *, settings: act.Settings, th: Thresholds, client: Any, directory: str,
        expected_uid: int, lock: SingletonLock | None = None, instance_id: str | None = None,
        watchdog_interval: float = 2.0, only_engagements: frozenset[str] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock_us: Callable[[], int] = lambda: time.time_ns() // 1000,
    ):
        self.settings, self.th, self.client = settings, th, client
        self.directory, self.expected_uid = directory, expected_uid
        self.lock = lock or SingletonLock()
        self.instance_id = instance_id or f"RECON-{uuid.uuid4().hex[:10]}"
        self.watchdog_interval = watchdog_interval
        self.only_engagements = only_engagements
        self._monotonic, self._wall_clock_us = monotonic, wall_clock_us
        self.started = False
        self._stopped = False
        self._idle_seen: dict[str, int] = {}
        self._reported: set[tuple[str, str, str]] = set()
        self._window: Counter = Counter()
        self._window_passes = 0
        self._window_started = monotonic()
        self._audit_failed = False
        self._files_removed: Counter = Counter()

    @property
    def audits(self) -> bool:
        """Only a pass that changes things writes audit records."""
        return self.settings.mode is act.Mode.STATE_ONLY

    # ------------------------------------------------------------------ lifecycle
    def begin(self) -> None:
        """Take the lock, look once without acting, record ``reconciler.started``."""
        if not self.audits:                         # a dry run: no lock, no audit, no state
            self.started = True
            return
        try:
            got = self.lock.acquire()
        except Exception as exc:  # noqa: BLE001
            raise _translate(exc) from exc
        if not got:
            try:
                emit.emit(emit.START_REFUSED, {"instance_id": self.instance_id,
                                               "reason_code": emit.LOCK_HELD},
                          subject_type="reconciler", subject_id=self.instance_id)
            except Exception:  # noqa: BLE001 - refusing to start needs no further record
                pass
            raise StopService(emit.LOCK_HELD, EXIT_LOCK_HELD)
        try:
            self.lock.start_watchdog(self.watchdog_interval)
            planned = _planned(make_plan(self._observe(), self.th))
            emit.emit(emit.STARTED, {"instance_id": self.instance_id, "mode": "state_only",
                                     "planned": planned},
                      subject_type="reconciler", subject_id=self.instance_id)
        except BaseException as exc:
            self.lock.close()
            raise _translate(exc) from exc
        self.started = True

    def finish(self, reason: str) -> None:
        """Record ``reconciler.stopped`` (best effort: the audit may be what failed); let go."""
        if self._stopped:
            return
        self._stopped = True
        if self.started and self.audits and reason in emit.STOP_REASONS:
            try:
                emit.emit(emit.STOPPED, {"instance_id": self.instance_id, "reason_code": reason},
                          subject_type="reconciler", subject_id=self.instance_id)
            except Exception:  # noqa: BLE001 - an unclean stop reads as started-without-stopped
                pass
        self.lock.close()

    def serve(self, *, interval: float = 60.0, max_passes: int | None = None,
            stop_event: threading.Event | None = None,
            on_pass: Callable[[PassReport], None] | None = None) -> int:
        """Reconcile until stopped; returns the process exit code."""
        stop_event = stop_event or threading.Event()
        try:
            self.begin()
            passes = 0
            while not stop_event.is_set() and (max_passes is None or passes < max_passes):
                report = self.pass_once()
                if on_pass is not None:
                    on_pass(report)
                passes += 1
                if max_passes is None or passes < max_passes:
                    stop_event.wait(interval)
        except BaseException as exc:  # noqa: BLE001
            stop = _translate(exc)
            self.finish(stop.reason)
            return stop.exit_code
        self.finish(emit.STOP_SIGNAL)
        return EXIT_OK

    # ------------------------------------------------------------------ one pass
    def pass_once(self) -> PassReport:
        """One pass: observe, plan, act, audit. Raises ``StopService``."""
        try:
            if self.audits:
                self._assert_lock()
            plan = make_plan(self._observe(), self.th)
            results = act.carry_out(
                plan.actions, self.settings, th=self.th, client=self.client,
                directory=self.directory, expected_uid=self.expected_uid,
                on_verified=self._audit if self.audits else None,
                wall_clock_us=self._wall_clock_us)
            if self.audits:
                self._after(results)
                self._assert_lock()
        except BaseException as exc:
            raise _translate(exc) from exc
        report = PassReport(planned=_planned(plan), outcomes=Counter(r.outcome for r in results),
                            results=results, reports=len(plan.reports))
        return report

    def _assert_lock(self) -> None:
        if not self.lock.held():
            raise StopService(emit.STOP_LOCK_LOST)

    def _observe(self) -> Observation:
        with reconciler_reader_scope() as conn:
            obs = observe.observe(conn, self.client, directory=self.directory,
                                  expected_uid=self.expected_uid,
                                  clock_us=self._wall_clock_us)
        # This process's memory of how long each network has been idle: first seen idle *now* if
        # it has not been seen before, so nothing is removed in the first idle period.
        idle_now = {n.network_id for n in obs.networks if not n.attached}
        self._idle_seen = {nid: self._idle_seen.get(nid, obs.host_now_us) for nid in idle_now}
        obs = dataclasses.replace(obs, networks=tuple(
            dataclasses.replace(n, idle_seen_since_us=self._idle_seen.get(n.network_id))
            for n in obs.networks))
        if self.only_engagements is None:
            return obs
        # A pass limited to named engagements (a cautious first run): their proposals and the
        # containers they own. Networks and files belong to no engagement, so they are left out.
        keep = self.only_engagements
        return dataclasses.replace(
            obs, rows=tuple(r for r in obs.rows if r.engagement_id in keep),
            containers=tuple(c for c in obs.containers if c.owner in keep),
            networks=(), files=())

    # ------------------------------------------------------------------ audit
    def _audit(self, result: Result) -> None:
        """The hook ``act.carry_out`` calls for a verified result, and for no other."""
        try:
            event = emit.for_result(result)
            if event is None:
                self._files_removed[result.action.reason_code] += 1
                return
            event_type, payload, engagement_id, subject_type, subject_id = event
            emit.emit(event_type, payload, engagement_id=engagement_id,
                      subject_type=subject_type, subject_id=subject_id)
        except Exception:
            self._audit_failed = True
            raise

    def _after(self, results: list[Result]) -> None:
        """What is written once the pass has acted: removed files (counted), failed actions (once
        each), the summary (when its period has passed). An audit record that cannot be written
        stops the service -- after the pass, so the rest of it is not left half-reported."""
        try:
            for kind, count in sorted(self._files_removed.items()):
                emit.emit(emit.FILES_REMOVED, {"kind": kind, "count": count})
            self._files_removed.clear()
            self._window_passes += 1
            for result in results:
                if result.outcome != FAILED:
                    continue
                event_type, payload, engagement_id, subject_type = emit.failure(result)
                self._window[f"{payload['kind']}:{payload['reason_code']}"] += 1
                key = (payload["subject_id"], payload["kind"], payload["reason_code"])
                if key in self._reported:
                    continue
                self._reported.add(key)
                emit.emit(event_type, payload, engagement_id=engagement_id,
                          subject_type=subject_type, subject_id=payload["subject_id"])
            self._summarise()
        except Exception:
            self._audit_failed = True
            raise
        if self._audit_failed:                      # the hook failed inside act.carry_out
            raise StopService(emit.STOP_AUDIT_FAILED)

    def _summarise(self) -> None:
        now = self._monotonic()
        if now - self._window_started < self.th.summary_period_s:
            return
        if self._window:
            emit.emit(emit.FAILURE_SUMMARY, {"instance_id": self.instance_id,
                                             "passes": self._window_passes,
                                             "failed": dict(sorted(self._window.items()))},
                      subject_type="reconciler", subject_id=self.instance_id)
        self._window.clear()
        self._window_passes = 0
        self._window_started = now
