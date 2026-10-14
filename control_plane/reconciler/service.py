"""The reconciler loop (D64): lock, observe, plan, act, audit -- in that order and no other.

This is the only module that imports both halves (the reader's scope on one side, ``act`` on the
other) and it hands one to the other nothing but plain data (``tests/test_reconciler_structure.py``
pins that). The rules are the scheduler's, for the same reason -- conservative until D58-6's failure
ladder exists:

* ``state-only`` takes the singleton lock, audits what it did, and stops on an audit record it
  cannot write, a lost connection, an unreachable Docker, a lost lock or any unexpected exception,
  each with its own exit code; nothing is retried or reconnected. ``dry-run`` takes no lock, writes
  nothing -- not even an audit record -- and only says what it would do;
* **a proposal transition is audited in the transaction that makes it** (act's ``record`` hook): the
  record exists exactly when the change committed. **A kill, a removal or an unlink is announced
  first** (act's ``intend`` hook: ``reconciler.action_intended``, committed before the call) and
  audited after it was verified (``on_verified``), never before; an intent with no result is a
  process that died in between and is listed by ``audit.query.unresolved_reconciler_intents``. An
  audit record that fails to write makes the service stop at the end of the pass: for a proposal
  nothing was changed; for an irreversible act no call was made, or the action happened and the stop
  is what says so;
* an irreversible action that **failed** is not tried again on the same object by this process for
  ``retry_after_failure_s``, so a persistently failing object costs one intent and one call per
  period, not per pass;
* **a backlog is worked off in bounded passes** (D64 pre-deletion item 6): a pass reads at most
  ``max_pages`` pages of stuck proposals and carries out at most ``max_actions_per_pass`` actions;
  what is left is planned again by the next pass. A pass that was truncated or limited and still
  got nothing done makes the wait before the next one double, up to ``backoff_max_s``; any other
  pass resets it. A pass that gets something done never slows down;
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
from control_plane.reconciler import act, emit, observe, vocab
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.lock import SingletonLock
from control_plane.reconciler.model import US, Observation, name_hash_n
from control_plane.reconciler.outcome import DONE, FAILED, Result
from control_plane.reconciler.plan import plan as make_plan
from control_plane.state.db import reconciler_reader_scope

#: the daily cap on removals for a range conflict counts this long back
DAY_US = 86_400 * US

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
    #: actions left alone this pass: the same object failed less than ``retry_after_failure_s`` ago
    held_back: int = 0
    #: actions planned and not carried out this pass because ``max_actions_per_pass`` was reached
    limited: int = 0
    #: the whole plan, uncapped: what the pass saw (the command line prints it all)
    plan: Any = None


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
        self._failed_at: dict[tuple[str, str], float] = {}
        self._backoff_steps = 0
        #: when (host clock, microseconds) this process removed each blocking network, by the
        #: number its name spells: the daily cap's memory (plan rule 5)
        self._conflict_removed: dict[int, list[int]] = {}

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
                                     "planned": planned,
                                     "enabled": sorted(self.settings.enabled)},
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
                    stop_event.wait(self.next_wait(report, interval))
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
            actions, held_back = self._not_recently_failed(plan.actions)
            limited = max(0, len(actions) - self.th.max_actions_per_pass)
            actions = actions[:self.th.max_actions_per_pass]
            results = act.carry_out(
                actions, self.settings, th=self.th, client=self.client,
                directory=self.directory, expected_uid=self.expected_uid,
                on_verified=self._audit if self.audits else None,
                record=self._record if self.audits else None,
                intend=self._intend if self.audits else None,
                wall_clock_us=self._wall_clock_us)
            if self.audits:
                self._after(results)
                self._assert_lock()
        except BaseException as exc:
            raise _translate(exc) from exc
        report = PassReport(
            planned=_planned(plan), outcomes=Counter(r.outcome for r in results), results=results,
            reports=len(plan.reports), held_back=held_back, limited=limited, plan=plan,
            truncated=any(r.reason_code == vocab.RESULT_TRUNCATED for r in plan.reports))
        if report.truncated or report.limited:
            log.warning("reconciler: a backlog (read truncated: %s, actions not carried out: %d)",
                        report.truncated, report.limited)
        return report

    def next_wait(self, report: PassReport, interval: float) -> float:
        """The wait before the next pass: ``interval``, or -- after a pass that was truncated or
        limited and got nothing done -- twice the last wait, up to ``backoff_max_s``. A pass that
        got something done, or had no backlog, resets it."""
        backlog = report.truncated or report.limited > 0
        if backlog and report.outcomes.get(DONE, 0) == 0:
            self._backoff_steps += 1
            return min(interval * 2 ** self._backoff_steps, max(interval, self.th.backoff_max_s))
        self._backoff_steps = 0
        return interval

    def _not_recently_failed(self, actions) -> tuple[tuple, int]:
        """Drop the irreversible actions whose object this process failed on less than
        ``retry_after_failure_s`` ago (a dry run writes nothing and makes no call: nothing to
        hold)."""
        if not self.audits:
            return tuple(actions), 0
        now = self._monotonic()
        kept, held = [], 0
        for action in actions:
            failed = self._failed_at.get(self._attempt_key(action))
            if (action.kind in emit.IRREVERSIBLE_KINDS and failed is not None
                    and now - failed < self.th.retry_after_failure_s):
                held += 1
                continue
            kept.append(action)
        return tuple(kept), held

    @staticmethod
    def _attempt_key(action) -> tuple[str, str]:
        return (action.kind, emit.intent_for(action)[4]) if action.kind in emit.IRREVERSIBLE_KINDS \
            else (action.kind, action.subject_id)

    def _assert_lock(self) -> None:
        if not self.lock.held():
            raise StopService(emit.STOP_LOCK_LOST)

    def conflict_removals_24h(self, now_us: int) -> dict[int, int]:
        """Removals of each blocking network (by the number its name spells) this process made in
        the 24 hours before ``now_us``; older ones are forgotten."""
        horizon = now_us - DAY_US
        self._conflict_removed = {h: [t for t in times if t > horizon]
                                  for h, times in self._conflict_removed.items()}
        return {h: len(t) for h, t in self._conflict_removed.items() if t}

    def _observe(self) -> Observation:
        with reconciler_reader_scope() as conn:
            obs = observe.observe(conn, self.client, directory=self.directory,
                                  expected_uid=self.expected_uid,
                                  clock_us=self._wall_clock_us, max_pages=self.th.max_pages,
                                  conflict_window_s=self.th.network_conflict_window_s)
        # This process's memory of how long each network has been idle: first seen idle *now* if
        # it has not been seen before, so nothing is removed in the first idle period.
        idle_now = {n.network_id for n in obs.networks if not n.attached}
        self._idle_seen = {nid: self._idle_seen.get(nid, obs.host_now_us) for nid in idle_now}
        obs = dataclasses.replace(
            obs, conflict_removals_24h=self.conflict_removals_24h(obs.host_now_us),
            networks=tuple(
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
            networks=(), files=(), conflicts=())

    # ------------------------------------------------------------------ audit
    def _record(self, conn, action) -> None:
        """The hook ``act.carry_out`` calls inside a proposal transition's transaction: the
        transition's own record, committed or rolled back with it."""
        try:
            event_type, payload, engagement_id, subject_type, subject_id = (
                emit.for_proposal_action(action))
            emit.emit_in_transaction(conn, event_type, payload, engagement_id=engagement_id,
                                     subject_type=subject_type, subject_id=subject_id)
        except Exception:
            self._audit_failed = True
            raise

    def _intend(self, action) -> None:
        """The hook called right before an irreversible call: the intent, committed first."""
        try:
            event_type, payload, engagement_id, subject_type, subject_id = emit.intent_for(action)
            emit.emit(event_type, payload, engagement_id=engagement_id,
                      subject_type=subject_type, subject_id=subject_id)
        except Exception:
            self._audit_failed = True
            raise

    def _audit(self, result: Result) -> None:
        """The hook ``act.carry_out`` calls for a verified result, and for no other. A proposal
        transition was already recorded in its own transaction."""
        if result.audited:
            return
        try:
            event_type, payload, engagement_id, subject_type, subject_id = emit.for_result(result)
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
            self._window_passes += 1
            for result in results:
                if (result.outcome == DONE and result.action.kind == vocab.REMOVE_NETWORK
                        and result.action.reason_code == vocab.RANGE_CONFLICT
                        and (blocked := name_hash_n(result.action.name or "")) is not None):
                    self._conflict_removed.setdefault(blocked, []).append(self._wall_clock_us())
                if result.outcome != FAILED:
                    continue
                if result.action.kind in emit.IRREVERSIBLE_KINDS:
                    self._failed_at[self._attempt_key(result.action)] = self._monotonic()
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
