"""Dispatch state machine (§4.1, §8.8, I7).

    QUEUED → DISPATCHING → RUNNING → SUCCEEDED / FAILED
                    │
                    └── crash ──▶ UNKNOWN_OUTCOME   (never auto-retried)

§8.8 downgraded I7 from "exactly-once side effects" to something a distributed
system can actually promise. The window it names is real: the control plane
hands an action to the tool gateway, the target receives and executes it, and
the control plane dies before recording the result. On restart it does not know
whether the action happened.

The wrong repair is to assume failure and retry — that turns an unknown into a
second execution of something with side effects. So a dispatch interrupted
between DISPATCHING and a recorded result goes to UNKNOWN_OUTCOME and stays
there until a reconciler learns better or a human decides. Not every tool can
be asked after the fact; when it cannot be, the state persists and escalates.
It is a worse operational experience and an honest one.

Idempotent Dispatch is the part that *is* guaranteed: one
``request_idempotency_key`` is dispatched at most once by the control plane,
enforced by a conditional UPDATE rather than a read followed by a write.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit
from control_plane.dedup.fingerprint import execution_fingerprint
from control_plane.evidence.store import record_evidence
from tool_gateway.adapters import nmap
from tool_gateway.sandbox import DockerSandbox, SandboxResult, SandboxUnavailable

QUEUED = "queued"
DISPATCHING = "dispatching"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
UNKNOWN_OUTCOME = "unknown_outcome"

# States a dispatch can be interrupted in. Anything found here after a restart
# is unresolved, not failed.
IN_FLIGHT = (DISPATCHING, RUNNING)


class DispatchError(RuntimeError):
    """The dispatch could not be started."""


@dataclass(frozen=True)
class DispatchOutcome:
    dispatched: bool
    run_id: str | None
    state: str
    evidence_id: str | None = None
    reason: str | None = None
    result: SandboxResult | None = None


def claim_for_dispatch(conn: Connection, proposal_id: str) -> bool:
    """Move a proposal QUEUED → DISPATCHING, exactly once (I7).

    One conditional UPDATE. Reading the state and then writing it would let two
    workers both observe QUEUED and both proceed, which is the duplicate
    dispatch the invariant exists to prevent.
    """
    claimed = conn.execute(
        text("""
            UPDATE action_proposals SET dispatch_state = :dispatching, updated_at = now()
            WHERE proposal_id = :pid AND dispatch_state = :queued
            RETURNING proposal_id
        """),
        {"pid": proposal_id, "queued": QUEUED, "dispatching": DISPATCHING},
    ).scalar_one_or_none()
    return claimed is not None


def _set_state(conn: Connection, proposal_id: str, state: str) -> None:
    conn.execute(
        text("UPDATE action_proposals SET dispatch_state = :s, updated_at = now() "
             "WHERE proposal_id = :pid"),
        {"pid": proposal_id, "s": state},
    )


def find_cached_run(
    conn: Connection, fingerprint: str
) -> Mapping[str, Any] | None:
    """A completed, still-fresh run with the same fingerprint (§7).

    Exact match only. §1.2(c) and §7 both refuse automatic coverage inference
    for MVP: deciding that a broader scan subsumes a narrower one, and getting
    the lattice wrong, skips work that should have happened.
    """
    return conn.execute(
        text("""
            SELECT run_id, status, fresh_until FROM tool_runs
            WHERE execution_fingerprint = :fp
              AND status = :succeeded
              AND fresh_until IS NOT NULL
              AND fresh_until > now()
            ORDER BY finished_at DESC LIMIT 1
        """),
        {"fp": fingerprint, "succeeded": SUCCEEDED},
    ).mappings().one_or_none()


def dispatch_scan(
    conn: Connection,
    *,
    engagement_id: str,
    proposal_id: str,
    capability,
    target: str,
    actor: str,
    sandbox: DockerSandbox | None = None,
    network_allowlist: list[str] | None = None,
    execution_context: Mapping[str, Any] | None = None,
    fresh_for_seconds: int = 1800,
) -> DispatchOutcome:
    """Run one scan and record run, evidence and state transitions.

    The capability supplies the constraints and the budget; the sandbox
    supplies the network boundary. Both are required — a scan with neither is
    an unbounded command with a route to everywhere.
    """
    if capability.revoked or not capability.is_live():
        return DispatchOutcome(False, None, QUEUED, reason="capability_not_live")

    plan = nmap.build_plan(
        constraints=capability.constraints, budget=capability.budget.as_dict(),
        target=target,
    )
    tool_version = nmap.tool_version()
    fingerprint = execution_fingerprint(
        engagement_id=engagement_id, tool=nmap.TOOL, tool_version=tool_version,
        normalized_target=target, normalized_params=plan.as_params(),
        execution_context=execution_context,
    )

    cached = find_cached_run(conn, fingerprint)
    if cached is not None:
        _set_state(conn, proposal_id, SUCCEEDED)
        return DispatchOutcome(False, cached["run_id"], SUCCEEDED, reason="dedup_hit")

    if not claim_for_dispatch(conn, proposal_id):
        # Someone else already took it, or it is not in a dispatchable state.
        state = conn.execute(
            text("SELECT dispatch_state FROM action_proposals WHERE proposal_id = :p"),
            {"p": proposal_id},
        ).scalar_one_or_none()
        return DispatchOutcome(False, None, state or QUEUED, reason="not_claimable")

    run_id = f"RUN-{uuid.uuid4().hex[:12]}"
    allowlist = network_allowlist or [target]

    conn.execute(
        text("""
            INSERT INTO tool_runs (run_id, engagement_id, proposal_id, capability_id,
                tool, tool_version, normalized_target, normalized_params,
                execution_context, execution_fingerprint, status, network_allowlist,
                started_at)
            VALUES (:run, :eng, :pid, :cap, :tool, :tver, :target,
                    CAST(:params AS jsonb), CAST(:ctx AS jsonb), :fp, :status,
                    :allowlist, now())
        """),
        {
            "run": run_id, "eng": engagement_id, "pid": proposal_id,
            "cap": capability.capability_id, "tool": nmap.TOOL, "tver": tool_version,
            "target": target, "params": _json(plan.as_params()),
            "ctx": _json(dict(execution_context or {})), "fp": fingerprint,
            "status": RUNNING, "allowlist": allowlist,
        },
    )
    _set_state(conn, proposal_id, RUNNING)
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="tool_run.started",
        subject_type="tool_run", subject_id=run_id,
        payload={"tool": nmap.TOOL, "target": target, "command": list(plan.command),
                 "network_allowlist": allowlist, "capability_id": capability.capability_id},
    )

    sandbox = sandbox or DockerSandbox()
    try:
        result = sandbox.run(
            command=plan.command, network_allowlist=allowlist,
            max_duration_seconds=plan.max_duration_seconds, run_id=run_id,
        )
    except SandboxUnavailable as exc:
        # The tool may or may not have run — the sandbox failed at a point we
        # cannot distinguish. §8.8 says that is UNKNOWN_OUTCOME, not FAILED,
        # because "failed" invites a retry.
        _finish_run(conn, run_id, UNKNOWN_OUTCOME, exit_code=None)
        _set_state(conn, proposal_id, UNKNOWN_OUTCOME)
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.unknown_outcome", subject_type="tool_run",
            subject_id=run_id, reasons=("sandbox_unavailable",),
            payload={"error": str(exc)},
        )
        return DispatchOutcome(True, run_id, UNKNOWN_OUTCOME, reason=str(exc))

    raw = (
        f"$ {' '.join(plan.command)}\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}\n"
    ).encode()
    evidence_id = f"NMAP-{uuid.uuid4().hex[:12]}"
    record_evidence(
        conn, engagement_id=engagement_id, evidence_id=evidence_id, run_id=run_id,
        evidence_type="tool_output", raw=raw,
        derived_view=nmap.derive_view(result.stdout, result.stderr),
        tool=nmap.TOOL, tool_version=tool_version,
    )

    status = SUCCEEDED if result.succeeded else FAILED
    _finish_run(
        conn, run_id, status, exit_code=result.exit_code,
        fresh_for_seconds=fresh_for_seconds if status == SUCCEEDED else None,
    )
    _set_state(conn, proposal_id, status)
    record_audit(
        engagement_id=engagement_id, actor=actor,
        event_type=f"tool_run.{status}", subject_type="tool_run", subject_id=run_id,
        decision="ALLOW" if status == SUCCEEDED else None,
        payload={**result.as_dict(), "evidence_id": evidence_id},
    )
    return DispatchOutcome(True, run_id, status, evidence_id=evidence_id, result=result)


def _finish_run(
    conn: Connection, run_id: str, status: str, *,
    exit_code: int | None, fresh_for_seconds: int | None = None,
) -> None:
    conn.execute(
        text("""
            UPDATE tool_runs
            SET status = :status, exit_code = :code, finished_at = now(),
                fresh_until = CASE
                    WHEN CAST(:fresh AS double precision) IS NULL THEN NULL
                    ELSE now() + make_interval(secs => CAST(:fresh AS double precision))
                END
            WHERE run_id = :run
        """),
        {"run": run_id, "status": status, "code": exit_code, "fresh": fresh_for_seconds},
    )


def reconcile_stale_dispatches(
    conn: Connection, *, engagement_id: str, older_than_seconds: int, actor: str
) -> list[str]:
    """Move interrupted dispatches to UNKNOWN_OUTCOME (§8.8, I7).

    Run after a restart. Anything still in flight past the threshold had its
    control plane die mid-dispatch, and the one thing that must not happen is
    a silent re-execution: this marks them unresolved and audits each, so they
    surface for a human rather than being retried.
    """
    stale = conn.execute(
        text("""
            UPDATE action_proposals
            SET dispatch_state = :unknown, updated_at = now()
            WHERE engagement_id = :eng
              AND dispatch_state = ANY(:inflight)
              AND updated_at < now() - make_interval(secs => :age)
            RETURNING proposal_id
        """),
        {"eng": engagement_id, "unknown": UNKNOWN_OUTCOME,
         "inflight": list(IN_FLIGHT), "age": older_than_seconds},
    ).scalars().all()

    for proposal_id in stale:
        conn.execute(
            text("UPDATE tool_runs SET status = :unknown WHERE proposal_id = :pid "
                 "AND status = ANY(:inflight)"),
            {"pid": proposal_id, "unknown": UNKNOWN_OUTCOME, "inflight": list(IN_FLIGHT)},
        )
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="dispatch.unknown_outcome", subject_type="action_proposal",
            subject_id=proposal_id, reasons=("interrupted_before_result",),
            payload={"requires_human_review": True,
                     "note": "not retried: the action may already have executed"},
        )
    return list(stale)


def _json(value: Mapping[str, Any]) -> str:
    import json

    return json.dumps(dict(value), default=str, sort_keys=True)


def now_utc() -> datetime:
    return datetime.now(UTC)
