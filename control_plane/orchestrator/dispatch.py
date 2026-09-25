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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit
from control_plane.capability.broker import BUDGET_EXHAUSTED, consume_request
from control_plane.dedup.fingerprint import execution_fingerprint
from control_plane.evidence.store import record_evidence
from tool_gateway import registry
from tool_gateway.adapters import browser, http_get, http_post, nmap
from tool_gateway.sandbox import (
    TOOL_CA_PATH,
    DockerSandbox,
    SandboxResult,
    SandboxUnavailable,
)

QUEUED = "queued"
DISPATCHING = "dispatching"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
UNKNOWN_OUTCOME = "unknown_outcome"

#: A capability whose constraints the tool adapter cannot turn into a command.
#: Distinct from a failed run: nothing executed, and nothing was going to.
UNBUILDABLE_PLAN = "unbuildable_plan"
DENY_DECISION = "DENY"

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


def fingerprint_context(
    execution_context: Mapping[str, Any] | None, allowlist: Sequence[str],
) -> dict[str, Any]:
    """The §7 execution context, with the network boundary folded in.

    The D11 live run found the dedup cache treating two runs as the same
    execution when they were not. A scan of 10.79.0.2 confined to
    ``10.88.0.0/24`` — a range with no route to it — succeeded and reported
    nothing open. The identical proposal under ``10.79.0.0/24``, which *can*
    reach the host, matched that fingerprint, was answered from the cache, and
    never ran. Three open ports went unreported and the engagement's record
    said the scan completed successfully with nothing found.

    That is the failure §7 names as a security bug rather than a performance
    one: the scan that gets skipped is the one that would have found something.

    The allowlist belongs in ``execution_context`` rather than as a new
    component of the hash, because §7's v0.3 amendment already put exactly this
    kind of thing there — "the same target scanned with a different credential
    is a different execution". A namespace that can reach the target and one
    that cannot are different executions by the same argument, and a stronger
    one: the difference decides whether any packet is sent at all.

    The stored ``tool_runs.execution_context`` stays the caller's, so a reader
    recomputing a fingerprint needs that column *and* ``network_allowlist``,
    which sits beside it in the same row.
    """
    return {**dict(execution_context or {}), "network_allowlist": sorted(allowlist)}


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


#: Which adapter serves which capability action (§4.1.5, D31).
#:
#: Keyed on the action the *capability* carries, not on anything the Worker
#: says at dispatch time — the action was fixed when OPA decided and the broker
#: issued, so routing on it cannot be steered later.
#:
#: Re-exported from :mod:`tool_gateway.registry`, which owns the table since
#: D34 because the authorization path reads it too: the side-effect floor looks
#: up what an action actually does, and that lookup and this routing must be
#: the same fact. Two tables would let OPA judge one tool and dispatch run
#: another.
ADAPTERS = registry.ADAPTERS
adapter_for = registry.adapter_for

#: Evidence id prefix per tool, so an id keeps saying what produced it.
EVIDENCE_PREFIX = {
    nmap.TOOL: "NMAP", http_get.TOOL: "HTTP", http_post.TOOL: "HTTP",
    browser.TOOL: "BROWSER",
}

#: A capability naming an action no adapter implements.
UNKNOWN_ACTION = registry.UNKNOWN_ACTION

#: A web.* capability dispatched with no egress proxy to route it through.
PROXY_REQUIRED = registry.PROXY_REQUIRED

#: The capability's §4.6 request budget is spent.
#:
#: The broker's constant, re-exported rather than restated. consume_request
#: audits the refusal with this reason and dispatch returns it; two spellings
#: of one refusal is how a search for "why did this stop" finds half the
#: answer.


def _build_plan_params(adapter) -> frozenset[str]:
    """The keyword names ``adapter.build_plan`` accepts.

    Used to hand each adapter only the proxy-trust input it declares, so a tool
    is never passed a parameter it does not use (D36).
    """
    import inspect

    return frozenset(inspect.signature(adapter.build_plan).parameters)


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
    proxy_url: str | None = None,
    ca_cert_pem: str | None = None,
    proxy_cert_spki: str | None = None,
) -> DispatchOutcome:
    """Run one scan and record run, evidence and state transitions.

    The capability supplies the constraints and the budget; the sandbox
    supplies the network boundary. Both are required — a scan with neither is
    an unbounded command with a route to everywhere.

    ``proxy_url`` is the policy-aware egress proxy for web.* actions (§8.3,
    D34). It is **required** for an adapter that declares ``REQUIRES_PROXY``:
    a web request with no proxy is not a degraded run, it is an unchecked one,
    so it is refused here rather than executed directly.

    ``ca_cert_pem`` is the per-engagement CA the proxy terminates TLS with
    (D35). When present the tool trusts the proxy's leaf (mounted at
    ``TOOL_CA_PATH``, passed to the adapter as ``--cacert``) and an https
    request is checkable; when absent the adapter refuses https with the reason
    named, rather than a socket error. It is threaded here the same way
    ``proxy_url`` is, and like it goes only to the adapters that use the
    proxy.

    Note what this signature does *not* accept, because D34 rests a property on
    it: there is no ``action`` parameter and no ``writes_data`` /
    ``changes_state`` parameter. The action comes off the issued capability,
    which was fixed when OPA decided, and the side effects are looked up from
    it. There is no argument on this path that could carry a different value —
    the same shape as D13's Worker interface, which has no ``discovery``
    argument to falsify.
    """
    if capability.revoked or not capability.is_live():
        return DispatchOutcome(False, None, QUEUED, reason="capability_not_live")

    adapter = adapter_for(capability.action)
    if adapter is None:
        # Refused for the same reason an unbuildable plan is (below): a
        # capability the gateway cannot execute must not fall through to a tool
        # that happens to be wired up.
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.refused", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY_DECISION,
            reasons=(UNKNOWN_ACTION,),
            payload={"action": capability.action,
                     "capability_id": capability.capability_id},
        )
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=UNKNOWN_ACTION)

    if registry.requires_proxy(capability.action) and not proxy_url:
        # Refused, not downgraded to a direct request. The tool container has
        # no route to the target anyway (§8.3's two-network topology), so this
        # would fail at the socket a moment later and read as an unreachable
        # target; saying it here keeps the reason attached to the cause.
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.refused", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY_DECISION,
            reasons=(PROXY_REQUIRED,),
            payload={"action": capability.action,
                     "capability_id": capability.capability_id},
        )
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=PROXY_REQUIRED)

    # Only the adapters that go through the proxy are told about it. nmap's
    # build_plan has no proxy_url parameter and should not grow one: §8.3 routes
    # raw TCP through the namespace precisely because there is no application
    # protocol there for a proxy to read.
    proxy_kwargs: dict[str, Any] = {}
    if registry.requires_proxy(capability.action):
        proxy_kwargs["proxy_url"] = proxy_url
        # How the tool trusts the proxy's terminated TLS differs by tool: curl
        # verifies the CA at TOOL_CA_PATH (--cacert, D35); the browser pins the
        # leaf's SPKI (D36). Each adapter's build_plan declares only the one it
        # takes, so pass by signature rather than give a tool a trust input it
        # does not use.
        accepted = _build_plan_params(adapter)
        if ca_cert_pem is not None and "ca_cert_path" in accepted:
            proxy_kwargs["ca_cert_path"] = TOOL_CA_PATH
        if proxy_cert_spki is not None and "proxy_cert_spki" in accepted:
            proxy_kwargs["proxy_cert_spki"] = proxy_cert_spki
    try:
        plan = adapter.build_plan(
            constraints=capability.constraints, budget=capability.budget.as_dict(),
            target=target, **proxy_kwargs,
        )
    except adapter.AdapterError as exc:
        # A capability the adapter cannot turn into a command. Refused, and
        # audited, rather than raised — D15 found this the hard way: a real
        # Worker proposed ``ports: "n/a"`` for a ping scan, the AdapterError
        # propagated out of dispatch_scan, out of propose_action, and killed
        # the orchestrator process.
        #
        # Whoever supplied the malformed constraint is not the point. Every
        # other refusal on this path returns a DispatchOutcome, and an
        # unparseable constraint has to as well, or one bad proposal takes down
        # the loop that would have refused the next one.
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.refused", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY_DECISION,
            reasons=(UNBUILDABLE_PLAN,),
            payload={"tool": adapter.TOOL, "error": str(exc),
                     "constraints": dict(capability.constraints),
                     "capability_id": capability.capability_id},
        )
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=UNBUILDABLE_PLAN)
    tool_version = adapter.tool_version()
    allowlist = network_allowlist or [target]
    fingerprint = execution_fingerprint(
        engagement_id=engagement_id, tool=adapter.TOOL, tool_version=tool_version,
        normalized_target=target, normalized_params=plan.as_params(),
        execution_context=fingerprint_context(execution_context, allowlist),
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

    # §4.6's request budget, spent here (D34).
    #
    # **This is the repair of an existing defect, not a mechanism D34
    # invented.** consume_request and its atomic check-and-increment have been
    # in the broker since the capability work, written exactly as §8.5
    # specifies, and nothing on any production path called it: grep found it
    # only in tests. max_requests was a number in a database. D31 did not
    # notice because its adapter refuses any value above one, so a run was
    # always exactly one request.
    #
    # Placed after the claim and before anything executes. Before the claim and
    # a lost race would burn a request nothing used; after the run and a
    # crashed control plane would execute without ever counting it.
    #
    # Nmap is exempt by §4.6's own reasoning -- "one request" has no meaning
    # for a port scan, which is why the budget object separates tool-specific
    # dimensions from the universal ones. The adapters that count declare a
    # max_requests on their plan; the ones that do not, do not.
    max_requests = getattr(plan, "max_requests", None)
    if max_requests is not None and not consume_request(
        conn, capability_id=capability.capability_id, max_requests=max_requests,
        engagement_id=engagement_id, actor=actor,
    ):
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=BUDGET_EXHAUSTED)

    run_id = f"RUN-{uuid.uuid4().hex[:12]}"

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
            "cap": capability.capability_id, "tool": adapter.TOOL, "tver": tool_version,
            "target": target, "params": _json(plan.as_params()),
            "ctx": _json(dict(execution_context or {})), "fp": fingerprint,
            "status": RUNNING, "allowlist": allowlist,
        },
    )
    _set_state(conn, proposal_id, RUNNING)
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="tool_run.started",
        subject_type="tool_run", subject_id=run_id,
        payload={"tool": adapter.TOOL, "target": target, "command": list(plan.command),
                 "network_allowlist": allowlist, "capability_id": capability.capability_id},
    )

    # A tool that ships its own image says so; the rest run in the shared one.
    # When the caller passed a sandbox it already chose the image, so respect it.
    adapter_image = getattr(adapter, "IMAGE", None)
    sandbox = sandbox or (
        DockerSandbox(image=adapter_image) if adapter_image else DockerSandbox()
    )
    try:
        result = sandbox.run(
            command=plan.command, network_allowlist=allowlist,
            max_duration_seconds=plan.max_duration_seconds, run_id=run_id,
            # web.post feeds its body here rather than through argv, so the
            # body never reaches the process table or the audit payload below,
            # and curl's @- sigil stays fixed (see http_post.build_plan).
            stdin=getattr(plan, "stdin", None) or None,
            # The public CA the tool verifies the proxy's leaf against (D35).
            # None for nmap and for plain-HTTP web runs.
            ca_cert_pem=ca_cert_pem,
            # Writable tmpfs the tool's image needs over its read-only root
            # (the browser; D36). None for tools that need no writable path.
            tmpfs=getattr(adapter, "TMPFS", None),
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
    prefix = EVIDENCE_PREFIX.get(adapter.TOOL, "TOOL")
    evidence_id = f"{prefix}-{uuid.uuid4().hex[:12]}"
    record_evidence(
        conn, engagement_id=engagement_id, evidence_id=evidence_id, run_id=run_id,
        evidence_type="tool_output", raw=raw,
        derived_view=adapter.derive_view(result.stdout, result.stderr),
        tool=adapter.TOOL, tool_version=tool_version,
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
