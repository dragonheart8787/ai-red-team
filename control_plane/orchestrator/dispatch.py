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

import ipaddress
import logging
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text
from sqlalchemy.exc import SQLAlchemyError

from control_plane.audit.logger import record_audit
from control_plane.capability.broker import BUDGET_EXHAUSTED, consume_request, get_capability
from control_plane.dedup.fingerprint import execution_fingerprint
from control_plane.evidence.store import record_evidence, write_raw_artifact
from control_plane.graph.store import record_batch
from control_plane.orchestrator import stages
from control_plane.orchestrator.git_fetch import (
    GitFetchError,
    cleanup_repo,
    fetch_repo,
    parse_repo_scope_value,
)
from control_plane.state.db import engagement_scope
from control_plane.vault import vault
from tool_gateway import registry
from tool_gateway.adapters import (
    ad_collector,
    browser,
    gitleaks,
    http_get,
    http_post,
    nmap,
    semgrep,
)
from tool_gateway.sandbox import (
    TOOL_CA_PATH,
    DockerSandbox,
    NetworkNotAvailable,
    SandboxResult,
    SandboxUnavailable,
)

logger = logging.getLogger("cyberorch.dispatch")

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
    browser.TOOL: "BROWSER", ad_collector.TOOL: "ADCOLLECT", semgrep.TOOL: "CODE",
    gitleaks.TOOL: "SECRETS",
}

#: A malformed collection result: the run succeeded, but its stdout could
#: not be turned into a graph batch. Distinct from UNBUILDABLE_PLAN (nothing
#: ran) and from FAILED (the tool itself reported failure) -- this is the
#: tool reporting success with output this adapter's parser refuses.
UNPARSEABLE_COLLECTION_RESULT = "unparseable_collection_result"

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


#: The sandbox refused before any container existed because the network is held
#: by another engagement, or its range collides with another network (D59).
#: Distinct from UNKNOWN_OUTCOME on purpose: nothing started, so the outcome is
#: *known* and the same proposal can be tried again once the network is free.
#: Recording it as unknown (what every ``SandboxUnavailable`` gets) would park a
#: proposal for a human over something the system can simply retry.
NETWORK_UNAVAILABLE = "network_unavailable"


def _network_refused(
    conn: Connection, *, engagement_id: str, actor: str, run_id: str,
    proposal_id: str, exc: NetworkNotAvailable,
) -> DispatchOutcome:
    """Record a run the sandbox declined to start for a network reason (D59).

    The audit payload carries the sandbox's message and the stable code, which
    by construction name no other engagement; who holds the network is in the
    operator log, not in this engagement's trail.
    """
    _finish_run(conn, run_id, FAILED, exit_code=None)
    _set_state(conn, proposal_id, FAILED)
    record_audit(
        engagement_id=engagement_id, actor=actor,
        event_type="tool_run.refused", subject_type="tool_run", subject_id=run_id,
        decision=DENY_DECISION, reasons=(NETWORK_UNAVAILABLE, exc.reason),
        payload={"error": str(exc)},
    )
    # run_id is not returned: nothing executed, so propose_action must not draw
    # an "executed" provenance edge for it.
    return DispatchOutcome(False, None, FAILED, reason=exc.reason)


@dataclass
class _Started:
    """What a run's first stage committed, and what the later stages need of it."""

    run_id: str
    adapter: Any
    plan: Any
    tool_version: str
    target: str
    allowlist: list[str]
    capability_id: str
    fresh_for_seconds: int
    ruleset_version: str | None = None


def _fresh_capability(conn: Connection, engagement_id: str, capability):
    """The capability as it is *now*, or a refusal (D60).

    The one the caller holds was read in an earlier stage, and a stage that committed is exactly
    what lets a kill switch, a pause or a revocation reach it: the capability row is visible to
    ``revoke_all_for_engagement`` the moment its stage commits. So the dispatch stage starts by
    asking again -- of the capability, and of the engagement it belongs to -- rather than trusting
    what it was handed. Returns ``(capability, None)`` or ``(None, DispatchOutcome)``.
    """
    fresh = get_capability(conn, capability.capability_id)
    if fresh is None or fresh.revoked or not fresh.is_live():
        return None, DispatchOutcome(False, None, QUEUED, reason="capability_not_live")
    engagement = conn.execute(
        text("SELECT status, kill_switch_engaged FROM engagements WHERE engagement_id = :e"),
        {"e": engagement_id},
    ).one_or_none()
    if engagement is None or engagement[1] or engagement[0] != "active":
        return None, DispatchOutcome(False, None, QUEUED, reason="engagement_not_active")
    return fresh, None


def _close_early(conn: Connection, proposal_id: str, outcome: DispatchOutcome) -> None:
    """A dispatch that ended before a run row existed ends the pipeline, with its reason."""
    detail = outcome.reason or "closed"
    if outcome.reason == "dedup_hit" and outcome.run_id:
        detail = f"dedup_hit:{outcome.run_id}"
    if outcome.reason == "not_claimable":
        return  # someone else owns this dispatch; its stage is theirs to move
    stages.advance(conn, proposal_id, expected=stages.BEFORE_DISPATCH,
                   new=stages.CLOSED, detail=detail)


def _begin(engagement_id: str, proposal_id: str, start) -> _Started | DispatchOutcome:
    """Stage 3a, in its own transaction: everything up to and including the committed run row.

    ``start(conn)`` is the old dispatch body up to the point it would have called the sandbox, and
    returns either a refusal (a ``DispatchOutcome``) or a ``_Started``. Whatever it returns is
    committed here -- the run row, the ``running`` state, the ``dispatching`` stage -- *before* any
    container exists, so a process that dies from here on leaves a row for the reconciler to find.
    Losing the stage race rolls the whole transaction back and reports a lost claim.
    """
    try:
        with engagement_scope(engagement_id) as conn:
            started = start(conn)
            if isinstance(started, DispatchOutcome):
                _close_early(conn, proposal_id, started)
            return started
    except stages.StageConflict:
        with engagement_scope(engagement_id) as conn:
            state = conn.execute(
                text("SELECT dispatch_state FROM action_proposals WHERE proposal_id = :p"),
                {"p": proposal_id},
            ).scalar_one_or_none()
        return DispatchOutcome(False, None, state or QUEUED, reason="not_claimable")


def _execute(
    sandbox_run, *, engagement_id: str, proposal_id: str, actor: str, run_id: str,
) -> SandboxResult | DispatchOutcome:
    """Stage 3b: the container. No database connection is held while it runs.

    A refusal the sandbox made *before* a container existed, and a failure of the sandbox itself,
    are each recorded here in their own short transaction and returned as the outcome. Anything
    else propagates with the stage still ``dispatching`` -- which is what the reconciler reads.
    """
    try:
        return sandbox_run()
    except NetworkNotAvailable as exc:
        with engagement_scope(engagement_id) as conn:
            outcome = _network_refused(
                conn, engagement_id=engagement_id, actor=actor, run_id=run_id,
                proposal_id=proposal_id, exc=exc,
            )
            stages.advance(conn, proposal_id, expected=stages.DISPATCHING,
                           new=stages.CLOSED, detail=exc.reason)
        return outcome
    except SandboxUnavailable as exc:
        # The tool may or may not have run — the sandbox failed at a point we
        # cannot distinguish. §8.8 says that is UNKNOWN_OUTCOME, not FAILED,
        # because "failed" invites a retry.
        with engagement_scope(engagement_id) as conn:
            _finish_run(conn, run_id, UNKNOWN_OUTCOME, exit_code=None)
            _set_state(conn, proposal_id, UNKNOWN_OUTCOME)
            record_audit(
                engagement_id=engagement_id, actor=actor,
                event_type="tool_run.unknown_outcome", subject_type="tool_run",
                subject_id=run_id, reasons=("sandbox_unavailable",),
                payload={"error": str(exc)},
            )
            stages.advance(conn, proposal_id, expected=stages.DISPATCHING,
                           new=stages.RECORDED, detail=UNKNOWN_OUTCOME)
        return DispatchOutcome(True, run_id, UNKNOWN_OUTCOME, reason=str(exc))


def _revoked_during_run(conn: Connection, capability_id: str) -> dict[str, Any]:
    """Audit-payload fields saying the capability was revoked while its run was in flight.

    Nothing stops a container that is already running (that is D44-7 / D58-16, not built); what the
    stage boundary can do is say so. Empty when nothing happened.
    """
    capability = get_capability(conn, capability_id)
    if capability is not None and capability.revoked:
        return {"capability_revoked_during_run": capability.revoked_reason or True}
    return {}


def _record_scan_result(
    *, engagement_id: str, proposal_id: str, actor: str, started: _Started,
    result: SandboxResult, view_fn=None, incomplete_reason: str | None = None,
) -> DispatchOutcome:
    """Stage 3c: the result, in its own short transaction, as soon as the container is gone.

    The raw bytes are made durable on disk *first* -- they are the one thing that cannot be had
    again if the database is unreachable at this moment -- and only then is the transaction
    opened. If it fails, the run row is still ``running`` (the reconciler's job) and the log says
    where the output is.
    """
    adapter = started.adapter
    raw = (
        f"$ {' '.join(started.plan.command)}\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}\n"
    ).encode()
    evidence_id = f"{EVIDENCE_PREFIX.get(adapter.TOOL, 'TOOL')}-{uuid.uuid4().hex[:12]}"
    path, digest = write_raw_artifact(engagement_id, evidence_id, raw)
    # ``incomplete_reason``: a tool may declare that its exit code cannot tell "found nothing" from
    # "could not read the input" (Gitleaks, D55). Such a run is FAILED, not SUCCEEDED -- so it is
    # not a clean bill of health in the evidence and, because only SUCCEEDED runs are ever served
    # from the dedup cache, not an "already scanned" for the next proposal either.
    status = SUCCEEDED if result.succeeded and incomplete_reason is None else FAILED
    view_fn = view_fn or adapter.derive_view
    audit_extra = ({"scan_incomplete_reason": incomplete_reason}
                   if incomplete_reason is not None else {})
    try:
        with engagement_scope(engagement_id) as conn:
            record_evidence(
                conn, engagement_id=engagement_id, evidence_id=evidence_id,
                run_id=started.run_id, evidence_type="tool_output", raw=raw,
                derived_view=view_fn(result.stdout, result.stderr),
                tool=adapter.TOOL, tool_version=started.tool_version,
                ruleset_version=started.ruleset_version,
            )
            _finish_run(
                conn, started.run_id, status, exit_code=result.exit_code,
                fresh_for_seconds=started.fresh_for_seconds if status == SUCCEEDED else None,
            )
            _set_state(conn, proposal_id, status)
            record_audit(
                engagement_id=engagement_id, actor=actor,
                event_type=f"tool_run.{status}", subject_type="tool_run",
                subject_id=started.run_id, decision="ALLOW" if status == SUCCEEDED else None,
                payload={**result.as_dict(), "evidence_id": evidence_id, **audit_extra,
                         **_revoked_during_run(conn, started.capability_id)},
            )
            stages.advance(conn, proposal_id, expected=stages.DISPATCHING,
                           new=stages.RECORDED, detail=status)
    except Exception:
        logger.critical(
            "run %s finished (exit %s) but its result could not be recorded; the output is "
            "on disk at %s (sha256 %s) and the run row is still 'running'",
            started.run_id, result.exit_code, path, digest,
        )
        raise
    return DispatchOutcome(True, started.run_id, status, evidence_id=evidence_id, result=result)


def _scan_start(
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
    """The first stage of one scan: everything up to a committed ``running`` run row (D60).

    (The rest of this docstring is the original ``dispatch_scan``'s, and every rule in it still
    holds; the container and the result are now ``dispatch_scan``'s second and third stages.)

    Run one scan and record run, evidence and state transitions.

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
    capability, refusal = _fresh_capability(conn, engagement_id, capability)
    if refusal is not None:
        return refusal

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
    # The stage transition is taken in the same transaction as the run row, so "dispatching" is
    # committed exactly when "a run row exists in state running" is -- never one without the other.
    stages.take(conn, proposal_id, expected=stages.BEFORE_DISPATCH, new=stages.DISPATCHING)
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="tool_run.started",
        subject_type="tool_run", subject_id=run_id,
        payload={"tool": adapter.TOOL, "target": target, "command": list(plan.command),
                 "network_allowlist": allowlist, "capability_id": capability.capability_id},
    )
    return _Started(
        run_id=run_id, adapter=adapter, plan=plan, tool_version=tool_version,
        target=target, allowlist=list(allowlist), capability_id=capability.capability_id,
        fresh_for_seconds=fresh_for_seconds,
    )


def dispatch_scan(
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
    """Run one scan: three stages, each committed on its own (D58-5, D60).

    1. **Start** (:func:`_scan_start`, one transaction): re-read the capability and the engagement,
       build the plan, claim the dispatch, spend the request budget, insert the ``tool_runs`` row as
       ``running``, move the proposal to ``dispatching``. Committed before a container exists.
    2. **Run**: the sandbox, with no database connection held. An LLM-sized wait and a container-
       sized wait used to pin a pooled connection and a snapshot; they no longer do.
    3. **Record** (one short transaction): the evidence, the finished run, the proposal's state, the
       ``recorded`` stage. Opened the moment the container is gone, with the raw output already on
       disk.

    There is no ``conn`` parameter: a caller's transaction is exactly what cannot be allowed to
    contain these stages, since it would commit them all at once, at its own exit.

    The note that matters from the old docstring, kept because D34 rests on it: there is no
    ``action``, ``writes_data`` or ``changes_state`` parameter. The action comes off the capability,
    which was fixed when OPA decided, and the side effects are looked up from it.
    """
    started = _begin(
        engagement_id, proposal_id,
        lambda conn: _scan_start(
            conn, engagement_id=engagement_id, proposal_id=proposal_id,
            capability=capability, target=target, actor=actor, sandbox=sandbox,
            network_allowlist=network_allowlist, execution_context=execution_context,
            fresh_for_seconds=fresh_for_seconds, proxy_url=proxy_url,
            ca_cert_pem=ca_cert_pem, proxy_cert_spki=proxy_cert_spki,
        ),
    )
    if isinstance(started, DispatchOutcome):
        return started

    # A tool that ships its own image says so; the rest run in the shared one.
    # When the caller passed a sandbox it already chose the image, so respect it.
    adapter_image = getattr(started.adapter, "IMAGE", None)
    sandbox = sandbox or (
        DockerSandbox(image=adapter_image) if adapter_image else DockerSandbox()
    )
    plan = started.plan
    ran = _execute(
        lambda: sandbox.run(
            command=plan.command, network_allowlist=started.allowlist,
            max_duration_seconds=plan.max_duration_seconds, run_id=started.run_id,
            # web.post feeds its body here rather than through argv, so the
            # body never reaches the process table or the audit payload below,
            # and curl's @- sigil stays fixed (see http_post.build_plan).
            stdin=getattr(plan, "stdin", None) or None,
            # The public CA the tool verifies the proxy's leaf against (D35).
            # None for nmap and for plain-HTTP web runs.
            ca_cert_pem=ca_cert_pem,
            # Writable tmpfs the tool's image needs over its read-only root
            # (the browser; D36). None for tools that need no writable path.
            tmpfs=getattr(started.adapter, "TMPFS", None),
            # Who this run is for (D59): the sandbox keeps two engagements off one
            # network, and cannot know which is which unless it is told.
            engagement_id=engagement_id,
        ),
        engagement_id=engagement_id, proposal_id=proposal_id, actor=actor,
        run_id=started.run_id,
    )
    if isinstance(ran, DispatchOutcome):
        return ran
    return _record_scan_result(
        engagement_id=engagement_id, proposal_id=proposal_id, actor=actor,
        started=started, result=ran,
    )


def _collection_start(
    conn: Connection,
    *,
    engagement_id: str,
    proposal_id: str,
    capability,
    target: str,
    actor: str,
    network_allowlist: list[str] | None = None,
    execution_context: Mapping[str, Any] | None = None,
    fresh_for_seconds: int = 1800,
    mounts: list,
) -> DispatchOutcome | _Started:
    """The first stage of ``ad.collect`` (D60): everything up to a committed ``running`` run row.

    ``mounts`` is an out-parameter: the credential file is appended the moment it exists, so the
    caller's ``finally`` removes it however this stage -- or any later one -- ends.

    (The rest of this docstring is the original ``dispatch_collection``'s, and every rule in it
    still holds.)

    Run one bulk collection (``ad.collect``) and record its two artifacts.

    Parallel to :func:`dispatch_scan`, not a retrofit of it (D42-1/D42-6
    design doc §2.5, Option B): reuses the same ``tool_runs`` row, the same
    dispatch state machine, the same execution fingerprint and dedup, and
    the same ``tool_run.*`` audit vocabulary, because a collection run is
    still, mechanically, one proposal producing one tool run. What is new is
    what happens after it succeeds — a second, unbounded write
    (:func:`control_plane.graph.store.record_batch`) alongside the ordinary
    bounded evidence record, exactly the shape §4.1/§4.2 of the ADR named.

    No proxy handling: ``ad.collect`` is not proxy-routed (LDAP goes through
    the sandbox's raw namespace, like nmap's TCP — ``ad_collector
    .REQUIRES_PROXY`` is ``False``). No ``consume_request`` call: this is one
    dispatch, one run, not the multi-request shape that budget dimension
    exists for (nmap is exempt for the identical reason).

    ``dns_server`` authorization (D49) is decided here, not in
    ``ad_collector.build_plan``: the constraint's *shape* (a real IP) is the
    adapter's business, but whether that IP is one this dispatch is allowed
    to have the container query is a fact about ``network_allowlist``, which
    only this function holds alongside the constraint. A ``dns_server``
    outside every allowlisted CIDR is refused as ``UNBUILDABLE_PLAN`` before
    ``sandbox.run`` is ever called — the same fail-closed default every
    other CIDR-adjacent decision in this system uses, applied to a
    dimension (which server a tool's own DNS queries go to) nothing before
    this deliverable had modeled as something a capability could name at
    all.

    An ``ad.collect`` capability with no ``credential_id`` (D50 F1) is refused
    as ``UNBUILDABLE_PLAN`` the same way, before any container or credential
    mount: the real ``bloodhound-python`` has no credential-free mode, so such
    a run could only ever print its usage text and fail. The former
    uncredentialed plan was a D42 interim path that D44 never retired.

    **The bind identity comes from the credential (D50-B).** The account a run
    binds as and how it authenticates are read from the credential
    (``vault.identity_for``, which never returns the secret); a ``domain_
    username`` / ``auth_mode`` on the capability is only an assertion that must
    match, and a mismatch is refused. A credential stored before D50-B carries
    no identity and is refused too -- unknown, never "none needed".
    """
    capability, refusal = _fresh_capability(conn, engagement_id, capability)
    if refusal is not None:
        return refusal

    adapter = ad_collector
    if capability.action != adapter.ACTION:
        # Routed here by the caller naming the action explicitly (unlike
        # dispatch_scan, which routes any nmap/http/browser action through
        # one function) -- refused rather than silently run under the wrong
        # adapter if that ever drifts.
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.refused", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY_DECISION,
            reasons=(registry.UNKNOWN_ACTION,),
            payload={"action": capability.action, "capability_id": capability.capability_id},
        )
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=registry.UNKNOWN_ACTION)

    def refuse_unbuildable(error: str, **payload: Any) -> DispatchOutcome:
        """One refusal shape for every reason a plan cannot be run, all raised
        before any sandbox, tool_runs row or credential mount."""
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.refused", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY_DECISION,
            reasons=(UNBUILDABLE_PLAN,),
            payload={"tool": adapter.TOOL, "error": error,
                     "capability_id": capability.capability_id, **payload},
        )
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=UNBUILDABLE_PLAN)

    # The bind identity comes from the *credential*, not the proposal (D50-B).
    # The real bloodhound-python has no credential-free mode (D50 F1), so a
    # capability with no credential_id has nothing it could run as; and an
    # ad_domain_bind credential is one indivisible unit -- secret, account and
    # auth mode stored together -- so who the run binds as is a fact about the
    # credential. The adapter never sees credential_id (that stays in
    # capability territory, not adapter territory), so this belongs here.
    if capability.credential_id is None:
        return refuse_unbuildable(
            "ad.collect requires a credential_id on the capability: the real "
            "bloodhound-python has no credential-free mode, so a run with no "
            "credential behind it cannot succeed",
        )
    try:
        identity = vault.identity_for(conn, capability.credential_id)
    except vault.VaultError as exc:
        # Includes a credential stored before D50-B: it holds no identity, and
        # an absent identity means unknown, never "none needed" (D30's reading).
        return refuse_unbuildable(str(exc))

    # A proposal may still *state* a username / auth mode (execution_constraints
    # carries them); they are now assertions that must match, never a way to
    # pair a stored secret with a different account or a different mechanism.
    constraints = dict(capability.constraints)
    for key, bound in (("domain_username", identity.username),
                       ("auth_mode", identity.auth_mode)):
        stated = constraints.get(key)
        if stated is not None and stated != bound:
            return refuse_unbuildable(
                f"{key} constraint {stated!r} does not match the credential's "
                f"bound {key} {bound!r}",
            )
        constraints[key] = bound

    try:
        plan = adapter.build_plan(
            constraints=constraints, budget=capability.budget.as_dict(),
            target=target,
        )
    except adapter.AdapterError as exc:
        return refuse_unbuildable(str(exc), constraints=dict(capability.constraints))

    tool_version = adapter.tool_version()
    allowlist = network_allowlist or [target]

    # dns_server authorization (D49): a new dimension nothing before this
    # deliverable had ever considered. ad_collector.build_plan validates the
    # value is a real IP but has no network_allowlist to check it against
    # (build_plan never receives one, matching every other adapter); this is
    # the one place both the constraint and the allowlist are in hand.
    # Fail-closed, checked before any container starts, for the same reason
    # sandbox.py's own network confinement is fail-closed: a compromised or
    # simply misconfigured capability naming a dns_server outside the
    # authorized range would otherwise get a container that queries an
    # address nothing here ever reasoned about letting it reach -- exactly
    # the kind of egress the CIDR allowlist exists to bound, reached through
    # a side door the allowlist check on the *scan target* was never asked
    # to cover. This is refused as UNBUILDABLE_PLAN, the same reason the
    # domain_username-without-credential_id case above uses, for the
    # identical reason: the plan is well-formed on its own terms and still
    # cannot be run given what else is true about this dispatch.
    if plan.dns_server is not None:
        dns_ip = ipaddress.ip_address(plan.dns_server)
        if not any(
            dns_ip in ipaddress.ip_network(cidr, strict=False) for cidr in allowlist
        ):
            record_audit(
                engagement_id=engagement_id, actor=actor,
                event_type="tool_run.refused", subject_type="action_proposal",
                subject_id=proposal_id, decision=DENY_DECISION,
                reasons=(UNBUILDABLE_PLAN,),
                payload={"tool": adapter.TOOL,
                         "error": f"dns_server {plan.dns_server!r} is outside "
                                  f"network_allowlist {list(allowlist)!r}",
                         "capability_id": capability.capability_id},
            )
            _set_state(conn, proposal_id, FAILED)
            return DispatchOutcome(False, None, FAILED, reason=UNBUILDABLE_PLAN)

    # A different credential against the same domain is a different
    # execution (D11-3/§7 v0.3's own reasoning, already applied to D43's
    # commit_sha) -- folded into execution_context, never into
    # normalized_params, so the fingerprint changes without the credential
    # id ever needing to look like a scan parameter.
    ctx = dict(execution_context or {})
    ctx["credential_id"] = capability.credential_id
    fingerprint = execution_fingerprint(
        engagement_id=engagement_id, tool=adapter.TOOL, tool_version=tool_version,
        normalized_target=target, normalized_params=plan.as_params(),
        execution_context=fingerprint_context(ctx, allowlist),
    )

    cached = find_cached_run(conn, fingerprint)
    if cached is not None:
        _set_state(conn, proposal_id, SUCCEEDED)
        return DispatchOutcome(False, cached["run_id"], SUCCEEDED, reason="dedup_hit")

    if not claim_for_dispatch(conn, proposal_id):
        state = conn.execute(
            text("SELECT dispatch_state FROM action_proposals WHERE proposal_id = :p"),
            {"p": proposal_id},
        ).scalar_one_or_none()
        return DispatchOutcome(False, None, state or QUEUED, reason="not_claimable")

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
            "ctx": _json(ctx), "fp": fingerprint,
            "status": RUNNING, "allowlist": allowlist,
        },
    )
    _set_state(conn, proposal_id, RUNNING)
    stages.take(conn, proposal_id, expected=stages.BEFORE_DISPATCH, new=stages.DISPATCHING)
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="tool_run.started",
        subject_type="tool_run", subject_id=run_id,
        payload={"tool": adapter.TOOL, "target": target, "command": list(plan.command),
                 "network_allowlist": allowlist, "capability_id": capability.capability_id},
    )

    # Minted only now -- after the dedup check, the claim and the stage -- so a dedup
    # hit or a lost claim race never mints (and never has to clean up) a
    # credential file nothing will use (D44). ad.collect is the one dispatch
    # path that can defer this past the fingerprint step at all: unlike
    # D43's commit_sha, credential_id is already known from the capability
    # itself, with nothing to discover that the fingerprint depends on.
    mounts.append(vault.mount_for_run(
        conn, credential_id=capability.credential_id, run_id=run_id,
        engagement_id=engagement_id, actor=actor,
    ))
    return _Started(
        run_id=run_id, adapter=adapter, plan=plan, tool_version=tool_version,
        target=target, allowlist=list(allowlist), capability_id=capability.capability_id,
        fresh_for_seconds=fresh_for_seconds,
    )


def _record_collection_graph(
    *, engagement_id: str, actor: str, run_id: str, adapter, stdout: str,
) -> None:
    """The second artifact (§2.5 of the design doc): the full, unbounded graph, never the bounded
    derived_view. Its own transaction, *after* the run's result is committed (D60): a run whose
    output cannot be parsed or whose batch cannot be written is still a recorded, successful run,
    and the graph can be rebuilt from the raw artifact. A failure here is its own audited event,
    never a re-judgment of the run -- and never a reason to lose the evidence.
    """
    try:
        nodes, edges = adapter.parse_graph(stdout)
        with engagement_scope(engagement_id) as conn:
            record_batch(
                conn, engagement_id=engagement_id, run_id=run_id,
                nodes=nodes, edges=edges,
            )
            record_audit(
                engagement_id=engagement_id, actor=actor,
                event_type="security_graph.recorded", subject_type="tool_run",
                subject_id=run_id,
                payload={"node_count": len(nodes), "edge_count": len(edges)},
            )
    except (ValueError, KeyError) as exc:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="security_graph.record_failed", subject_type="tool_run",
            subject_id=run_id, reasons=(UNPARSEABLE_COLLECTION_RESULT,),
            payload={"error": str(exc)},
        )
    except SQLAlchemyError as exc:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="security_graph.record_failed", subject_type="tool_run",
            subject_id=run_id, reasons=("graph_write_failed",),
            payload={"error": str(exc)[:500]},
        )


def dispatch_collection(
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
    """Run one bulk collection (``ad.collect``): start, run, record, then the graph (D60).

    The stages are :func:`dispatch_scan`'s, with two additions that are this action's. The
    credential file is minted in the start stage and removed in the ``finally`` below no matter
    where the stages end (D44-5). And the Security Graph batch is written in a transaction of its
    own *after* the evidence and the run's result are committed.
    """
    mounts: list = []
    started = None
    try:
        started = _begin(
            engagement_id, proposal_id,
            lambda conn: _collection_start(
                conn, engagement_id=engagement_id, proposal_id=proposal_id,
                capability=capability, target=target, actor=actor,
                network_allowlist=network_allowlist, execution_context=execution_context,
                fresh_for_seconds=fresh_for_seconds, mounts=mounts,
            ),
        )
        if isinstance(started, DispatchOutcome):
            return started

        # A tool that ships its own image says so (adapter.IMAGE); the rest
        # run in the shared one -- same lookup dispatch_scan and
        # dispatch_code_scan already do for their own adapters (D45: this one
        # was missing, so a caller that did not hand-pick a sandbox got
        # DockerSandbox's default nmap image instead of bloodhound-python's).
        adapter = started.adapter
        adapter_image = getattr(adapter, "IMAGE", None)
        sandbox = sandbox or (
            DockerSandbox(image=adapter_image) if adapter_image else DockerSandbox()
        )
        plan = started.plan
        ran = _execute(
            lambda: sandbox.run(
                command=plan.command, network_allowlist=started.allowlist,
                max_duration_seconds=plan.max_duration_seconds, run_id=started.run_id,
                source_mounts={mounts[0].host_path: adapter.CONTAINER_CRED_PATH},
                engagement_id=engagement_id,
            ),
            engagement_id=engagement_id, proposal_id=proposal_id, actor=actor,
            run_id=started.run_id,
        )
        if isinstance(ran, DispatchOutcome):
            return ran
        outcome = _record_scan_result(
            engagement_id=engagement_id, proposal_id=proposal_id, actor=actor,
            started=started, result=ran,
        )
        # Attempted only when the tool itself reported success -- a failed run has no graph to
        # write.
        if outcome.state == SUCCEEDED:
            _record_collection_graph(
                engagement_id=engagement_id, actor=actor, run_id=started.run_id,
                adapter=adapter, stdout=ran.stdout,
            )
        return outcome
    finally:
        # Always -- success, failure, or sandbox-unavailable all leave a
        # minted credential file on the control-plane host's disk that
        # nothing else will clean up (D44-5, the same caller-owns-cleanup
        # contract D43's git_fetch.cleanup_repo already established).
        for mounted in mounts:
            vault.cleanup_mount(
                mounted, engagement_id=engagement_id, actor=actor,
                run_id=getattr(started, "run_id", "unstarted"),
            )


#: A control-plane-side repo fetch failed before any sandbox run started
#: (D43-5). Distinct from UNBUILDABLE_PLAN (the capability's shape itself
#: was wrong -- no fetch was attempted) and from FAILED (a tool inside the
#: sandbox reported failure): here the capability was valid and a fetch was
#: attempted, but the source it names could not be retrieved.
REPO_FETCH_FAILED = "repo_fetch_failed"

#: Semgrep and Gitleaks need no network access at all (the adapters' module
#: docstrings): the repository and the ruleset both arrive as read-only bind
#: mounts. This range is therefore only a *record* -- it is what the execution
#: fingerprint and ``tool_runs.network_allowlist`` carry for "no egress", and what
#: ``validate_allowlist`` requires to be non-empty. Since D59 the container does
#: not join a network built from it: ``dispatch_code_scan`` passes
#: ``no_network=True``. Before that it did, and since the name came from this one
#: constant, *every* engagement's code scans ran on one shared bridge.
NO_EGRESS_ALLOWLIST = ["10.255.255.0/29"]


def _code_scan_start(
    conn: Connection,
    *,
    engagement_id: str,
    proposal_id: str,
    capability,
    target: str,
    actor: str,
    execution_context: Mapping[str, Any] | None = None,
    fresh_for_seconds: int = 1800,
    ruleset_path: str | None = None,
    fetched_out: list,
) -> DispatchOutcome | _Started:
    """The first stage of a code scan (D60): everything up to a committed ``running`` run row.

    ``fetched_out`` is an out-parameter: the checkout is appended the moment it exists, so the
    caller's ``finally`` removes it however this stage -- or any later one -- ends. The fetch runs
    inside this stage's transaction, holding a pooled connection for its duration (a shallow clone;
    see ``git_fetch``). It reads, writes nothing, and if the process dies during it nothing was
    committed past ``capability_issued``, so a resumed proposal simply fetches again.

    (The rest of this docstring is the original ``dispatch_code_scan``'s.)

    Run one code-scan action (``code.scan``, ``code.secrets``) and record it (D43, D55).

    A third bespoke dispatch function, alongside :func:`dispatch_scan` and
    :func:`dispatch_collection`, for the same reason ``dispatch_collection``
    is not a branch of ``dispatch_scan``: this action needs an extra step
    the generic adapter call site does not have a place for. Here it is two
    steps, one on each side of the sandbox run — a control-plane-side git
    fetch *before* it (D43-5 Option B: the repository is cloned outside any
    container, with whatever credential this step alone holds, and handed
    in as a read-only bind mount; the scanning container itself never has
    network egress and never holds a git credential) and cleanup *after*.

    The fetch happens, and the commit it resolves to is folded into
    ``execution_context``, *before* the fingerprint is computed and the
    dedup cache is consulted — not after. A ``repo`` scope authorizes a
    repository and a mutable branch (D43-1 Option C), and a branch can move
    between two proposals that name the same target string. Fingerprinting
    on the branch name alone would let a later commit on the same branch
    match an earlier run's fingerprint and be served from cache instead of
    scanned — the exact D11-3 shape (a real difference the dedup cache
    could not see, folded into a v0.3 amendment that put the network
    allowlist into ``execution_context`` for the identical reason), here
    applied to a ref that moved instead of a route that never existed. The
    cost is that a fetch happens even on what turns out to be a dedup hit;
    a shallow clone is cheap enough control-plane-side that this is the
    right side to pay it on, per :mod:`control_plane.orchestrator.git_fetch`'s
    own module docstring.

    A private repository's ``credential_id`` (D44, `docs/
    ADR_CREDENTIAL_VAULT.md` §4.2) is resolved here, via
    ``vault.material_for``, and handed to ``fetch_repo`` as ``auth_token`` --
    never mounted into the sandbox, because the fetch that needs it happens
    entirely before any sandbox exists for this dispatch. ``credential_id``
    absent (D43-6's original public-repo-only scope) means ``auth_token``
    stays ``None`` and this function behaves exactly as it did before D44.
    """
    capability, refusal = _fresh_capability(conn, engagement_id, capability)
    if refusal is not None:
        return refusal

    # The adapter is the one the capability's action names, not a hard-wired
    # one (D55: this function serves every code-scan tool, and was written
    # when there was one). It must also *declare* this function as its
    # dispatch -- an action routed here whose adapter says otherwise is the D45
    # gap, and is refused rather than run with nothing mounted.
    adapter = registry.adapter_for(capability.action)
    if adapter is None or getattr(adapter, "NEEDS_DISPATCH", None) != "dispatch_code_scan":
        # Routed here by the caller naming the action explicitly, the same
        # as dispatch_collection -- refused rather than silently run under
        # the wrong adapter if that ever drifts.
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.refused", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY_DECISION,
            reasons=(registry.UNKNOWN_ACTION,),
            payload={"action": capability.action, "capability_id": capability.capability_id},
        )
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=registry.UNKNOWN_ACTION)

    try:
        plan = adapter.build_plan(
            constraints=capability.constraints, budget=capability.budget.as_dict(),
            target=target,
        )
    except adapter.AdapterError as exc:
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

    try:
        location, branch = parse_repo_scope_value(target)
    except GitFetchError as exc:
        # build_plan already checked for a '#' -- this is defensive, not the
        # expected path, but a malformed scope value is still an unbuildable
        # plan, not a fetch failure: nothing was attempted against a real
        # remote yet.
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.refused", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY_DECISION,
            reasons=(UNBUILDABLE_PLAN,),
            payload={"tool": adapter.TOOL, "error": str(exc),
                     "capability_id": capability.capability_id},
        )
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=UNBUILDABLE_PLAN)

    # A private repository's credential is resolved here, control-plane-side
    # (D44 §4.2): git_fetch.fetch_repo consumes it directly and never returns
    # it, the same trust tier as engagement_ca.mint_leaf_for_host, not the
    # sandbox-mount tier dispatch_collection's LDAP credential needs. Public
    # repos (D43-6's original scope) are unaffected -- credential_id absent
    # means auth_token stays None and fetch_repo behaves exactly as before.
    auth_token = None
    if capability.credential_id is not None:
        try:
            material = vault.material_for(conn, capability.credential_id)
        except vault.VaultError as exc:
            record_audit(
                engagement_id=engagement_id, actor=actor,
                event_type="tool_run.refused", subject_type="action_proposal",
                subject_id=proposal_id, decision=DENY_DECISION,
                reasons=(UNBUILDABLE_PLAN,),
                payload={"tool": adapter.TOOL, "error": str(exc),
                         "capability_id": capability.capability_id},
            )
            _set_state(conn, proposal_id, FAILED)
            return DispatchOutcome(False, None, FAILED, reason=UNBUILDABLE_PLAN)
        if material.credential_type != "git_token":
            record_audit(
                engagement_id=engagement_id, actor=actor,
                event_type="tool_run.refused", subject_type="action_proposal",
                subject_id=proposal_id, decision=DENY_DECISION,
                reasons=(UNBUILDABLE_PLAN,),
                payload={"tool": adapter.TOOL,
                         "error": f"credential_type {material.credential_type!r} is not "
                                  "git_token", "capability_id": capability.capability_id},
            )
            _set_state(conn, proposal_id, FAILED)
            return DispatchOutcome(False, None, FAILED, reason=UNBUILDABLE_PLAN)
        auth_token = material.fields.get("secret")

    try:
        fetched = fetch_repo(
            location, branch, auth_token=auth_token,
            depth=getattr(plan, "fetch_depth", 1),
            bare=getattr(adapter, "FETCH_BARE", False),
        )
    except GitFetchError as exc:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="tool_run.refused", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY_DECISION,
            reasons=(REPO_FETCH_FAILED,),
            payload={"tool": adapter.TOOL, "error": str(exc), "target": target,
                     "capability_id": capability.capability_id},
        )
        _set_state(conn, proposal_id, FAILED)
        return DispatchOutcome(False, None, FAILED, reason=REPO_FETCH_FAILED)

    fetched_out.append(fetched)
    rules_version = adapter.ruleset_version(ruleset_path)
    tool_version = adapter.tool_version()
    ctx = {**dict(execution_context or {}),
           "commit_sha": fetched.commit_sha, "branch": fetched.branch}
    if capability.credential_id is not None:
        ctx["credential_id"] = capability.credential_id
    fingerprint = execution_fingerprint(
        engagement_id=engagement_id, tool=adapter.TOOL, tool_version=tool_version,
        normalized_target=target, normalized_params=plan.as_params(),
        execution_context=fingerprint_context(ctx, NO_EGRESS_ALLOWLIST),
        ruleset_version=rules_version,
    )

    cached = find_cached_run(conn, fingerprint)
    if cached is not None:
        _set_state(conn, proposal_id, SUCCEEDED)
        return DispatchOutcome(False, cached["run_id"], SUCCEEDED, reason="dedup_hit")

    if not claim_for_dispatch(conn, proposal_id):
        state = conn.execute(
            text("SELECT dispatch_state FROM action_proposals WHERE proposal_id = :p"),
            {"p": proposal_id},
        ).scalar_one_or_none()
        return DispatchOutcome(False, None, state or QUEUED, reason="not_claimable")

    run_id = f"RUN-{uuid.uuid4().hex[:12]}"

    conn.execute(
        text("""
            INSERT INTO tool_runs (run_id, engagement_id, proposal_id, capability_id,
                tool, tool_version, ruleset_version, normalized_target, normalized_params,
                execution_context, execution_fingerprint, status, network_allowlist,
                started_at)
            VALUES (:run, :eng, :pid, :cap, :tool, :tver, :rver, :target,
                    CAST(:params AS jsonb), CAST(:ctx AS jsonb), :fp, :status,
                    :allowlist, now())
        """),
        {
            "run": run_id, "eng": engagement_id, "pid": proposal_id,
            "cap": capability.capability_id, "tool": adapter.TOOL, "tver": tool_version,
            "rver": rules_version, "target": target, "params": _json(plan.as_params()),
            "ctx": _json(ctx), "fp": fingerprint,
            "status": RUNNING, "allowlist": list(NO_EGRESS_ALLOWLIST),
        },
    )
    _set_state(conn, proposal_id, RUNNING)
    stages.take(conn, proposal_id, expected=stages.BEFORE_DISPATCH, new=stages.DISPATCHING)
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="tool_run.started",
        subject_type="tool_run", subject_id=run_id,
        payload={"tool": adapter.TOOL, "target": target, "command": list(plan.command),
                 "commit_sha": fetched.commit_sha,
                 "capability_id": capability.capability_id},
    )
    return _Started(
        run_id=run_id, adapter=adapter, plan=plan, tool_version=tool_version,
        target=target, allowlist=list(NO_EGRESS_ALLOWLIST),
        capability_id=capability.capability_id, fresh_for_seconds=fresh_for_seconds,
        ruleset_version=rules_version,
    )


def dispatch_code_scan(
    *,
    engagement_id: str,
    proposal_id: str,
    capability,
    target: str,
    actor: str,
    sandbox: DockerSandbox | None = None,
    execution_context: Mapping[str, Any] | None = None,
    fresh_for_seconds: int = 1800,
    ruleset_path: str | None = None,
) -> DispatchOutcome:
    """Run one code-scan action: start, run, record -- the stages of :func:`dispatch_scan` (D60).

    The checkout the start stage fetches is removed in the ``finally`` below however the stages
    end: a dedup hit, a lost claim race, a sandbox failure and a completed run all leave one on
    disk that nobody else will clean up (``git_fetch.fetch_repo``'s own docstring: the caller owns
    cleanup).
    """
    fetched_out: list = []
    try:
        started = _begin(
            engagement_id, proposal_id,
            lambda conn: _code_scan_start(
                conn, engagement_id=engagement_id, proposal_id=proposal_id,
                capability=capability, target=target, actor=actor,
                execution_context=execution_context, fresh_for_seconds=fresh_for_seconds,
                ruleset_path=ruleset_path, fetched_out=fetched_out,
            ),
        )
        if isinstance(started, DispatchOutcome):
            return started
        fetched = fetched_out[0]
        adapter = started.adapter
        plan = started.plan

        sandbox = sandbox or DockerSandbox(image=adapter.IMAGE)
        ran = _execute(
            lambda: sandbox.run(
                command=plan.command, network_allowlist=NO_EGRESS_ALLOWLIST,
                max_duration_seconds=plan.max_duration_seconds, run_id=started.run_id,
                tmpfs=adapter.TMPFS,
                source_mounts={
                    fetched.local_path: adapter.CONTAINER_REPO_PATH,
                    (ruleset_path or adapter.DEFAULT_RULESET_HOST_PATH):
                        adapter.CONTAINER_RULESET_PATH,
                },
                engagement_id=engagement_id,
                # No segment at all (D59). The allowlist above is the fingerprint's
                # and the audit trail's record that this run had no egress; the
                # container itself joins no network, so there is nothing for
                # another engagement's scan to share with it.
                no_network=True,
            ),
            engagement_id=engagement_id, proposal_id=proposal_id, actor=actor,
            run_id=started.run_id,
        )
        if isinstance(ran, DispatchOutcome):
            return ran

        # A tool may declare that its exit code cannot tell "found nothing" from "could not read
        # the input" (Gitleaks, D55: an unreadable repository is reported as "no leaks found",
        # exit 0). Such a run is FAILED, not SUCCEEDED.
        incomplete_reason = None
        completeness = getattr(adapter, "scan_incomplete_reason", None)
        if ran.succeeded and completeness is not None:
            incomplete_reason = completeness(ran.stdout, ran.stderr)
        return _record_scan_result(
            engagement_id=engagement_id, proposal_id=proposal_id, actor=actor,
            started=started, result=ran, incomplete_reason=incomplete_reason,
            view_fn=lambda out, err: adapter.derive_view(
                out, err, repo_local_path=fetched.local_path,
            ),
        )
    finally:
        for fetched in fetched_out:
            cleanup_repo(fetched.local_path)


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
        # The stage follows the state it describes (D60): an interrupted run's outcome is now
        # recorded -- as unknown -- and the proposal is no longer "dispatching".
        stages.advance(conn, proposal_id, expected=stages.DISPATCHING,
                       new=stages.RECORDED, detail=UNKNOWN_OUTCOME)
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
