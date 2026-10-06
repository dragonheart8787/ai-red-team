"""The narrow function API — the only surface an agent may call (§2).

    create_task / claim_task / propose_action / complete_task / query_*

:func:`propose_action` is the whole pipeline behind one call:

    Target Canonicalizer
        → Authorization Resolver    (Scope Registry)
        → Metadata Resolver         (Authoritative Metadata Registry)
        → Policy Reviewer           (fake now, a real model at MVP-0)
        → OPA
        → Capability Broker
        → Tool Gateway

It is one function on purpose. An orchestration that agents assemble step by
step is an orchestration whose steps can be skipped — and the interesting
skips are precisely the ones that matter: consult the reviewer but not the
registry, obtain a capability without a decision, dispatch without a
capability. Tests drive this function for the same reason. A test that wires
the stages together by hand verifies the wiring the test wrote, not the wiring
production uses, and the two drift apart silently.

MVP-0 replaces exactly one argument: ``reviewer``. Nothing else here changes
when a real model arrives, which is the point of doing it this way now.

**Ordering is a security property, not a style choice.** The reviewer runs
after both resolvers, and its opinion is placed only where the policy reads it
for escalation. It cannot see a decision to influence, and it cannot supply a
fact anything depends on (I6b). After a DENY the function returns; the broker
and the gateway are not reached, rather than reached and refused.

**Where the reviewer's output is recorded, and why not in the registry.** The
reviewer's claim goes to ``audit_log``, beside the authoritative classification
it contradicts. It does *not* become an ``LLM_HINT`` row in the Authoritative
Metadata Registry, even though that tier exists and the resolver already
surfaces such rows as observations.

The reason is §5, which states that the Policy Reviewer AI has no write access
to the registry at all. Since D4.5 that is enforced by the database:
``registry_admin`` writes the registries and this pipeline runs as
``cyberorch_app``. A reviewer able to file its own observation would be writing
to the table the Metadata Resolver reads — the exact channel I6b exists to
close, reached from a different direction. The tier is for classifications an
Engagement Manager records *about* model output, not a channel a model writes
to itself.

So the observations mechanism stays reachable only through the registry_admin
path, and the live reviewer's claim is preserved in the audit trail instead.
That still answers the question §10 cares about — proving the AI lied and the
kernel was not fooled — because the claim and the contradicting classification
are recorded together and can be read back with
``audit.query.reconstruct_decision``.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

from sqlalchemy import Connection, text
from sqlalchemy.exc import SQLAlchemyError

from agents.base_agent import ProposedAction, ProposedTask, ReviewerOpinion
from control_plane.audit.logger import record_audit
from control_plane.canonicalizer.authorization import resolve_authorization
from control_plane.canonicalizer.metadata import resolve_metadata
from control_plane.canonicalizer.target import CanonicalizationError, normalize_target
from control_plane.capability.broker import Budget, get_capability, issue_capability
from control_plane.evidence.redaction import detect_secret_formats
from control_plane.orchestrator import stages
from control_plane.orchestrator.dispatch import (
    dispatch_code_scan,
    dispatch_collection,
    dispatch_scan,
)
from control_plane.policy.engine import build_policy_input, evaluate
from control_plane.policy.merge import EffectivePolicy
from control_plane.provenance import graph
from control_plane.registry.scope_registry import list_scope_objects
from control_plane.state.db import engagement_scope
from tool_gateway.adapters._http import AdapterError
from tool_gateway.registry import adapter_for, side_effect_floor

logger = logging.getLogger("cyberorch.api")

ALLOW = "ALLOW"
DENY = "DENY"
HUMAN_APPROVAL = "HUMAN_APPROVAL"


@dataclass(frozen=True)
class ActionOutcome:
    """Everything the pipeline decided and did, in one object."""

    decision: str
    proposal_id: str
    deny_reasons: tuple[str, ...] = field(default_factory=tuple)
    approval_reasons: tuple[str, ...] = field(default_factory=tuple)
    capability_id: str | None = None
    run_id: str | None = None
    evidence_id: str | None = None
    reviewer_opinion: ReviewerOpinion | None = None
    metadata_authority: str | None = None
    canonical_data_class: tuple[str, ...] = field(default_factory=tuple)
    failure: str | None = None

    @property
    def executed(self) -> bool:
        return self.run_id is not None


# ---------------------------------------------------------------------------
# Task lifecycle (§4.2, §6)
# ---------------------------------------------------------------------------

#: A task is "in flight" when it is queued or being worked. A completed,
#: failed or cancelled task is not work anyone is about to redo, so it is not
#: what an overlap warning is about — the blind-arm harm D17 measured was live
#: leases piling up on the same sweep, not history.
_LIVE_TASK_STATUSES = ("queued", "claimed", "running")


def _task_identity(action: str, target: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """The target-level work identity of a task (ADR_TASK_IDENTITY.md, Option 1).

    Returns ``(canonical_target, identity_key)``. ``canonical_target`` is the
    logical identity — ``type:value`` — at host/network granularity, from the
    real Target Canonicalizer, so ``10.79.0.0/24`` and any other spelling of
    that network collapse to one value. Deliberately *not* ``CanonicalTarget.
    normalized``: that appends a port when one is present, and Option 1's whole
    point is that the task layer identifies work at host granularity and leaves
    the port distinction to §7's execution fingerprint.

    ``identity_key`` is ``action`` and that canonical target together. Scope is
    not in it: the same host under two valid scope objects is the same work.

    Both are ``None`` when the target will not canonicalize — a task nobody can
    reduce must match nothing rather than match everything (that would be a
    fail-open drop, the exact failure §1.2c/ADR G call a security bug).
    """
    try:
        canonical = normalize_target(dict(target))
    except CanonicalizationError:
        return None, None
    identity = canonical.logical_identity
    canonical_target = f"{identity.type}:{identity.value}"
    return canonical_target, f"{action}\x1f{canonical_target}"


def create_task(
    conn: Connection, *, engagement_id: str, task: ProposedTask, created_by: str
) -> str:
    """Create a task, and mark — never drop — any in-flight task it overlaps (§11.3).

    ADR_TASK_IDENTITY.md Option 1. The task is always inserted; if its
    target-level identity matches tasks already in flight in this engagement,
    ``overlaps_with`` is populated on the new task and symmetrically on the ones
    it matched. A duplicate is made visible to the Supervisor and to a human,
    not deleted: dropping a task that turns out not to be redundant is a false
    negative, and §1.2c is explicit that that is a security bug, while §7 still
    deduplicates the redundant *execution* downstream where it is safe to.
    """
    task_id = f"TASK-{uuid.uuid4().hex[:10]}"
    canonical_target, identity_key = _task_identity(task.action, task.target)

    overlaps: list[str] = []
    if identity_key is not None:
        overlaps = [
            row[0]
            for row in conn.execute(
                text("""
                    SELECT task_id FROM tasks
                    WHERE engagement_id = :eid
                      AND identity_key = :key
                      AND status = ANY(:live)
                """),
                {"eid": engagement_id, "key": identity_key,
                 "live": list(_LIVE_TASK_STATUSES)},
            )
        ]

    conn.execute(
        text("""
            INSERT INTO tasks (task_id, engagement_id, goal, created_by, priority,
                               action, canonical_target, scope_object_id,
                               identity_key, overlaps_with)
            VALUES (:tid, :eid, :goal, :by, :priority,
                    :action, :ctarget, :scope, :key, :overlaps)
        """),
        {"tid": task_id, "eid": engagement_id, "goal": task.goal,
         "by": created_by, "priority": task.priority,
         "action": task.action, "ctarget": canonical_target,
         "scope": task.scope_object_id, "key": identity_key,
         "overlaps": overlaps},
    )
    if overlaps:
        # Symmetric: each existing task now points back at the new one, so the
        # overlap is readable from either end. array_append rather than a
        # rewrite, so a task overlapping three others accumulates all three.
        conn.execute(
            text("""
                UPDATE tasks
                SET overlaps_with = array_append(overlaps_with, :new),
                    updated_at = now()
                WHERE task_id = ANY(:ids)
            """),
            {"new": task_id, "ids": overlaps},
        )
    record_audit(
        engagement_id=engagement_id, actor=created_by, event_type="task.created",
        subject_type="task", subject_id=task_id,
        payload={"goal": task.goal, "identity_key": identity_key,
                 "overlaps_with": overlaps},
    )
    return task_id


def claim_task(conn: Connection, *, engagement_id: str, agent_id: str) -> str | None:
    """Claim one queued task (§6).

    ``FOR UPDATE SKIP LOCKED`` plus a lease, so two workers cannot take the
    same task and a worker that dies does not strand it.
    """
    task_id = conn.execute(
        text("""
            UPDATE tasks
            SET status = 'claimed', owner_agent_id = :agent,
                lease_expires_at = now() + interval '5 minutes', updated_at = now()
            WHERE task_id = (
                SELECT task_id FROM tasks
                WHERE status = 'queued' AND engagement_id = :eid
                ORDER BY priority DESC, created_at ASC
                FOR UPDATE SKIP LOCKED LIMIT 1
            )
            RETURNING task_id
        """),
        {"agent": agent_id, "eid": engagement_id},
    ).scalar_one_or_none()
    if task_id is not None:
        # Which agent took which task, and when. Without this the audit trail
        # attributes everything downstream to the orchestrator, and the agent
        # that actually did the work appears nowhere.
        record_audit(
            engagement_id=engagement_id, actor=agent_id, event_type="task.claimed",
            subject_type="task", subject_id=task_id,
            payload={"lease_seconds": 300},
        )
    return task_id


def complete_task(
    conn: Connection, *, engagement_id: str, task_id: str, result_summary: str, actor: str
) -> None:
    conn.execute(
        text("UPDATE tasks SET status = 'completed', result_summary = :s, "
             "updated_at = now() WHERE task_id = :tid"),
        {"tid": task_id, "s": result_summary},
    )
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="task.completed",
        subject_type="task", subject_id=task_id, payload={"result": result_summary},
    )


# ---------------------------------------------------------------------------
# propose_action — the pipeline
# ---------------------------------------------------------------------------

#: Every dispatch function an issued capability can be routed to, named
#: exactly as each adapter's own ``NEEDS_DISPATCH`` constant spells it
#: (D46). This dict, not a hand-written if/elif on ``capability.action``, is
#: what makes the correspondence checkable: ``tests/test_dispatch_routing
#: .py`` iterates every action in ``registry.ADAPTERS`` and asserts this
#: table's entry for it is exactly the function the adapter names.
_DISPATCH_FUNCTIONS = {
    "dispatch_scan": dispatch_scan,
    "dispatch_collection": dispatch_collection,
    "dispatch_code_scan": dispatch_code_scan,
}


def _dispatch_for_action(
    *,
    engagement_id: str,
    proposal_id: str,
    capability,
    target: str,
    actor: str,
    sandbox,
    network_allowlist: Sequence[str] | None,
    execution_context: Mapping[str, Any] | None,
    proxy_url: str | None,
    ca_cert_pem: str | None,
    proxy_cert_spki: str | None,
):
    """Route to the dispatch function this issued capability's action needs.

    ``dispatch_scan`` is the generic path every single-target scan action
    shares. ``ad.collect`` (D42) and ``code.scan`` (D43) each need a second,
    action-specific step their own bespoke dispatch function alone
    performs — the Security Graph write, and the control-plane-side git
    fetch/cleanup, respectively — that ``dispatch_scan`` does not know how
    to do.

    **This routing did not exist until D45.** Every call to
    ``propose_action`` for either action, since the day each shipped, ran
    ``dispatch_scan`` instead: the underlying tool would execute, but
    ``ad.collect``'s Security Graph batch would never be written and
    ``code.scan``'s repository would never be fetched at all (its
    container would start with nothing mounted at ``CONTAINER_REPO_PATH``
    and fail immediately). D42's and D43's own test suites never caught
    this because they called ``dispatch_collection``/``dispatch_code_scan``
    directly, never ``propose_action`` — exactly the shape of gap this
    module's own docstring warns about: "a test that wires the stages
    together by hand verifies the wiring the test wrote, not the wiring
    production uses." D45, which insisted on driving a real proposal
    through the one real production entry point instead of calling a
    dispatch function directly, is what finally exercised this path and
    found it broken.

    **D46 rebuilt this as a declaration, not a guess.** The original D45 fix
    was still a hand-written ``if capability.action == ad_collector.ACTION``
    — correct for the two actions it named, but exactly the shape that let
    the bug exist in the first place: a *third* action needing its own
    dispatch function would only be caught here if whoever added it also
    remembered to add a branch here, in a file its own adapter module never
    has to import or know about. Every adapter now names its own requirement
    (``NEEDS_DISPATCH``, checked structurally as a required constant, not an
    optional one an adapter could omit) and this function does nothing but
    look it up and call it — there is no per-action branch left to forget.
    """
    import inspect

    from tool_gateway.registry import adapter_for

    adapter = adapter_for(capability.action)
    # No adapter at all is the one case this function does not resolve
    # itself: routed to dispatch_scan, whose own UNKNOWN_ACTION branch is the
    # single place that refusal is decided and audited (registry.py's own
    # docstring: "a capability whose action has no adapter is refused rather
    # than defaulted to one").
    dispatch_name = adapter.NEEDS_DISPATCH if adapter is not None else "dispatch_scan"
    dispatch_fn = _DISPATCH_FUNCTIONS[dispatch_name]

    all_kwargs = {
        "engagement_id": engagement_id, "proposal_id": proposal_id,
        "capability": capability, "target": target, "actor": actor,
        "sandbox": sandbox,
        "network_allowlist": list(network_allowlist) if network_allowlist else None,
        "execution_context": execution_context,
        "proxy_url": proxy_url, "ca_cert_pem": ca_cert_pem,
        "proxy_cert_spki": proxy_cert_spki,
    }
    # Each dispatch function accepts a different subset (dispatch_collection
    # takes no proxy_*; dispatch_code_scan takes no network_allowlist either)
    # — handed only what its own signature declares, the same
    # inspect.signature technique dispatch.py's own _build_plan_params
    # already uses to hand each adapter only the proxy-trust input it takes.
    accepted = frozenset(inspect.signature(dispatch_fn).parameters)
    return dispatch_fn(**{k: v for k, v in all_kwargs.items() if k in accepted})


#: Deny reasons for a proposal whose request body is refused at the door.
BODY_INVALID = "web_post_body_invalid"
BODY_HAS_SECRET_FORMAT = "body_contains_secret_format"


def body_secret_formats(body: str) -> tuple[str, ...]:
    """The known secret formats in a request body, as sent *and* as decoded.

    The redactor's patterns are written against text as a person would read it.
    A body is often form-encoded (``application/x-www-form-urlencoded`` is the
    adapter's default), where ``Bearer%20<token>`` or ``%3A``/``%40`` inside a
    URL credential would pass a check of the raw string on the encoding alone.
    So both the raw and the percent-decoded form are checked. Still a known set of
    shapes and no more (see :mod:`control_plane.evidence.redaction`).
    """
    found = list(detect_secret_formats(body))
    for label in detect_secret_formats(unquote_plus(body)):
        if label not in found:
            found.append(label)
    return tuple(found)


def refuse_proposed_body(proposal: ProposedAction) -> tuple[str, str] | None:
    """``(deny_reason, failure)`` if this proposal's body must be refused, else None.

    ACCEPTANCE 5.29, option C. A body is Worker-authored, *constructed* test data.
    A real secret enters an execution path only through the D44 vault (ADR
    section 0), so a body that matches a known secret **format** is refused
    outright -- not masked, because the approved body and the sent body must be
    the same bytes (D30). Run before ``_persist_proposal`` on purpose: a body
    that got as far as the proposal row, the reviewer's prompt or the audit
    trail would already have reached the surfaces the analysis lists, and a
    refusal after that would be too late.

    Applies only to an adapter that declares ``CARRIES_BODY`` (web.post); for any
    other action ``body`` is not a field anyone reads. The failure message names
    the *formats* found, never the value.

    A proposal that names no body is not judged here: it stays what it was, a
    capability ``build_plan`` refuses as unbuildable, so this change alters no
    decision for it.
    """
    adapter = adapter_for(proposal.action)
    if adapter is None or not getattr(adapter, "CARRIES_BODY", False):
        return None
    target = proposal.target
    if "body" not in target:
        return None
    try:
        adapter.validate_body(
            {"body": target["body"], "content_type": target.get("content_type")}
        )
    except AdapterError as exc:
        return BODY_INVALID, str(exc)
    formats = body_secret_formats(target["body"])
    if formats:
        return BODY_HAS_SECRET_FORMAT, (
            f"the request body matches a known secret format ({', '.join(formats)}). "
            "A web.post body must be constructed test data; a real credential "
            "belongs in the D44 vault, which has no delivery path for a request "
            "body yet (ACCEPTANCE 5.29)"
        )
    return None



@dataclass
class _Run:
    """One ``propose_action`` call: what it was given, and what its stages have learned."""

    engagement_id: str
    proposal: ProposedAction
    target: Any
    reviewer: Any
    policy: EffectivePolicy
    agent_id: str
    actor: str
    sandbox: Any
    network_allowlist: Sequence[str] | None
    execution_context: Mapping[str, Any] | None
    capability_ttl_seconds: int | None
    requested_budget: Budget
    proxy_url: str | None
    ca_cert_pem: str | None
    proxy_cert_spki: str | None
    credential_id: str | None
    # Learned as the stages run. None when this call resumed a proposal past the stage that
    # produces them -- the committed rows are then the source of truth, not this object.
    opinion: ReviewerOpinion | None = None
    metadata: Any = None
    decision: Any = None


#: Returned by a stage that lost the race for its own transition: someone else (a retry, a
#: restarted service) already moved the proposal on. Not a failure -- the driver reloads the stage
#: and goes on.
_RELOAD = object()


def propose_action(
    *,
    engagement_id: str,
    proposal: ProposedAction,
    reviewer,
    policy: EffectivePolicy,
    agent_id: str,
    actor: str = "orchestrator",
    sandbox=None,
    network_allowlist: Sequence[str] | None = None,
    execution_context: Mapping[str, Any] | None = None,
    capability_ttl_seconds: int | None = None,
    budget: Budget | None = None,
    proxy_url: str | None = None,
    ca_cert_pem: str | None = None,
    proxy_cert_spki: str | None = None,
    credential_id: str | None = None,
    idempotency_key: str | None = None,
) -> ActionOutcome:
    """Canonicalize, resolve, review, decide, and only then act -- in stages that each commit.

    **This function takes no connection (D58-5, D60).** It used to run on one the caller opened,
    which made the whole pipeline one transaction that committed only at the caller's exit: a crash,
    a Postgres restart or a kill switch in the middle rolled every state row back and left only the
    audit trail to say anything had started. It now opens its own short transactions, the way
    ``record_audit`` always has, and each commits before the next begins:

    1. **Decide.** The proposal row is committed (``received``); authorization and metadata are
       resolved; the reviewer is asked and OPA decides *with no transaction held*; then the decision
       and its reasons are committed (``decided``, or ``closed`` for a DENY / HUMAN_APPROVAL).
    2. **Issue.** Only for an ALLOW. The broker re-checks the engagement, the kill switch, the
       credential, the scope and the approval and, if it issues, the capability commits
       (``capability_issued``); if it refuses, the proposal closes with the reasons.
    3. **Dispatch** (``dispatch.py``): the run row commits as ``running`` *before* a container
       exists (``dispatching``); the container runs with no connection held; the evidence and the
       result commit in their own short transaction the moment it exits (``recorded``).
    4. **Provenance.** Written afterwards, derived from the committed rows, and repeatable: a
       failure here cannot touch a result that is already recorded.

    Every transition is a conditional UPDATE (``stages.py``) taken at the start of the transaction
    that does the stage's work, so a stage happens once however many times it is attempted. A
    proposal's stage (``action_proposals.pipeline_stage``) is therefore always the last one whose
    work is fully committed -- that is what a restarted service, or a reconciler, reads.

    **Retrying is safe.** ``idempotency_key`` names the request: a second call with the same key
    does not create a second proposal. It finds the first, reads its stage, and carries on from the
    next stage -- never repeating one that committed (no second decision, no second capability, no
    second dispatch). With no key every call is a new proposal, as before. A key reused for a
    *different* action or target is refused. A resumed call needs the same arguments it was first
    given; a proposal found at ``dispatching`` is not re-dispatched (the container may be running
    or may have run: that is ``unknown_outcome``, the reconciler's, §8.8).

    ``credential_id`` (D44/D45) names a Vault-stored credential the issued
    capability should carry — the caller's job to supply, the same way it
    already supplies ``budget``: this function does not choose one on its
    own initiative, it only threads through what it is given.

    ``proxy_url`` / ``ca_cert_pem`` / ``proxy_cert_spki`` are the egress-proxy
    inputs for web.* actions (§8.3, D34/D35/D36). They are threaded straight to
    the Tool Gateway, which hands each adapter only the ones its ``build_plan``
    declares; a non-web action ignores them.
    """
    proposal_id = f"PROP-{uuid.uuid4().hex[:10]}"

    # --- 1. Target Canonicalizer -------------------------------------------
    try:
        target = normalize_target(proposal.target)
    except CanonicalizationError as exc:
        # I10: a target that cannot be normalized is not a target that gets a
        # best guess. Nothing downstream runs.
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="proposal.rejected", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY,
            reasons=("target_not_canonicalizable",), payload={"error": str(exc)},
        )
        return ActionOutcome(
            decision=DENY, proposal_id=proposal_id,
            deny_reasons=("target_not_canonicalizable",), failure=str(exc),
        )

    # --- 1b. The request body, before anything records it ---------------------
    body_refusal = refuse_proposed_body(proposal)
    if body_refusal is not None:
        reason, failure = body_refusal
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="proposal.rejected", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY, reasons=(reason,),
            # The refusal is recorded; the body never is. `failure` names the
            # formats found and is safe to store.
            payload={"error": failure, "action": proposal.action},
        )
        return ActionOutcome(
            decision=DENY, proposal_id=proposal_id,
            deny_reasons=(reason,), failure=failure,
        )

    run = _Run(
        engagement_id=engagement_id, proposal=proposal, target=target, reviewer=reviewer,
        policy=policy, agent_id=agent_id, actor=actor, sandbox=sandbox,
        network_allowlist=network_allowlist, execution_context=execution_context,
        capability_ttl_seconds=capability_ttl_seconds,
        # Resolved before the decision rather than at the broker, because since D12 the policy
        # checks the requested budget against the size of the target (I3). The same object then
        # goes to the broker, so what OPA judged and what was issued cannot come apart.
        requested_budget=budget or Budget(max_duration_seconds=120),
        proxy_url=proxy_url, ca_cert_pem=ca_cert_pem, proxy_cert_spki=proxy_cert_spki,
        credential_id=credential_id,
    )

    # --- Stage 0: the proposal row, committed -------------------------------
    key = idempotency_key or f"idem-{proposal_id}"
    with engagement_scope(engagement_id) as conn:
        inserted = _persist_proposal(conn, engagement_id, proposal_id, proposal, target,
                                     agent_id, key)
        if inserted:
            # Attributed to the agent, unlike everything after it, which the
            # orchestrator does. "Which agent asked for this" is otherwise only in the
            # proposal row, and the audit trail should stand on its own.
            record_audit(
                engagement_id=engagement_id, actor=agent_id, event_type="proposal.submitted",
                subject_type="action_proposal", subject_id=proposal_id,
                payload={
                    "action": proposal.action,
                    "target": target.normalized,
                    "authorization": dict(proposal.authorization),
                    "discovery": dict(proposal.discovery),
                    "task_id": proposal.task_id,
                },
            )
        else:
            existing = conn.execute(
                text("SELECT proposal_id, action, target ->> 'normalized' AS normalized "
                     "FROM action_proposals "
                     "WHERE engagement_id = :e AND request_idempotency_key = :k"),
                {"e": engagement_id, "k": key},
            ).mappings().one()
    if not inserted:
        proposal_id = existing["proposal_id"]
        if existing["action"] != proposal.action or existing["normalized"] != target.normalized:
            # The key names a request; a different request under it is a bug in the caller, and
            # silently resuming the first would run something nobody asked for under this name.
            record_audit(
                engagement_id=engagement_id, actor=actor,
                event_type="proposal.rejected", subject_type="action_proposal",
                subject_id=proposal_id, decision=DENY,
                reasons=("idempotency_key_reused_with_a_different_request",),
                payload={"action": proposal.action, "target": target.normalized},
            )
            return ActionOutcome(
                decision=DENY, proposal_id=proposal_id,
                deny_reasons=("idempotency_key_reused_with_a_different_request",),
                failure="idempotency key names a different action or target",
            )
    return _drive(run, proposal_id)


def _stage_of(engagement_id: str, proposal_id: str) -> tuple[str, str | None]:
    with engagement_scope(engagement_id) as conn:
        return stages.stage_of(conn, proposal_id)


def _drive(run: _Run, proposal_id: str) -> ActionOutcome:
    """Carry a proposal from whatever stage it is in to the end, committing as it goes."""
    for _ in range(8):
        stage, _detail = _stage_of(run.engagement_id, proposal_id)
        if stage == stages.RECEIVED:
            out = _decide(run, proposal_id)
        elif stage == stages.DECIDED:
            out = _issue(run, proposal_id)
        elif stage == stages.CAPABILITY_ISSUED:
            out = _dispatch(run, proposal_id)
        else:
            # dispatching / recorded / closed: nothing left for this call to do. Reached by a
            # resumed proposal; a fresh one returns from the stage that finished it.
            return _outcome_from_rows(run, proposal_id)
        if out is not None and out is not _RELOAD:
            return out
    raise RuntimeError(f"proposal {proposal_id!r} did not settle after repeated stage passes")


def _common(run: _Run, proposal_id: str) -> dict[str, Any]:
    decision = run.decision
    return {
        "proposal_id": proposal_id,
        "deny_reasons": decision.deny_reasons if decision else (),
        "approval_reasons": decision.approval_reasons if decision else (),
        "reviewer_opinion": run.opinion,
        "metadata_authority": run.metadata.authority if run.metadata else None,
        "canonical_data_class": run.metadata.data_class if run.metadata else (),
    }


def _decide(run: _Run, proposal_id: str) -> ActionOutcome | object | None:
    """Stage 1: resolve, review, decide -- then commit the decision and nothing else."""
    proposal, target, eid = run.proposal, run.target, run.engagement_id

    # Reads only, in a transaction of their own: nothing below holds a connection while the
    # reviewer (a model call) and OPA (a subprocess) run.
    with engagement_scope(eid) as conn:
        # --- 2. Authorization Resolver ---
        authorization = resolve_authorization(
            conn, target=target, action=proposal.action,
            authorization=proposal.authorization,
        )
        # --- 3. Metadata Resolver ---
        metadata = resolve_metadata(conn, target=target)
        scope_objects = list_scope_objects(conn)
    run.metadata = metadata

    # --- 4. Policy Reviewer --------------------------------------------------
    # Runs after the resolvers so it cannot influence what they found, and its
    # output is recorded before the decision so a later reader can see what the
    # reviewer claimed alongside what the registry said. That pairing is the
    # evidence for "the AI lied and the kernel was not fooled"; without it the
    # audit trail would show only that the AI said nothing.
    opinion: ReviewerOpinion = run.reviewer.review(proposal=proposal, canonical_target=target)
    run.opinion = opinion
    record_audit(
        engagement_id=eid, actor=opinion.reviewer_id,
        event_type="policy_reviewer.opinion", subject_type="action_proposal",
        subject_id=proposal_id,
        payload={
            "opinion": opinion.as_dict(),
            # Recorded side by side on purpose. The reviewer's claim is only
            # interesting next to the classification it contradicts.
            "authoritative_classification": {
                "authority": metadata.authority,
                "known": metadata.known,
                "data_class": list(metadata.data_class),
            },
            "note": "advisory only; may tighten the decision, never satisfy a "
                    "prerequisite (I6b)",
        },
    )

    # --- 5. OPA --------------------------------------------------------------
    side_effects = side_effect_floor(
        action=proposal.action,
        writes_data=proposal.writes_data,
        changes_state=proposal.changes_state,
    )
    policy_input = build_policy_input(
        target=target, action=proposal.action, authorization=authorization,
        metadata=metadata, policy=run.policy,
        scope_objects=scope_objects,
        # The reviewer's words enter here and only here. Both fields are read
        # by approval_reasons alone, so the worst a dishonest reviewer can do
        # is ask for a human.
        risk_hint=opinion.risk_hint,
        possible_sensitive_data_hint=opinion.possible_sensitive_data_hint,
        discovery=proposal.discovery,
        # The Worker's claim, floored by what the action's tool actually does
        # (D34). The floor only raises: lowering it would be the system overriding an agent's
        # caution with its own optimism, the one direction I6c forbids. See
        # ``registry.side_effect_floor`` for the argument in full.
        writes_data=side_effects.writes_data,
        changes_state=side_effects.changes_state,
        capability_request=run.requested_budget.as_dict(),
    )
    decision = evaluate(policy_input)
    run.decision = decision

    # --- the decision, committed ----------------------------------------------
    allowed = decision.decision == ALLOW
    try:
        with engagement_scope(eid) as conn:
            # First statement: win the transition, or do nothing at all. The audit record below
            # is written only by the winner.
            stages.take(
                conn, proposal_id, expected=stages.RECEIVED,
                new=stages.DECIDED if allowed else stages.CLOSED,
                detail=None if allowed else f"decision_{decision.decision}",
            )
            _record_decision(
                conn, proposal_id, decision,
                authorized_scope_object_id=authorization.scope_object_id,
                classified_asset_id=metadata.asset_id,
            )
            record_audit(
                engagement_id=eid, actor=run.actor, event_type="policy.decided",
                subject_type="action_proposal", subject_id=proposal_id,
                decision=decision.decision,
                reasons=decision.deny_reasons + decision.approval_reasons,
                payload={
                    "authorization": authorization.as_dict(),
                    "resource_metadata": metadata.as_dict(),
                    "reviewer_opinion": opinion.as_dict(),
                    "engine_error": decision.engine_error,
                },
            )
    except stages.StageConflict:
        return _RELOAD

    if not allowed:
        # The function returns here. The Capability Broker and the Tool Gateway
        # are not called — not called and refused, not called with an empty
        # budget. Nothing downstream of this line runs.
        _record_provenance(run, proposal_id)
        return ActionOutcome(decision=decision.decision, **_common(run, proposal_id))
    return None


def _issue(run: _Run, proposal_id: str) -> ActionOutcome | object | None:
    """Stage 2: the broker's decision, committed on its own (independent of dispatch)."""
    proposal, eid = run.proposal, run.engagement_id
    capability_id = f"CAP-{uuid.uuid4().hex[:10]}"
    try:
        with engagement_scope(eid) as conn:
            stages.take(conn, proposal_id, expected=stages.DECIDED,
                        new=stages.CAPABILITY_ISSUED)
            scope_object_id = conn.execute(
                text("SELECT authorized_scope_object_id FROM action_proposals "
                     "WHERE proposal_id = :p"),
                {"p": proposal_id},
            ).scalar_one()
            # check_preconditions runs here, in this stage and not at the start of the
            # pipeline: the engagement's status, the kill switch, the credential, the scope
            # object and the approval are asked *now*, however long ago the decision was made.
            issued = issue_capability(
                conn, engagement_id=eid, capability_id=capability_id,
                agent_id=run.agent_id, action=proposal.action, actor=run.actor,
                constraints=execution_constraints(
                    proposal.target, run.target.logical_identity.value
                ),
                budget=run.requested_budget,
                ttl_seconds=run.capability_ttl_seconds
                or proposal.requested_capability_ttl_seconds,
                proposal_id=proposal_id,
                # The scope object the resolver actually authorized against, carried
                # forward so every later heartbeat can re-check that it still stands
                # (I8). Taken from the resolution rather than from the proposal: the
                # proposal is what an agent asked for, the resolution is what was
                # granted, and only the second is a fact about this system.
                scope_object_id=scope_object_id,
                credential_id=run.credential_id,
            )
            if not issued.issued:
                stages.take(
                    conn, proposal_id, expected=stages.CAPABILITY_ISSUED, new=stages.CLOSED,
                    detail="capability_refused:" + ",".join(issued.reasons),
                )
    except stages.StageConflict:
        return _RELOAD
    if not issued.issued:
        # The policy said yes and the broker said no. Both are recorded; the
        # disagreement is the interesting part and must not be flattened.
        _record_provenance(run, proposal_id)
        return ActionOutcome(
            decision=DENY, deny_reasons=tuple(issued.reasons),
            failure="capability_refused",
            **{k: v for k, v in _common(run, proposal_id).items() if k != "deny_reasons"},
        )
    return None


def _dispatch(run: _Run, proposal_id: str) -> ActionOutcome:
    """Stage 3: hand the committed capability to the dispatch function that action needs."""
    eid = run.engagement_id
    with engagement_scope(eid) as conn:
        capability_id = conn.execute(
            text("SELECT capability_id FROM capabilities WHERE proposal_id = :p "
                 "ORDER BY issued_at DESC LIMIT 1"),
            {"p": proposal_id},
        ).scalar_one_or_none()
        capability = get_capability(conn, capability_id) if capability_id else None
    if capability is None:
        # The stage says a capability was issued and none is there. Nothing runs.
        with engagement_scope(eid) as conn:
            stages.advance(conn, proposal_id, expected=stages.CAPABILITY_ISSUED,
                           new=stages.CLOSED, detail="capability_missing")
        return ActionOutcome(
            decision=ALLOW, failure="capability_missing", **_common(run, proposal_id),
        )

    outcome = _dispatch_for_action(
        engagement_id=eid, proposal_id=proposal_id, capability=capability,
        target=run.target.logical_identity.value, actor=run.actor, sandbox=run.sandbox,
        network_allowlist=run.network_allowlist, execution_context=run.execution_context,
        proxy_url=run.proxy_url, ca_cert_pem=run.ca_cert_pem,
        proxy_cert_spki=run.proxy_cert_spki,
    )
    _record_provenance(run, proposal_id)
    return ActionOutcome(
        decision=ALLOW, capability_id=capability.capability_id, run_id=outcome.run_id,
        evidence_id=outcome.evidence_id, failure=outcome.reason,
        **_common(run, proposal_id),
    )


def _record_provenance(run: _Run, proposal_id: str) -> None:
    """Provenance, after the result and apart from it (D60).

    A failure here is logged and nothing else: the proposal's result is already committed, and
    ``graph.record_provenance`` can be run again for it (``provenance_complete`` says whether it
    has been).
    """
    try:
        with engagement_scope(run.engagement_id) as conn:
            graph.record_provenance(
                conn, engagement_id=run.engagement_id, proposal_id=proposal_id,
            )
    except SQLAlchemyError as exc:
        logger.error(
            "provenance for %s was not recorded (%s); its result is committed and "
            "graph.record_provenance can be run again", proposal_id, exc,
        )


def _outcome_from_rows(run: _Run, proposal_id: str) -> ActionOutcome:
    """The outcome of a proposal that this call found already past the stages it could drive.

    Built from what is committed -- the point of committing it -- and nothing is re-executed. A
    proposal found ``dispatching`` is reported as such and left alone: its container may be
    running or may have run, which is ``unknown_outcome``, and the reconciler's to resolve.
    """
    with engagement_scope(run.engagement_id) as conn:
        row = conn.execute(
            text("SELECT decision, decision_reasons, pipeline_stage, stage_detail "
                 "FROM action_proposals WHERE proposal_id = :p"),
            {"p": proposal_id},
        ).mappings().one()
        capability_id = conn.execute(
            text("SELECT capability_id FROM capabilities WHERE proposal_id = :p "
                 "ORDER BY issued_at DESC LIMIT 1"),
            {"p": proposal_id},
        ).scalar_one_or_none()
        run_row = conn.execute(
            text("SELECT run_id FROM tool_runs WHERE proposal_id = :p "
                 "ORDER BY started_at DESC, run_id DESC LIMIT 1"),
            {"p": proposal_id},
        ).scalar_one_or_none()
        evidence_id = conn.execute(
            text("SELECT evidence_id FROM evidence WHERE run_id = :r LIMIT 1"),
            {"r": run_row},
        ).scalar_one_or_none() if run_row else None
    stage, detail = row["pipeline_stage"], row["stage_detail"] or ""
    reasons = tuple(row["decision_reasons"] or ())
    decision, failure = row["decision"] or DENY, None
    deny, approval = (reasons if decision == DENY else ()), (
        reasons if decision == HUMAN_APPROVAL else ())
    if stage == stages.DISPATCHING:
        failure = "dispatch_in_progress_or_unknown_outcome"
    elif detail.startswith("capability_refused:"):
        decision, deny, failure = DENY, tuple(detail.split(":", 1)[1].split(",")), \
            "capability_refused"
    elif stage == stages.CLOSED and not detail.startswith("decision_"):
        failure = "dedup_hit" if detail.startswith("dedup_hit:") else detail or None
        if detail.startswith("dedup_hit:"):
            run_row = detail.removeprefix("dedup_hit:")
    elif stage == stages.RECORDED and detail not in ("succeeded", "failed"):
        failure = detail or None
    if stage in stages.TERMINAL:
        _record_provenance(run, proposal_id)
    return ActionOutcome(
        decision=decision, proposal_id=proposal_id, deny_reasons=deny,
        approval_reasons=approval, capability_id=capability_id, run_id=run_row,
        evidence_id=evidence_id, failure=failure,
        reviewer_opinion=run.opinion,
        metadata_authority=run.metadata.authority if run.metadata else None,
        canonical_data_class=run.metadata.data_class if run.metadata else (),
    )


# ---------------------------------------------------------------------------
# Read-only queries agents may make (§2)
# ---------------------------------------------------------------------------

def query_evidence(conn: Connection, *, evidence_id: str) -> dict[str, Any] | None:
    """Return the derived view only.

    §4.4: the raw artifact never enters an LLM context. Not returning it here
    means no caller has to remember that.
    """
    row = conn.execute(
        text("SELECT evidence_id, run_id, tool, tool_version, derived_view "
             "FROM evidence WHERE evidence_id = :e"),
        {"e": evidence_id},
    ).mappings().one_or_none()
    return dict(row) if row else None


def query_state(
    conn: Connection,
    *,
    engagement_id: str,
    task_status: Sequence[str] | None = None,
    task_limit: int = 50,
    decision_limit: int = 20,
) -> dict[str, Any]:
    """What has happened in this engagement so far (§2).

    Counts alone were enough while the only planner was scripted. A real
    Supervisor (D17) has to decide what to do *next*, and a summary that cannot
    say which tasks already exist leaves it no way to answer that except by
    guessing — so this returns the task ledger and the recent decisions as well.

    **Read-only, and deliberately not an execution interface.** §2 draws the
    line at what an agent may *call*, not at what it may know: tool invocation,
    shell, network and registry writes stay absent, and adding a way to read
    state does not move that line. Three properties keep it on the right side:

    * Nothing here writes, and the whole function runs on the ordinary
      ``cyberorch_app`` connection, which holds SELECT and no more on these
      tables. D17 added no grant.
    * Every row is confined to the current engagement by RLS, exactly as the
      rest of the pipeline is (I4). There is no engagement-wide or
      cross-engagement variant of this call and no parameter that could ask for
      one — the ``engagement_id`` argument names the connection's own scope for
      the audit trail's benefit, it does not select which engagement to read.
    * ``filter`` in §2's signature is spelled here as explicit keyword
      arguments rather than a free-form predicate. A filter object that became
      SQL would be a query interface an agent could widen from the inside;
      ``task_status`` is checked against a fixed set and everything else is a
      bound parameter.

    What it does newly expose, stated plainly rather than glossed: an agent can
    now see decisions on proposals *other agents* made in the same engagement.
    Each such row was already returned to whoever submitted it — this is the
    same content with a wider readership, bounded by the engagement. §5's
    isolation boundary is the engagement, not the agent, so this is inside it;
    it is still a widening, and D17's report says so.
    """
    counts = conn.execute(
        text("""
            SELECT
              (SELECT count(*) FROM tasks) AS tasks,
              (SELECT count(*) FROM action_proposals) AS proposals,
              (SELECT count(*) FROM capabilities WHERE revoked IS FALSE) AS capabilities,
              (SELECT count(*) FROM tool_runs) AS runs,
              (SELECT count(*) FROM evidence) AS evidence
        """)
    ).mappings().one()

    statuses = _valid_task_statuses(task_status)
    tasks = conn.execute(
        text("""
            SELECT task_id, goal, status, owner_agent_id, created_by,
                   parent_task_id, overlaps_with, priority, result_summary,
                   lease_expires_at, created_at
            FROM tasks
            WHERE (:all_statuses OR status = ANY(:statuses))
            ORDER BY created_at ASC
            LIMIT :limit
        """),
        {"all_statuses": statuses is None, "statuses": list(statuses or ()),
         "limit": max(0, int(task_limit))},
    ).mappings().all()

    decisions = conn.execute(
        text("""
            SELECT proposal_id, task_id, agent_id, action,
                   target -> 'logical_identity' ->> 'value' AS target_value,
                   target -> 'logical_identity' ->> 'type' AS target_type,
                   decision, decision_reasons, created_at
            FROM action_proposals
            WHERE decision IS NOT NULL
            ORDER BY created_at DESC
            LIMIT :limit
        """),
        {"limit": max(0, int(decision_limit))},
    ).mappings().all()

    return {
        "counts": dict(counts),
        "tasks": [dict(r) for r in tasks],
        # Newest first: a planner reading this wants the most recent refusal,
        # and truncating at ``decision_limit`` must drop the oldest rather than
        # the ones that explain why the last attempt failed.
        "recent_decisions": [dict(r) for r in decisions],
    }


def query_tasks(
    conn: Connection, *, engagement_id: str, action: str, target: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """The in-flight tasks in this engagement that are the same work (§11.3).

    D17 withheld this function because "the same work" was undefined, and
    defining it *was* the task-identity decision. ADR_TASK_IDENTITY.md makes that
    decision, so the read side can exist without settling anything sideways: it
    matches on the identity key ``create_task`` writes — ``(action, canonical
    target)`` at host granularity — and on nothing else. There is no free-text
    argument, no similarity score and no dimension beyond that key, so a
    Supervisor can ask "is this already queued?" and get the same answer the
    write path would compute.

    Same three guarantees as ``query_state`` (§2): read-only; on the ordinary
    ``cyberorch_app`` connection with no new grant; confined to the caller's
    engagement by RLS. A target that will not canonicalize matches nothing —
    returning everything would be a fail-open read.
    """
    _, identity_key = _task_identity(action, target)
    if identity_key is None:
        return []
    rows = conn.execute(
        text("""
            SELECT task_id, goal, status, owner_agent_id, created_by,
                   action, canonical_target, scope_object_id,
                   overlaps_with, priority, created_at
            FROM tasks
            WHERE identity_key = :key AND status = ANY(:live)
            ORDER BY created_at ASC
        """),
        {"key": identity_key, "live": list(_LIVE_TASK_STATUSES)},
    ).mappings().all()
    return [dict(r) for r in rows]


#: §4.2's status vocabulary. Checked against rather than interpolated: the
#: status filter is the one place a caller supplies something that reaches a
#: WHERE clause, and an allowlist is what keeps it a filter rather than an
#: opening.
TASK_STATUSES = (
    "queued", "claimed", "running", "completed", "failed", "cancelled",
)

#: §4.3's states, for the same reason.
FINDING_STATES = (
    "candidate", "hypothesis", "pending_verification", "verified", "rejected",
    "mitigated", "accepted_risk",
)


def _valid_task_statuses(requested: Sequence[str] | None) -> tuple[str, ...] | None:
    if requested is None:
        return None
    unknown = [s for s in requested if s not in TASK_STATUSES]
    if unknown:
        raise ValueError(f"unknown task status(es) {unknown}; expected {TASK_STATUSES}")
    return tuple(requested)


def query_findings(
    conn: Connection,
    *,
    engagement_id: str,
    state: Sequence[str] | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Findings for this engagement (§2, §4.3).

    §2 has listed this since v0.1 and nothing implemented it, because until
    D17 no component needed it: the Worker is given one task and the Reviewer
    one proposal, and neither plans. A Supervisor does, and "what has this
    engagement actually established so far" is the question its whole job rests
    on.

    Read-only and RLS-confined, on the same terms as :func:`query_state`. Note
    that ``claim`` is *derived from tool output* and therefore carries whatever
    a target put in front of the system — a caller showing these to a model must
    wrap them in the untrusted block (§8.1), which the Supervisor's prompt
    builder does (D17).

    ``confidence`` is deliberately absent, because §4.3 removed the column. The
    strength of a finding is ``evidence_strength`` plus ``verifier_state``, two
    discrete fields, and a planner that wants to rank findings has to reason
    about those rather than sort by a number nobody computed.
    """
    if state is not None:
        unknown = [s for s in state if s not in FINDING_STATES]
        if unknown:
            raise ValueError(
                f"unknown finding state(s) {unknown}; expected {FINDING_STATES}"
            )
    rows = conn.execute(
        text("""
            SELECT finding_id, claim, state, evidence_strength, verifier_state,
                   evidence_ids, affects, attack_path_ids,
                   verification_conflict, created_at, confirmed_at
            FROM findings
            WHERE (:all_states OR state = ANY(:states))
            ORDER BY created_at ASC
            LIMIT :limit
        """),
        {"all_states": state is None, "states": list(state or ()),
         "limit": max(0, int(limit))},
    ).mappings().all()
    return [dict(r) for r in rows]


def execution_constraints(
    target_block: Mapping[str, Any], host: str
) -> dict[str, Any]:
    """The §4.6 ``constraints`` a capability carries, derived in one place (D30).

    Both routes to a capability need this — ``propose_action`` for a clean ALLOW,
    and ``grant_approval`` after a human approves an escalation — and before D30
    each computed it inline from a different source. The ALLOW path read the raw
    in-memory proposal and honoured what it asked for; the approval path read the
    persisted row, which had lost the fields, and silently substituted defaults.
    Two derivations of one fact, disagreeing exactly when a human was in the
    loop.

    So there is one now, and the §4.7 approval record is built from the same
    call (see ``approvals.approval_fields``), which is what makes "the approval
    describes what was authorized" structural rather than a property somebody
    has to keep re-establishing. Same reasoning as the shared containment
    primitive in D25 and the shared reconstruction in D26.

    The defaults stay: a proposal that names no ports is a proposal the tool
    still has to be told how to run. What changed is that they now apply only
    when the *proposal* said nothing, rather than whenever the storage layer
    happened to lose the answer.
    """
    constraints = {
        "host": host,
        "ports": target_block.get("ports", "8080"),
        "scan_type": target_block.get("scan_type", "connect"),
    }
    # The web.* adapters read the request port and path off the constraints
    # (a GET/POST to :8443/login, a render of /dynamic.html); nmap names
    # neither and ignores both. Before D37 they were dropped here, so no web
    # action could be driven through propose_action with a real port or path —
    # the gap D37 found when it took web.render the whole way. Carried only when
    # the proposal named them, so nmap's constraints are byte-for-byte unchanged.
    if target_block.get("port") is not None:
        constraints["port"] = target_block["port"]
    if target_block.get("path") is not None:
        constraints["path"] = target_block["path"]
    # web.post (5.29, D53): the request body and its content type. Without these
    # `http_post.build_plan` -- which reads the body from the capability alone, by
    # design -- raised on every capability issued through here. They are carried
    # unmodified (never redacted or truncated: what is approved is what is sent,
    # D30), and only after `propose_action` has refused a body in a known secret
    # format (`refuse_proposed_body`) or one the adapter would refuse. web.get
    # ignores them: its `build_plan` reads neither.
    if target_block.get("body") is not None:
        constraints["body"] = target_block["body"]
    if target_block.get("content_type") is not None:
        constraints["content_type"] = target_block["content_type"]
    if target_block.get("scheme") is not None:
        # https on a non-443 port (the D35 target on 8443) is expressed by the
        # scheme, not inferrable from a bare IP; the adapters read it.
        constraints["scheme"] = target_block["scheme"]
    # ad.collect (D42/D44) and code.scan (D43) constraints, carried through
    # only when the proposal named them -- same "defaults apply only when the
    # proposal said nothing" rule as port/path/scheme above. Found missing
    # entirely at D45: a proposal naming domain_username had it silently
    # dropped here, so a credentialed ad.collect capability issued through
    # this function could never actually reach ad_collector.build_plan's
    # credentialed branch, regardless of whether issue_capability was given a
    # credential_id -- the two would disagree exactly the way D30's own
    # docstring above warns a single derivation exists to prevent.
    if target_block.get("collection_methods") is not None:
        constraints["collection_methods"] = target_block["collection_methods"]
    if target_block.get("domain_username") is not None:
        constraints["domain_username"] = target_block["domain_username"]
    if target_block.get("auth_mode") is not None:
        constraints["auth_mode"] = target_block["auth_mode"]
    if target_block.get("exclude_paths") is not None:
        constraints["exclude_paths"] = target_block["exclude_paths"]
    # history_depth (D55): how many commits back code.secrets reads. Carried by the
    # same rule as every field above; without this line a proposal naming it is
    # scanned at the adapter's default depth and nothing says so.
    if target_block.get("history_depth") is not None:
        constraints["history_depth"] = target_block["history_depth"]
    # dns_server (D49): the nameserver ad_collector.build_plan passes to
    # bloodhound-python's own -ns flag. Carried through by the same rule as
    # every field above -- dispatch_collection, not this function, is what
    # checks it against network_allowlist before any container starts.
    if target_block.get("dns_server") is not None:
        constraints["dns_server"] = target_block["dns_server"]
    return constraints


def _persist_proposal(
    conn: Connection, engagement_id: str, proposal_id: str,
    proposal: ProposedAction, target, agent_id: str, idempotency_key: str,
) -> bool:
    """Insert the proposal; False if one with this idempotency key already exists (D60).

    ``ON CONFLICT DO NOTHING`` on the table's own unique index (engagement, key), so two callers
    that race with the same key cannot both create a proposal -- the loser gets False and resumes
    the winner's.
    """
    import json

    inserted = conn.execute(
        text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, task_id,
                agent_id, request_idempotency_key, action, target, "authorization",
                discovery, resources, expected_data, writes_data, changes_state,
                reason, requested_capability_ttl_seconds)
            VALUES (:pid, :eid, :tid, :agent, :key, :action, CAST(:target AS jsonb),
                    CAST(:auth AS jsonb), CAST(:disc AS jsonb), :resources,
                    :expected, :writes, :changes, :reason, :ttl)
            ON CONFLICT (engagement_id, request_idempotency_key) DO NOTHING
            RETURNING proposal_id
        """),
        {
            "pid": proposal_id, "eid": engagement_id, "tid": proposal.task_id,
            "agent": agent_id, "key": idempotency_key, "action": proposal.action,
            # D30: the canonical target *plus* the execution parameters it does
            # not carry. `CanonicalTarget.as_dict()` describes what the target
            # *is* -- logical_identity, port, path, normalized -- because that is
            # what authorization and the §7 fingerprint are about. It has no
            # `ports` or `scan_type`, since those say how to run the tool rather
            # than what is being targeted.
            #
            # Storing only the canonical form silently dropped them, and the two
            # paths that later need them diverged: `propose_action` still had the
            # in-memory proposal and honoured the request, while `grant_approval`
            # -- which may run minutes later in another process, holding only this
            # row -- found the keys missing and fell through to the defaults. A
            # proposal asking for ports 443 came back from human approval as a
            # capability for port 8080.
            #
            # Canonical values are applied last, so they stay authoritative for
            # every key they define; the agent's extras survive alongside them.
            "target": json.dumps(
                {**dict(proposal.target), **target.as_dict()}, default=str
            ),
            "auth": json.dumps(dict(proposal.authorization), default=str),
            "disc": json.dumps(dict(proposal.discovery), default=str),
            "resources": list(proposal.resources),
            "expected": list(proposal.expected_data),
            "writes": proposal.writes_data, "changes": proposal.changes_state,
            "reason": proposal.reason,
            "ttl": proposal.requested_capability_ttl_seconds,
        },
    ).scalar_one_or_none()
    return inserted is not None


def _record_decision(
    conn: Connection, proposal_id: str, decision, *,
    authorized_scope_object_id: str | None, classified_asset_id: str | None,
) -> None:
    """The decision, its reasons, and the two facts the resolvers established.

    The scope object and asset are kept on the proposal so that its provenance edges can be derived
    from committed rows later (``graph.record_provenance``) instead of being written alongside the
    decision from values only this call holds.
    """
    conn.execute(
        text("UPDATE action_proposals SET decision = :d, decision_reasons = :r, "
             "authorized_scope_object_id = :scope, classified_asset_id = :asset, "
             "updated_at = now() WHERE proposal_id = :p"),
        {"p": proposal_id, "d": decision.decision,
         "r": list(decision.deny_reasons + decision.approval_reasons),
         "scope": authorized_scope_object_id, "asset": classified_asset_id},
    )
