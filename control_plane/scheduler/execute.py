"""The execution step: derive what a dispatch needs, then dispatch (D62).

**This module can reach exactly one database connection: ``cyberorch_app``, bound to one engagement
at a time** (``engagement_scope``), plus Docker. It imports no ``scheduler_reader`` scope: whether
to dispatch was decided elsewhere, from ids alone. It reads what the decision may not -- the
proposal's target and the authorizing scope object -- because deriving the network allowlist needs
exactly that, and it does so inside one engagement's scope, through the existing functions.

The effective policy is loaded here, at the moment of dispatch, and handed to ``dispatch_approved``;
the scheduler never loads, caches or reasons about policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text

from control_plane.api.approved_dispatch import dispatch_approved
from control_plane.policy.layers import load_effective_policy
from control_plane.registry.scope_registry import get_scope_object
from control_plane.scheduler import allowlist
from control_plane.state.db import engagement_scope
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

ACTOR = "scheduler"


@dataclass(frozen=True)
class Prepared:
    """What ``dispatch_approved`` needs that the proposal row lacks, or why there is none."""

    allowlist: tuple[str, ...] | None = None
    skip: str | None = None


def prepare(engagement_id: str, proposal_id: str) -> Prepared:
    """Derive the network allowlist from the authorizing scope object, or a concrete skip code."""
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT action, target, authorized_scope_object_id FROM action_proposals "
                 "WHERE proposal_id = :p"), {"p": proposal_id}).mappings().one_or_none()
        if row is None:
            return Prepared()
        scope = (get_scope_object(conn, row["authorized_scope_object_id"])
                 if row["authorized_scope_object_id"] else None)
    if scope is None:
        # No authorizing scope to derive from. Not a skip: the pipeline's re-validation refuses a
        # proposal whose authorization is gone, with the reason on the record.
        return Prepared()
    identity = (row["target"] or {}).get("logical_identity", {})
    derived = allowlist.derive_network_allowlist(
        action=row["action"], scope_type=scope.type, scope_value=scope.value,
        target_type=identity.get("type", ""), target_value=str(identity.get("value", "")),
    )
    return Prepared(allowlist=derived.allowlist, skip=derived.skip)


def dispatch(engagement_id: str, proposal_id: str, prepared: Prepared, *, sandbox=None) -> None:
    """Hand one approved proposal to ``dispatch_approved``; the pipeline records the outcome."""
    with engagement_scope(engagement_id) as conn:
        policy = load_effective_policy(conn, engagement_id)
    dispatch_approved(
        engagement_id=engagement_id, proposal_id=proposal_id, policy=policy, actor=ACTOR,
        sandbox=sandbox,
        network_allowlist=list(prepared.allowlist) if prepared.allowlist else None,
    )


def docker_reachable() -> bool:
    """A ping outside the pipeline, so an outage stops the service instead of closing a proposal."""
    try:
        DockerSandbox().client()
    except SandboxUnavailable:
        return False
    return True
