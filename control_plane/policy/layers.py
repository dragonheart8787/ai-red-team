"""Publishing and loading policy layers (§4.5).

The Policy Pack lives in ``policy_layers``, and until now nothing could write to
it. Every test that needed an Emergency Overlay published one with a raw
``INSERT``, including the stateful test's ``emergency_tighten`` rule — which
means the mechanism I2 rests on was exercised only as a column, never as an
operation. That is the same shape as the kill switch D8 found and the credential
cascade D9 found: enforced, and unreachable.

Two functions, and the second is why the first is worth having:

:func:`publish_policy_layer`
    The operation. Validates, inserts, audits.
:func:`load_effective_policy`
    Reads the stored layers and merges them into an :class:`EffectivePolicy`.

The loader deserves a note, because its absence was itself a finding. Before
this, ``policy_layers`` was read by exactly one thing — ``current_policy_version``
— and only for its ``max(id)``. The policy actually enforced was built in Python
by whichever caller was constructing the pipeline, layer objects and all. So the
stored Policy Pack and the enforced policy were two different artifacts that
happened to be described by the same section of the design, and publishing an
overlay could not have changed a decision no matter how correct the write was.

That makes "publish an overlay and assert the merged policy tightened" the test
worth writing, and it needs a loader to be writable at all.

Role: ``cyberorch_app``, matching the existing grants — ``registry_admin`` holds
nothing on ``policy_layers`` and is not involved. That asymmetry against the
registries is deliberate rather than an oversight. §5's separation exists so the
component that classifies a resource cannot also be the component that acts on
it; the Policy Pack is not a classification of any resource, and its safety comes
from a different mechanism: the overlay can only tighten, enforced both here and
by a database CHECK constraint.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit
from control_plane.policy.merge import (
    INHERIT,
    LAYER_ORDER,
    EffectivePolicy,
    EmergencyOverlayError,
    PolicyLayer,
    intersect_allow,
    merge_policy,
    resolve_action,
    validate_emergency_overlay,
)

EMERGENCY_OVERLAY = "emergency_overlay"


class PolicyLayerError(ValueError):
    """Raised when a layer cannot be published as described."""


def publish_policy_layer(
    conn: Connection,
    *,
    engagement_id: str,
    layer: str,
    version: int,
    document: Mapping[str, Any],
    actor: str,
    scoped_to_engagement: bool = False,
    customer_id: str | None = None,
) -> int:
    """Publish one policy layer, or refuse (§4.5).

    ``scoped_to_engagement`` decides whether the layer applies globally
    (``engagement_id IS NULL``, which is how baseline and emergency layers reach
    every engagement) or only to this one. It is an explicit argument rather
    than inferred from ``engagement_id`` because the caller always has an
    engagement in hand — the RLS connection requires one — and inferring would
    make "publish globally" unreachable.

    Returns the new row's id, which is what ``current_policy_version`` reports
    once this layer is active, so a caller can record what it published against.

    The emergency overlay's tighten-only rule is checked here *and* by a CHECK
    constraint on the table. The duplication is the point: the constraint is
    what makes the guarantee true regardless of which code path writes, and this
    check is what turns a constraint violation into an error naming the field.
    A test asserts that bypassing this function still hits the constraint, so
    the API is not the only thing standing between an overlay and an ALLOW.
    """
    if layer not in LAYER_ORDER:
        raise PolicyLayerError(
            f"unknown policy layer {layer!r}; expected one of {LAYER_ORDER}"
        )
    if not actor:
        raise PolicyLayerError("policy layer writes must name an actor (§4.4)")

    if layer == EMERGENCY_OVERLAY:
        # Raises EmergencyOverlayError, which callers may want to catch
        # separately from a malformed request.
        validate_emergency_overlay(document)

    row_id = conn.execute(
        text("""
            INSERT INTO policy_layers (layer, version, engagement_id, customer_id,
                                       document, active)
            VALUES (:layer, :version, :eid, :cid, CAST(:doc AS jsonb), TRUE)
            RETURNING id
        """),
        {
            "layer": layer, "version": version,
            "eid": engagement_id if scoped_to_engagement else None,
            "cid": customer_id,
            "doc": json.dumps(dict(document), sort_keys=True),
        },
    ).scalar_one()

    record_audit(
        engagement_id=engagement_id, actor=actor,
        event_type="policy_layer.published", subject_type="policy_layer",
        subject_id=str(row_id), decision="DENY" if layer == EMERGENCY_OVERLAY else None,
        payload={
            "layer": layer,
            "version": version,
            "scope": "engagement" if scoped_to_engagement else "global",
            "customer_id": customer_id,
            # The document itself, not a summary. An overlay published during an
            # incident is exactly the record someone will want to read back
            # literally, and "what was in it" is not reconstructible from a
            # count of its keys.
            "document": dict(document),
            "policy_version": row_id,
        },
    )
    return row_id


def deactivate_policy_layer(
    conn: Connection, *, engagement_id: str, layer_id: int, actor: str
) -> bool:
    """Retire a layer. Soft, like the registries.

    This does not revoke capabilities directly, and removing a layer can only
    widen the effective policy — allow lists intersect, deny lists union, rate
    limits take the minimum — so nothing outstanding becomes more permissive
    than it already was.

    Outstanding capabilities are still revoked on their next heartbeat, though,
    and it is worth being precise about why rather than claiming they are not:
    ``current_policy_version`` is the maximum id over *active* layers, so
    retiring the highest one lowers it and the recorded version no longer
    matches. Over-revoking on a widening is the harmless direction; see
    ``current_policy_version`` for why it is left that way.
    """
    if not actor:
        raise PolicyLayerError("policy layer writes must name an actor (§4.4)")

    before = conn.execute(
        text("SELECT layer, version, document FROM policy_layers "
             "WHERE id = :lid AND active IS TRUE"),
        {"lid": layer_id},
    ).mappings().one_or_none()
    if before is None:
        return False

    conn.execute(
        text("UPDATE policy_layers SET active = FALSE WHERE id = :lid"),
        {"lid": layer_id},
    )
    record_audit(
        engagement_id=engagement_id, actor=actor,
        event_type="policy_layer.deactivated", subject_type="policy_layer",
        subject_id=str(layer_id),
        payload={
            "layer": before["layer"], "version": before["version"],
            "document": before["document"],
            "note": "widening only; capabilities are not revoked",
        },
    )
    return True


def _combine(name: str, layers: list[PolicyLayer]) -> PolicyLayer:
    """Fold every active row of one layer name into a single layer.

    Uses the same algebra as :func:`merge_policy` — allow lists intersect, deny
    lists union, rate limits take the minimum, actions resolve DENY-dominant —
    so combining rows can only tighten, never relax.

    That direction is the whole reason this exists rather than "latest row
    wins". Rows of one layer name can arrive at two scopes: a global emergency
    overlay (``engagement_id IS NULL``) and one scoped to a single engagement.
    Under latest-wins, publishing an empty engagement-scoped overlay would
    *mask* the global overlay it shadowed — a way to escape a global tightening
    by publishing something laxer underneath it, which is precisely what §4.5
    says the overlay must never permit. Combining cannot mask.

    The cost is that republishing a layer accumulates instead of replacing it.
    That is the safe direction to be wrong in, and :func:`deactivate_policy_layer`
    is how a layer is actually retired.
    """
    if not layers:
        return PolicyLayer(name=name)
    return PolicyLayer(
        name=name,
        scope_allow=intersect_allow(layer.scope_allow for layer in layers),
        scope_deny=frozenset().union(*(layer.scope_deny for layer in layers)),
        data_deny=frozenset().union(*(layer.data_deny for layer in layers)),
        rate_limit=min(layer.rate_limit for layer in layers),
        actions={
            key: resolve_action([layer.actions.get(key, INHERIT) for layer in layers])
            for key in {k for layer in layers for k in layer.actions}
        },
    )


def load_effective_policy(
    conn: Connection, engagement_id: str
) -> EffectivePolicy:
    """Merge the stored layers that apply to this engagement (§4.5).

    Selects the same set ``current_policy_version`` counts — active layers that
    are global or this engagement's — so the version a capability records and
    the policy it was issued under describe the same thing.

    Every active applicable row participates; see :func:`_combine` for why rows
    sharing a layer name are folded together rather than resolved by recency.

    A layer nobody has published resolves to its neutral element, so an empty
    table yields an unconstrained policy rather than an empty one — the §4.5 bug
    that ``intersect_allow`` exists to avoid, reached from the loading side.
    """
    rows = conn.execute(
        text("""
            SELECT layer, document FROM policy_layers
            WHERE active IS TRUE
              AND (engagement_id IS NULL OR engagement_id = :eid)
            ORDER BY id
        """),
        {"eid": engagement_id},
    ).mappings().all()

    grouped: dict[str, list[PolicyLayer]] = {name: [] for name in LAYER_ORDER}
    for row in rows:
        if row["layer"] in grouped:
            grouped[row["layer"]].append(
                PolicyLayer.from_document(row["layer"], row["document"])
            )

    return merge_policy(*(_combine(name, grouped[name]) for name in LAYER_ORDER))


__all__ = [
    "EMERGENCY_OVERLAY",
    "EmergencyOverlayError",
    "PolicyLayerError",
    "deactivate_policy_layer",
    "load_effective_policy",
    "publish_policy_layer",
]
