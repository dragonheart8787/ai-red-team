"""Publishing and loading policy layers (§4.5).

The Policy Pack lives in ``policy_layers``, and until now nothing could write to
it. Every test that needed an Emergency Overlay published one with a raw
``INSERT``, including the stateful test's ``emergency_tighten`` rule — which
means the mechanism I2 rests on was exercised only as a column, never as an
operation. That is the same shape as the kill switch D8 found and the credential
cascade D9 found: enforced, and unreachable.

Three functions, and each later one is why the earlier is worth having:

:func:`publish_policy_layer`
    The operation. Validates, inserts, audits.
:func:`load_effective_policy`
    Reads the stored layers and merges them into an :class:`EffectivePolicy`.
:func:`list_effective_policy_layers`
    Reports the rows behind that merge, and where each came from.

The third was added at D14, after DEFERRED 11.1 had happened twice. A merged
policy says ``network.scan: DENY`` and nothing about which of nineteen rows
said so, which is fine until the answer is surprising — and then the only tool
is SQL against ``policy_layers``. The listing and the merge share one selection
predicate (``_APPLICABLE``) rather than each having its own, because two
answers that can disagree about what is in force is worse than one answer that
is hard to read.

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
from dataclasses import dataclass
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

#: How a layer's reach is reported. A word, not an inference from a null column.
GLOBAL = "global"
ENGAGEMENT = "engagement"


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

    # D11-7: a layer published globally is a global operation, so its audit
    # record is global too (engagement_id NULL, readable by global_auditor)
    # rather than scoped to whichever engagement the publisher happened to be in.
    # That mis-scoping is exactly what left "published by: unknown" in the D11
    # live run.
    record_audit(
        engagement_id=engagement_id if scoped_to_engagement else None,
        scope="engagement" if scoped_to_engagement else "global",
        actor=actor,
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
        text("SELECT layer, version, document, engagement_id FROM policy_layers "
             "WHERE id = :lid AND active IS TRUE"),
        {"lid": layer_id},
    ).mappings().one_or_none()
    if before is None:
        return False

    conn.execute(
        text("UPDATE policy_layers SET active = FALSE WHERE id = :lid"),
        {"lid": layer_id},
    )
    # D11-7: deactivating a global layer is a global operation. The layer's own
    # engagement_id decides — NULL means it was global — not the engagement the
    # deactivator is connected through.
    layer_is_global = before["engagement_id"] is None
    record_audit(
        engagement_id=None if layer_is_global else engagement_id,
        scope="global" if layer_is_global else "engagement",
        actor=actor,
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


#: The one place the "which layers apply here" question is answered in SQL.
#:
#: Extracted at D14 so ``load_effective_policy`` and
#: ``list_effective_policy_layers`` cannot describe different sets. That is
#: DEFERRED 11.1's second binding constraint, and it is a constraint rather than
#: a preference: a listing that shows a different set from the one being
#: enforced is worse than no listing at all, because it will be believed.
#:
#: Sharing the predicate makes divergence impossible by construction rather than
#: by discipline. ``test_the_listing_returns_exactly_the_rows_the_merge_consumed``
#: still watches the statements ``load_effective_policy`` actually issues, so a
#: future edit that stops using this helper is caught rather than assumed away.
_APPLICABLE = """
    FROM policy_layers
    WHERE active IS TRUE
      AND (engagement_id IS NULL OR engagement_id = :eid)
"""


def _select_applicable(conn: Connection, engagement_id: str, columns: str):
    return conn.execute(
        text(f"SELECT {columns} {_APPLICABLE} ORDER BY id"), {"eid": engagement_id},
    ).mappings().all()


@dataclass(frozen=True)
class EffectiveLayer:
    """One row that is currently in force, as the merge sees it.

    ``scope`` is a field rather than something a reader derives from
    ``engagement_id`` being null. DEFERRED 11.1's third constraint: the whole
    D11-6 failure was a global layer read as though it were the engagement's
    own, and "you can tell because the other column is empty" is exactly the
    inference that failed.
    """

    id: int
    layer: str
    version: int
    scope: str
    engagement_id: str | None
    customer_id: str | None
    document: Mapping[str, Any]
    created_at: Any
    published_by: str | None
    published_at: Any
    attribution_note: str | None = None

    @property
    def is_global(self) -> bool:
        return self.scope == GLOBAL

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "layer": self.layer,
            "version": self.version,
            "scope": self.scope,
            "engagement_id": self.engagement_id,
            "customer_id": self.customer_id,
            "document": dict(self.document),
            "created_at": self.created_at,
            "published_by": self.published_by,
            "published_at": self.published_at,
            "attribution_note": self.attribution_note,
        }


def list_effective_policy_layers(
    conn: Connection, engagement_id: str
) -> tuple[EffectiveLayer, ...]:
    """Which layers are in force here, and where each came from (D14, 11.1).

    The operation D11-6 needed twice and did not have. ``load_effective_policy``
    answers "what is the policy" — ``network.scan: DENY`` — and nothing about
    why; ``current_policy_version`` answers with a number. Both were built on
    rows reachable only by writing SQL against ``policy_layers``, so "why is
    this engagement denied" was answerable by someone who already knew the
    schema and by nobody else. Twice: once in the D11 live run, and again in
    D12.5 when a container snapshot rolled the same nineteen rows back.

    **It reports; it does not decide.** No merge happens here and no judgement
    about what *should* be in force. The rows come from the same predicate
    ``load_effective_policy`` selects on, and the merged answer still comes from
    that function. A second implementation of §4.5's algebra that could disagree
    with the first would be worse than the unreadable state this replaces.

    **Attribution is honest about what it cannot say.** ``published_by`` comes
    from the ``policy_layer.published`` audit row, which is RLS-scoped to the
    engagement whose connection wrote it (§8.6, I4). For a global layer that is
    usually a different engagement, so the record is invisible from here — and
    the listing says so in ``attribution_note`` rather than leaving the field
    blank. A blank would read as "nobody published it", which is false and is
    precisely the confusion D11-7 is about. This function does not fix D11-7;
    it declines to hide it.

    Read-only, over the connection it is handed. No new grant: ``policy_layers``
    and ``audit_log`` are already readable by ``cyberorch_app``.
    """
    rows = _select_applicable(
        conn, engagement_id,
        "id, layer, version, engagement_id, customer_id, document, created_at",
    )
    attribution = _publication_audit(conn, [row["id"] for row in rows])

    layers: list[EffectiveLayer] = []
    for row in rows:
        is_global = row["engagement_id"] is None
        published = attribution.get(row["id"])
        note = None
        if published is None:
            note = (
                "the publication audit record is not visible from this "
                "engagement" + (
                    "; a global layer is normally published from another one, "
                    "and audit_log is scoped per engagement (DEFERRED 11.2)"
                    if is_global else ""
                )
            )
        layers.append(EffectiveLayer(
            id=row["id"], layer=row["layer"], version=row["version"],
            scope=GLOBAL if is_global else ENGAGEMENT,
            engagement_id=row["engagement_id"], customer_id=row["customer_id"],
            document=row["document"] or {}, created_at=row["created_at"],
            published_by=published["actor"] if published else None,
            published_at=published["ts"] if published else None,
            attribution_note=note,
        ))
    return tuple(layers)


def _publication_audit(
    conn: Connection, layer_ids: list[int]
) -> dict[int, Mapping[str, Any]]:
    """Who published each layer, for the ids whose audit row is visible here.

    Deliberately returns nothing for the rest rather than a placeholder. RLS
    decides what is visible and this function does not argue with it.
    """
    if not layer_ids:
        return {}
    rows = conn.execute(
        text("""
            SELECT subject_id, actor, ts FROM audit_log
            WHERE event_type = 'policy_layer.published'
              AND subject_id = ANY(:ids)
            ORDER BY audit_id
        """),
        {"ids": [str(i) for i in layer_ids]},
    ).mappings().all()
    return {int(row["subject_id"]): row for row in rows}


def load_effective_policy(
    conn: Connection, engagement_id: str
) -> EffectivePolicy:
    """Merge the stored layers that apply to this engagement (§4.5).

    Selects the same set ``current_policy_version`` counts — active layers that
    are global or this engagement's — so the version a capability records and
    the policy it was issued under describe the same thing.
    :func:`list_effective_policy_layers` reports that same set, through the same
    predicate, so the listing and the enforcement cannot come apart.

    Every active applicable row participates; see :func:`_combine` for why rows
    sharing a layer name are folded together rather than resolved by recency.

    A layer nobody has published resolves to its neutral element, so an empty
    table yields an unconstrained policy rather than an empty one — the §4.5 bug
    that ``intersect_allow`` exists to avoid, reached from the loading side.
    """
    rows = _select_applicable(conn, engagement_id, "id, layer, document")

    grouped: dict[str, list[PolicyLayer]] = {name: [] for name in LAYER_ORDER}
    for row in rows:
        if row["layer"] in grouped:
            grouped[row["layer"]].append(
                PolicyLayer.from_document(row["layer"], row["document"])
            )

    return merge_policy(*(_combine(name, grouped[name]) for name in LAYER_ORDER))


__all__ = [
    "EMERGENCY_OVERLAY",
    "ENGAGEMENT",
    "GLOBAL",
    "EffectiveLayer",
    "EmergencyOverlayError",
    "PolicyLayerError",
    "deactivate_policy_layer",
    "list_effective_policy_layers",
    "load_effective_policy",
    "publish_policy_layer",
]
