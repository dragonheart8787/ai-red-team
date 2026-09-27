"""Metadata Resolver (§5) — "what is this resource?"

The precedence rule is the entire security value of this module:

    An AUTHORITATIVE row, if one exists, determines the canonical
    resource_class and data_class. If there is no AUTHORITATIVE row — whether
    the identity is unregistered or carries only OBSERVED / INFERRED /
    LLM_HINT rows — the canonical classification is UNKNOWN. Lower tiers never
    fill the gap.

Filling the gap is the tempting mistake, and it is how the AI gets to launder a
claim into a fact: a Policy Reviewer that says "no sensitive data here" would
become the reason a deny rule fails to match, without ever overriding a
decision. §5 puts it as *LLM-derived attributes can tighten policy, they can
never satisfy a permission prerequisite* (I6b).

Lower-tier rows are not discarded — they are returned separately as
``observations``. OPA may use them to tighten (any tier can raise a deny or an
approval requirement, per I6c: SAFE→SUSPICIOUS is always permitted), but they
never appear in the canonical fields, so no amount of low-tier data can dilute
or contradict what the customer declared.

Ambiguity fails closed (I10): more than one live AUTHORITATIVE row for a single
identity resolves to CONFLICT, not to a picked winner.

Hierarchical classification inheritance (D25, downward restriction only)
------------------------------------------------------------------------
The canonical lookup above is by **exact canonical identity**, and that has not
changed: only a row registered against a resource's own identity can fill the
canonical fields or set ``known``. What D25 added is a second, separate read
that answers a different question — *does an AUTHORITATIVE ancestor of this
identity classify it as restricted?* — and feeds the answer into
``observations``, never into the canonical fields.

The gap it closes: classification is registered against ranges but resolved
against hosts. An Engagement Manager marks ``10.79.0.0/24`` AUTHORITATIVE PII; a
proposal names ``10.79.0.42``, which has no row of its own; exact lookup finds
nothing and the host reads as UNKNOWN, as though the declaration on its enclosing
range had never been made.

**One direction only, and the asymmetry is the design** (ADR_CLASSIFICATION_
INHERITANCE.md):

* *Downward restriction* — an AUTHORITATIVE classification on an ancestor
  reaches a descendant, which is treated as at least as restricted as its
  ancestor.
* *Downward relaxation* — never. The **absence** of a mark on an ancestor says
  nothing about a descendant. A range nobody classified does not make its hosts
  clean; a descendant with no row of its own stays UNKNOWN, and §5's
  per-action-class prerequisite still refuses to be satisfied by it.

Which is why inheritance is emitted as an **observation** rather than written
into the canonical fields. That single choice discharges the three D3 constraints
below and the fail-closed requirement at once, because §5's Rego already treats
observations as tightening-only: ``forbidden_data_observed`` raises a hard DENY
on a deny-listed class from *any* tier, while only an AUTHORITATIVE row on the
resource's own identity can clear a prerequisite. So an inherited PII classifi-
cation denies exactly as the customer's declaration on the parent intended, and
still cannot make anything permitted. No new Rego was needed, and none was added.

It also keeps CONFLICT meaning what it has always meant. A descendant carrying
its own AUTHORITATIVE non-PII row while an ancestor says PII is not a conflict:
those two rows describe two different identities and do not disagree. The
descendant keeps its own canonical classification, the ancestor's rides along as
an observation, and if PII is deny-listed the observation denies. CONFLICT stays
reserved for two AUTHORITATIVE rows about *the same* identity, where guessing is
least defensible (I10).

The three D3 constraints, and where each is discharged:

1. **Only downward from an AUTHORITATIVE parent.** ``_inherited_observations``
   filters on ``classification_authority == AUTHORITATIVE`` before anything
   else. A parent at OBSERVED/INFERRED/LLM_HINT contributes nothing, so
   inheritance never becomes a second route by which a low tier reaches a
   canonical field (I6b).
2. **Inheritance may only tighten.** Structurally guaranteed rather than
   asserted: the inherited rows are appended to ``observations`` and the
   canonical fields and ``known`` are computed before inheritance is consulted
   and are never touched by it. There is no code path by which an inherited row
   can remove a class, fill a canonical field, or turn UNKNOWN into known.
3. **Separate code path, separate tests.** The precedence logic in
   ``resolve_metadata`` is unchanged; inheritance is one call to a separate
   function at the end, and its tests live in ``tests/test_metadata_inheritance.py``
   rather than mixed into the exact-precedence suite.

Computed at query time, not materialized. A derived row written when a parent is
registered goes stale the moment the parent is reclassified, deactivated, or a
closer parent appears, and a stale *restriction* outliving its parent is silent
policy drift. The read here reflects the registry's current state by
construction, needs no new write path and no new grant, and names the exact
parent row each observation came from. See ADR §4.

Which identities have ancestors is decided by ``INHERITING_IDENTITY_TYPES``
below; the containment arithmetic itself is shared with the Authorization
Resolver and lives in :mod:`control_plane.canonicalizer.containment`. Sharing
the geometry is not sharing a decision — see that module's docstring, and ADR §6
for why importing ``scope_covers_target`` here would have been the wrong way to
get it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Connection

from control_plane.canonicalizer.containment import identity_contains
from control_plane.canonicalizer.target import CanonicalTarget
from control_plane.registry.metadata_registry import (
    MetadataRow,
    list_authoritative,
    lookup,
)

AUTHORITATIVE = "AUTHORITATIVE"
UNKNOWN = "UNKNOWN"
CONFLICT = "CONFLICT"

# The authority an inherited observation carries. Deliberately its own value
# rather than the parent row's ``AUTHORITATIVE`` (D25). The parent *is*
# authoritative — about the parent. Copying that word onto an observation about
# a different identity would leave a row in the observations channel that reads
# as canonical-grade, and the next reader to filter observations by
# ``authority == AUTHORITATIVE`` and promote them would reopen I6b from the
# side. A value nothing else matches cannot be promoted by accident.
INHERITED = "INHERITED"

# Prefix of an inherited observation's ``source``, followed by the type and
# value of the ancestor row it came from, so an investigator reading an
# observation can find the exact registry row that produced it.
INHERITED_SOURCE_PREFIX = "inherited_from:"

# Which identity types have ancestors at all, and what type an ancestor is.
#
# ``url``, ``repo`` and ``ad_domain`` are absent, and that is a decision rather
# than an omission (ADR §2.2). Each has internal structure a human reads as
# hierarchy — a URL path, a repo's org, an AD tree — and for none of them does
# the system define containment arithmetic. Guessing one here (is /admin the
# parent of /admin/users? is an org the parent of its repos?) would be inventing
# classification semantics the design does not record, which is the same mistake
# the exact-lookup rule above exists to refuse. A resource of those types with
# no row of its own stays UNKNOWN, and an Engagement Manager can always register
# one.
#
# Note what is *not* here either: no fqdn ancestor for an ip child, and no cidr
# ancestor for an fqdn child. Crossing between a name and an address would mean
# resolving one to the other, which §8.9/I8 forbids as an authorization input
# and D25 forbids as a classification input for the same reason.
ANCESTOR_TYPES: dict[str, tuple[str, ...]] = {
    "ip": ("cidr",),
    "cidr": ("cidr",),
    "fqdn": ("fqdn",),
}

INHERITING_IDENTITY_TYPES = frozenset(ANCESTOR_TYPES)


@dataclass(frozen=True)
class Observation:
    """A non-authoritative classification. May tighten; never a prerequisite."""

    authority: str
    source: str
    resource_class: tuple[str, ...]
    data_class: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "source": self.source,
            "resource_class": list(self.resource_class),
            "data_class": list(self.data_class),
        }


@dataclass(frozen=True)
class MetadataResolution:
    """Canonical classification plus the non-authoritative observations.

    ``known`` is the flag §5's per-action-class prerequisite table reads: an
    action class that requires a known data_class before it may touch content
    cannot proceed while this is False, whereas passive identification — whose
    whole job is to *produce* classifications — is unaffected.
    """

    authority: str
    known: bool
    asset_id: str | None = None
    resource_class: tuple[str, ...] = field(default_factory=tuple)
    data_class: tuple[str, ...] = field(default_factory=tuple)
    classification_source: str | None = None
    classification_version: int | None = None
    observations: tuple[Observation, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        """Shape handed to OPA as ``input.resource_metadata``."""
        return {
            "known": self.known,
            "asset_id": self.asset_id,
            "resource_class": list(self.resource_class),
            "data_class": list(self.data_class),
            "classification": {
                "authority": self.authority,
                "source": self.classification_source,
                "version": self.classification_version,
            },
            "observations": [o.as_dict() for o in self.observations],
        }


def _inherited_observations(
    conn: Connection, *, identity_type: str, identity_value: str
) -> tuple[Observation, ...]:
    """AUTHORITATIVE ancestors of this identity, as tightening-only observations.

    The separate code path D3's third constraint asks for: it is called once,
    at the end of :func:`resolve_metadata`, and the precedence logic there does
    not know it exists. Everything it returns goes into ``observations``.

    Three filters, in order, and each is load-bearing:

    1. **Does this type inherit at all?** ``ANCESTOR_TYPES`` decides, and says no
       for ``url`` / ``repo`` / ``ad_domain``.
    2. **AUTHORITATIVE ancestors only**, enforced by ``list_authoritative``
       (D3 constraint 1).
    3. **Proper ancestors only.** A row against the resource's own identity is
       not its ancestor — it is the row the exact lookup already resolved, and
       letting it through here would duplicate a resource's own canonical
       classification into its observations, where a rule comparing the two
       (``non_authoritative_sensitivity``) would see a disagreement that is not
       one. ``identity_contains`` is reflexive, because a set does contain
       itself, so the equal case is excluded here where "a row is not its own
       ancestor" is a statement about classification rather than geometry.

    The fqdn spelling is worth reading twice. Metadata rows store bare domains —
    ``pii.example.com`` classifies a named thing — while ``identity_contains``
    reads a bare fqdn as *one host* and ``*.`` as *the subtree*, per §4.1.5. So
    asking whether a stored domain is an ancestor means asking about its
    subtree explicitly, by passing ``"*." + value``. That also makes the
    exclusion in (3) automatic for fqdn: a domain is never a proper subdomain of
    itself.

    Never widens anything it is given. The returned observations can only add
    entries to a channel §5's Rego already treats as tightening-only.
    """
    ancestor_types = ANCESTOR_TYPES.get(identity_type)
    if not ancestor_types:
        return ()

    inherited: list[Observation] = []
    for row in list_authoritative(conn, identity_types=ancestor_types):
        if row.identity_type == identity_type and row.identity_value == identity_value:
            continue  # a row is not its own ancestor

        parent_value = (
            "*." + row.identity_value if row.identity_type == "fqdn"
            else row.identity_value
        )
        if not identity_contains(
            row.identity_type, parent_value, identity_type, identity_value
        ):
            continue

        inherited.append(
            Observation(
                authority=INHERITED,
                source=(
                    f"{INHERITED_SOURCE_PREFIX}"
                    f"{row.identity_type}:{row.identity_value}"
                ),
                resource_class=row.resource_class,
                data_class=row.data_class,
            )
        )
    return tuple(inherited)


def resolve_metadata(conn: Connection, *, target: CanonicalTarget) -> MetadataResolution:
    """Resolve the canonical classification for a canonical target.

    The **canonical** answer comes from an exact canonical-identity lookup and
    from nothing else — no fallback to a broader identity, ever. That is what
    makes ``known`` mean "the customer declared this, about this resource".

    Since D25 a second, separate read adds AUTHORITATIVE *ancestors* of the
    identity to ``observations`` (see the module docstring). Note where that
    happens below: the inherited rows join the observation tuple, and the
    canonical fields and ``known`` are computed from ``authoritative`` — the
    exact-lookup rows — with no reference to inheritance in any branch. An
    inherited classification can therefore tighten a decision and can never
    satisfy a prerequisite, which is D3's second constraint made structural
    rather than asserted.
    """
    identity_type = target.logical_identity.type
    identity_value = target.logical_identity.value

    rows = lookup(conn, identity_type=identity_type, identity_value=identity_value)

    authoritative = [r for r in rows if r.classification_authority == AUTHORITATIVE]
    observations = tuple(
        Observation(
            authority=r.classification_authority,
            source=r.classification_source,
            resource_class=r.resource_class,
            data_class=r.data_class,
        )
        for r in rows
        if r.classification_authority != AUTHORITATIVE
    ) + _inherited_observations(
        conn, identity_type=identity_type, identity_value=identity_value
    )

    if len(authoritative) > 1:
        # Unreachable through register_metadata (a unique index prevents it),
        # so reaching it means something wrote around the registry API. That is
        # precisely when guessing is worst.
        return MetadataResolution(
            authority=CONFLICT, known=False, observations=observations
        )

    if not authoritative:
        # No AUTHORITATIVE row. Any OBSERVED/INFERRED/LLM_HINT rows stay in
        # observations and the canonical fields stay empty — this is the branch
        # that keeps a lying reviewer from manufacturing "known and harmless".
        return MetadataResolution(
            authority=UNKNOWN, known=False, observations=observations
        )

    row: MetadataRow = authoritative[0]
    return MetadataResolution(
        authority=AUTHORITATIVE,
        known=True,
        asset_id=row.asset_id,
        resource_class=row.resource_class,
        data_class=row.data_class,
        classification_source=row.classification_source,
        classification_version=row.classification_version,
        observations=observations,
    )
