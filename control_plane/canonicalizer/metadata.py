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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Connection

from control_plane.canonicalizer.target import CanonicalTarget
from control_plane.registry.metadata_registry import MetadataRow, lookup

AUTHORITATIVE = "AUTHORITATIVE"
UNKNOWN = "UNKNOWN"
CONFLICT = "CONFLICT"


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


def resolve_metadata(conn: Connection, *, target: CanonicalTarget) -> MetadataResolution:
    """Resolve the canonical classification for a canonical target.

    Lookup is by exact canonical identity. There is deliberately no fallback to
    a broader identity (a URL's host, an IP's enclosing network): inheriting a
    classification would mean a statement made about one resource silently
    standing in for another, and the design does not define when that is sound.
    An unregistered identity is UNKNOWN, which §5 already has an answer for.
    """
    rows = lookup(
        conn,
        identity_type=target.logical_identity.type,
        identity_value=target.logical_identity.value,
    )

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
