"""Authoritative Metadata Registry (§5).

Stores what a resource *is* — resource_class and data_class — with a
provenance tier attached to every row. The tiers are ordered but not
interchangeable (§5, I6b, I6c):

``AUTHORITATIVE``
    Customer-declared, or pre-registered and reviewed. The only tier that can
    satisfy a privilege prerequisite.
``OBSERVED``
    Parsed out of something the target itself controls — a TLS SAN, an HTTP
    header, an Nmap banner. The tool parsed it honestly; that says nothing
    about whether the value is true. Renamed from ``tool_verified`` in v0.3 for
    exactly this reason.
``INFERRED`` / ``LLM_HINT``
    Model output. May tighten, never satisfies a prerequisite.

Rows of different tiers coexist for one identity rather than overwriting each
other: an LLM_HINT never displaces the customer's declaration, and the
resolver decides what each tier is allowed to do.

Writes require the ``registry_admin`` role (§5). ``cyberorch_app`` — what the
resolvers, the orchestrator and the agents connect as — holds SELECT only. That
matters most for exactly the case MVP-Kernel exists to test: a component that
could write an AUTHORITATIVE row could reclassify a PII database as a static
site, and no amount of care in the resolver would help.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit
from control_plane.state.db import REGISTRY_ADMIN_ROLE, assert_registry_admin

AUTHORITY_TIERS = ("AUTHORITATIVE", "OBSERVED", "INFERRED", "LLM_HINT")


@dataclass(frozen=True)
class MetadataRow:
    asset_id: str
    engagement_id: str
    identity_type: str
    identity_value: str
    resource_class: tuple[str, ...]
    data_class: tuple[str, ...]
    classification_source: str
    classification_authority: str
    classification_version: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "resource_class": list(self.resource_class),
            "data_class": list(self.data_class),
            "classification": {
                "source": self.classification_source,
                "authority": self.classification_authority,
                "version": self.classification_version,
            },
        }


def lookup(
    conn: Connection, *, identity_type: str, identity_value: str
) -> list[MetadataRow]:
    """Every live row for one identity, across all authority tiers."""
    rows = conn.execute(
        text("""
            SELECT asset_id, engagement_id, identity_type, identity_value,
                   resource_class, data_class, classification_source,
                   classification_authority, classification_version
            FROM metadata_registry
            WHERE active IS TRUE
              AND valid_from <= now()
              AND identity_type = :itype
              AND identity_value = :ivalue
            ORDER BY classification_authority, asset_id
        """),
        {"itype": identity_type, "ivalue": identity_value},
    ).mappings().all()
    return [
        MetadataRow(
            asset_id=r["asset_id"],
            engagement_id=r["engagement_id"],
            identity_type=r["identity_type"],
            identity_value=r["identity_value"],
            resource_class=tuple(r["resource_class"]),
            data_class=tuple(r["data_class"]),
            classification_source=r["classification_source"],
            classification_authority=r["classification_authority"],
            classification_version=r["classification_version"],
        )
        for r in rows
    ]


def deactivate_metadata(
    conn: Connection,
    *,
    engagement_id: str,
    identity_type: str,
    identity_value: str,
    authority: str,
    actor: str,
) -> bool:
    """Retire a classification. Engagement Manager only (§5).

    Soft delete, matching :func:`deactivate_scope_object`: neither role holds
    DELETE on the registries, so the row stays and the audit trail keeps
    something to point at.

    Retiring an AUTHORITATIVE row is a security-relevant act in its own right —
    :func:`lookup` filters on ``active``, so the resolver stops seeing it and
    the identity falls back to UNKNOWN. That is the correct behaviour (an
    unknown classification cannot satisfy a prerequisite, I10) but it is a
    reduction in what the system knows, and it must be visible in the audit log
    rather than looking like the classification was never there.

    Returns True if a row was retired.
    """
    if not actor:
        raise ValueError("registry writes must name an actor (§5)")
    assert_registry_admin(conn)

    before = conn.execute(
        text("""
            SELECT asset_id, resource_class, data_class, classification_source,
                   classification_version
            FROM metadata_registry
            WHERE engagement_id = :eid AND identity_type = :itype
              AND identity_value = :ivalue AND classification_authority = :authority
              AND active IS TRUE
        """),
        {"eid": engagement_id, "itype": identity_type,
         "ivalue": identity_value, "authority": authority},
    ).mappings().one_or_none()

    if before is None:
        return False

    conn.execute(
        text("""
            UPDATE metadata_registry SET active = FALSE, updated_at = now()
            WHERE engagement_id = :eid AND identity_type = :itype
              AND identity_value = :ivalue AND classification_authority = :authority
        """),
        {"eid": engagement_id, "itype": identity_type,
         "ivalue": identity_value, "authority": authority},
    )
    record_audit(
        conn,
        engagement_id=engagement_id,
        actor=actor,
        event_type="metadata.deactivated",
        subject_type="asset",
        subject_id=before["asset_id"],
        payload={
            "db_role": REGISTRY_ADMIN_ROLE,
            "identity": f"{identity_type}:{identity_value}",
            "authority": authority,
            "before": {
                "resource_class": list(before["resource_class"]),
                "data_class": list(before["data_class"]),
                "source": before["classification_source"],
                "version": before["classification_version"],
                "active": True,
            },
            "after": {"active": False},
        },
    )
    return True


def register_metadata(
    conn: Connection,
    *,
    engagement_id: str,
    asset_id: str,
    identity_type: str,
    identity_value: str,
    authority: str,
    source: str,
    actor: str,
    resource_class: Sequence[str] = (),
    data_class: Sequence[str] = (),
) -> MetadataRow:
    """Register or update a classification. Engagement Manager only (§5).

    Requires a :func:`registry_admin_scope` connection.
    """
    if authority not in AUTHORITY_TIERS:
        raise ValueError(f"unknown classification authority {authority!r}")
    if not actor:
        raise ValueError("registry writes must name an actor (§5)")
    assert_registry_admin(conn)

    # Captured before the upsert so the audit says what changed. A
    # reclassification is the single most security-relevant edit in the system;
    # recording only the new value would leave an investigator unable to tell
    # whether a host had just been downgraded from PII.
    before = conn.execute(
        text("""
            SELECT resource_class, data_class, classification_source,
                   classification_version
            FROM metadata_registry
            WHERE engagement_id = :eid AND identity_type = :itype
              AND identity_value = :ivalue AND classification_authority = :authority
        """),
        {"eid": engagement_id, "itype": identity_type,
         "ivalue": identity_value, "authority": authority},
    ).mappings().one_or_none()

    row = conn.execute(
        text("""
            INSERT INTO metadata_registry (asset_id, engagement_id, identity_type,
                identity_value, resource_class, data_class, classification_source,
                classification_authority)
            VALUES (:aid, :eid, :itype, :ivalue, :rclass, :dclass, :source, :authority)
            ON CONFLICT (engagement_id, identity_type, identity_value,
                         classification_authority)
            DO UPDATE SET resource_class = EXCLUDED.resource_class,
                          data_class = EXCLUDED.data_class,
                          classification_source = EXCLUDED.classification_source,
                          classification_version =
                              metadata_registry.classification_version + 1,
                          updated_at = now()
            RETURNING asset_id, engagement_id, identity_type, identity_value,
                      resource_class, data_class, classification_source,
                      classification_authority, classification_version
        """),
        {
            "aid": asset_id,
            "eid": engagement_id,
            "itype": identity_type,
            "ivalue": identity_value,
            "rclass": list(resource_class),
            "dclass": list(data_class),
            "source": source,
            "authority": authority,
        },
    ).mappings().one()

    record_audit(
        conn,
        engagement_id=engagement_id,
        actor=actor,
        event_type="metadata.registered" if before is None else "metadata.reclassified",
        subject_type="asset",
        subject_id=row["asset_id"],
        payload={
            "db_role": REGISTRY_ADMIN_ROLE,
            "identity": f"{identity_type}:{identity_value}",
            "authority": authority,
            "before": (
                {
                    "resource_class": list(before["resource_class"]),
                    "data_class": list(before["data_class"]),
                    "source": before["classification_source"],
                    "version": before["classification_version"],
                }
                if before
                else None
            ),
            "after": {
                "resource_class": list(row["resource_class"]),
                "data_class": list(row["data_class"]),
                "source": row["classification_source"],
                "version": row["classification_version"],
            },
        },
    )
    return MetadataRow(
        asset_id=row["asset_id"],
        engagement_id=row["engagement_id"],
        identity_type=row["identity_type"],
        identity_value=row["identity_value"],
        resource_class=tuple(row["resource_class"]),
        data_class=tuple(row["data_class"]),
        classification_source=row["classification_source"],
        classification_authority=row["classification_authority"],
        classification_version=row["classification_version"],
    )
