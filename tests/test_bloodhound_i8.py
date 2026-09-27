"""D42-1 §1.9: I8 verification for BloodHound-discovered edges.

A fabricated high-privilege edge is structurally observed (LDAP-shaped,
like D20's ``_discovery_provenance``), not injected text the way D13's lure
was — but I8 (Authorization Provenance) is the same rule either way: *any
action executed must trace back to an authoritative scope object; discovery
never authorizes.* This constructs the concrete case the ADR (§1.6) and the
design doc (§1.9) both name: a collection run reports
``AttackerUser --AdminTo--> DomainController``, where ``DomainController``
was never registered by anyone, and confirms the graph write does not, by
itself, get that host any closer to being actionable.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text

from control_plane.canonicalizer.authorization import (
    DENY_TARGET_NOT_COVERED,
    resolve_authorization,
)
from control_plane.canonicalizer.target import normalize_target
from control_plane.graph.store import GraphEdge, GraphNode, record_batch
from control_plane.state.db import engagement_scope
from tests.helpers import make_tool_run

ATTACKER_USER = GraphNode(
    identity_type="fqdn", identity_value="attacker@corp.example.com", kind="user",
)
# Never registered in scope_registry or metadata_registry by anyone -- the
# entire point of the test is that the fabricated edge below is the *only*
# thing that ever asserts this host's existence.
UNREGISTERED_DC = GraphNode(
    identity_type="fqdn", identity_value="dc01.corp.example.com", kind="computer",
)


def test_a_fabricated_admin_to_edge_authorizes_nothing(engagement_id, registry):
    """The core I8 claim, end to end: observe, then try to act, and fail closed."""
    with engagement_scope(engagement_id) as conn:
        run_id = make_tool_run(conn, engagement_id=engagement_id)
        record_batch(
            conn, engagement_id=engagement_id, run_id=run_id,
            nodes=[ATTACKER_USER, UNREGISTERED_DC],
            edges=[GraphEdge(src=ATTACKER_USER, dst=UNREGISTERED_DC, edge_type="AdminTo")],
        )

        # 1. The edge exists in the Security Graph -- record_batch did its job.
        edge_count = conn.execute(
            text("SELECT COUNT(*) FROM security_graph_edges WHERE engagement_id = :e "
                 "AND edge_type = 'AdminTo'"),
            {"e": engagement_id},
        ).scalar_one()
        assert edge_count == 1

        # 2. No metadata_registry row of any kind exists for the discovered
        # host -- not AUTHORITATIVE, not OBSERVED, nothing. §1.7: there is no
        # write path from a collection run into metadata_registry at all.
        metadata_rows = conn.execute(
            text("SELECT COUNT(*) FROM metadata_registry WHERE engagement_id = :e "
                 "AND identity_type = :t AND identity_value = :v"),
            {"e": engagement_id, "t": UNREGISTERED_DC.identity_type,
             "v": UNREGISTERED_DC.identity_value},
        ).scalar_one()
        assert metadata_rows == 0

        # 3. The graph write created or renewed no capability of any kind.
        capability_count = conn.execute(
            text("SELECT COUNT(*) FROM capabilities WHERE engagement_id = :e"),
            {"e": engagement_id},
        ).scalar_one()
        assert capability_count == 0

    # 4. The actual authorization attempt: register a real scope object for
    # an *unrelated* host (the only registered scope in this engagement),
    # then try to authorize network.scan against the fabricated edge's
    # target by naming that unrelated scope object -- the shape a Worker
    # would produce if it treated "this host appeared in a structurally-
    # observed edge" as equivalent to "this host is in scope". The resolver
    # must refuse: a real scope object existing elsewhere in the engagement
    # does not make it cover a host it was never registered against.
    sid = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(
        scope_object_id=sid, type="fqdn", value="unrelated-host.corp.example.com",
        allowed_actions=["network.scan"],
    )

    target = normalize_target({
        "logical_identity": {"type": "fqdn", "value": UNREGISTERED_DC.identity_value},
    })
    with engagement_scope(engagement_id) as conn:
        resolution = resolve_authorization(
            conn, target=target, action="network.scan",
            authorization={"source": "engagement_scope", "scope_object_id": sid},
        )
    assert resolution.authorized is False
    assert DENY_TARGET_NOT_COVERED in resolution.reasons


def test_no_scope_object_at_all_is_also_refused(engagement_id):
    """The more common real shape: nothing was ever registered for this host,
    so a proposal naming it has no candidate to select in the first place --
    checked directly against the resolver with no scope_object_id at all.
    """
    target = normalize_target({
        "logical_identity": {"type": "fqdn", "value": UNREGISTERED_DC.identity_value},
    })
    with engagement_scope(engagement_id) as conn:
        resolution = resolve_authorization(
            conn, target=target, action="network.scan",
            authorization={"source": "engagement_scope", "scope_object_id": None},
        )
    assert resolution.authorized is False
