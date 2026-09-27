"""Security Graph store + queries (D42-6): record_batch, shortest_path, paths_within_hops.

Exercises the real cyberorch_app connection and real RLS — the same
discipline every other suite in this repo follows (see conftest.py's own
docstring): a test that connects as a privileged role would pass while
production leaked.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from control_plane.graph.queries import NodeRef, paths_within_hops, shortest_path
from control_plane.graph.store import GraphEdge, GraphNode, record_batch
from control_plane.state.db import engagement_scope
from tests.helpers import make_tool_run

USER_A = GraphNode(identity_type="fqdn", identity_value="usera@corp.local", kind="user")
COMPUTER_B = GraphNode(identity_type="fqdn", identity_value="wkstn-b.corp.local", kind="computer")
GROUP_C = GraphNode(identity_type="fqdn", identity_value="domain-admins", kind="group")
UNRELATED = GraphNode(identity_type="fqdn", identity_value="unrelated.corp.local", kind="user")


def _ref(node: GraphNode) -> NodeRef:
    return NodeRef(identity_type=node.identity_type, identity_value=node.identity_value)


def test_shortest_path_and_paths_within_hops_over_a_recorded_batch(engagement_id):
    """A -> B -> C, recorded in one batch, is 2 hops and both are reachable."""
    with engagement_scope(engagement_id) as conn:
        run_id = make_tool_run(conn, engagement_id=engagement_id)
        record_batch(
            conn, engagement_id=engagement_id, run_id=run_id,
            nodes=[USER_A, COMPUTER_B, GROUP_C, UNRELATED],
            edges=[
                GraphEdge(src=USER_A, dst=COMPUTER_B, edge_type="AdminTo"),
                GraphEdge(src=COMPUTER_B, dst=GROUP_C, edge_type="MemberOf"),
            ],
        )

        assert shortest_path(conn, start=_ref(USER_A), target=_ref(GROUP_C), max_depth=10) == 2
        assert shortest_path(conn, start=_ref(USER_A), target=_ref(COMPUTER_B), max_depth=10) == 1
        assert shortest_path(conn, start=_ref(USER_A), target=_ref(UNRELATED), max_depth=10) is None

        reachable = paths_within_hops(conn, start=_ref(USER_A), max_depth=1)
        assert {n.identity_value for n in reachable} == {COMPUTER_B.identity_value}

        reachable_2 = paths_within_hops(conn, start=_ref(USER_A), max_depth=2)
        assert {n.identity_value for n in reachable_2} == {
            COMPUTER_B.identity_value, GROUP_C.identity_value,
        }
        depth_by_value = {n.identity_value: n.depth for n in reachable_2}
        assert depth_by_value[COMPUTER_B.identity_value] == 1
        assert depth_by_value[GROUP_C.identity_value] == 2


def test_shortest_path_against_an_unobserved_identity_is_none_not_an_error(engagement_id):
    with engagement_scope(engagement_id) as conn:
        run_id = make_tool_run(conn, engagement_id=engagement_id)
        record_batch(
            conn, engagement_id=engagement_id, run_id=run_id,
            nodes=[USER_A], edges=[],
        )
        never_seen = NodeRef(identity_type="fqdn", identity_value="never-collected.corp.local")
        assert shortest_path(conn, start=_ref(USER_A), target=never_seen, max_depth=10) is None
        assert shortest_path(conn, start=never_seen, target=_ref(USER_A), max_depth=10) is None
        assert paths_within_hops(conn, start=never_seen, max_depth=10) == []


def test_record_batch_dedups_a_node_rediscovered_by_a_later_run(engagement_id):
    """The bug caught during implementation: two runs must not fragment one identity.

    Without the unique index on (engagement_id, identity_type, identity_value),
    this second record_batch call would mint a second row for COMPUTER_B, and
    the edge from the second run (B -> C) would attach to a *different* node
    than the edge from the first run (A -> B) -- so A could never reach C,
    even though both edges are real and B is the same computer both times.
    """
    with engagement_scope(engagement_id) as conn:
        run_1 = make_tool_run(conn, engagement_id=engagement_id)
        record_batch(
            conn, engagement_id=engagement_id, run_id=run_1,
            nodes=[USER_A, COMPUTER_B],
            edges=[GraphEdge(src=USER_A, dst=COMPUTER_B, edge_type="AdminTo")],
        )

        run_2 = make_tool_run(conn, engagement_id=engagement_id)
        record_batch(
            conn, engagement_id=engagement_id, run_id=run_2,
            # COMPUTER_B rediscovered by the second run, alongside a new node.
            nodes=[COMPUTER_B, GROUP_C],
            edges=[GraphEdge(src=COMPUTER_B, dst=GROUP_C, edge_type="MemberOf")],
        )

        assert shortest_path(conn, start=_ref(USER_A), target=_ref(GROUP_C), max_depth=10) == 2

        row_count = conn.execute(
            text(
                "SELECT COUNT(*) FROM security_graph_nodes WHERE engagement_id = :e "
                "AND identity_type = :t AND identity_value = :v"
            ),
            {"e": engagement_id, "t": COMPUTER_B.identity_type, "v": COMPUTER_B.identity_value},
        ).scalar_one()
        assert row_count == 1, "COMPUTER_B must be exactly one row across both runs"


def test_record_batch_raises_when_an_edge_references_an_identity_not_in_nodes(engagement_id):
    with engagement_scope(engagement_id) as conn:
        run_id = make_tool_run(conn, engagement_id=engagement_id)
        with pytest.raises(ValueError, match="not present in nodes"):
            record_batch(
                conn, engagement_id=engagement_id, run_id=run_id,
                nodes=[USER_A],  # COMPUTER_B omitted
                edges=[GraphEdge(src=USER_A, dst=COMPUTER_B, edge_type="AdminTo")],
            )


def test_security_graph_is_isolated_by_engagement(engagement_factory):
    """RLS, exercised the same way every other table's isolation test is:
    write in one engagement, confirm the other engagement's connection
    cannot see it at all -- not even to say a path doesn't exist for the
    right reason, since the node itself should be invisible.
    """
    eid_1, _ = engagement_factory()
    eid_2, _ = engagement_factory()

    with engagement_scope(eid_1) as conn:
        run_id = make_tool_run(conn, engagement_id=eid_1)
        record_batch(
            conn, engagement_id=eid_1, run_id=run_id,
            nodes=[USER_A, COMPUTER_B],
            edges=[GraphEdge(src=USER_A, dst=COMPUTER_B, edge_type="AdminTo")],
        )

    with engagement_scope(eid_2) as conn:
        assert shortest_path(
            conn, start=_ref(USER_A), target=_ref(COMPUTER_B), max_depth=10,
        ) is None
        assert paths_within_hops(conn, start=_ref(USER_A), max_depth=10) == []
