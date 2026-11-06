"""The harness's read-only view of the Scope Registry (D69 H2).

Thin on purpose. ``list_scope_objects`` already returns only the live scope objects of the
caller's engagement -- row-level security confines it -- so the only thing this adds is the
allowlist filter. The pure function it delegates to is what the tests exercise; this
module exists so that the one place the harness reads the registry is a named one, and so
that the harness never queries it from inside a role.

Nothing here writes. Registering a scope object needs the Engagement Manager's role, which
the harness does not have and must not acquire.
"""

from __future__ import annotations

from sqlalchemy import Connection

from agents.llm.worker_base import ScopeCandidate
from control_plane.registry.scope_registry import list_scope_objects
from harness.action_allowlist import candidates_from_scope_objects


def candidates_from_registry(conn: Connection) -> tuple[ScopeCandidate, ...]:
    """The live scope objects of the current engagement, filtered to the allowlist."""
    return candidates_from_scope_objects(list_scope_objects(conn))
