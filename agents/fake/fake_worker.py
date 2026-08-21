"""Scripted worker — turns a task into an Action Proposal (§4.1, §10).

The proposal it emits is a real one: authorization and discovery are separate
fields, and the worker fills each from what it actually knows. It never invents
an authorization, because the only thing it can put there is a scope object id
that came from the task — which is the shape §8.9/I8 requires. A worker that
could write "discovery: dns" into the authorization field would be a worker
that could widen scope by describing how it found something.
"""

from __future__ import annotations

from agents.base_agent import ProposedAction, ProposedTask


class FakeWorker:
    """Produces one fixed proposal per task."""

    agent_id = "fake-worker"

    def __init__(self, *, discovery_source: str = "explicit_scope",
                 ports: str = "8080", scan_type: str = "connect") -> None:
        self._discovery_source = discovery_source
        self._ports = ports
        # Constructor argument for the same reason ``ports`` is one, and added
        # when the D11 live run needed to drive a scan type other than the
        # default through the real pipeline. "connect" stays the default so
        # every existing caller is unchanged.
        self._scan_type = scan_type

    def propose(self, *, task: ProposedTask, task_id: str | None = None) -> ProposedAction:
        return ProposedAction(
            action=task.action,
            target={**task.target, "ports": self._ports,
                    "scan_type": self._scan_type},
            # The only authorization an agent can express: a pointer to a scope
            # object someone else registered. It cannot mint one.
            authorization={
                "source": "engagement_scope",
                "scope_object_id": task.scope_object_id,
            },
            # How the candidate was found. Never consulted for authorization.
            discovery={"source": self._discovery_source},
            task_id=task_id,
            resources=("network_host",),
            expected_data=("port_state",),
            reason=task.goal,
            requested_capability_ttl_seconds=60,
        )
