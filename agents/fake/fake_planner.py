"""Scripted planner — no model, no reasoning (§10 MVP-Kernel).

MVP-Kernel removes the AI from the variable list entirely. This planner emits
a fixed list of tasks so that when a scenario fails, the failure is in the
kernel and not in what a model happened to say that run.
"""

from __future__ import annotations

from collections.abc import Sequence

from agents.base_agent import ProposedTask


class FakePlanner:
    """Replays a scripted list of tasks."""

    agent_id = "fake-planner"

    def __init__(self, script: Sequence[ProposedTask]) -> None:
        self._script = list(script)

    def plan(self, *, engagement_id: str) -> list[ProposedTask]:
        return list(self._script)


def scan_task(*, target_ip: str, scope_object_id: str, goal: str = "") -> ProposedTask:
    """One network scan against one address."""
    return ProposedTask(
        goal=goal or f"Scan {target_ip} for exposed services",
        target={"logical_identity": {"type": "ip", "value": target_ip}},
        action="network.scan",
        scope_object_id=scope_object_id,
    )
