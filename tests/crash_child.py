"""A process that is killed in the middle of a dispatch (D60; D58 report experiment E1).

Not a test (the name does not start with ``test_``): ``tests/test_pipeline_stages.py`` starts it as
a real subprocess, waits for the line it prints when the "container" has started, and sends it
SIGKILL -- the process dies with no ``finally``, no rollback and no chance to say anything, which is
the one failure ``try/except`` cannot model.

    python -m tests.crash_child <engagement_id> <scope_object_id> <idempotency_key>
"""

from __future__ import annotations

import sys
import time

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.config import load_dotenv
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy


class BlockingSandbox:
    """Reports that it has started, then never returns."""

    def run(self, **_kwargs):
        print("CONTAINER_STARTED", flush=True)
        time.sleep(600)


def main() -> None:
    load_dotenv()
    engagement_id, scope_object_id, key = sys.argv[1:4]
    policy = merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": "10.82.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": scope_object_id},
        discovery={"source": "explicit_scope"},
    )
    propose_action(
        engagement_id=engagement_id, proposal=proposal, reviewer=HonestFakeReviewer(),
        policy=policy, agent_id="crash-child", sandbox=BlockingSandbox(), idempotency_key=key,
    )


if __name__ == "__main__":
    main()
