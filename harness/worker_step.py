"""D69 H5a2 (a8): what to do with the answer of one Worker call, as a pure decision.

The Worker is called once per claimed task and never asked again (plan items 47 and 60). Its answer
is one of three things, and the first two end the task without a proposal:

* a refusal or no proposal at all -> ``not_run``. This is the model's failure, not the allowlist's,
  so the refusal counter is not touched;
* a proposal whose action is outside the allowlist -> ``not_run``, and the refusal is counted
  (:func:`harness.action_allowlist.check_proposal_action`, with the counter given here);
* a proposal whose action is on the list -> ``propose``: the loop goes on to the pause check, the
  cap check and the proposal.

Nothing is called here: no port, no model. The only effect is the count of a refused action.
"""

from __future__ import annotations

from harness.action_allowlist import RefusalCounter, check_proposal_action
from harness.ports import WorkResult

STEP_PROPOSE = "propose"
STEP_NOT_RUN = "not_run"


def decide_after_work(result: WorkResult, refusals: RefusalCounter) -> str:
    """``propose`` or ``not_run``, for one Worker answer."""
    if result.refusal or result.proposal is None:
        return STEP_NOT_RUN
    if not check_proposal_action(result.action, counter=refusals).allowed:
        return STEP_NOT_RUN
    return STEP_PROPOSE
