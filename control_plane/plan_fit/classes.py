"""Q1 per action class: who may be asked, who is let in, who is taken out (D68 DP-15).

Q1's failure rate depends on the *class of action* the goal is about -- Active-Directory
collection and reconnaissance wording is stopped by the service's safety classifier much more often
than a secrets scan or a web fetch (``docs/D68_S7_CODE_SECRETS_FAILURE.md``) -- and with the
goal-fit switch on a failed check is a person. So Q1 is asked only about the classes an operator
has let in:

* **The list** is policy (``goal_fit_actions``, merged by union, default empty). A class outside it
  is not asked: no model is called, the proposal records ``not_assessed`` / ``class_not_enabled``,
  which no rule reads. This holds with the switch on or off.
* **Admission** is a recommendation and never an act: a class with at least :data:`ADMIT_MIN`
  judgements on the real ``propose_action`` path whose failure rate has a Wilson 95% upper bound
  of at most :data:`ADMIT_UPPER` is *offered* to the operator by
  ``scripts/manage_goal_fit_classes.py``. The operator publishes the layer that adds it.
* **Exit** is automatic and one-way: when the last :data:`EXIT_WINDOW` calls of a class (at least
  :data:`EXIT_MIN` of them) failed at a rate above :data:`EXIT_RATE`, the control plane records a
  suspension; the class is then ``not_assessed`` / ``class_suspended`` until an operator clears it.
  The runtime role can write a suspension and cannot clear one.

Nothing here changes how a question is worded to move a rate. A rate is recorded.

This module is pure -- numbers in, a verdict out -- so that the rules can be tested without a
database; the storage and the call sites are in ``goal_fit.py`` and ``function_api.py``.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass

#: admission: judgements on the real path, and the bound the failure rate must be under
ADMIT_MIN = 40
ADMIT_UPPER = 0.15
#: exit: the last EXIT_WINDOW calls, at least EXIT_MIN of them, failing above EXIT_RATE
EXIT_WINDOW = 50
EXIT_MIN = 30
EXIT_RATE = 0.30

ANSWERED = "answered"
FAILED = "failed"
OUTCOMES = (ANSWERED, FAILED)

#: what a class name may look like (``family.verb``); the policy refuses anything else
ACTION_NAME = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")


def wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    """The upper end of the Wilson score interval for ``k`` failures in ``n`` calls (95%).

    Not the rule of three: for ``k == 0`` it is ``z^2 / (n + z^2)``. No data is no evidence:
    ``1.0``.
    """
    if n <= 0:
        return 1.0
    p = k / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + margin) / (1 + z * z / n))


def valid_action_name(value: object) -> bool:
    return isinstance(value, str) and ACTION_NAME.match(value) is not None


@dataclass(frozen=True)
class Admission:
    """What the numbers say about one class; ``recommend`` is advice, not an act."""

    action: str
    n: int
    failed: int
    upper: float
    recommend: bool
    reason: str


def admission(action: str, n: int, failed: int) -> Admission:
    upper = wilson_upper(failed, n)
    if n < ADMIT_MIN:
        return Admission(action, n, failed, upper, False,
                         f"{n} judgements on the real path, {ADMIT_MIN} needed")
    if upper > ADMIT_UPPER:
        return Admission(action, n, failed, upper, False,
                         f"failure rate upper bound {upper:.1%} is above {ADMIT_UPPER:.0%}")
    return Admission(action, n, failed, upper, True,
                     f"{n} judgements, upper bound {upper:.1%} <= {ADMIT_UPPER:.0%}")


@dataclass(frozen=True)
class ExitVerdict:
    take_out: bool
    n: int
    failed: int
    rate: float


def review_exit(recent: Sequence[str]) -> ExitVerdict:
    """The exit rule over the outcomes of a class, newest first, as the store returns them.

    Only the last :data:`EXIT_WINDOW` are read. Fewer than :data:`EXIT_MIN` is too few to judge: the
    class stays. Strictly above :data:`EXIT_RATE` takes it out; at the rate it stays.
    """
    window = list(recent)[:EXIT_WINDOW]
    n = len(window)
    failed = sum(1 for o in window if o == FAILED)
    rate = failed / n if n else 0.0
    return ExitVerdict(take_out=n >= EXIT_MIN and rate > EXIT_RATE, n=n, failed=failed, rate=rate)
