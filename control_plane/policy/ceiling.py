"""The longest a capability may be asked to last, as the Python side knows it (D58-16, D64).

``authz.rego`` denies a capability request whose ``max_duration_seconds`` is above this
(``budget_duration_exceeds_ceiling``), below 1, or not a number. This module carries the same number
for the code that must reason about it without asking OPA -- the reconciler's time bounds, which use
``min(budget, ceiling)`` because the budget is a number the database holds and a capability issued
before the ceiling existed may exceed it. ``tests/test_duration_ceiling.py`` reads the Rego and
fails if the two differ, so there is one number in two places and no way for them to drift.

1,800 s is three times the largest budget any code path builds (``Budget()`` is 600 s): room to
grow without a change, short enough that the reconciler's worst bound stays under an hour.
Chosen, not derived.
"""

MAX_DURATION_CEILING_SECONDS = 1800
