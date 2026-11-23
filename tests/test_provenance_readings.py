"""D69-TB-1's table (plan items 146 c and 148): forms that only the second or the third reading of
``_text_forms`` finds.

Written by the review layer from plan item 147's enumeration (B1), committed with its sha256 before
its first run, and not changed after it. Every case uses the helpers and the scope arrangement of
``tests/test_provenance_token_boundaries.py`` (``SCOPES``: the cidr 10.82.0.0/24 and the fqdn
``*.lure.example``), the raw form only (the stdout itself, no escaping of any kind), at every
position of its ``POSITIONS``. A text below is a Python raw string: a backslash is one character.

* R1 to R7: by item 147 B1's reasoning, only reading 2 or reading 3 finds the target in the text,
  so the current code is expected to escalate (``introduced_by_untrusted`` true), and the mutant
  D69-TB-1, which keeps only reading 1, is expected to miss at least one of them. R6 and R7 target
  the cidr 10.82.0.0/25: the table's first draft had 10.82.0.0/24, but that is the offered scope
  object SCOPE-TB-1, which step 1 of ``_discovery_provenance`` decides as explicit scope before
  any text is read; step 1 compares identities for equality, not containment, so the /25 is not
  explicit scope. The /25 still takes the original rule's boundary, and as a range wider than /32
  it would be denied by the budget before its escalation could change a decision: R6 and R7 only
  pin the code.
* C1 and C2: texts that name another address or another name; expected not escalated.

Not decided by explicit scope: every case first asserts that no key of an offered scope object
(``_scope_keys``) is a key of the target (``_target_keys``), the comparison step 1 makes; both are
private functions of ``agents/llm/worker_base.py``, imported and called, not changed. An R case
also asserts that its decision came from the observation (``source`` is ``tool:nmap`` and
``evidence_id`` is the observation's), which only step 3 returns with an escalation. A C case
that is false with disjoint keys can only have been decided at step 2 (observed) or step 4 (named
nowhere); the only observed identity is 10.82.0.5, which no target here is.

Every stdout is a hand-written fixture, not a real nmap run: no nmap, no container, no traffic.
"""

from __future__ import annotations

import pytest

from agents.llm.worker_base import _scope_keys, _target_keys
from harness.observations import NMAP_TOOL
from tests.test_provenance_token_boundaries import (
    EVIDENCE_ID,
    POSITIONS,
    SCOPES,
    _provenance,
    _stdout,
)

# BEGIN PREREGISTERED READINGS TABLE -- written by the review layer before the first run; not to
# be changed after it (plan item 148). (case id: target, text, expected introduced_by_untrusted)
CASES = {
    "R1": (("ip", "10.82.0.77"), r"1\10.82.0.77", True),
    "R2": (("ip", "10.82.0.77"), r"10.82.0.77\5", True),
    "R3": (("ip", "10.82.0.77"), r"\u000110.82.0.77", True),
    "R4": (("fqdn", "dc99.lure.example"), r"x.\dc99.lure.example", True),
    "R5": (("fqdn", "dc99.lure.example"), r"dc99.lure.example\-x", True),
    "R6": (("cidr", "10.82.0.0/25"), r"10.82.0.0/25\n", True),
    "R7": (("cidr", "10.82.0.0/25"), r"\n10.82.0.0/25", True),
    "C1": (("ip", "10.82.0.77"), r"10.82.0.78", False),
    "C2": (("fqdn", "dc99.lure.example"), r"dc98.lure.example", False),
}
FORM = "raw"
# END PREREGISTERED READINGS TABLE


@pytest.mark.parametrize("position", list(POSITIONS))
@pytest.mark.parametrize("case", list(CASES))
def test_a_reading_case_is_judged_at_every_position(case, position):
    """The stdout is a fixture, not a real nmap run (way A, not B)."""
    target, text, expected = CASES[case]
    kind, value = target
    offered = {key for candidate in SCOPES for key in _scope_keys(candidate)}
    assert not offered & _target_keys({"type": kind, "value": value}), case   # not step 1
    discovery = _provenance(target, _stdout(position, text), FORM)
    assert discovery["introduced_by_untrusted"] is expected, (case, position)
    if case.startswith("R"):                                                  # step 3
        assert discovery["source"] == f"tool:{NMAP_TOOL}", (case, position)
        assert discovery["evidence_id"] == EVIDENCE_ID, (case, position)
