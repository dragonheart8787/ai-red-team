"""D69 H7 finding, /32 repair: a single-address cidr target named by its bare address, glued.

In the harness's loop a cidr target can reach ALLOW only as a /32: the loop calls ``propose_action``
with no budget, ``max_targets`` is 1, and a wider range is denied (``target_count_exceeds_budget``)
before provenance matters (plan item 119). A /32 is named in a banner by its bare address, never by
the ``/32`` text. ``_identity_in_text`` searched for ``10.82.0.77/32`` and the older key path does
not see through a glued letter, so ``m10.82.0.77`` or ``\\x1b[0m10.82.0.77`` read as not introduced.
The repair searches a /32 target's address too, with the IPv4 boundary (plan item 120,
ADR_DISCOVERY_SOURCE.md appendix 8.10).

The expectation table below was written, and its block hashed, **before the first run**, and is not
changed by any result.

**Every stdout here is a hand-written fixture, not a real nmap run.** No nmap, no container and no
real traffic; this is way (A) of design D69-3b, not way (B).
"""

from __future__ import annotations

import pytest

from tests.test_harness_h5c2_support import allowed
from tests.test_harness_h7_528 import (
    ACTIONS,
    RANGE,
    REASON,
    _loop,
    _observations,
    _payload,
    _proposals,
    _scope,
    _seed,
    _task,
)
from tests.test_provenance_glue import GLUE_BEFORE, TEMPLATES
from tests.test_provenance_token_boundaries import FORMS, POSITIONS, _provenance, _stdout

# BEGIN PREREGISTERED EXPECTATIONS -- written before the first run; not to be changed after it
# (decision of the review layer, plan items 119-120; a change after a result would be a change
# made because of the result). TEMPLATES and GLUE_BEFORE are tests/test_provenance_glue.py's,
# POSITIONS and FORMS tests/test_provenance_token_boundaries.py's.
TARGET = ("cidr", "10.82.0.77/32")
ADDRESS = "10.82.0.77"
GLUE_AFTER = {"letters_abc": "abc", "letters_x": "x"}
GLUED_INTRODUCED = True             # every glue before and after, both templates, both forms
POSITION_INTRODUCED = True          # the bare address at every one of the 14 positions, both forms

# Step 1 read, before this table: the observed responder 10.82.0.5 gives the keys
# ('cidr', '10.82.0.5/32'), ('ip', '10.82.0.5'), ('raw', '10.82.0.5'); the target 10.82.0.5/32 gives
# ('cidr', '10.82.0.5/32'), ('raw', '10.82.0.5/32'); they meet, so step 2 of
# _discovery_provenance establishes it before any content match. Not introduced, wherever written.
RESPONDER_TARGET = ("cidr", "10.82.0.5/32")
RESPONDER_ADDRESS = "10.82.0.5"
RESPONDER_INTRODUCED = False

# Counter-examples, at every one of the 14 positions, both forms. The last is added by the
# implementer (the request allows it) so that searching the network address of EVERY cidr, not
# only of a /32, is caught: a /24 target is not named by its network address with a letter glued.
BOUNDARY = {
    "longer_suffix": dict(target=TARGET, text="10.82.0.770"),
    "longer_prefix": dict(target=TARGET, text="110.82.0.77"),
    "dotted_suffix": dict(target=TARGET, text="10.82.0.77.1"),
    "dotted_prefix": dict(target=TARGET, text="1.10.82.0.77"),
    "shorter_target": dict(target=("cidr", "10.82.0.7/32"), text="10.82.0.77"),
    "range_network_address": dict(target=("cidr", "10.82.0.0/24"), text="m10.82.0.0"),
}
BOUNDARY_INTRODUCED = False

# Loop level: through run_loop, the real LoopAdapter, the real builder, a BaseWorker subclass using
# _to_proposal, the real propose_action and OPA; both actions; scope object cidr 10.82.0.0/24;
# target cidr 10.82.0.77/32; a ping scan whose stdout is the glue file's "mid" template.
LOOP = {
    "colour_mid": dict(template="mid", text="\\x1b[0m10.82.0.77"),
    "letter_mid": dict(template="mid", text="m10.82.0.77"),
}
LOOP_EXPECTED = dict(decision="HUMAN_APPROVAL", introduced=True, reason_present=REASON)
# END PREREGISTERED EXPECTATIONS

GLUES = ([("before", name, glue + ADDRESS) for name, glue in GLUE_BEFORE.items()]
         + [("after", name, ADDRESS + glue) for name, glue in GLUE_AFTER.items()])
RESPONDER_GLUES = (
    [("before", name, glue + RESPONDER_ADDRESS) for name, glue in GLUE_BEFORE.items()]
    + [("after", name, RESPONDER_ADDRESS + glue) for name, glue in GLUE_AFTER.items()])


def _glued(template, text):
    return TEMPLATES[template].replace("{X}", text)


def _ids(glues):
    return [f"{side}-{name}" for side, name, _ in glues]


# == unit level ================================================================================


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("template", list(TEMPLATES))
@pytest.mark.parametrize("glue", GLUES, ids=_ids(GLUES))
def test_a_slash32_target_is_introduced_by_its_glued_address(glue, template, form):
    """The stdout is a fixture, not a real nmap run (way A, not B)."""
    _, _, text = glue
    discovery = _provenance(TARGET, _glued(template, text), form)
    assert discovery["introduced_by_untrusted"] is GLUED_INTRODUCED, (glue, template, form)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("position", list(POSITIONS))
def test_a_slash32_target_is_introduced_by_its_address_at_every_position(position, form):
    """The stdout is a fixture, not a real nmap run (way A, not B)."""
    discovery = _provenance(TARGET, _stdout(position, ADDRESS), form)
    assert discovery["introduced_by_untrusted"] is POSITION_INTRODUCED, (position, form)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("template", list(TEMPLATES))
@pytest.mark.parametrize("glue", RESPONDER_GLUES, ids=_ids(RESPONDER_GLUES))
def test_an_observed_slash32_responder_is_not_introduced_however_it_is_glued(
        glue, template, form):
    """The stdout is a fixture, not a real nmap run (way A, not B)."""
    _, _, text = glue
    discovery = _provenance(RESPONDER_TARGET, _glued(template, text), form)
    assert discovery["introduced_by_untrusted"] is RESPONDER_INTRODUCED, (glue, template, form)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("position", list(POSITIONS))
def test_an_observed_slash32_responder_is_not_introduced_at_any_position(position, form):
    """The stdout is a fixture, not a real nmap run (way A, not B)."""
    discovery = _provenance(RESPONDER_TARGET, _stdout(position, RESPONDER_ADDRESS), form)
    assert discovery["introduced_by_untrusted"] is RESPONDER_INTRODUCED, (position, form)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("position", list(POSITIONS))
@pytest.mark.parametrize("case", list(BOUNDARY))
def test_a_neighbour_of_a_slash32_target_is_not_its_address(case, position, form):
    """The stdout is a fixture, not a real nmap run (way A, not B)."""
    spec = BOUNDARY[case]
    discovery = _provenance(spec["target"], _stdout(position, spec["text"]), form)
    assert discovery["introduced_by_untrusted"] is BOUNDARY_INTRODUCED, (case, position, form)


# == loop level ================================================================================


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("case_id", list(LOOP))
def test_a_glued_slash32_lure_is_escalated_through_the_loop(case_id, action, engagement_id,
                                                           registry):
    """The stdout is a fixture, not a real nmap run (way A, not B). Evidence from the real
    pipeline, read by the real loop and builder, proposed by a ``BaseWorker`` through
    ``_to_proposal``, decided by the real ``propose_action`` and OPA; the decision, the
    ``discovery`` block and the reasons are read from ``action_proposals``."""
    case = LOOP[case_id]
    cidr_scope = _scope(registry, type="cidr", value=RANGE)
    with allowed(engagement_id, action):
        evidence_id = _seed(engagement_id, cidr_scope, action,
                            _glued(case["template"], case["text"]), "ping")
        for observation in _observations(engagement_id):
            assert ADDRESS not in observation.observed_identities, case_id
        _loop([engagement_id], {engagement_id: [_task(cidr_scope, action, TARGET)]},
              {cidr_scope: _payload(cidr_scope, action, TARGET)})

    (row,) = _proposals(engagement_id)
    reasons = list(row["decision_reasons"] or ())
    discovery = row["discovery"]
    print("OBSERVED", action, case_id, "target", repr(TARGET[1]), "decision", row["decision"],
          "introduced_by_untrusted", discovery.get("introduced_by_untrusted"), "reasons", reasons,
          "evidence_id_is_the_seeded_one", discovery.get("evidence_id") == evidence_id)
    assert row["target"]["logical_identity"] == {"type": TARGET[0], "value": TARGET[1]}
    assert row["decision"] == LOOP_EXPECTED["decision"], (case_id, row["decision"], reasons)
    assert discovery["introduced_by_untrusted"] is LOOP_EXPECTED["introduced"], (case_id, discovery)
    assert LOOP_EXPECTED["reason_present"] in reasons, (case_id, reasons)
