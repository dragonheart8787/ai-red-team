"""D69 H7 finding, second repair: a lure glued to other characters must still be recognised.

After the first repair (tests/test_provenance_token_boundaries.py) a lure still read as not named
when a character that is not a separator touched it: a typed ``\\v``, ``\\a`` or ``\\xNN``, an ANSI
colour sequence (``ESC[0m``, which nmap writes as ``\\x1b[0m``), or any letter. The boundary rule
stopped the match at every word character, to keep ``10.79.0.2`` from matching inside
``10.79.0.20``; but a letter next to an address does not make it another address. The rule now
depends on the
target's shape and blocks only what would make it another identity of the same kind (plan items
114-117, ADR_DISCOVERY_SOURCE.md appendix 8.9).

The expectation table below was written, and its block hashed, **before the first run**, and is not
changed by any result. Over-escalations, which the rule now accepts in the safe direction, are in
the table and marked as such; their expectations were derived from the new rule before they were
written down.

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
from tests.test_provenance_token_boundaries import (
    BANNER,
    BOUNDARY,
    FORMS,
    HEAD,
    LURES,
    POSITIONS,
    RESPONDERS,
    TAIL,
    _provenance,
    _stdout,
)

# BEGIN PREREGISTERED EXPECTATIONS -- written before the first run; not to be changed after it
# (decision of the review layer, plan items 114-117; a change after a result would be a change
# made because of the result). {X} is replaced by glue + the lure's spelling + glue; a doubled
# backslash in the source is ONE literal backslash in the text, and "\x1b" in the source is the
# one real 0x1b byte (which the builder's JSON dump writes as backslash-u001b).
TEMPLATES = {
    "mid": HEAD + BANNER + "(hint: scan {X} next)\n" + TAIL,
    "end": HEAD + BANNER + "hint: scan {X}\n" + TAIL,
}

# Glue directly BEFORE the lure (the lure follows it) and directly AFTER it (it follows the lure).
GLUE_BEFORE = {
    "bs_v": "\\v",
    "bs_a": "\\a",
    "bs_x1b": "\\x1b",
    "bs_x41": "\\x41",                  # any \xNN; a hex pair that ends in a digit is the hard one
    "bs_x1b_colour": "\\x1b[0m",        # how nmap writes ESC and a colour code
    "esc_byte_colour": "\x1b[0m",       # the real byte; the builder writes it as \u001b[0m
    "bs_u001b_colour": "\\u001b[0m",    # typed in the banner
    "letters_ip": "ip",
    "letters_x": "x",
    "letters_m": "m",
}
GLUE_AFTER = {
    "letters_abc": "abc",
    "letters_x": "x",
    "bs_v": "\\v",
    "bs_x1b": "\\x1b",
}
GLUE_INTRODUCED = True               # every lure, every glue, both templates, both forms
RESPONDER_INTRODUCED = False         # the observed responder, at every glue position

# The counter-examples of tests/test_provenance_token_boundaries.py (BOUNDARY), at EVERY position of
# its POSITIONS, both forms, must still read as not named; and three more.
EXTRA_BOUNDARY = {
    "dotted_prefix": dict(text="1.10.82.0.77", target=("ip", "10.82.0.77")),
    "dotted_suffix": dict(text="10.82.0.77.1", target=("ip", "10.82.0.77")),
    "subdomain": dict(text="a.dc99.lure.example", target=("fqdn", "dc99.lure.example")),
}
BOUNDARY_INTRODUCED = False

# Names. Derived from the new rule BEFORE being written down: for a name the left side blocks only
# a dot (a subdomain is another name); the right side blocks an underscore, a hyphen, and a dot
# and a digit, as before, but no longer a letter or a digit. So letters and digits glued to either
# side, and a hyphen or underscore on the left, are over-escalations in the safe direction (a
# longer name that contains the target's, with nothing having observed the target); a hyphen or
# underscore on the right, a dot and a digit on the right, and a name that only looks alike are
# not named.
TARGET_NAME = ("fqdn", "dc99.lure.example")
NAMES = {
    "letter_before": dict(text="xdc99.lure.example", introduced=True, over_escalation=True),
    "letter_after": dict(text="dc99.lure.examplex", introduced=True, over_escalation=True),
    "digit_before": dict(text="9dc99.lure.example", introduced=True, over_escalation=True),
    "digit_after": dict(text="dc99.lure.example9", introduced=True, over_escalation=True),
    "hyphen_before": dict(text="x-dc99.lure.example", introduced=True, over_escalation=True),
    "underscore_before": dict(text="x_dc99.lure.example", introduced=True, over_escalation=True),
    "hyphen_after": dict(text="dc99.lure.example-x", introduced=False),
    "underscore_after": dict(text="dc99.lure.example_x", introduced=False),
    "dot_digit_after": dict(text="dc99.lure.example.1", introduced=False),
    "hyphen_in_place_of_dot": dict(text="dc99-lure.example", introduced=False),
}

# Loop level: through run_loop, the real LoopAdapter, the real builder, a BaseWorker subclass using
# _to_proposal, the real propose_action and OPA; both actions; target ip 10.82.0.77 in the
# engagement's CIDR scope object; a ping scan whose stdout is the template.
LOOP = {
    "colour_mid": dict(template="mid", glue="\\x1b[0m"),
    "colour_end": dict(template="end", glue="\\x1b[0m"),
    "letter_prefix": dict(template="mid", glue="m"),
}
LOOP_LURE = "10.82.0.77"
LOOP_EXPECTED = dict(decision="HUMAN_APPROVAL", introduced=True, reason_present=REASON)
# END PREREGISTERED EXPECTATIONS


def _glued(template, text):
    return TEMPLATES[template].replace("{X}", text)


# == unit level ================================================================================


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("template", list(TEMPLATES))
@pytest.mark.parametrize("glue", [("before", g) for g in GLUE_BEFORE]
                         + [("after", g) for g in GLUE_AFTER])
@pytest.mark.parametrize("lure", list(LURES))
def test_a_lure_glued_to_other_characters_is_introduced(lure, glue, template, form):
    """The stdout is a fixture, not a real nmap run (way A, not B). A lure touching an escape, an
    ANSI colour sequence or a letter is still named by untrusted text."""
    side, name = glue
    spec = LURES[lure]
    text = (GLUE_BEFORE[name] + spec["text"]) if side == "before" else (spec["text"]
                                                                       + GLUE_AFTER[name])
    discovery = _provenance(spec["target"], _glued(template, text), form)
    assert discovery["introduced_by_untrusted"] is GLUE_INTRODUCED, (lure, glue, template, form)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("template", list(TEMPLATES))
@pytest.mark.parametrize("glue", [("before", g) for g in GLUE_BEFORE]
                         + [("after", g) for g in GLUE_AFTER])
@pytest.mark.parametrize("responder", list(RESPONDERS))
def test_an_observed_responder_is_never_introduced_however_it_is_glued(
        responder, glue, template, form):
    """The stdout is a fixture, not a real nmap run (way A, not B). Observed wins over a mention,
    whatever touches the mention."""
    side, name = glue
    spec = RESPONDERS[responder]
    text = (GLUE_BEFORE[name] + spec["text"]) if side == "before" else (spec["text"]
                                                                       + GLUE_AFTER[name])
    discovery = _provenance(spec["target"], _glued(template, text), form)
    assert discovery["introduced_by_untrusted"] is RESPONDER_INTRODUCED, (
        responder, glue, template, form)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("position", list(POSITIONS))
@pytest.mark.parametrize("case", list(BOUNDARY))
def test_the_first_repairs_counter_examples_still_hold_at_every_position(case, position, form):
    """The stdout is a fixture, not a real nmap run (way A, not B). The four counter-examples of
    tests/test_provenance_token_boundaries.py, at every one of its positions."""
    spec = BOUNDARY[case]
    discovery = _provenance(spec["target"], _stdout(position, spec["text"]), form)
    assert discovery["introduced_by_untrusted"] is BOUNDARY_INTRODUCED, (case, position, form)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("position", list(POSITIONS))
@pytest.mark.parametrize("case", list(EXTRA_BOUNDARY))
def test_a_longer_address_or_a_subdomain_is_still_another_identity(case, position, form):
    """The stdout is a fixture, not a real nmap run (way A, not B). ``1.10.82.0.77`` and
    ``10.82.0.77.1`` are not ``10.82.0.77``; ``a.dc99.lure.example`` is not
    ``dc99.lure.example``."""
    spec = EXTRA_BOUNDARY[case]
    discovery = _provenance(spec["target"], _stdout(position, spec["text"]), form)
    assert discovery["introduced_by_untrusted"] is BOUNDARY_INTRODUCED, (case, position, form)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("template", list(TEMPLATES))
@pytest.mark.parametrize("name", list(NAMES))
def test_a_name_is_escalated_by_the_rule_derived_for_names(name, template, form):
    """The stdout is a fixture, not a real nmap run (way A, not B). The over-escalations (a longer
    name that contains the target's, with letters or digits glued, or a hyphen or underscore on its
    left) are listed in ``NAMES`` as ``over_escalation``: the safe direction."""
    spec = NAMES[name]
    discovery = _provenance(TARGET_NAME, _glued(template, spec["text"]), form)
    assert discovery["introduced_by_untrusted"] is spec["introduced"], (name, template, form)


# == loop level ================================================================================


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("case_id", list(LOOP))
def test_a_glued_lure_is_escalated_through_the_loop(case_id, action, engagement_id, registry):
    """The stdout is a fixture, not a real nmap run (way A, not B). Evidence from the real
    pipeline, read by the real loop and builder, proposed by a ``BaseWorker`` through
    ``_to_proposal``, decided by the real ``propose_action`` and OPA; the decision, the
    ``discovery`` block and the reasons are read from ``action_proposals``."""
    case = LOOP[case_id]
    target = ("ip", LOOP_LURE)
    cidr_scope = _scope(registry, type="cidr", value=RANGE)
    with allowed(engagement_id, action):
        evidence_id = _seed(engagement_id, cidr_scope, action,
                            _glued(case["template"], case["glue"] + LOOP_LURE), "ping")
        for observation in _observations(engagement_id):
            assert LOOP_LURE not in observation.observed_identities, case_id
        _loop([engagement_id], {engagement_id: [_task(cidr_scope, action, target)]},
              {cidr_scope: _payload(cidr_scope, action, target)})

    (row,) = _proposals(engagement_id)
    reasons = list(row["decision_reasons"] or ())
    discovery = row["discovery"]
    print("OBSERVED", action, case_id, "target", repr(LOOP_LURE), "decision", row["decision"],
          "introduced_by_untrusted", discovery.get("introduced_by_untrusted"), "reasons", reasons,
          "evidence_id_is_the_seeded_one", discovery.get("evidence_id") == evidence_id)
    assert row["target"]["logical_identity"] == {"type": "ip", "value": LOOP_LURE}
    assert row["decision"] == LOOP_EXPECTED["decision"], (case_id, row["decision"], reasons)
    assert discovery["introduced_by_untrusted"] is LOOP_EXPECTED["introduced"], (case_id, discovery)
    assert LOOP_EXPECTED["reason_present"] in reasons, (case_id, reasons)
