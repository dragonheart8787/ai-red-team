"""D69 H5a1 (a2): the closed ``result_summary`` of a task (``harness/result_summary.py``).

The outcome here is a plain stand-in with the five fields the module reads; ``function_api`` is not
imported, and no database is used. The one import from the control plane is ``dispatch``, only to
compare ``REFUSAL_CODES`` with the copy in the module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from harness import result_summary as rs
from harness.result_summary import (
    build_summary,
    executed_state,
    is_key_conflict,
    is_valid_summary,
)

#: The free texts the pipeline can put into ``ActionOutcome.failure`` (the first is
#: ``CanonicalizationError``'s message with the Worker's target string, the third the pipeline's own
#: sentence for a reused key) and a marker nobody could mistake for a code.
FREE_TEXTS = (
    "invalid fqdn 'evil.example' in url 'http://evil.example/x'",
    "MODEL-WORDS-7c1f",
    "idempotency key names a different action or target",
)

#: Written out again here, on purpose: the module's own tuples are what is being checked.
FIXED_CODES = (
    "capability_refused", "approval_revalidation_failed", "capability_missing", "abandoned",
    "dispatch_in_progress_or_unknown_outcome", "dedup_hit", "tool_run_timed_out", "not_claimable",
    "capability_not_live", "engagement_not_active", "unbuildable_plan", "no_adapter_for_action",
    "egress_proxy_required", "repo_fetch_failed", "stage_moved_before_record", "unknown_proposal",
    "not_approved", "approval_missing", "unknown_outcome", "budget_exhausted",
)


@dataclass
class Outcome:
    decision: str
    failure: str | None = None
    run_id: str | None = None
    evidence_id: str | None = None
    deny_reasons: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------- the three states


@pytest.mark.parametrize("run_id,evidence_id,state", [
    ("RUN-1", "EV-1", "executed"),
    ("RUN-1", None, "unknown_outcome"),
    ("RUN-1", "", "unknown_outcome"),
    (None, None, "not_executed"),
    ("", "", "not_executed"),
    (None, "", "not_executed"),
])
def test_the_state_is_executed_unknown_outcome_or_not_executed_from_the_two_ids(
        run_id, evidence_id, state):
    assert executed_state(run_id, evidence_id) == state


def test_an_evidence_id_without_a_run_id_is_refused_and_so_is_a_non_string():
    with pytest.raises(ValueError):
        executed_state(None, "EV-1")
    with pytest.raises(ValueError):
        executed_state("", "EV-1")
    for bad in (5, b"RUN-1", ["RUN-1"]):
        with pytest.raises(ValueError):
            executed_state(bad, None)
        with pytest.raises(ValueError):
            executed_state("RUN-1", bad)


@pytest.mark.parametrize("decision", rs.DECISIONS)
def test_the_state_is_judged_by_the_ids_and_never_by_the_decision(decision):
    both = SimpleNamespace(decision=decision, failure=None, run_id="RUN-1", evidence_id="EV-1")
    only_run = SimpleNamespace(decision=decision, failure=None, run_id="RUN-1", evidence_id=None)
    assert build_summary(both) == "executed"
    assert build_summary(only_run) == "unknown_outcome"


# ---------------------------------------------------------------- the summary


def test_an_allow_without_a_run_id_is_not_executed():
    assert build_summary(Outcome("ALLOW")) == "not_executed"
    # the NetworkInUse outcome of plan item 55: ALLOW, a failure code, no ids
    assert build_summary(Outcome("ALLOW", failure="network_in_use_by_another_engagement")) \
        == "not_executed"


@pytest.mark.parametrize("decision", ["DENY", "HUMAN_APPROVAL"])
def test_a_deny_or_a_human_approval_without_a_run_id_is_never_not_executed(decision):
    assert build_summary(Outcome(decision)) == decision
    assert build_summary(Outcome(decision, failure="capability_refused")) \
        == f"{decision}:capability_refused"
    for failure in (None, "", "capability_refused", "network_unavailable", *FREE_TEXTS):
        assert build_summary(Outcome(decision, failure=failure)) != "not_executed"


def test_an_allow_with_only_a_run_id_is_unknown_outcome_and_not_other():
    out = Outcome("ALLOW", run_id="RUN-1")
    assert build_summary(out) == "unknown_outcome"
    assert build_summary(Outcome("ALLOW", run_id="RUN-1", failure="unknown_outcome")) \
        == "unknown_outcome"
    assert build_summary(out) != "other"


def test_an_allow_with_both_ids_is_executed_whatever_the_failure_says():
    assert build_summary(Outcome("ALLOW", run_id="R", evidence_id="E")) == "executed"
    assert build_summary(Outcome("ALLOW", run_id="R", evidence_id="E",
                                 failure="tool_run_timed_out")) == "executed"


@pytest.mark.parametrize("text", FREE_TEXTS)
def test_a_failure_with_free_text_becomes_other_and_the_text_is_nowhere_in_the_summary(text):
    cases = {
        "DENY": ("DENY:other", Outcome("DENY", failure=text)),
        "HUMAN_APPROVAL": ("HUMAN_APPROVAL:other", Outcome("HUMAN_APPROVAL", failure=text)),
        "ALLOW, no ids": ("not_executed", Outcome("ALLOW", failure=text)),
        # dispatch.py:482 puts an exception's text into the reason of an unknown outcome
        "ALLOW, run only": ("unknown_outcome", Outcome("ALLOW", run_id="R", failure=text)),
        "ALLOW, both ids": ("executed", Outcome("ALLOW", run_id="R", evidence_id="E",
                                                failure=text)),
    }
    for label, (expected, outcome) in cases.items():
        summary = build_summary(outcome)
        assert summary == expected, label
        assert text not in summary, label
        assert is_valid_summary(summary), label


@pytest.mark.parametrize("token", rs.VOCABULARY)
def test_a_failure_in_the_vocabulary_is_kept_as_it_is_after_the_decision(token):
    assert build_summary(Outcome("DENY", failure=token)) == f"DENY:{token}"
    assert build_summary(Outcome("HUMAN_APPROVAL", failure=token)) == f"HUMAN_APPROVAL:{token}"


def test_a_decision_outside_the_three_is_refused():
    for bad in ("allow", "ERROR", "", None):
        with pytest.raises(ValueError):
            build_summary(Outcome(bad))


def test_every_summary_the_builder_can_produce_is_valid():
    failures = (None, "", "capability_refused", "unknown_outcome", "something else", *FREE_TEXTS)
    for decision in rs.DECISIONS:
        for run_id, evidence_id in (("R", "E"), ("R", None), (None, None)):
            for failure in failures:
                summary = build_summary(Outcome(decision, failure, run_id, evidence_id))
                assert is_valid_summary(summary), (decision, run_id, evidence_id, failure, summary)


# ---------------------------------------------------------------- the vocabulary


def test_the_vocabulary_is_the_one_specified():
    assert rs.DECISIONS == ("ALLOW", "DENY", "HUMAN_APPROVAL")
    assert rs.FIXED_CODES == FIXED_CODES
    assert len(rs.REFUSAL_CODES) == 16
    assert rs.LOOP_TOKENS == ("not_run", "not_executed", "other")
    assert rs.VOCABULARY == rs.DECISIONS + FIXED_CODES + rs.REFUSAL_CODES + rs.LOOP_TOKENS
    assert len(rs.VOCABULARY) == len(set(rs.VOCABULARY)) == 3 + 20 + 16 + 3


def test_the_16_refusal_codes_are_the_ones_of_dispatch():
    from control_plane.orchestrator import dispatch
    assert rs.REFUSAL_CODES == tuple(dispatch.REFUSAL_CODES)


# ---------------------------------------------------------------- the validator


def test_every_token_of_the_vocabulary_and_every_summary_form_is_accepted():
    for token in rs.VOCABULARY:
        assert is_valid_summary(token), token
    assert is_valid_summary("executed")
    for token in rs.VOCABULARY:
        assert is_valid_summary(f"DENY:{token}"), token
        assert is_valid_summary(f"HUMAN_APPROVAL:{token}"), token


@pytest.mark.parametrize("not_a_summary", [
    "", " ", "free text", "MODEL-WORDS-7c1f", "invalid fqdn 'evil.example'", "DENY:",
    "DENY:free text",
    "DENY:Capability_Refused", "ALLOW:other", "ALLOW:capability_refused", "executed:x",
    "unknown_outcome:x", "not_executed:x", " executed", "executed ", "other:other",
    "DENY:capability_refused:x", "idempotency key names a different action or target",
    None, 5, b"executed", ["executed"],
])
def test_a_string_outside_the_closed_set_is_not_a_valid_summary(not_a_summary):
    assert is_valid_summary(not_a_summary) is False


# ---------------------------------------------------------------- the key conflict


def test_a_deny_reason_of_a_reused_key_is_a_key_conflict_and_only_that():
    reason = "idempotency_key_reused_with_a_different_request"
    assert rs.KEY_CONFLICT_REASON == reason
    assert is_key_conflict(Outcome("DENY", deny_reasons=(reason,))) is True
    assert is_key_conflict(Outcome("DENY", deny_reasons=("other_reason", reason))) is True
    assert is_key_conflict(Outcome("DENY", deny_reasons=("other_reason",))) is False
    assert is_key_conflict(Outcome("DENY", deny_reasons=())) is False
    assert is_key_conflict(SimpleNamespace(deny_reasons=None)) is False
    # the failure sentence alone is not what the harness tests: the reason is
    assert is_key_conflict(Outcome(
        "DENY", failure="idempotency key names a different action or target")) is False
