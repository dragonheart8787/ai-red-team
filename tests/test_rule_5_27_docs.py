"""ACCEPTANCE 5.27's decided rule must read the same everywhere it is stated (D54).

The rule -- a Security Graph node is a directory record, not a host's liveness, and is never by
itself "established" -- is written in three documents that a future harness author may open
first: the ACCEPTANCE entry, ``ADR_BLOODHOUND_NEO4J.md`` section 1.6 and
``D42_1_D42_6_DESIGN.md`` section 1.8. D52 left the question open in exactly those places, and
three independent restatements drift. This makes "one decision, three pointers to it"
mechanical: the paragraph between ``Decided rule (D54`` and its last sentence must appear
word for word, ignoring line wrapping and blockquote markers, in all three.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "docs"
ACCEPTANCE = DOCS / "ACCEPTANCE_MVP1_AGENTS.md"
ADR_BLOODHOUND = DOCS / "ADR_BLOODHOUND_NEO4J.md"
D42_DESIGN = DOCS / "D42_1_D42_6_DESIGN.md"

START = "**Decided rule (D54, ACCEPTANCE 5.27).**"
END = "requires when a harness is first written."


def _flat(text: str) -> str:
    """Line wrapping and blockquote markers are formatting, not wording."""
    text = re.sub(r"\n\s*>\s?", " ", text)
    return re.sub(r"\s+", " ", text)


def _rule(path: Path) -> str:
    text = _flat(path.read_text(encoding="utf-8"))
    assert START in text, f"{path.name} does not state the 5.27 decided rule"
    begin = text.index(START)
    end = text.index(END, begin) + len(END)
    return text[begin:end]


def test_the_rule_reads_identically_in_all_three_places():
    canonical = _rule(ACCEPTANCE)
    for path in (ADR_BLOODHOUND, D42_DESIGN):
        assert _rule(path) == canonical, (
            f"{path.name} states 5.27 differently from ACCEPTANCE_MVP1_AGENTS.md; "
            "edit the canonical text and copy it, do not paraphrase"
        )


def test_the_rule_says_what_the_decision_was():
    """Guards against the three staying identical while losing the point."""
    rule = _rule(ACCEPTANCE)
    for phrase in (
        "never by itself \"established\"",
        "structural observation",
        "`Observation.observed_identities`",
        "`Observation.content`",
        "D20's strict criterion",
    ):
        assert phrase in rule, phrase


def test_the_two_documents_that_carried_the_open_question_now_point_at_the_decision():
    """D52 wrote 'pending 5.27' into both; neither may still say so."""
    for path in (ADR_BLOODHOUND, D42_DESIGN):
        text = _flat(path.read_text(encoding="utf-8"))
        assert "ACCEPTANCE_MVP1_AGENTS.md` **5.27**" in text
        assert "D52 pointer" not in text or "replaces the D52 pointer" in text
        assert "(Class C)" not in text.split("5.27", 1)[1][:200]


def test_5_27_is_class_b_and_left_the_class_c_table():
    text = ACCEPTANCE.read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith("| **5.27** |"))
    assert "Decided at D54 — Class B" in row
    # The design-priority table (the Class C list of open decisions) no longer holds it.
    open_decisions = text.split("### Still open — the ones that need a decision", 1)[1]
    open_decisions = open_decisions.split("### Interface note", 1)[0]
    assert "| **5.27** |" not in open_decisions
