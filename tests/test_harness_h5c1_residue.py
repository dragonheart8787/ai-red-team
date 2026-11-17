"""D69 H5c1: the end-of-session residue check sees a live row of ``harness_enrolment`` (D63, H5b).

A live row there is one the harness's real reader returns on its next round, so a session that makes
one and does not end it must fail at its end, as it does for the scheduler's enrollment
(``tests/test_residue_check.py``, ACCEPTANCE 5.109). The row is made for real, with the CLI's own
functions as ``cyberorch_app``, and ended in a ``finally``: the CLI withdraws it, and the owner
removes the test's rows (``cyberorch_app`` has no DELETE, which is the point of the table).
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from tests import residue
from tests.helpers import make_engagement

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import manage_harness_enrolment as cli  # noqa: E402


def _register(engagement_id: str) -> None:
    with cli._connect(False) as conn:
        assert cli.register(conn, engagement_id, "harness_lab", "residue-test") is None


def _end(*engagement_ids: str) -> None:
    """Withdraw, then remove the rows (as the owner): leave the table as it was found."""
    for engagement_id in engagement_ids:
        with cli._connect(False) as conn:
            cli.withdraw(conn, engagement_id, "residue-test")
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE harness_enrolment NO FORCE ROW LEVEL SECURITY"))
            conn.execute(text("DELETE FROM harness_enrolment WHERE engagement_id = ANY(:ids)"),
                         {"ids": list(engagement_ids)})
            conn.execute(text("ALTER TABLE harness_enrolment FORCE ROW LEVEL SECURITY"))
    finally:
        engine.dispose()


def test_a_registration_made_after_the_snapshot_is_residue_and_one_before_it_is_not(
        engagement_id):
    other = "ENG-RESIDUE-" + uuid.uuid4().hex[:8]
    make_engagement(other)
    _register(engagement_id)
    try:
        before = residue.snapshot()                              # it is live now: not residue
        assert engagement_id in before.harness_enrollments
        assert residue.leftovers(before).harness_enrollments == []
        _register(other)
        found = residue.leftovers(before)
        assert found.harness_enrollments == [other]
        assert any(other in line and "harness" in line for line in found.failures())
    finally:
        _end(engagement_id, other)
    assert residue.leftovers(residue.snapshot()).harness_enrollments == []


def test_the_live_list_is_what_the_reader_would_return(engagement_id):
    from harness.enrolment_db import EnrolledFromDatabase
    _register(engagement_id)
    try:
        assert engagement_id in residue.live_harness_enrollments()
        assert set(EnrolledFromDatabase().enrolled()) == residue.live_harness_enrollments()
    finally:
        _end(engagement_id)
    assert engagement_id not in residue.live_harness_enrollments()


def test_a_withdrawn_registration_is_not_residue(engagement_id):
    before = residue.snapshot()
    _register(engagement_id)
    try:
        with cli._connect(False) as conn:
            assert cli.withdraw(conn, engagement_id, "residue-test") is None
        assert residue.leftovers(before).harness_enrollments == []
    finally:
        _end(engagement_id)


def test_the_failure_line_of_the_session_names_the_harness_enrolment_and_is_empty_otherwise():
    assert residue.Leftovers().failures() == []
    lines = residue.Leftovers(harness_enrollments=["ENG-X"]).failures()
    assert len(lines) == 1 and "harness enrolments left live" in lines[0] and "ENG-X" in lines[0]


@pytest.mark.parametrize("field", ["harness_enrollments"])
def test_the_snapshot_and_the_leftovers_carry_the_field_with_an_empty_default(field):
    assert getattr(residue.Snapshot(layers=frozenset(), containers=None, networks=None),
                   field) == frozenset()
    assert getattr(residue.Leftovers(), field) == []
