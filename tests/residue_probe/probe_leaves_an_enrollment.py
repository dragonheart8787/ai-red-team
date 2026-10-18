"""Run only by tests/test_residue_wiring.py, as a session of its own (the name is not collected
by a normal run). A module-scoped fixture enrolls an engagement in the scheduler and never
withdraws it: the test that ends does not own it, so only the session end can see it."""

import os
import uuid

import pytest

from tests import scheduler_support as sup
from tests.helpers import make_engagement


@pytest.fixture(scope="module")
def enrolled_for_ever(db_available):
    eid = f"ENG-PROBE-{uuid.uuid4().hex[:10]}"
    make_engagement(eid)
    sup.enroll(eid)
    with open(os.environ["RESIDUE_PROBE_OUT"], "w") as handle:
        handle.write(eid)
    return eid


def test_leave_an_enrollment_live(enrolled_for_ever):
    assert enrolled_for_ever
