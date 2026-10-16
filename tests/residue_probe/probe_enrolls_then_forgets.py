"""Run only by tests/test_residue_wiring.py, as a session of its own (the name is not collected
by a normal run). A test enrolls an engagement and ends: the test's own end withdraws it."""

import os
import uuid

from tests import scheduler_support as sup
from tests.helpers import make_engagement


def test_enroll_and_forget(db_available):
    eid = f"ENG-PROBE-{uuid.uuid4().hex[:10]}"
    make_engagement(eid)
    sup.enroll(eid)
    with open(os.environ["RESIDUE_PROBE_OUT"], "w") as handle:
        handle.write(eid)
