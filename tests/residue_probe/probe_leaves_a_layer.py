"""Run only by tests/test_residue_wiring.py, as a session of its own (the name is not collected
by a normal run). Publishes a global layer and does not retire it."""

import os
import uuid

from tests.helpers import publish_global_layer


def test_leave_an_overlay_active(db_available):
    layer_id = publish_global_layer(
        layer="emergency_overlay", version=uuid.uuid4().int % 2_000_000_000, document={})
    with open(os.environ["RESIDUE_PROBE_OUT"], "w") as handle:
        handle.write(str(layer_id))
