"""Run only by tests/test_residue_wiring.py: a session that does what a session should."""

import uuid

from tests.helpers import deactivate_global_layer, publish_global_layer


def test_publish_and_retire_an_overlay(db_available):
    layer_id = publish_global_layer(
        layer="emergency_overlay", version=uuid.uuid4().int % 2_000_000_000, document={})
    deactivate_global_layer(layer_id)
