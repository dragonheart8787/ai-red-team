"""A role factory NOT in ``scripts/run_harness.py``'s ``APPROVED_ROLE_FACTORIES`` (plan item 131).

``tests/test_harness_approved_factory.py`` names ``tests.harness_unapproved_roles:build`` and
asserts that the entry refuses it before importing this module. The mark of an import is the
module's entry in ``sys.modules``: the test removes it first and checks afterwards that it was not
put back. The factory itself would work -- it returns H5c2's scripted roles -- so a refusal cannot
be put down to a factory that fails. No model, no container.
"""

from __future__ import annotations

from tests.harness_h5c2_roles import Roles
from tests.harness_h5c2_roles import build as _approved_build


def build() -> Roles:
    return _approved_build()
