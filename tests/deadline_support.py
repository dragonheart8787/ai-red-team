"""Lets the deadline tests run against a helper built from a *mutated* source (D65-A mutations).

``scripts/mutations_d65a.py`` edits ``tool_gateway/deadline/src/main.rs``, builds the result into a
scratch directory with the pinned toolchain, and runs the tests with
``CYBERORCH_DEADLINE_UNDER_TEST`` naming that binary. The fixture below then points the *test
process's* view of the helper at it: the default helper path and a pin file listing its hash.
Production code is unchanged and still checks every helper against the committed ``SHA256SUMS``;
only these tests see the substitute, and only when the variable is set (nothing in CI or in a
normal run sets it).
"""

from __future__ import annotations

import hashlib
import os

import pytest

from tool_gateway import deadline_helper as dh

UNDER_TEST = "CYBERORCH_DEADLINE_UNDER_TEST"


@pytest.fixture(autouse=True)
def helper_under_test(monkeypatch, tmp_path_factory):
    path = os.environ.get(UNDER_TEST)
    if not path:
        yield
        return
    sums = tmp_path_factory.mktemp("pin") / "SHA256SUMS"
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    sums.write_text(f"{digest}  {dh.helper_name()}\n")
    monkeypatch.setattr(dh, "SHA256SUMS", sums)
    monkeypatch.setattr(dh, "default_path", lambda arch=None: path)
    yield
