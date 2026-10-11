"""The end-of-session residue check is wired into the session, not only correct on its own (D63).

``tests/test_residue_check.py`` shows the comparison sees each kind of residue. This shows that a
**session** which leaves something behind actually fails, and one that does not, passes -- by
running two small sessions in a subprocess (their files are ``probe_*.py``, which a normal run does
not collect). A comparison that is never asked for at the end of the run protects nothing.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tests.helpers import deactivate_global_layer

REPO = Path(__file__).resolve().parents[1]


def _session(probe: str, out: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o",
         "python_files=probe_*.py", f"tests/residue_probe/{probe}"],
        cwd=REPO, capture_output=True, text=True, timeout=300,
        env={**os.environ, "RESIDUE_PROBE_OUT": str(out)})


def test_a_session_that_leaves_a_global_layer_behind_fails(db_available, tmp_path):
    out = tmp_path / "layer_id"
    done = _session("probe_leaves_a_layer.py", out)
    try:
        output = done.stdout + done.stderr
        assert done.returncode != 0, output[-800:]
        assert "the test session left state behind" in output, output[-800:]
        assert "active policy layers with no engagement" in output
        # the test itself passed; the session did not
        assert "1 passed" in output and "1 error" in output
    finally:
        if out.exists():
            deactivate_global_layer(int(out.read_text()))   # the probe's mess is not kept


def test_a_session_that_leaves_nothing_behind_passes(db_available, tmp_path):
    done = _session("probe_leaves_nothing.py", tmp_path / "unused")
    assert done.returncode == 0, (done.stdout + done.stderr)[-800:]
