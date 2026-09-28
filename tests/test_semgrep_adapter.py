"""Semgrep adapter (D43): snippet extraction, and that redaction is actually wired in.

Three things this file pins down, none of them covered by ``tests/
test_redaction.py`` (which tests ``redact_snippet`` itself, in isolation,
and is not in question here):

* ``parse_findings`` reads the matched snippet from the mounted repository
  file on disk, never from semgrep's own ``extra.lines`` — confirmed
  empirically (adapter module docstring) to come back as the literal string
  ``"requires login"`` in this semgrep version, which would otherwise leak
  silently into evidence as an inert, wrong value.

* ``derive_view`` always carries two independent markers,
  ``untrusted_content`` and ``first_party_source_content`` (D43-4) — present
  and ``True`` together even when parsing fails, because they answer two
  different questions ("is this true" vs. "should this be seen in full")
  and neither one's presence should depend on the other succeeding.

* **The mutation test D43-4 specifically asked for**: with the real
  ``redact_snippet`` wired in, a synthetic fake credential does not appear
  in full in the derived view; with it swapped for a no-op (monkeypatched
  identity function, simulating the wiring being silently dropped), the
  identical fake credential DOES appear in full. A test that only exercised
  the "redacted" path could not tell "the mechanism worked" from "this
  particular input happened not to trigger it" — this is the corresponding
  negative control, proving derive_view actually calls redact_snippet on
  the path that reaches evidence, not just that redact_snippet works when
  called directly.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from control_plane.evidence.redaction import RedactedSnippet
from tool_gateway.adapters import semgrep

FAKE_SECRET = "hunter2_mutation_canary_9f3c1a"  # noqa: S105 - synthetic test fixture


def _write_target(tmp_path):
    target = tmp_path / "vulnerable.py"
    target.write_text(
        "import subprocess\n"
        f'password = "{FAKE_SECRET}"\n'
        "subprocess.run(cmd, shell=True)\n"
    )
    return target


def _semgrep_stdout(*, check_id: str, start_line: int, end_line: int) -> str:
    # Same shape real semgrep --json emits, including the "requires login"
    # placeholder this adapter must never trust (module docstring).
    return json.dumps({
        "results": [{
            "check_id": check_id,
            "path": f"{semgrep.CONTAINER_REPO_PATH}/vulnerable.py",
            "start": {"line": start_line, "col": 1},
            "end": {"line": end_line, "col": 1},
            "extra": {
                "message": "hardcoded credential",
                "severity": "ERROR",
                "lines": "requires login",
                "fingerprint": "requires login",
            },
        }],
    })


def test_parse_findings_reads_the_snippet_from_disk_not_from_extra_lines(tmp_path):
    _write_target(tmp_path)
    stdout = _semgrep_stdout(check_id="hardcoded-credential-assignment",
                              start_line=2, end_line=2)

    findings = semgrep.parse_findings(stdout, repo_local_path=str(tmp_path))

    assert len(findings) == 1
    assert findings[0].path == "vulnerable.py"
    # The real matched line, not semgrep's "requires login" placeholder.
    assert FAKE_SECRET in findings[0].snippet
    assert "requires login" not in findings[0].snippet


def test_derive_view_carries_both_markers_independently_even_on_parse_failure():
    view = semgrep.derive_view("not valid json", "", repo_local_path="/nonexistent")

    # Both present and True on a total parse failure: neither marker's
    # presence is contingent on the other, or on there being any finding at
    # all -- they describe the *evidence type*, not any one result in it.
    assert view["untrusted_content"] is True
    assert view["first_party_source_content"] is True
    assert view["finding_count"] == 0


def test_derive_view_redacts_the_fake_secret_by_default(tmp_path):
    _write_target(tmp_path)
    stdout = _semgrep_stdout(check_id="hardcoded-credential-assignment",
                              start_line=2, end_line=2)

    view = semgrep.derive_view(stdout, "", repo_local_path=str(tmp_path))

    rendered = json.dumps(view)
    assert FAKE_SECRET not in rendered
    assert view["notable_findings"][0]["snippet"] != ""


def test_mutation_removing_redaction_lets_the_fake_secret_through_in_full(monkeypatch):
    """The test D43-4 requires: prove the protection is real, not coincidental.

    Swap ``redact_snippet`` for the identity function -- exactly what a
    regression that silently stopped calling it, or called the wrong thing,
    would look like from ``derive_view``'s point of view. The fake secret
    must then reach the derived view unredacted, or this test could not
    distinguish "redaction ran and worked" from "redaction never ran and
    nothing in this input needed it anyway".
    """
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        _write_target(repo)
        stdout = _semgrep_stdout(check_id="hardcoded-credential-assignment",
                                  start_line=2, end_line=2)

        def _identity(text: str):
            return RedactedSnippet(text=text, patterns_matched=())

        monkeypatch.setattr(semgrep, "redact_snippet", _identity)

        view = semgrep.derive_view(stdout, "", repo_local_path=str(repo))

    assert FAKE_SECRET in view["notable_findings"][0]["snippet"]
