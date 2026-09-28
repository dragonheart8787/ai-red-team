"""Semgrep adapter — static analysis over a fetched repository (D43).

``code.scan`` is the first action whose target is not fetched *by* the
sandboxed tool: the repository is cloned by
:mod:`control_plane.orchestrator.git_fetch`, entirely outside any container,
and handed in as a read-only bind mount (D43-5 Option B, ADR §3.1). This
adapter's ``build_plan`` therefore never sees a network address to reach —
only the already-resolved local mount point the sandbox will present at
``CONTAINER_REPO_PATH``, plus the bundled ruleset mounted alongside it at
``CONTAINER_RULESET_PATH``. The scanning container has no network egress at
all (``REQUIRES_PROXY = False`` for the same reason as nmap: there is no
application protocol here for the D34 proxy to read, and unlike nmap this
tool has no protocol to speak to anything outside the container in the first
place).

Two things this module does not do, both confirmed empirically rather than
assumed, and both load-bearing for what :func:`derive_view` reads:

* Semgrep's ``--json`` output does not carry the real matched source in
  ``extra.lines`` — every result's ``extra.lines`` and ``extra.fingerprint``
  come back as the literal string ``"requires login"`` (semgrep 1.178.0
  OSS, gated behind a Semgrep.dev account for JSON export). A snippet is
  read directly from the mounted repository file, by ``path`` and the
  ``start``/``end`` line numbers, which the JSON output does report
  correctly.
* ``--disable-version-check`` is not a style preference. Under
  ``--network none`` (every run here), semgrep's own version-check HTTP
  call does not fail fast — it hangs past any sandbox kill timeout rather
  than getting a quick connection-refused. It is always in the built
  command, never a constraint a caller could omit.

Every snippet read off disk is redacted (:mod:`control_plane.evidence
.redaction`) before it leaves this module. What that snippet is redacted
*for* is a second, independent fact from ``untrusted_content`` — see
``derive_view``'s ``first_party_source_content`` marker below.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from control_plane.evidence.redaction import redact_snippet

TOOL = "semgrep"
ACTION = "code.scan"
IMAGE = "cyberorch/semgrep:local"

#: A scan reads the repository and writes nothing to it or anywhere else —
#: the same WRITES_DATA/CHANGES_STATE reasoning as nmap's port scan and
#: ad_collector's LDAP reads: no verb in the built command has a write
#: effect on the target.
WRITES_DATA = False
CHANGES_STATE = False

#: No application-layer protocol for the D34 egress proxy to read, and no
#: egress at all in this container in the first place (module docstring).
REQUIRES_PROXY = False

#: semgrep writes ~/.semgrep/settings.yml and ~/.semgrep/semgrep.log on
#: every run (confirmed empirically) -- needs a writable HOME over the
#: sandbox's otherwise read-only root, the same D36 shape as the browser.
TMPFS = {"/home/semgrep": "rw,mode=1777", "/tmp": "rw,mode=1777"}

TOOL_STOP_GRACE_SECONDS = 5

#: Where the sandbox mounts the fetched repository and the bundled ruleset
#: (tool_gateway.sandbox.DockerSandbox.run's source_mounts, D43-5).
CONTAINER_REPO_PATH = "/repo"
CONTAINER_RULESET_PATH = "/rules/ruleset.yml"

#: The bundled, locally-mounted ruleset (module docstring, D43-5): never
#: fetched from Semgrep's registry at run time, since the container has no
#: network egress to fetch one with.
DEFAULT_RULESET_HOST_PATH = str(
    Path(__file__).resolve().parent.parent / "rulesets" / "semgrep_default.yml"
)

#: Bounds how many *findings* the derived view carries in full detail (every
#: snippet is redacted regardless of this limit) — the same D40/5.21
#: argv-length reasoning ad_collector.py's notable_edge_limit already
#: applies to a differently-shaped unbounded result.
DEFAULT_NOTABLE_FINDING_LIMIT = 10


class AdapterError(ValueError):
    """The capability cannot be turned into a scan run."""


@dataclass(frozen=True)
class SemgrepPlan:
    """What will actually be executed, before it is executed."""

    command: tuple[str, ...]
    target: str
    exclude_paths: tuple[str, ...]
    max_duration_seconds: int

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint.

        Deliberately excludes ``max_duration_seconds``: a budget change is
        not a different scan of the same target, the same reasoning every
        other adapter's ``as_params`` already applies.
        """
        return {
            "target": self.target,
            "exclude_paths": list(self.exclude_paths),
        }


def tool_version() -> str:
    """The installed semgrep version, for the fingerprint (§7).

    Same pattern as every other adapter's ``tool_version`` (ad_collector.py,
    nmap.py): best-effort against the host binary, ``"unknown"`` if absent
    rather than raising. ``--disable-version-check --metrics=off`` for the
    same reason the built command always carries them (module docstring).
    """
    binary = shutil.which("semgrep")
    if binary is None:
        return "unknown"
    try:
        out = subprocess.run(
            [binary, "--version", "--disable-version-check", "--metrics=off"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return "unknown"
    return out.strip() or "unknown"


def ruleset_version(ruleset_path: str | None = None) -> str:
    """A content hash of the bundled ruleset — never a hand-maintained number.

    This is the same reasoning ``CanonicalTarget.address_count`` uses for
    being a computed property rather than a stored field (see
    ``tool_gateway/rulesets/semgrep_default.yml``'s own header comment): a
    version string a developer must remember to bump can be forgotten, and
    a forgotten bump is exactly the D11-3 shape — a real change silently
    absorbed into "the same execution" by the dedup cache. Hashing the
    file's actual bytes means a one-character rule edit changes this value
    with no separate step to remember.
    """
    path = Path(ruleset_path or DEFAULT_RULESET_HOST_PATH)
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def build_plan(
    *, constraints: Mapping[str, Any], budget: Mapping[str, Any], target: str,
) -> SemgrepPlan:
    """Turn a capability into a scan command.

    ``target`` is the ``repo`` scope object's value in
    ``<location>#<branch>`` form (D43-1 Option C,
    :func:`control_plane.orchestrator.git_fetch.parse_repo_scope_value`).
    This adapter does not fetch it — by the time ``build_plan`` runs, the
    repository is already on disk (``dispatch_code_scan`` calls
    :func:`control_plane.orchestrator.git_fetch.fetch_repo` first) — it only
    validates that the identity shape is the one the scope authorized.

    ``exclude_paths`` is an adapter constraint, not scope containment: D43-2
    found no case for defining subdirectory containment (matches D25 §2.2's
    refusal for URL paths), so excluding a subdirectory from one particular
    scan is a ``--exclude`` flag on this plan, not a narrower scope object.
    """
    if not target:
        raise AdapterError("no target")
    if "#" not in target:
        raise AdapterError(
            f"invalid repo target {target!r}: expected '<location>#<branch>' (D43-1)"
        )

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    exclude_paths = tuple(constraints.get("exclude_paths") or ())

    command = [
        "/usr/local/bin/semgrep",
        "--config", CONTAINER_RULESET_PATH,
        "--json",
        "--metrics=off",
        "--disable-version-check",
    ]
    for excluded in exclude_paths:
        command += ["--exclude", excluded]
    command.append(CONTAINER_REPO_PATH)

    return SemgrepPlan(
        command=tuple(command), target=target, exclude_paths=exclude_paths,
        max_duration_seconds=max_duration,
    )


@dataclass(frozen=True)
class Finding:
    """One semgrep result, with its snippet read from disk — never from JSON.

    ``snippet`` is the raw, unredacted text. Redaction happens in
    :func:`derive_view`, which is the only place a finding's text is bound
    for evidence a model will read — ``parse_findings`` on its own is a pure
    parse, tested against real semgrep output without needing an opinion on
    redaction.
    """

    check_id: str
    path: str
    start_line: int
    end_line: int
    severity: str
    message: str
    snippet: str


def _read_snippet(repo_local_path: str, rel_path: str, start_line: int, end_line: int) -> str:
    full_path = os.path.join(repo_local_path, rel_path)
    with open(full_path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    # semgrep's line numbers are 1-indexed and inclusive on both ends.
    return "".join(lines[max(start_line - 1, 0):end_line])


def parse_findings(stdout: str, *, repo_local_path: str) -> list[Finding]:
    """The full parse of semgrep's ``--json`` output.

    Never reads ``result["extra"]["lines"]`` (confirmed empirically to be
    the literal string ``"requires login"``, module docstring) — every
    snippet is read from ``repo_local_path`` using ``path``/``start``/
    ``end``, which are the paths and line numbers this adapter's own
    ``--json`` command was run against, still on disk at the point
    ``dispatch_code_scan`` calls this (before ``git_fetch.cleanup_repo``).
    """
    doc = json.loads(stdout)
    findings = []
    for r in doc.get("results", []):
        rel_path = os.path.relpath(r["path"], CONTAINER_REPO_PATH)
        start_line = r["start"]["line"]
        end_line = r["end"]["line"]
        findings.append(Finding(
            check_id=r["check_id"],
            path=rel_path,
            start_line=start_line,
            end_line=end_line,
            severity=r.get("extra", {}).get("severity", "UNKNOWN"),
            message=r.get("extra", {}).get("message", ""),
            snippet=_read_snippet(repo_local_path, rel_path, start_line, end_line),
        ))
    return findings


def derive_view(
    stdout: str, stderr: str, *,
    repo_local_path: str, notable_finding_limit: int = DEFAULT_NOTABLE_FINDING_LIMIT,
) -> dict[str, Any]:
    """Build the §4.4 derived view — bounded, redacted, prompt-facing.

    Two independent booleans, not one collapsed into the other (D43-4's
    explicit requirement):

    * ``untrusted_content`` (§4.4, every other adapter's meaning unchanged):
      is this evidence's *claim about reality* trustworthy on its face —
      code fetched from a repository could have been placed there by an
      adversary, exactly like an nmap banner or an HTTP response body.

    * ``first_party_source_content``: should this evidence be shown *in
      full* — this is the customer's own repository, not a third party's
      response, and it can contain a live credential a reviewer must not
      see unredacted merely for reading a finding. It answers "should this
      be seen in full", the opposite axis from "is this true", and the two
      never collapse into each other: an nmap banner is untrusted and not
      first-party; this repository's code is (from the scanner's point of
      view) both true and potentially sensitive at once.

    ``repo_local_path`` deliberately makes this adapter's ``derive_view``
    diverge from every other adapter's plain two-argument signature — a
    real snippet needs the fetched tree on disk, which only
    ``dispatch_code_scan`` (a bespoke dispatch function, not
    ``dispatch_scan``'s generic adapter call site — the same reason
    ``dispatch_collection`` already has its own bespoke post-processing
    step) can supply, since it alone controls fetch-then-scan-then-cleanup
    ordering.
    """
    try:
        findings = parse_findings(stdout, repo_local_path=repo_local_path)
    except (ValueError, KeyError, OSError):
        findings = []

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    notable = []
    for f in findings[:notable_finding_limit]:
        redacted = redact_snippet(f.snippet)
        notable.append({
            "check_id": f.check_id,
            "path": f.path,
            "start_line": f.start_line,
            "end_line": f.end_line,
            "severity": f.severity,
            "message": f.message,
            "snippet": redacted.text,
        })

    return {
        "untrusted_content": True,
        "first_party_source_content": True,
        "finding_count": len(findings),
        "findings_by_severity": by_severity,
        "notable_findings": notable,
        "stderr_excerpt": stderr[:2000],
    }
