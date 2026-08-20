"""Evidence store — immutable raw artifact plus a derived view (§4.4).

One raw artifact, one derived view, both kept. The raw bytes never change and
never enter an LLM context; the derived view is what agents, reviewers and
verifiers are shown, and it always carries ``untrusted_content: true``.

§4.4 is careful about the word immutable, and so is this module. The guarantee
is that the application cannot rewrite the artifact: ``cyberorch_app`` holds
INSERT and SELECT on ``evidence`` and nothing else, and files are written once
under a content-addressed name. A sha256 detects tampering; it does not prevent
it. Anyone who can reach the filesystem and the database can change both. Real
cryptographic or physical immutability means WORM storage, which §4.4 defers
until a customer actually requires it — so the field is called
``logically_immutable`` and means exactly what it says.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit

DEFAULT_STORE = Path(os.environ.get("EVIDENCE_STORE", "evidence_store"))


def store_root() -> Path:
    root = Path(os.environ.get("EVIDENCE_STORE", str(DEFAULT_STORE)))
    root.mkdir(parents=True, exist_ok=True)
    return root


def write_raw_artifact(engagement_id: str, evidence_id: str, raw: bytes) -> tuple[str, str]:
    """Write the raw bytes once and return (path, sha256).

    Content-addressed: identical output written twice lands on the same path
    and the second write is skipped rather than overwriting. Nothing here ever
    opens an existing artifact for writing.
    """
    digest = hashlib.sha256(raw).hexdigest()
    directory = store_root() / engagement_id / digest[:2]
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{digest}.bin"
    if not path.exists():
        # Exclusive create: if two runs produce identical bytes concurrently,
        # one wins and the other finds the file already there. Neither
        # truncates.
        try:
            with open(path, "xb") as handle:
                handle.write(raw)
        except FileExistsError:
            pass
    return str(path), digest


def record_evidence(
    conn: Connection,
    *,
    engagement_id: str,
    evidence_id: str,
    run_id: str | None,
    evidence_type: str,
    raw: bytes,
    derived_view: dict[str, Any],
    tool: str,
    tool_version: str,
    ruleset_version: str | None = None,
    collected_at: datetime | None = None,
) -> dict[str, Any]:
    """Persist raw bytes and the derived view as one evidence record (§4.4)."""
    if not derived_view.get("untrusted_content"):
        # Everything in a derived view came from a scanned host. A view that
        # does not say so would eventually be read by something that forgot.
        raise ValueError(
            "derived_view must carry untrusted_content: true (§4.4, §8.1)"
        )

    path, digest = write_raw_artifact(engagement_id, evidence_id, raw)
    collected_at = collected_at or datetime.now(UTC)

    conn.execute(
        text("""
            INSERT INTO evidence (evidence_id, engagement_id, run_id, type,
                raw_artifact_path, raw_sha256, raw_logically_immutable,
                raw_collected_at, derived_view, tool, tool_version, ruleset_version)
            VALUES (:eid, :eng, :run, :type, :path, :sha, TRUE, :collected,
                    CAST(:view AS jsonb), :tool, :tver, :rver)
        """),
        {
            "eid": evidence_id, "eng": engagement_id, "run": run_id,
            "type": evidence_type, "path": path, "sha": digest,
            "collected": collected_at,
            "view": json.dumps(derived_view, default=str, sort_keys=True),
            "tool": tool, "tver": tool_version, "rver": ruleset_version,
        },
    )
    # The artifact's digest, recorded at the moment it was written. §4.4 is
    # careful that "logically immutable" is an application promise rather than
    # a cryptographic one; an independently committed record of the digest is
    # what makes a later mismatch attributable to a point in time.
    record_audit(
        engagement_id=engagement_id, actor="tool_gateway",
        event_type="evidence.recorded", subject_type="evidence",
        subject_id=evidence_id,
        payload={
            "run_id": run_id, "tool": tool, "tool_version": tool_version,
            "raw_sha256": digest, "raw_artifact_path": path,
            "type": evidence_type,
        },
    )
    return {"evidence_id": evidence_id, "raw_artifact_path": path, "raw_sha256": digest}


def read_raw_artifact(path: str) -> bytes:
    """Read raw bytes back, for human audit and provenance only (§4.4).

    Never call this to build a prompt. The raw artifact is the unfiltered
    output of a host under test; the derived view exists so that nothing has to
    decide, at the point of use, whether this particular blob is safe.
    """
    return Path(path).read_bytes()


def verify_artifact(conn: Connection, evidence_id: str) -> bool:
    """Re-hash the artifact and compare it with the recorded digest.

    Detects tampering after the fact. It cannot prevent it — see the module
    docstring on what "logically immutable" claims.
    """
    row = conn.execute(
        text("SELECT raw_artifact_path, raw_sha256 FROM evidence "
             "WHERE evidence_id = :eid"),
        {"eid": evidence_id},
    ).mappings().one_or_none()
    if row is None:
        return False
    try:
        actual = hashlib.sha256(Path(row["raw_artifact_path"]).read_bytes()).hexdigest()
    except OSError:
        return False
    return actual == row["raw_sha256"]
