"""The harness's nmap Observation builder, and the evidence window it reads (D69 H3).

Two things live here:

* :func:`read_evidence_window` -- the engagement's evidence, newest first, each row joined to
  the ``tool_runs`` row it came from. The whole engagement's window, not one target's: a
  Worker's proposal is judged against everything the engagement has observed, and a window
  narrowed to the target of the moment would make a host observed by an earlier scan look
  like one nobody ever saw. Row-level security confines the read to the caller's engagement,
  so the query carries no engagement predicate of its own. ``limit`` is required and has no
  default: how much evidence a round may carry is a decision for a person, not something this
  module should quietly pick (the ceiling itself is still open -- see the plan's H3 notes).
* :func:`observation_from_evidence` -- one row, plus its run, to one
  :class:`agents.llm.worker_base.Observation`.

What the builder may and may not say, and why each rule is a rule:

``content`` is ``json.dumps(derived_view, sort_keys=True, default=str)``, produced once and
never transformed again. The Worker is shown this string JSON-escaped a second time by
``BaseWorker.build_prompt``, while ``_discovery_provenance`` matches against the raw string --
so the only difference between what the model reads and what provenance reads must be JSON
string escaping. Stripping, truncating or "cleaning" the content here would make the two
disagree, and a lure that provenance could no longer see is exactly the D13 failure.

``source`` and ``description`` are built from kernel-set fields only -- the tool's name and the
evidence id. Neither carries the target or any text out of ``derived_view``: they sit *outside*
the untrusted block in the prompt, so a sentence from a scanned host that reached them would be
presented to the model as the system's own words.

``observed_identities`` is the strict "actually responded" list the escalation turns on, so it
is filled only where the system knows that is what the field means:

* the row's tool is nmap, and
* ``tool_runs.normalized_params->>'scan_type'`` is exactly ``ping``.

Only then do the IP literals in ``derived_view["hosts"]`` go in, in canonical form
(``normalize_ip``), de-duplicated, in the order nmap reported them. Everything else is left
out: a hostname, the name half of nmap's ``name (address)`` line, a port, a ``host:port``
form, and -- above all -- the target that was *requested*. A requested target that nothing
answered is not an observed identity, and treating it as one would turn "we asked about this
host" into "this host responded", which is the distinction the whole field exists to keep.

Why ``scan_type`` comes from the run and never from the proposal: D69-3a. A connect or version
scan adds ``-Pn``, so nmap reports a host as up whether or not it answered -- its ``hosts``
list is then the hosts it was *told* to scan, not the ones that responded. Only ``-sn``'s
``hosts`` are responders. What was actually run is in ``tool_runs``; what was asked for is in
the proposal, and the two are not the same claim. Unknown counts as not-ping: a NULL
``run_id``, a missing run row, a missing or non-``ping`` value all collect nothing.

Nothing here writes, and nothing here creates a task, claims one, proposes an action or
completes one.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from agents.llm.worker_base import Observation
from control_plane.canonicalizer.target import CanonicalizationError, normalize_ip

#: The tool whose structural output the ping rule is about.
NMAP_TOOL = "nmap"

#: The one scan type whose ``hosts`` are responders (D69-3a FINAL).
PING_SCAN_TYPE = "ping"


@dataclass(frozen=True)
class EvidenceWindowRow:
    """One evidence row with the facts of the run that produced it.

    ``requested_target`` is carried and never read by the builder. It is here because it is
    what the builder must be seen *not* to use: a test can assert that the requested target
    is in the row and absent from ``observed_identities``, and a mutation that smuggles it in
    has a field to smuggle.
    """

    evidence_id: str
    run_id: str | None
    tool: str
    derived_view: Mapping[str, Any]
    scan_type: str | None
    requested_target: str | None


_WINDOW_SQL = """
    SELECT e.evidence_id,
           e.run_id,
           e.tool,
           e.derived_view,
           r.normalized_params->>'scan_type' AS scan_type,
           r.normalized_params->>'target' AS requested_target
      FROM evidence e
      LEFT JOIN tool_runs r ON r.run_id = e.run_id
     ORDER BY e.created_at DESC, e.evidence_id DESC
     LIMIT :limit
"""


def read_evidence_window(conn: Connection, *, limit: int) -> tuple[EvidenceWindowRow, ...]:
    """The engagement's evidence, newest first, at most ``limit`` rows.

    ``created_at`` then ``evidence_id`` as the order: both are ``NOT NULL``, and the second
    breaks ties, so two rows written in the same transaction come back in a fixed order
    rather than whichever Postgres happens to return.
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError(f"limit must be an int, got {type(limit).__name__}")
    if limit < 1:
        raise ValueError(f"limit must be at least 1, got {limit}")
    rows = conn.execute(text(_WINDOW_SQL), {"limit": limit}).mappings().all()
    return tuple(
        EvidenceWindowRow(
            evidence_id=row["evidence_id"],
            run_id=row["run_id"],
            tool=row["tool"],
            derived_view=row["derived_view"],
            scan_type=row["scan_type"],
            requested_target=row["requested_target"],
        )
        for row in rows
    )


def _canonical_ip(value: object) -> str | None:
    """``value`` as a canonical IP, or None when it is not an IP literal at all."""
    if not isinstance(value, str):
        return None
    try:
        return normalize_ip(value)
    except CanonicalizationError:
        return None


def observed_identities(row: EvidenceWindowRow) -> tuple[str, ...]:
    """The identities the tool structurally observed: responders, or nothing."""
    if row.tool != NMAP_TOOL:
        return ()
    if row.scan_type != PING_SCAN_TYPE:
        return ()
    view = row.derived_view if isinstance(row.derived_view, Mapping) else {}
    hosts = view.get("hosts")
    if not isinstance(hosts, Sequence) or isinstance(hosts, str | bytes):
        return ()
    found: list[str] = []
    for host in hosts:
        identity = _canonical_ip(host)
        if identity is None:
            continue
        if identity not in found:
            found.append(identity)
    return tuple(found)


def observation_from_evidence(row: EvidenceWindowRow) -> Observation:
    """One evidence row as the Worker's Observation."""
    content = json.dumps(row.derived_view, sort_keys=True, default=str)
    return Observation(
        source=f"tool:{row.tool}",
        description=f"evidence {row.evidence_id}",
        content=content,
        evidence_id=row.evidence_id,
        run_id=row.run_id,
        observed_identities=observed_identities(row),
    )


def observations_from_window(rows: Iterable[EvidenceWindowRow]) -> tuple[Observation, ...]:
    """The window's rows as Observations, in the window's order."""
    return tuple(observation_from_evidence(row) for row in rows)
