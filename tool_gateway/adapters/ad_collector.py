"""AD collector adapter — bulk graph collection, not single-target scanning (§4.6, D42-6).

``bloodhound-python`` (the Impacket-based, pure-Python BloodHound collector)
rather than SharpHound: it runs in the existing Linux sandbox with no new
base image and no Windows host, the same reasoning §8.3 already applies to
every other tool here (D42-1/D42-6 design doc §2.1/§4).

This is the first adapter whose action authorizes *collection over a set*
rather than an action against one target (D42-1 Option C): the capability
names an ``ad_domain`` identity, and everything this run discovers is a
**discovery candidate**, never itself authorization for anything (§1.6/§1.9
of the design doc) — nothing in this module writes ``metadata_registry``,
and nothing here can.

No credential parameter anywhere in this file. BloodHound-style collection
needs an authenticated LDAP bind, and the Credential Vault (§48,
ARCHITECTURE.md §10) does not exist (confirmed absent, ADR §4.3) — so
``build_plan`` produces a command with no ``-u``/``-p``/``-hashes`` flag at
all. That is a known, documented limitation, not an oversight: this adapter
is buildable and testable against fixture output today, and has no
live/production path until the Vault lands, the same way ``http_get``
existed with nothing to route it to before D34's proxy work.

**Flag names below are bloodhound-python's documented CLI as of this
writing, not independently verified against an installed binary in this
environment** — there is no way to verify them here, since no credential
means no run could succeed against a real domain regardless. Re-check
against ``bloodhound-python --help`` the first time a live run becomes
possible.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from control_plane.graph.store import GraphEdge, GraphNode

TOOL = "bloodhound-python"
ACTION = "ad.collect"

#: A collection run issues LDAP reads and writes nothing to the domain it
#: queries — the same D31/D34 reasoning nmap's port scan and web.get give,
#: applied to LDAP instead of TCP/HTTP: nothing in the command this adapter
#: builds has a write verb of any kind.
WRITES_DATA = False
CHANGES_STATE = False

#: LDAP goes through the sandbox's raw namespace, the same as nmap's TCP —
#: there is no application-layer HTTP here for the §8.3 egress proxy to
#: read, so routing through it would add a hop that inspects nothing.
REQUIRES_PROXY = False

TOOL_STOP_GRACE_SECONDS = 5

#: bloodhound-python's own collection-method vocabulary (``-c``). Kept
#: closed rather than passed through verbatim, matching every other
#: adapter's refusal to let a constraint become an arbitrary argv escape
#: hatch (nmap's SCAN_TYPES, http's fixed METHOD).
COLLECTION_METHODS = frozenset({
    "Group", "LocalAdmin", "Session", "Trusts", "ACL", "ObjectProps",
    "RDP", "DCOM", "Container", "All",
})

_DOMAIN_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


class AdapterError(ValueError):
    """The capability cannot be turned into a collection run."""


@dataclass(frozen=True)
class AdCollectPlan:
    """What will actually be executed, before it is executed."""

    command: tuple[str, ...]
    target: str
    collection_methods: tuple[str, ...]
    max_duration_seconds: int
    max_queries_issued: int | None

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint."""
        return {
            "target": self.target,
            "collection_methods": list(self.collection_methods),
        }


def tool_version() -> str:
    """The installed bloodhound-python version, for the fingerprint (§7)."""
    binary = shutil.which("bloodhound-python")
    if binary is None:
        return "unknown"
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return "unknown"
    return out.strip() or "unknown"


def tool_deadline(max_duration_seconds: int) -> int:
    """When the collector is asked to stop, given when the sandbox will kill it.

    Same D11-derived reasoning as every other adapter's grace margin
    (nmap.py, _http.py): ask before the sandbox kills, so a well-behaved
    run's partial output survives rather than being destroyed mid-write.
    """
    return max(1, max_duration_seconds - TOOL_STOP_GRACE_SECONDS)


def validate_collection_methods(spec: Sequence[str] | None) -> tuple[str, ...]:
    if not spec:
        return ("Group", "LocalAdmin", "Session", "ACL")
    unknown = set(spec) - COLLECTION_METHODS
    if unknown:
        raise AdapterError(
            f"unsupported collection method(s) {sorted(unknown)}; expected a "
            f"subset of {sorted(COLLECTION_METHODS)}"
        )
    return tuple(spec)


def build_plan(
    *, constraints: Mapping[str, Any], budget: Mapping[str, Any], target: str,
) -> AdCollectPlan:
    """Turn a capability into a collection command.

    ``target`` is the ``ad_domain`` identity's value — a domain name, opaque
    per D42-1 §1.1, compared verbatim. This adapter does not resolve it to
    a domain controller address; that is exactly the kind of discovery-vs-
    authorization line §8.9/I8 draws elsewhere, and DNS/DC location is the
    collector binary's own business at run time, not this module's.
    """
    if not target:
        raise AdapterError("no target")
    if not _DOMAIN_LABEL.match(target.split(".", 1)[0]):
        raise AdapterError(f"invalid ad_domain target {target!r}")

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    tool_budget = budget.get("tool") or {}
    max_queries = constraints.get("max_queries_issued") or tool_budget.get("max_queries_issued")
    max_queries = int(max_queries) if max_queries is not None else None

    methods = validate_collection_methods(constraints.get("collection_methods"))

    # No -u/-p/-hashes: see module docstring. A real run has no way to
    # authenticate until the Credential Vault exists; this command is
    # buildable and its shape testable, not a runnable invocation today.
    command = [
        "/usr/bin/bloodhound-python",
        "-d", target,
        "-c", ",".join(methods),
        "--zip",
    ]
    # max_queries_issued is recorded on the plan for observability and audit
    # (as_params/dispatch payload) but is not mapped to a CLI flag here:
    # bloodhound-python is not confirmed to have a native per-run query-count
    # cap (see module docstring on unverified flags), and inventing one would
    # be asserting tool behaviour nobody has checked. max_duration_seconds,
    # enforced by the sandbox kill exactly like every other adapter, is the
    # bound this adapter actually enforces today.

    return AdCollectPlan(
        command=tuple(command), target=target, collection_methods=methods,
        max_duration_seconds=max_duration, max_queries_issued=max_queries,
    )


def derive_view(stdout: str, stderr: str, *, notable_edge_limit: int = 20) -> dict[str, Any]:
    """Build the §4.4 derived view — the bounded, prompt-facing summary.

    Deliberately not the full graph. A BloodHound-shaped graph put inline in
    a prompt would recreate D40/5.21's argv-length crash at a much larger
    scale (design doc §2.1/§4.1 of the ADR) — the full parse lives in
    :func:`parse_graph`, whose output goes to ``control_plane.graph.store
    .record_batch`` as a side effect of dispatch, never into a prompt.
    """
    try:
        nodes, edges = parse_graph(stdout)
    except (ValueError, KeyError):
        nodes, edges = [], []

    by_kind: dict[str, int] = {}
    for n in nodes:
        by_kind[n.kind] = by_kind.get(n.kind, 0) + 1

    return {
        "untrusted_content": True,
        "computers_seen": by_kind.get("computer", 0),
        "users_seen": by_kind.get("user", 0),
        "groups_seen": by_kind.get("group", 0),
        "edge_count": len(edges),
        "notable_edges": [
            {"src": e.src.identity_value, "dst": e.dst.identity_value, "edge_type": e.edge_type}
            for e in edges[:notable_edge_limit]
        ],
        "stdout_excerpt": stdout[:2000],
        "stderr_excerpt": stderr[:2000],
    }


def parse_graph(stdout: str) -> tuple[list[GraphNode], list[GraphEdge]]:
    """The full, unbounded parse — every discovered node and edge.

    Consumes a JSON object of this adapter's own definition:
    ``{"nodes": [{"identity_type", "identity_value", "kind"}, ...],
      "edges": [{"src", "dst", "edge_type"}, ...]}`` where each edge's
    ``src``/``dst`` is an ``identity_value`` from ``nodes``.

    **This is not bloodhound-python's native output shape.** The real tool
    (with ``--zip``) emits a zip of per-object-type JSON files
    (``users.json``, ``computers.json``, ``groups.json``, ...), each with
    its own ``Aces``/``Members``/``Sessions`` arrays. Translating that into
    the shape above is unverified against a real collection — there has
    been no credential to produce one with (§4.3) — and is left as explicit
    follow-on work, not silently assumed solved. What this function does is
    fully tested against fixture data in the shape above, so
    ``dispatch_collection`` → ``record_batch`` → ``queries.py`` is exercised
    end to end; only the translation from the real tool's own output format
    into this one remains open.
    """
    doc = json.loads(stdout)
    nodes = [
        GraphNode(
            identity_type=n["identity_type"], identity_value=n["identity_value"], kind=n["kind"],
        )
        for n in doc.get("nodes", [])
    ]
    by_value = {n.identity_value: n for n in nodes}
    edges = []
    for e in doc.get("edges", []):
        src = by_value.get(e["src"])
        dst = by_value.get(e["dst"])
        if src is None or dst is None:
            raise ValueError(f"edge references a node not in this batch: {e}")
        edges.append(GraphEdge(src=src, dst=dst, edge_type=e["edge_type"]))
    return nodes, edges
