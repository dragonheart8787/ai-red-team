"""Execution fingerprint (§7).

    execution_fingerprint = sha256(
        engagement_id, tool, tool_version, ruleset_version,
        normalized_target, normalized_params, execution_context
    )

Every component is there because leaving it out causes a *false negative* —
the system decides a scan has already been done and skips it. §7 is explicit
that this is a security bug rather than a performance one: the scan that gets
skipped is the one that would have found something.

``tool_version`` and ``ruleset_version`` because new templates or a new nmap
find things the old one did not. ``execution_context`` because the same target
scanned with a different credential, or the same code at a different commit,
is a different execution (§7 v0.3). Task id is deliberately absent (§4.1), so
two tasks proposing the same work can still deduplicate against each other.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def execution_fingerprint(
    *,
    engagement_id: str,
    tool: str,
    tool_version: str,
    normalized_target: str,
    normalized_params: Mapping[str, Any] | None = None,
    execution_context: Mapping[str, Any] | None = None,
    ruleset_version: str | None = None,
) -> str:
    """Compute the fingerprint. Missing values are distinguishable from empty."""
    payload = {
        "engagement_id": engagement_id,
        "tool": tool,
        "tool_version": tool_version,
        "ruleset_version": ruleset_version,
        "normalized_target": normalized_target,
        # sort_keys so two callers building the same parameters in a different
        # order produce the same fingerprint; without it dedup would silently
        # stop working rather than fail loudly.
        "normalized_params": dict(normalized_params or {}),
        "execution_context": dict(execution_context or {}),
    }
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def execution_context(
    *,
    auth_context_id: str | None = None,
    source_revision: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build an execution context (§7).

    Identifiers only. A credential's id belongs here; the credential does not —
    the fingerprint is stored in a table many roles can read, and a secret in a
    cache key is a secret in a log.
    """
    context = {"auth_context_id": auth_context_id, "source_revision": source_revision}
    context.update(extra)
    return {k: v for k, v in context.items() if v is not None}
