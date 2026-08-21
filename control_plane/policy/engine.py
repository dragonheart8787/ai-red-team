"""OPA client wrapper (§3, §5).

Evaluation runs `opa eval` as a subprocess rather than talking to an OPA
server. MVP-Kernel has no scaling requirement, and a subprocess removes a
network dependency from the decision path — a policy engine that can be
unreachable is a policy engine that can be bypassed by making it unreachable.

Failure is fail-closed by construction (I10). Every error path — OPA missing,
non-zero exit, malformed output, an undefined decision — returns DENY carrying
``policy_engine_unavailable``, rather than raising and leaving each caller to
remember what to do about it. ``engine_error`` preserves the detail for the
audit record, so a broken engine is visible rather than merely quiet.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from control_plane.canonicalizer.authorization import AuthorizationResolution
from control_plane.canonicalizer.metadata import MetadataResolution
from control_plane.canonicalizer.target import CanonicalTarget
from control_plane.policy.merge import EffectivePolicy

REGO_DIR = Path(__file__).resolve().parent / "rego"
QUERY = "data.cyberorch.authz.result"

ALLOW = "ALLOW"
DENY = "DENY"
HUMAN_APPROVAL = "HUMAN_APPROVAL"

ENGINE_UNAVAILABLE = "policy_engine_unavailable"


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    deny_reasons: tuple[str, ...] = field(default_factory=tuple)
    approval_reasons: tuple[str, ...] = field(default_factory=tuple)
    engine_error: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "deny_reasons": list(self.deny_reasons),
            "approval_reasons": list(self.approval_reasons),
            "engine_error": self.engine_error,
        }


def _denied(reason: str, detail: str) -> PolicyDecision:
    return PolicyDecision(decision=DENY, deny_reasons=(reason,), engine_error=detail)


def evaluate(policy_input: Mapping[str, Any], *, rego_dir: Path = REGO_DIR) -> PolicyDecision:
    """Evaluate one request against the policy. Never raises."""
    opa = shutil.which("opa")
    if opa is None:
        return _denied(ENGINE_UNAVAILABLE, "opa binary not found on PATH")

    try:
        completed = subprocess.run(
            [opa, "eval", "--format", "json", "--data", str(rego_dir),
             "--stdin-input", QUERY],
            input=json.dumps(policy_input),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _denied(ENGINE_UNAVAILABLE, f"opa invocation failed: {exc}")

    if completed.returncode != 0:
        return _denied(
            ENGINE_UNAVAILABLE,
            f"opa exited {completed.returncode}: {completed.stderr.strip()[:500]}",
        )

    try:
        payload = json.loads(completed.stdout)
        value = payload["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        # An undefined query lands here too: `opa eval` reports an empty result
        # set rather than an error. Undefined means the policy reached no
        # conclusion, which is exactly when defaulting to permit would be worst.
        return _denied(ENGINE_UNAVAILABLE, f"could not read opa output: {exc}")

    decision = value.get("decision")
    if decision not in (ALLOW, DENY, HUMAN_APPROVAL):
        return _denied(ENGINE_UNAVAILABLE, f"unrecognized decision {decision!r}")

    return PolicyDecision(
        decision=decision,
        deny_reasons=tuple(value.get("deny_reasons") or ()),
        approval_reasons=tuple(value.get("approval_reasons") or ()),
    )


def build_policy_input(
    *,
    target: CanonicalTarget,
    action: str,
    authorization: AuthorizationResolution,
    metadata: MetadataResolution,
    policy: EffectivePolicy,
    scope_objects: Sequence[Any],
    risk_hint: str | None = None,
    discovery: Mapping[str, Any] | None = None,
    possible_sensitive_data_hint: Sequence[str] = (),
    writes_data: bool = False,
    changes_state: bool = False,
    requests_in_window: int = 0,
    capability_request: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble ``input`` for the policy.

    Note where the AI's contributions land. ``risk_hint`` and
    ``possible_sensitive_data_hint`` sit under ``canonical.risk`` and
    ``action.possible_sensitive_data_hint``, which the policy reads only in
    ``approval_reasons`` — they can add caution and nothing else. The fields
    that decide whether an action may proceed come from the resolvers and the
    registries. That separation is I6b, expressed as a data shape rather than
    as a rule someone has to follow.

    ``capability_request`` is the §4.6 budget the caller is about to ask the
    broker for — the ``Budget`` that will be handed to ``issue_capability``,
    serialized. Present tense on purpose: no capability exists yet at this
    point, and the policy is deciding whether one should. It arrives as a plain
    mapping rather than a ``Budget`` so this module keeps knowing nothing about
    the Capability Broker.

    A caller that passes nothing gets an empty object here rather than a
    permissive default, and the policy denies on it (I10). Filling in "no
    stated budget means no limit" would be the opposite of what §4.6 asks for,
    at the one place nobody would look again.
    """
    return {
        "action": {
            "action": action,
            "authorization": {
                "source": "engagement_scope",
                "scope_object_id": authorization.scope_object_id,
            },
            "discovery": dict(discovery or {"source": "explicit_scope"}),
            "possible_sensitive_data_hint": list(possible_sensitive_data_hint),
            "writes_data": writes_data,
            "changes_state": changes_state,
        },
        "canonical": {
            "target": target.as_dict(),
            "risk": risk_hint,
        },
        "capability_request": dict(capability_request or {}),
        "authorization_resolution": authorization.as_dict(),
        "resource_metadata": metadata.as_dict(),
        "policy": {
            **policy.as_dict(),
            "scope_objects": [s.as_dict() for s in scope_objects],
        },
        "usage": {"requests_in_window": requests_in_window},
    }
