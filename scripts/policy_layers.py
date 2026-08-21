"""Ask which policy layers are in force, and why an action is denied (D14).

The command DEFERRED 11.1 asks for. It exists because "why is ``network.scan``
denied for this engagement" had no answer short of writing SQL against
``policy_layers`` — twice, in the D11 live run and again in D12.5 when a
container snapshot rolled the same nineteen global overlays back.

    python scripts/policy_layers.py --engagement ENG-...
    python scripts/policy_layers.py --engagement ENG-... --action network.scan
    python scripts/policy_layers.py --engagement ENG-... --json

Minimal on purpose, in the shape ``scripts/reviewer_baseline.py`` already uses:
argparse, a readable default, ``--json`` for anything that wants to parse it.

Read-only. It opens the ordinary ``engagement_scope`` connection — the same
``cyberorch_app`` role the pipeline runs as — and issues SELECTs. No new grant
exists for it, and none is needed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.policy.layers import (  # noqa: E402
    list_effective_policy_layers,
    load_effective_policy,
)
from control_plane.state.db import engagement_scope  # noqa: E402


def render(layers, policy, action: str | None) -> str:
    out: list[str] = []
    actions = policy.as_dict()["actions"]

    if action:
        verdict = policy.action_decision(action)
        out.append(f"{action}: {verdict}")
        mentioning = [
            layer for layer in layers
            if action in (layer.document.get("actions") or {})
        ]
        if mentioning:
            out.append(
                f"  decided by {len(mentioning)} of {len(layers)} active layer(s):"
            )
            for layer in mentioning:
                out.append(
                    f"    {layer.document['actions'][action]:<6} "
                    f"id={layer.id} {layer.layer} v{layer.version} "
                    f"[{layer.scope.upper()}]"
                )
        else:
            out.append(
                "  no active layer mentions it, so it resolves to DENY "
                "(§4.5: silence is not permission)"
            )
        out.append("")

    out.append(f"{len(layers)} active layer(s) apply to this engagement:")
    out.append("")
    for layer in layers:
        marker = "GLOBAL    " if layer.is_global else "engagement"
        out.append(
            f"  [{marker}] id={layer.id} {layer.layer} v{layer.version}"
            + (f"  engagement_id={layer.engagement_id}" if not layer.is_global else "")
        )
        out.append(f"              {json.dumps(layer.document, sort_keys=True)}")
        if layer.published_by:
            out.append(
                f"              published by {layer.published_by} at {layer.published_at}"
            )
        else:
            # Never blank. A missing attribution and an absent publisher are
            # different things, and conflating them is DEFERRED 11.2's confusion
            # reached from the reporting side.
            out.append(f"              published by: unknown -- {layer.attribution_note}")
        out.append("")

    if not layers:
        out.append("  (none -- every layer resolves to its neutral element, "
                   "and every action to DENY)")
        out.append("")

    out.append("merged effective policy:")
    out.append(f"  actions      {json.dumps(actions, sort_keys=True)}")
    merged = policy.as_dict()
    out.append(f"  data_deny    {merged['data_deny']}")
    out.append(f"  scope_deny   {merged['scope_deny']}")
    out.append(f"  scope_allow  {merged['scope_allow']}")
    out.append(f"  rate_limit   {merged['rate_limit']}")

    if any(layer.is_global for layer in layers):
        out.append("")
        out.append(
            "note: layers marked GLOBAL were published with engagement_id NULL "
            "and apply to every engagement in this database. Nothing expires "
            "them; deactivate_policy_layer retires one."
        )
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engagement", required=True,
                        help="engagement id to report for")
    parser.add_argument("--action", default=None,
                        help="highlight which layers decide this action class")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit the layers and the merged policy as JSON")
    args = parser.parse_args()

    load_dotenv()
    with engagement_scope(args.engagement) as conn:
        layers = list_effective_policy_layers(conn, args.engagement)
        policy = load_effective_policy(conn, args.engagement)

    if args.as_json:
        print(json.dumps({
            "engagement_id": args.engagement,
            "layers": [layer.as_dict() for layer in layers],
            "effective_policy": policy.as_dict(),
            "action": args.action,
            "action_decision": (
                policy.action_decision(args.action) if args.action else None
            ),
        }, indent=2, default=str))
    else:
        print(render(layers, policy, args.action))

    # Exit non-zero when the named action is not permitted, so this is usable
    # in a shell condition without parsing the output.
    if args.action and policy.action_decision(args.action) != "ALLOW":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
