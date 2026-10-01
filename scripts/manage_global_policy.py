"""Publish or retire a *global* policy layer -- an operator's action (5.37, D54).

    python scripts/manage_global_policy.py list
    python scripts/manage_global_policy.py publish --layer emergency_overlay --version 7 \\
        --document '{"actions": {"network.scan": "DENY"}}' --actor alice
    python scripts/manage_global_policy.py deactivate --layer-id 812 --actor alice

A global layer (``engagement_id IS NULL``) applies to every engagement in the database. A
baseline can widen all of them at once; retiring an emergency overlay is a relaxation -- the
same seriousness as engaging the kill switch. Until 5.37 either could be done from any
engagement's runtime connection. They can now be done only over the ``global_policy_admin``
connection, and this is the tool that opens it.

**This is deliberately not part of the pipeline.** Nothing in dispatch, the agents, the
console or the tool gateway may import the connection it uses; a test scans for that. It asks
for a person: without ``--yes`` it prints what will happen and waits for the word on a
terminal, and it refuses when there is no terminal to ask. ``--yes`` exists for scripted
provisioning and is the caller's statement that a person already decided.

The same checks as any publish apply first: an emergency overlay that would relax anything is
refused before the database is asked, and again by the table's own ``CHECK``.

Exit status: 0 done, 1 refused, 2 not confirmed.
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
    EMERGENCY_OVERLAY,
    EmergencyOverlayError,
    PolicyLayerError,
    deactivate_policy_layer,
    publish_policy_layer,
)
from control_plane.state.db import global_policy_admin_scope  # noqa: E402

GLOBAL_LAYERS = ("baseline_global", "emergency_overlay", "customer", "engagement")


def _confirm(summary: str, word: str, assume_yes: bool) -> bool:
    print(summary)
    if assume_yes:
        print("--yes given: proceeding without asking.")
        return True
    if not sys.stdin.isatty():
        print("refusing: no terminal to confirm on (use --yes only if a person has "
              "already decided).", file=sys.stderr)
        return False
    try:
        answer = input(f"type {word} to continue: ").strip()
    except EOFError:
        return False
    return answer == word


def _list() -> int:
    from sqlalchemy import text

    with global_policy_admin_scope() as conn:
        rows = conn.execute(text(
            "SELECT id, layer, version, customer_id, document, created_at "
            "FROM policy_layers WHERE active IS TRUE ORDER BY id")).mappings().all()
    if not rows:
        print("no active global layer")
    for row in rows:
        customer = f"  customer={row['customer_id']}" if row["customer_id"] else ""
        print(f"id={row['id']} {row['layer']} v{row['version']}{customer}  "
              f"{json.dumps(row['document'], sort_keys=True)}")
    return 0


def _publish(args: argparse.Namespace) -> int:
    if args.document_file:
        document = json.loads(Path(args.document_file).read_text(encoding="utf-8"))
    else:
        document = json.loads(args.document)
    effect = (
        "It only tightens (an emergency overlay cannot relax)."
        if args.layer == EMERGENCY_OVERLAY
        else "It applies to EVERY engagement and, unlike an overlay, can widen."
    )
    summary = (
        f"PUBLISH global {args.layer} v{args.version}"
        + (f" for customer {args.customer_id}" if args.customer_id else "")
        + f" as {args.actor}\n  document: {json.dumps(document, sort_keys=True)}\n  {effect}"
    )
    if not _confirm(summary, "PUBLISH", args.yes):
        return 2
    try:
        with global_policy_admin_scope() as conn:
            layer_id = publish_policy_layer(
                conn, engagement_id=None, layer=args.layer, version=args.version,
                document=document, actor=args.actor, scoped_to_engagement=False,
                customer_id=args.customer_id)
    except (PolicyLayerError, EmergencyOverlayError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"published layer id={layer_id}")
    return 0


def _deactivate(args: argparse.Namespace) -> int:
    from sqlalchemy import text

    with global_policy_admin_scope() as conn:
        row = conn.execute(
            text("SELECT layer, version, customer_id, document FROM policy_layers "
                 "WHERE id = :i AND active IS TRUE"), {"i": args.layer_id}).mappings().first()
    if row is None:
        print(f"refused: no active global layer with id {args.layer_id} "
              "(an engagement-scoped layer is not this tool's)", file=sys.stderr)
        return 1
    relaxes = (
        "RELAXES policy: retiring an emergency overlay lifts a restriction on every engagement."
        if row["layer"] == EMERGENCY_OVERLAY
        else "Retiring a layer can only widen the effective policy."
    )
    summary = (
        f"DEACTIVATE global layer id={args.layer_id} ({row['layer']} v{row['version']}) "
        f"as {args.actor}\n  document: {json.dumps(row['document'], sort_keys=True)}\n  {relaxes}"
    )
    if not _confirm(summary, "DEACTIVATE", args.yes):
        return 2
    try:
        with global_policy_admin_scope() as conn:
            done = deactivate_policy_layer(
                conn, layer_id=args.layer_id, actor=args.actor)
    except PolicyLayerError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print("deactivated" if done else "nothing changed")
    return 0 if done else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="show the active global layers and their ids")

    pub = sub.add_parser("publish", help="publish a global layer")
    pub.add_argument("--layer", required=True, choices=GLOBAL_LAYERS)
    pub.add_argument("--version", required=True, type=int)
    source = pub.add_mutually_exclusive_group(required=True)
    source.add_argument("--document", help="the layer document, as JSON")
    source.add_argument("--document-file", help="a file holding the layer document")
    pub.add_argument("--customer-id", default=None,
                     help="required for a global 'customer' layer; scopes the layer to it")
    pub.add_argument("--actor", required=True, help="who is publishing (audited)")
    pub.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    deact = sub.add_parser("deactivate", help="retire a global layer")
    deact.add_argument("--layer-id", required=True, type=int)
    deact.add_argument("--actor", required=True, help="who is retiring it (audited)")
    deact.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    args = parser.parse_args(argv)
    load_dotenv()
    if args.command == "list":
        return _list()
    if args.command == "publish":
        return _publish(args)
    return _deactivate(args)


if __name__ == "__main__":
    raise SystemExit(main())
