"""The engagements a soak runs in, made and retired the way the tests make and retire theirs.

``setup`` creates a few engagements (each with a scope object over a /24 of its own, a policy that
lets the pipeline decide, and an enrollment in the scheduler); ``teardown`` withdraws the
enrollments, moves what is still stuck in them to a terminal state (nothing is deleted) and retires
the baseline layer if ``setup`` had to publish one. Rows stay: an engagement cannot be removed, and
the audit trail of a soak is meant to be read afterwards.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from scripts.soak import lib

#: three hosts per engagement: the sandbox keeps one network per allowlist, so the number of hosts
#: is the number of networks the host is allowed to end with
HOSTS = (11, 12, 13)


def _free_prefix(client, first: int) -> int:
    taken = []
    for network in client.networks.list():
        for conf in (network.attrs.get("IPAM", {}) or {}).get("Config") or []:
            taken.append(conf.get("Subnet", ""))
    for n in range(first, first + 200):
        if not any(t.startswith(f"10.66.{n}.") for t in taken):
            return n
    raise SystemExit("no free 10.66.x.0/24 range")


def setup(run_dir: Path, engagements: int, *, p1_enforce: bool = False) -> dict:
    lib.load_env()
    from tests import scheduler_support as sup
    from tests.helpers import (
        EngagementManager,
        ensure_test_baseline,
        make_engagement,
        publish_global_layer,
    )

    stamp = time.strftime("%m%d%H%M%S", time.gmtime())
    client = lib.docker_client()
    baseline = ensure_test_baseline()
    first = _free_prefix(client, 10)
    world = {"started": lib.stamp(), "baseline_layer_id": baseline, "engagements": []}
    if p1_enforce:
        # D68 S8a: a global baseline carrying the switch, published before the engagements exist
        # (a baseline applies to engagements created after it, D54), by the same path the platform
        # owner's script uses. Retired at teardown.
        world["p1_enforce_layer_id"] = publish_global_layer(
            layer="baseline_global", version=int(time.time()) % 2_000_000_000,
            document={"task_relation_enforce": True}, actor="soak-harness")
    for index in range(engagements):
        eid = f"ENG-SOAK-{stamp}-{index}"
        make_engagement(eid, actor="soak-harness")
        sup.publish_engagement_policy(eid)
        cidr = f"10.66.{first + index}.0/24"
        scope_id = sup.register_scope(EngagementManager(eid), type="cidr", value=cidr)
        sup.enroll(eid, by="soak-harness")
        world["engagements"].append({
            "id": eid, "scope_id": scope_id, "cidr": cidr,
            "hosts": [f"10.66.{first + index}.{h}" for h in HOSTS],
            "outside": f"10.67.{first + index}.9"})
    (run_dir / "world.json").write_text(json.dumps(world, indent=1))
    return world


def load(run_dir: Path) -> dict:
    return json.loads((run_dir / "world.json").read_text())


def teardown(run_dir: Path) -> dict:
    lib.load_env()
    from tests import residue
    from tests import scheduler_support as sup
    from tests.helpers import deactivate_global_layer

    world = load(run_dir)
    ids = [e["id"] for e in world["engagements"]]
    for eid in ids:
        sup.withdraw(eid)
    closed = residue.close_rows(ids)
    if world.get("p1_enforce_layer_id"):
        deactivate_global_layer(world["p1_enforce_layer_id"], actor="soak-harness")
    if world.get("baseline_layer_id"):
        deactivate_global_layer(world["baseline_layer_id"], actor="soak-harness")
    return {"withdrawn": ids, "closed_proposals": closed.proposals if hasattr(
        closed, "proposals") else None, "closed_runs": getattr(closed, "runs", None),
        "baseline_retired": bool(world.get("baseline_layer_id"))}
