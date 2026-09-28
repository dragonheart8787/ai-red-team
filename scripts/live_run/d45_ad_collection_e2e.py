"""D45 — AD Collection end-to-end verification: real dispatch, not fixtures.

D42 (ad_domain scope authorization) and D44 (credential Vault mount_for_run)
each shipped with green test suites, and every one of those suites drove
``dispatch_collection`` directly. Nothing had ever driven a proposal through
``propose_action`` — the one real production entry point (Target
Canonicalizer -> Authorization Resolver -> Metadata Resolver -> Policy
Reviewer -> OPA -> Capability Broker -> Tool Gateway) — for ``ad.collect``.
That gap is exactly D37's own lesson (``execution_constraints`` silently
dropping ``port``/``path``/``scheme`` until a real ``web.render`` run
surfaced it): a test that wires stages together by hand verifies the wiring
the test wrote, not the wiring production uses.

Driving this script for the first time found four real, previously
undiscovered bugs, none of which any prior fixture-based test could see:

1. ``ad_collector.py`` hardcoded ``/usr/bin/bloodhound-python`` -- the real
   pip install location is ``/usr/local/bin/bloodhound-python``. Invisible
   because every prior test used ``StubSandbox``, which records
   ``plan.command`` without ever executing it.
2. ``propose_action`` never imported or called ``dispatch_collection`` (or
   ``dispatch_code_scan``) at all -- step 7 unconditionally called
   ``dispatch_scan``, so a real ``ad.collect`` capability issued through the
   real entry point would run bloodhound-python but never write the
   Security Graph.
3. ``execution_constraints`` (the D30 single derivation both ``propose_
   action`` and ``grant_approval`` share) never carried ``collection_
   methods``/``domain_username``/``auth_mode``/``exclude_paths`` through
   from the proposal's target block -- a credentialed ``ad.collect``
   proposal would have its ``domain_username`` silently dropped before the
   capability was even issued.
4. ``dispatch_collection`` never looked up ``adapter.IMAGE`` the way
   ``dispatch_scan``/``dispatch_code_scan`` already do for their own
   adapters -- a caller that did not hand-pick a sandbox got
   ``DockerSandbox``'s default ``cyberorch/nmap:local`` image, which has no
   bloodhound-python binary in it at all.

All four are fixed in this branch (see ``tool_gateway/adapters/
ad_collector.py``, ``control_plane/api/function_api.py``, ``control_plane/
orchestrator/dispatch.py``). This script is what found them, and it is also
the record that a real proposal now reaches a real bloodhound-python
container against a real domain controller through the fully-fixed path.

The target: a real Samba AD DC (``nowsci/samba-domain``), the only
lightweight, non-Windows environment found that gives ``bloodhound-python``
a genuine LDAP/Kerberos endpoint to bind against (see the module docstring
of ``ad_collector.py`` for what was ruled out and why). Real DNS resolution,
a real TCP connection, and real Kerberos/NTLM authentication attempts all
happen. Authentication itself cannot succeed against this specific server
for two independent, verified reasons that are properties of the client
libraries (``ldap3``'s Sicily-only NTLM bind; ``impacket``'s Kerberos
TGS-REQ never setting the Authenticator checksum) against Samba's AD DC
implementation, not of anything this project's adapter builds -- see
``ad_collector.py``'s module docstring for the full technical detail. This
script's outcome is expected to be ``FAILED`` at the tool level for that
reason, and everything upstream of that boundary (proposal, authorization,
OPA, capability issuance, credential mount, real command execution, cleanup,
audit trail) is what is actually under verification here.

Setup this script assumes already exists (built once per environment, not by
this script -- provisioning a domain controller is not this deliverable's
job):

* ``tool_gateway/images/build_bloodhound_image.sh`` has been run, producing
  ``cyberorch/bloodhound:local``.
* A Samba AD DC container is running and reachable on the CIDR named by
  ``--network-allowlist``, with a network alias equal to ``--domain`` (Docker's
  embedded DNS resolves container *names* automatically for containers on the
  same user-defined network, but bloodhound-python needs the AD *domain
  name* to resolve, which needs an explicit ``--alias``:
  ``docker network connect --alias <domain> <network> <dc-container>``).
* A low-privilege domain user exists in that domain, and its password is
  saved in a file named by ``--secret-file`` -- never passed on this script's
  own command line or hardcoded here, the same discipline every other
  credential in this project follows.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text  # noqa: E402

from agents.base_agent import ProposedAction  # noqa: E402
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer  # noqa: E402
from control_plane.api import function_api  # noqa: E402
from control_plane.capability.broker import Budget  # noqa: E402
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.orchestrator.engagement import create_engagement, revoke_credential  # noqa: E402
from control_plane.policy.layers import load_effective_policy, publish_policy_layer  # noqa: E402
from control_plane.registry.scope_registry import register_scope_object  # noqa: E402
from control_plane.state.db import (  # noqa: E402
    credential_admin_scope,
    engagement_scope,
    registry_admin_scope,
)
from control_plane.vault.vault import store_credential  # noqa: E402
from tool_gateway.adapters import ad_collector  # noqa: E402
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable  # noqa: E402

ACTOR = "d45-e2e-verification"


def uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def check(label: str, condition: bool, detail: str = "") -> bool:
    print(f"    [{'PASS' if condition else 'FAIL'}] {label}"
          + (f"  ({detail})" if detail else ""))
    return condition


def container_ip(name: str, network: str) -> str:
    out = subprocess.run(
        ["docker", "inspect", name,
         "--format", f"{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if not out:
        raise SystemExit(f"container {name!r} has no address on {network!r}")
    return out


def setup(*, engagement_id: str, domain: str) -> tuple[str, str]:
    """Register the ad_domain scope (Option C: ad.collect only) and an
    engagement-scoped policy layer ALLOWing ad.collect.

    A fresh, engagement-scoped layer rather than the shared global baseline
    (D40's own lesson: a global row published by one verification run
    persists forever and can silently satisfy or break an unrelated run) --
    scoped_to_engagement=True keeps this ALLOW confined to this one
    throwaway engagement.
    """
    scope_object_id = uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            type="ad_domain", value=domain, allowed_actions=["ad.collect"],
            actor=ACTOR,
        )
    with engagement_scope(engagement_id) as conn:
        policy_layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"actions": {"ad.collect": "ALLOW"}},
            actor=ACTOR, scoped_to_engagement=True,
        )
    return scope_object_id, str(policy_layer_id)


def store_domain_credential(*, engagement_id: str, username: str, secret: str) -> str:
    credential_id = uid("CRED")
    with credential_admin_scope(engagement_id) as conn:
        store_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            label=f"D45 real domain bind account ({username})",
            credential_type="ad_domain_bind", secret=secret, actor=ACTOR,
        )
    return credential_id


def build_proposal(*, domain: str, scope_object_id: str, username: str) -> ProposedAction:
    return ProposedAction(
        action="ad.collect",
        target={
            "logical_identity": {"type": "ad_domain", "value": domain},
            "collection_methods": ["Group", "ACL"],
            "domain_username": username,
            "auth_mode": "password",
        },
        authorization={"source": "engagement_scope", "scope_object_id": scope_object_id},
        discovery={"source": "explicit_scope"},
        resources=("ad_object",), expected_data=("group_membership", "acl"),
        reason="D45 end-to-end verification against a real Samba AD DC",
    )


def collect_trail(engagement_id: str, *, proposal_id: str,
                  capability_id: str | None, run_id: str | None) -> dict[str, Any]:
    """The full audit trail across all three subjects one proposal touches.

    A single event_type is recorded against whichever object it is actually
    about -- 'capability.issued' against the capability_id, 'tool_run.
    started' against the run_id -- never against the proposal_id for every
    stage indiscriminately. Querying by proposal_id alone (as this script's
    first draft did) silently only ever sees the earliest two or three
    events and nothing downstream of them, which looks exactly like "the
    pipeline stopped early" when nothing of the kind happened.
    """
    subject_ids = [s for s in (proposal_id, capability_id, run_id) if s is not None]
    with engagement_scope(engagement_id) as conn:
        events = [
            r[0] for r in conn.execute(
                text("SELECT event_type FROM audit_log WHERE subject_id = ANY(:ids) "
                     "ORDER BY audit_id"),
                {"ids": subject_ids},
            ).all()
        ]
        run_row = conn.execute(
            text("SELECT run_id, status FROM tool_runs "
                 "WHERE proposal_id = :p"),
            {"p": proposal_id},
        ).mappings().first()
    return {"proposal_events": events, "run_row": dict(run_row) if run_row else None}


def run_main_dispatch(*, engagement_id: str, domain: str, scope_object_id: str,
                      username: str, credential_id: str, network_allowlist: list[str],
                      max_duration_seconds: int, sandbox) -> dict[str, Any]:
    proposal = build_proposal(domain=domain, scope_object_id=scope_object_id, username=username)
    with engagement_scope(engagement_id) as conn:
        policy = load_effective_policy(conn, engagement_id)
        outcome = function_api.propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=policy, agent_id="d45-scripted-worker",
            actor=ACTOR, sandbox=sandbox, network_allowlist=network_allowlist,
            budget=Budget(max_duration_seconds=max_duration_seconds),
            execution_context={"auth_context_id": "AUTHCTX-D45"},
            credential_id=credential_id,
        )
    trail = collect_trail(
        engagement_id, proposal_id=outcome.proposal_id,
        capability_id=outcome.capability_id, run_id=outcome.run_id,
    )
    return {
        "decision": outcome.decision,
        "deny_reasons": list(outcome.deny_reasons),
        "approval_reasons": list(outcome.approval_reasons),
        "proposal_id": outcome.proposal_id,
        "capability_id": outcome.capability_id,
        "run_id": outcome.run_id,
        "evidence_id": outcome.evidence_id,
        "failure": outcome.failure,
        **trail,
    }


def part_one_two_three(*, domain: str, username: str, secret: str,
                       network_allowlist: list[str], max_duration_seconds: int) -> dict[str, Any]:
    """The main chain: engagement -> scope -> vault -> OPA -> capability ->
    dispatch -> real bloodhound-python -> Security Graph attempt -> audit.
    """
    engagement_id = uid("ENG-D45")
    with registry_admin_scope(engagement_id) as conn:
        create_engagement(
            conn, engagement_id=engagement_id, customer_id="CUST-D45-LOCAL", actor=ACTOR,
        )
    scope_object_id, policy_layer_id = setup(engagement_id=engagement_id, domain=domain)
    credential_id = store_domain_credential(
        engagement_id=engagement_id, username=username, secret=secret,
    )

    sandbox = DockerSandbox(image=ad_collector.IMAGE)
    try:
        sandbox.ensure_image()
    except SandboxUnavailable as exc:
        raise SystemExit(f"sandbox unavailable: {exc}") from exc

    print(f"engagement     {engagement_id}")
    print(f"scope object   {scope_object_id}  ad_domain {domain}")
    print(f"policy layer   id={policy_layer_id} (engagement-scoped, ad.collect ALLOW)")
    print(f"credential_id  {credential_id}  (ad_domain_bind, username={username})")
    print(f"image          {ad_collector.IMAGE}")
    print(f"allowlist      {network_allowlist}\n")

    started = time.monotonic()
    result = run_main_dispatch(
        engagement_id=engagement_id, domain=domain, scope_object_id=scope_object_id,
        username=username, credential_id=credential_id,
        network_allowlist=network_allowlist, max_duration_seconds=max_duration_seconds,
        sandbox=sandbox,
    )
    elapsed = time.monotonic() - started

    print(f"decision       {result['decision']}")
    print(f"deny_reasons   {result['deny_reasons']}")
    print(f"proposal_id    {result['proposal_id']}")
    print(f"capability_id  {result['capability_id']}")
    print(f"run_id         {result['run_id']}")
    print(f"failure        {result['failure']}")
    print(f"elapsed        {elapsed:.1f}s")
    print(f"audit trail    {result['proposal_events']}")
    print(f"tool_runs row  {result['run_row']}\n")

    ok = True
    ok &= check("proposal was ALLOWed at OPA", result["decision"] == "ALLOW", result["decision"])
    ok &= check("a capability was issued", result["capability_id"] is not None)
    ok &= check("a tool_runs row exists (dispatch_collection was actually reached, "
                "not dispatch_scan)", result["run_row"] is not None)
    ok &= check("policy_reviewer.opinion is in the audit trail",
                "policy_reviewer.opinion" in result["proposal_events"])
    ok &= check("policy.decided is in the audit trail",
                "policy.decided" in result["proposal_events"])
    ok &= check("capability.issued is in the audit trail",
                "capability.issued" in result["proposal_events"])
    ok &= check("tool_run.started is in the audit trail",
                "tool_run.started" in result["proposal_events"])

    with engagement_scope(engagement_id) as conn:
        # credential.stored is recorded against the credential_id;
        # credential.issued_to_run (D44-6) is recorded against the run_id,
        # not the credential_id -- the same "one event, one real subject"
        # rule collect_trail() above already had to learn.
        cred_subject_ids = [s for s in (credential_id, result["run_id"]) if s is not None]
        cred_events = [
            r[0] for r in conn.execute(
                text("SELECT event_type FROM audit_log WHERE subject_id = ANY(:ids) "
                     "ORDER BY audit_id"),
                {"ids": cred_subject_ids},
            ).all()
        ]
        if result["run_id"]:
            execution_context = conn.execute(
                text("SELECT execution_context FROM tool_runs WHERE run_id = :r"),
                {"r": result["run_id"]},
            ).scalar_one()
            command = conn.execute(
                text("SELECT payload->'command' FROM audit_log WHERE subject_id = :r "
                     "AND event_type = 'tool_run.started'"),
                {"r": result["run_id"]},
            ).scalar_one()
        else:
            execution_context, command = None, None

    print(f"credential audit events  {cred_events}")
    print(f"execution_context        {execution_context}")
    print(f"real command executed    {command}\n")

    ok &= check("credential.stored is in the credential's own audit trail",
                "credential.stored" in cred_events)
    ok &= check("credential.issued_to_run is in the credential's own audit trail",
                "credential.issued_to_run" in cred_events)
    ok &= check("execution_context carries this run's credential_id",
                bool(execution_context) and execution_context.get("credential_id") == credential_id,
                str(execution_context))
    ok &= check("the real command uses the fixed binary path",
                bool(command) and ad_collector.BLOODHOUND_PYTHON_PATH in " ".join(command),
                str(command))
    ok &= check("the real command names the real domain",
                bool(command) and domain in " ".join(command), str(command))
    ok &= check("the real command never carries the plaintext secret",
                bool(command) and secret not in " ".join(command))

    return {
        "ok": ok, "engagement_id": engagement_id, "scope_object_id": scope_object_id,
        "credential_id": credential_id, "domain": domain, "username": username,
        "secret": secret, "network_allowlist": network_allowlist,
        "sandbox": sandbox, "result": result,
    }


def part_four_revocation(*, engagement_id: str, domain: str, scope_object_id: str,
                         username: str, secret: str, network_allowlist: list[str],
                         max_duration_seconds: int, sandbox) -> dict[str, Any]:
    """D44-7: revoke_credential() triggered while dispatch_collection is
    actually running.

    What this found is sharper than D44-7's own framing. D44-7 assumed
    revocation takes effect immediately in the database and only the
    container keeps running past it. In reality ``propose_action`` runs its
    entire pipeline -- canonicalize, OPA, issue_capability, and the fully
    synchronous, blocking ``sandbox.run()`` -- inside one transaction
    (``engagement_scope`` wraps ``engine.begin()``). Postgres's own
    read-committed isolation means the capability row a concurrent
    ``revoke_credential`` call needs to see and flip does not exist to any
    other connection until that whole transaction commits, which happens
    only after the container has already finished. A revoke issued while the
    dispatch is genuinely in flight is not merely "too late to stop the
    container" -- it is a complete no-op against that specific run, with
    nothing queued or retried, because there is nothing yet in the database
    for it to act on.

    The second ``revoke_credential`` call below, issued *after* the dispatch
    thread has joined (the transaction has committed, the row now exists),
    is the control that separates this from "revoke_credential is just
    broken": the identical call against the identical credential_id succeeds
    once the row is actually visible.

    A *new* credential (never used by part 1-3) so this run's own dedup
    fingerprint cannot collide with the earlier one.
    """
    credential_id = store_domain_credential(
        engagement_id=engagement_id, username=username, secret=secret,
    )

    timeline: dict[str, float] = {}
    dispatch_result: dict[str, Any] = {}

    def _dispatch() -> None:
        timeline["dispatch_start"] = time.monotonic()
        dispatch_result.update(run_main_dispatch(
            engagement_id=engagement_id, domain=domain, scope_object_id=scope_object_id,
            username=username, credential_id=credential_id,
            network_allowlist=network_allowlist, max_duration_seconds=max_duration_seconds,
            sandbox=sandbox,
        ))
        timeline["dispatch_end"] = time.monotonic()

    thread = threading.Thread(target=_dispatch)
    thread.start()
    # A short, deliberately small delay -- long enough for the dispatch
    # thread to have started the container (DB inserts, mount_for_run,
    # docker container create/start all take real wall-clock time) but far
    # short of bloodhound-python's own observed real-auth-failure duration
    # (D45's part 1-3 run above), so the revoke lands while the container is
    # still up rather than after it has already exited on its own.
    time.sleep(0.5)
    with engagement_scope(engagement_id) as conn:
        timeline["revoke_at"] = time.monotonic()
        revoked_capabilities = revoke_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            actor=ACTOR, reason="D45 mid-flight revocation timing verification",
        )
    thread.join()

    revoke_t = timeline["revoke_at"] - timeline["dispatch_start"]
    end_t = timeline["dispatch_end"] - timeline["dispatch_start"]
    print(f"credential_id (this test)  {credential_id}")
    print("dispatch started at        t=0.00s")
    print(f"revoke_credential called   t={revoke_t:.2f}s")
    print(f"dispatch returned          t={end_t:.2f}s")
    print(f"revoked_capabilities       {revoked_capabilities}")
    print(f"dispatch outcome           decision={dispatch_result.get('decision')} "
          f"run_id={dispatch_result.get('run_id')} "
          f"status={(dispatch_result.get('run_row') or {}).get('status')}\n")

    ok = True
    ok &= check(
        "revoke_credential was called strictly before dispatch returned "
        "(genuinely mid-flight, not after)",
        timeline["revoke_at"] < timeline["dispatch_end"],
        f"revoke_at={timeline['revoke_at']:.2f} dispatch_end={timeline['dispatch_end']:.2f}",
    )
    ok &= check(
        "the run still completed (succeeded or failed, not aborted) despite "
        "the mid-flight revoke attempt",
        (dispatch_result.get("run_row") or {}).get("status") in ("succeeded", "failed"),
        str(dispatch_result.get("run_row")),
    )
    ok &= check(
        "the mid-flight revoke call itself found nothing to revoke -- the "
        "capability row was not yet visible outside propose_action's own "
        "open transaction",
        revoked_capabilities == (),
        str(revoked_capabilities),
    )
    with engagement_scope(engagement_id) as conn:
        cap_row = conn.execute(
            text("SELECT revoked FROM capabilities WHERE capability_id = :c"),
            {"c": dispatch_result.get("capability_id")},
        ).mappings().one()
    print(f"capability row right after the mid-flight attempt  {dict(cap_row)}")
    ok &= check(
        "...and correspondingly the capability is still NOT revoked, even "
        "though the run it authorized already fully completed -- the real, "
        "sharper shape of D44-7's exposure window",
        cap_row["revoked"] is False,
    )

    # The control: the identical call, against the identical credential_id,
    # once the row the first attempt could not see now exists.
    with engagement_scope(engagement_id) as conn:
        revoked_after_commit = revoke_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            actor=ACTOR, reason="D45 control: revoke after the pipeline's own "
                                 "transaction has committed",
        )
        cap_row_after = conn.execute(
            text("SELECT revoked FROM capabilities WHERE capability_id = :c"),
            {"c": dispatch_result.get("capability_id")},
        ).mappings().one()
    print(f"revoke retried post-commit  revoked_capabilities={revoked_after_commit}  "
          f"capability row now  {dict(cap_row_after)}\n")
    ok &= check(
        "the same revoke_credential call succeeds once the capability row "
        "is actually visible -- confirming the earlier no-op was a "
        "transaction-visibility artifact, not a broken revoke_credential",
        dispatch_result.get("capability_id") in revoked_after_commit
        and cap_row_after["revoked"] is True,
        f"{revoked_after_commit}, {dict(cap_row_after)}",
    )

    return {"ok": ok, "timeline": timeline, "dispatch_result": dispatch_result}


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", default="d45test.local")
    parser.add_argument("--username", default="collector")
    parser.add_argument("--secret-file", required=True,
                        help="path to a file holding the domain account's "
                             "password, never passed on the command line")
    parser.add_argument("--network-allowlist", default="10.85.0.0/24")
    parser.add_argument("--max-duration-seconds", type=int, default=90)
    args = parser.parse_args()

    secret = Path(args.secret_file).read_text().strip()
    if not secret:
        raise SystemExit(f"{args.secret_file} is empty")
    network_allowlist = [args.network_allowlist]

    print("=" * 78)
    print("Part 1-3: engagement -> scope -> vault -> OPA -> capability -> "
          "dispatch -> real bloodhound-python -> Security Graph -> audit")
    print("=" * 78)
    main_run = part_one_two_three(
        domain=args.domain, username=args.username, secret=secret,
        network_allowlist=network_allowlist,
        max_duration_seconds=args.max_duration_seconds,
    )

    print("=" * 78)
    print("Part 4: mid-flight revoke_credential() during a real dispatch (D44-7)")
    print("=" * 78)
    revocation_run = part_four_revocation(
        engagement_id=main_run["engagement_id"], domain=main_run["domain"],
        scope_object_id=main_run["scope_object_id"], username=main_run["username"],
        secret=main_run["secret"], network_allowlist=main_run["network_allowlist"],
        max_duration_seconds=args.max_duration_seconds, sandbox=main_run["sandbox"],
    )

    ok = main_run["ok"] and revocation_run["ok"]
    print("=" * 78)
    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
