"""Stateful property tests over the capability lifecycle (§11, I1/I2/I3/I7/I9).

§11 is explicit that single-input property testing is not enough here. The bug
it names — renewal that extends a lease without re-authorizing — is invisible
to any test that examines one operation, because every operation is correct on
its own. It only appears in a sequence: issue, then revoke, then heartbeat.

So this drives real operations against a real database in orders Hypothesis
chooses, and checks the invariants after every step rather than at the end. A
property asserted only at the end tells you the machine finished in a good
state, not that it was never in a bad one.

Every state transition goes through the public interfaces — the broker and
``orchestrator/engagement.py`` — rather than raw SQL. A state machine that sets
``kill_switch_engaged`` with an UPDATE tests the column, not the kill switch,
which is precisely how D8 found that the kill switch had no implementation at
all while appearing to be covered.
"""

from __future__ import annotations

import uuid

from hypothesis import HealthCheck, event, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    initialize,
    invariant,
    multiple,
    precondition,
    rule,
)
from sqlalchemy import text

from control_plane.canonicalizer.authorization import resolve_authorization
from control_plane.canonicalizer.target import normalize_target
from control_plane.capability.broker import (
    ALREADY_REVOKED,
    CREDENTIAL_REVOKED,
    ENGAGEMENT_NOT_ACTIVE,
    KILL_SWITCH,
    POLICY_CHANGED,
    SCOPE_OBJECT_DEACTIVATED,
    Budget,
    get_capability,
    issue_capability,
    renew_capability,
)
from control_plane.orchestrator.dispatch import claim_for_dispatch
from control_plane.orchestrator.engagement import (
    engage_kill_switch,
    pause_engagement,
    resume_engagement,
    retire_scope_object,
    revoke_credential,
)
from control_plane.policy.layers import (
    EMERGENCY_OVERLAY,
    load_effective_policy,
    publish_policy_layer,
)
from control_plane.policy.merge import EffectivePolicy
from control_plane.registry.metadata_registry import register_metadata
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import engagement_scope, registry_admin_scope

ACTION = "network.scan"
BUDGET_SECONDS = 300

# Two scope objects, so retiring one can be shown not to disturb the other.
# With a single scope object "revoke everything in the engagement" and "revoke
# what this scope object authorized" are indistinguishable, and the over-broad
# implementation passes.
SCOPE_CIDRS = {"a": "10.90.0.0/24", "b": "10.91.0.0/24"}
SCOPE_PREFIX = {"a": "10.90.0", "b": "10.91.0"}


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class CapabilityLifecycle(RuleBasedStateMachine):
    """One engagement, driven through arbitrary interleavings of its controls."""

    capabilities = Bundle("capabilities")

    def __init__(self) -> None:
        super().__init__()
        self.engagement_id = f"ENG-SM-{uuid.uuid4().hex[:12]}"
        self.scope_ids = {key: _uid(f"SCOPE-{key.upper()}") for key in SCOPE_CIDRS}
        self.credential_id = _uid("CRED")

        # Model state. Kept separately from the database on purpose: comparing
        # the system against the test's own expectation is the point.
        self.killed = False
        self.paused = False
        self.credential_revoked = False
        self.scope_active = dict.fromkeys(SCOPE_CIDRS, True)
        self.policy_tightened_at: dict[str, bool] = {}
        self.issued: dict[str, dict] = {}
        # Once here, a capability must never renew again by any route (I9).
        self.must_fail_renewal: set[str] = set()
        # Once here, the database row must already read revoked.
        self.must_be_revoked: set[str] = set()
        self.policy_shape: EffectivePolicy | None = None
        self.tighten_counter = 0
        self.dispatch_claims: dict[str, int] = {}
        # Capabilities revoked specifically by a scope retirement, and by
        # which scope object -- the cascade's own claim, kept apart from
        # the general revocation ledger so its reason can be asserted.
        self.revoked_by_scope: dict[str, str] = {}

    def _mark_revoked(self, capability_id: str) -> None:
        """Record, in one place, that a capability is now dead.

        Three separate pieces of model state have to move together, and keeping
        them in step by hand did not survive contact with Hypothesis: a renewal
        refused on a policy change revoked the row but left ``issued`` saying
        otherwise, so a later cascade was blamed for correctly finding nothing
        to revoke. The bug was in the model, not the system, which is its own
        argument for the model having exactly one way to express this.
        """
        if capability_id in self.issued:
            self.issued[capability_id]["revoked"] = True
        self.must_fail_renewal.add(capability_id)
        self.must_be_revoked.add(capability_id)

    @initialize(target=capabilities)
    def setup(self):
        """Register the engagement, both scope objects, and one capability each.

        The seed capabilities are not decoration. Without them ``issue`` has to
        fire before ``deactivate_scope`` for the cascade to have anything to
        revoke, and across eleven competing rules that combination is rare: two
        instrumented runs of 300 examples reached it 46 times and 3 times
        respectively, and one 300-example run reached it never while still
        reporting success. Starting from a state where both scope objects carry
        a live capability makes the retirement cascade and its precision check
        reachable from step zero. Hypothesis still explores freely on top.
        """
        with engagement_scope(self.engagement_id) as conn:
            conn.execute(
                text("INSERT INTO engagements (engagement_id, customer_id, "
                     "policy_snapshot_version) VALUES (:e, 'CUST-SM', 1)"),
                {"e": self.engagement_id},
            )
            conn.execute(
                text("INSERT INTO credentials (credential_id, engagement_id, label) "
                     "VALUES (:c, :e, 'stateful test credential')"),
                {"c": self.credential_id, "e": self.engagement_id},
            )
        with registry_admin_scope(self.engagement_id) as conn:
            for key, cidr in SCOPE_CIDRS.items():
                register_scope_object(
                    conn, engagement_id=self.engagement_id,
                    scope_object_id=self.scope_ids[key], type="cidr", value=cidr,
                    allowed_actions=["network.recon", ACTION],
                    actor="engagement-manager",
                )
                register_metadata(
                    conn, engagement_id=self.engagement_id, asset_id=_uid("ASSET"),
                    identity_type="cidr", identity_value=cidr,
                    authority="AUTHORITATIVE", source="customer_declared",
                    data_class=["network_service"], actor="engagement-manager",
                )
        with engagement_scope(self.engagement_id) as conn:
            self.policy_shape = load_effective_policy(conn, self.engagement_id)

        seeded = []
        for key in sorted(SCOPE_CIDRS):
            capability_id = _uid("CAP")
            target = f"{SCOPE_PREFIX[key]}.10"
            with engagement_scope(self.engagement_id) as conn:
                result = issue_capability(
                    conn, engagement_id=self.engagement_id,
                    capability_id=capability_id, agent_id="fake-worker",
                    action=ACTION, actor="orchestrator",
                    constraints={"host": target, "ports": "8080"},
                    budget=Budget(max_duration_seconds=BUDGET_SECONDS),
                    ttl_seconds=60, credential_id=self.credential_id,
                    scope_object_id=self.scope_ids[key],
                )
            assert result.issued is True, result.reasons
            self.issued[capability_id] = {
                "target": target, "revoked": False, "scope": key,
            }
            seeded.append(capability_id)
        return multiple(*seeded)

    # -----------------------------------------------------------------
    # Rules
    # -----------------------------------------------------------------

    @rule(target=capabilities, octet=st.integers(min_value=1, max_value=250),
          which=st.sampled_from(sorted(SCOPE_CIDRS)))
    def issue(self, octet: int, which: str):
        """Ask for a capability, through the pipeline's ordering.

        The Authorization Resolver runs first and the broker is reached only if
        it authorizes — which is what ``propose_action`` does, and is not an
        incidental detail. The broker never decides authorization: it checks
        that the scope object recorded on a capability is still live, which is
        a different and much narrower question. A rule that called the broker
        directly would be testing it without the layer that owns the decision,
        and would then report the missing check as the broker's bug.

        This is not hypothetical. The first version of this rule did exactly
        that, and the resulting counterexample blamed the broker for a check it
        was never meant to perform.

        ``propose_action`` itself is not called here because it dispatches a
        real Nmap run; at 100 examples x 20 steps that is thousands of scans.
        This reproduces the ordering, not the execution.
        """
        capability_id = _uid("CAP")
        scope_object_id = self.scope_ids[which]
        target = f"{SCOPE_PREFIX[which]}.{octet}"
        with engagement_scope(self.engagement_id) as conn:
            resolution = resolve_authorization(
                conn,
                target=normalize_target(
                    {"logical_identity": {"type": "ip", "value": target}}
                ),
                action=ACTION,
                authorization={"source": "engagement_scope",
                               "scope_object_id": scope_object_id},
            )
            # I1 at the gate: an unauthorized target never reaches the broker.
            assert resolution.authorized is self.scope_active[which], (
                f"resolver said authorized={resolution.authorized} with "
                f"scope_active[{which}]={self.scope_active[which]}: "
                f"{resolution.reasons}"
            )
            if not resolution.authorized:
                event("issue: refused by the resolver (scope retired)")
                return None

            result = issue_capability(
                conn, engagement_id=self.engagement_id, capability_id=capability_id,
                agent_id="fake-worker", action=ACTION, actor="orchestrator",
                constraints={"host": target, "ports": "8080"},
                budget=Budget(max_duration_seconds=BUDGET_SECONDS),
                ttl_seconds=60, credential_id=self.credential_id,
                scope_object_id=scope_object_id,
            )

        expected_refusal = self.killed or self.paused or self.credential_revoked
        assert result.issued is not expected_refusal, (
            f"issue returned issued={result.issued} with killed={self.killed} "
            f"paused={self.paused} credential_revoked={self.credential_revoked}; "
            f"reasons={result.reasons}"
        )

        if result.issued:
            event("issue: capability granted")
            self.issued[capability_id] = {
                "target": target, "revoked": False, "scope": which,
            }
            return capability_id
        event(f"issue: broker refused ({','.join(sorted(result.reasons))})")
        return None

    @rule(capability=capabilities)
    def renew(self, capability):
        """A heartbeat. The step §11 says only a sequence can test."""
        if capability is None:
            return
        with engagement_scope(self.engagement_id) as conn:
            result = renew_capability(
                conn, engagement_id=self.engagement_id, capability_id=capability,
                actor="orchestrator", ttl_seconds=60,
            )

        if capability in self.must_fail_renewal:
            # I9. Renewal is a new authorization, and everything this
            # capability depended on has since been withdrawn.
            event("renew: correctly refused after a dependency was withdrawn")
            assert result.renewed is False, (
                f"{capability} renewed after {sorted(self._why_dead(capability))}"
            )
            self._mark_revoked(capability)
        elif result.renewed:
            event("renew: succeeded, I3 bound checked")
            # I3, checked here rather than only in the invariant so the
            # renewal that produced the lease is the one blamed.
            expiry = result.capability.lease_expires_at
            deadline = result.capability.issued_at
            assert (expiry - deadline).total_seconds() <= BUDGET_SECONDS + 1, (
                f"{capability} lease {expiry} exceeds issued_at + budget"
            )

    @rule(capability=capabilities, times=st.integers(min_value=2, max_value=4))
    def renew_repeatedly(self, capability, times: int):
        """The control group.

        Nothing else changes; the capability is simply heartbeated several
        times in a row. Without this, every invariant here would only ever be
        exercised against a system under attack, and a bug that appears during
        ordinary operation would go unseen.
        """
        if capability is None:
            return
        for _ in range(times):
            with engagement_scope(self.engagement_id) as conn:
                result = renew_capability(
                    conn, engagement_id=self.engagement_id, capability_id=capability,
                    actor="orchestrator", ttl_seconds=60,
                )
            if capability in self.must_fail_renewal:
                event("renew_repeatedly: refused mid-loop")
                assert result.renewed is False
                self._mark_revoked(capability)
                return
            if result.renewed:
                event("renew_repeatedly: consecutive renewal held the budget")
                cap = result.capability
                assert (
                    cap.lease_expires_at - cap.issued_at
                ).total_seconds() <= BUDGET_SECONDS + 1, (
                    "repeated renewal walked the lease past the duration budget"
                )

    @rule()
    def emergency_tighten(self):
        """Publish a tightening overlay (§4.5).

        Scoped to this engagement so concurrent examples stay independent; the
        mechanism under test is that the policy version moves and outstanding
        capabilities are re-checked against it.
        """
        self.tighten_counter += 1
        with engagement_scope(self.engagement_id) as conn:
            before = load_effective_policy(conn, self.engagement_id)
            publish_policy_layer(
                conn, engagement_id=self.engagement_id,
                layer=EMERGENCY_OVERLAY, version=self.tighten_counter,
                document={
                    "data_deny": [f"tightened_{self.tighten_counter}"],
                    "actions": {"destructive_action": "DENY"},
                },
                actor="incident-commander", scoped_to_engagement=True,
            )
            after = load_effective_policy(conn, self.engagement_id)

        # I2, at the moment of the change, against the merged policy the system
        # would actually enforce rather than a shape the test computed itself.
        assert after.data_deny >= before.data_deny, (
            "an emergency overlay removed entries from data_deny"
        )
        assert after.scope_deny >= before.scope_deny
        assert after.rate_limit <= before.rate_limit
        for action, decision in before.actions.items():
            if decision == "DENY":
                assert after.actions.get(action) == "DENY", (
                    f"{action} moved from DENY to {after.actions.get(action)}"
                )
        self.policy_shape = after

        event("emergency_tighten: overlay published, policy version moved")
        # Every capability issued before the change now depends on a policy
        # version that no longer exists.
        for capability_id, state in self.issued.items():
            if not state["revoked"]:
                self.must_fail_renewal.add(capability_id)

    @rule()
    @precondition(lambda self: not self.credential_revoked)
    def revoke_credential(self):
        """Pull the credential, through the real control.

        This rule used raw SQL until D9, because there was no control to call:
        the cascade existed in a docstring only. Driving the operation rather
        than the column is what surfaced that.
        """
        with engagement_scope(self.engagement_id) as conn:
            revoked = revoke_credential(
                conn, engagement_id=self.engagement_id,
                credential_id=self.credential_id, actor="operator",
                reason="stateful test",
            )
        event(f"revoke_credential: cascade revoked {len(revoked)}")
        self.credential_revoked = True
        for capability_id in revoked:
            self._mark_revoked(capability_id)
        for capability_id, state in self.issued.items():
            if not state["revoked"]:
                self.must_fail_renewal.add(capability_id)

    @rule()
    @precondition(lambda self: not self.killed and not self.paused)
    def pause(self):
        """Pause through the real control, which also revokes in flight work."""
        with engagement_scope(self.engagement_id) as conn:
            state = pause_engagement(
                conn, engagement_id=self.engagement_id, actor="operator",
                reason="stateful test",
            )
        event(f"pause: cascade revoked {len(state.revoked_capabilities)}")
        self.paused = True
        for capability_id in state.revoked_capabilities:
            self._mark_revoked(capability_id)

    @rule()
    @precondition(lambda self: self.paused or self.killed)
    def resume(self):
        """Resume — which must be refused once the kill switch has been used.

        Reachable whenever the engagement is paused *or* killed, so the refusal
        is exercised rather than left to chance. §11's point about sequences
        applies to the test's own coverage too: a rule that can only fire in
        the safe case proves nothing about the dangerous one.
        """
        if self.killed:
            with engagement_scope(self.engagement_id) as conn:
                try:
                    resume_engagement(
                        conn, engagement_id=self.engagement_id, actor="operator",
                        reason="stateful test",
                    )
                except ValueError:
                    event("resume: REFUSED after kill switch (I9)")  # expected
                else:
                    raise AssertionError(
                        "resume_engagement succeeded after the kill switch (I9)"
                    )
            return

        with engagement_scope(self.engagement_id) as conn:
            resume_engagement(
                conn, engagement_id=self.engagement_id, actor="operator",
                reason="stateful test",
            )
        event("resume: allowed after a plain pause")
        self.paused = False
        # I9: resuming does not bring revoked capabilities back. They stay in
        # must_fail_renewal and must_be_revoked.

    @rule()
    @precondition(lambda self: not self.killed)
    def kill_switch(self):
        with engagement_scope(self.engagement_id) as conn:
            state = engage_kill_switch(
                conn, engagement_id=self.engagement_id, actor="operator",
                reason="stateful test",
            )
        event(f"kill_switch: cascade revoked {len(state.revoked_capabilities)}")
        self.killed = True
        for capability_id in state.revoked_capabilities:
            self._mark_revoked(capability_id)
        for capability_id, cap_state in self.issued.items():
            if not cap_state["revoked"]:
                self.must_fail_renewal.add(capability_id)

    @rule(which=st.sampled_from(sorted(SCOPE_CIDRS)))
    @precondition(lambda self: any(self.scope_active.values()) and any(
        not state["revoked"] for state in self.issued.values()
    ))
    def deactivate_scope(self, which: str):
        """Retire one of the scope objects capabilities were authorized against.

        Not in §4.6's renewal checklist, which lists policy, approval,
        credential, engagement and kill switch. It was included because I1 is
        about capabilities staying inside their scope, and an invariant that no
        rule can disturb is an invariant that proves nothing.

        It found one. On the first run this rule produced a three-step
        counterexample — issue, deactivate, violated — because retiring a scope
        object revoked nothing and renewal never re-checked it. The fix was to
        record scope_object_id on the capability and re-check its liveness on
        every heartbeat; this rule is what keeps that honest.

        The precondition requiring a live capability is not decoration. Without
        it Hypothesis found the cheap path — retire both scope objects in the
        first two steps, after which every ``issue`` is refused and nothing can
        follow. The rule fired 95 times in 100 examples and revoked nothing on
        any of them, so the cascade it exists to exercise was never run once
        while the suite reported success.
        """
        if not self.scope_active[which]:
            return
        revoked = retire_scope_object(
            engagement_id=self.engagement_id,
            scope_object_id=self.scope_ids[which], actor="engagement-manager",
            reason="stateful test",
        )
        self.scope_active[which] = False

        # Eager: the capabilities this scope object authorized are revoked now,
        # not at their next heartbeat. Asserted rather than merely recorded —
        # a cascade that silently revoked nothing would otherwise look the same
        # as one that worked, since renewal would refuse them either way.
        expected = {
            capability_id for capability_id, state in self.issued.items()
            if not state["revoked"] and state["scope"] == which
        }
        assert set(revoked) == expected, (
            f"retiring scope {which} revoked {sorted(revoked)}, expected "
            f"{sorted(expected)} — the cascade is imprecise in "
            f"{'both directions' if revoked and expected else 'one direction'}"
        )
        event(f"deactivate_scope: cascade revoked {len(revoked)}")
        for capability_id in revoked:
            self.revoked_by_scope[capability_id] = which
            self._mark_revoked(capability_id)

    @rule()
    @precondition(lambda self: any(
        not active for active in self.scope_active.values()
    ))
    def scope_retirement_is_precise(self):
        """Retiring a scope object revokes its capabilities and no others.

        Guards against the over-broad fix. Folding scope changes into
        policy_version would have made every heartbeat in the engagement fail
        after any scope edit — fail-closed, and still wrong: a control that
        stops unrelated work is a control operators learn to route around, and
        the audit trail would blame policy_version_changed for a policy that
        never moved.

        Written as a rule rather than an invariant because it asserts on
        renewal outcomes, which requires performing renewals.
        """
        # Side of the ledger 1: what the scope cascade actually revoked. Tracked
        # separately from must_be_revoked because a capability killed earlier by
        # the kill switch and only later caught by a retirement carries the
        # earlier reason, and asserting the scope reason on it would be wrong.
        event(f"precision: checking {len(self.revoked_by_scope)} cascade-revoked")
        for capability_id in self.revoked_by_scope:
            with engagement_scope(self.engagement_id) as conn:
                stored = get_capability(conn, capability_id)
                result = renew_capability(
                    conn, engagement_id=self.engagement_id,
                    capability_id=capability_id, actor="orchestrator",
                    ttl_seconds=60,
                )
            assert stored.revoked is True
            assert SCOPE_OBJECT_DEACTIVATED in (stored.revoked_reason or ""), (
                f"{capability_id} was revoked by a scope retirement but records "
                f"{stored.revoked_reason!r} — a borrowed reason sends an "
                f"investigator to the wrong table"
            )
            assert result.renewed is False, (
                f"{capability_id} renewed after its scope object was retired (I1)"
            )

        # Side 2: everything still resting on a live scope object. If retirement
        # revoked more than it should have, these are where it shows.
        #
        # The first assertion reads the database rather than the model, and that
        # is deliberate. Requiring a capability to be otherwise-pristine before
        # checking it made this branch unreachable in practice: a tighten, a
        # pause, a kill switch or a credential revocation poisons every
        # capability at once, and in a twenty-step random walk over eleven rules
        # at least one of those almost always fires first. Asking "was this
        # revoked *by a scope retirement*" instead is answerable whatever else
        # has happened to it.
        for capability_id, state in self.issued.items():
            if not self.scope_active[state["scope"]]:
                continue

            with engagement_scope(self.engagement_id) as conn:
                stored = get_capability(conn, capability_id)
                eligible = capability_id not in self.must_fail_renewal
                result = renew_capability(
                    conn, engagement_id=self.engagement_id,
                    capability_id=capability_id, actor="orchestrator",
                    ttl_seconds=60,
                ) if eligible else None

            assert SCOPE_OBJECT_DEACTIVATED not in (stored.revoked_reason or ""), (
                f"{capability_id} rests on scope object {state['scope']}, which "
                f"is still active, but was revoked by a scope retirement — the "
                f"cascade reached past the scope object it was retiring"
            )
            assert capability_id not in self.revoked_by_scope, (
                f"{capability_id} rests on a live scope object but the cascade "
                f"claimed it"
            )
            event("precision: bystander on a live scope object checked")
            if eligible:
                event("precision: bystander renewal asserted to succeed")
                assert result.renewed is True, (
                    f"{capability_id} rests on scope object {state['scope']}, "
                    f"which is still active, and had no other reason to fail, "
                    f"but renewal failed with {result.reasons}"
                )

    @rule(key_suffix=st.integers(min_value=0, max_value=3))
    def duplicate_dispatch(self, key_suffix: int):
        """I7: one idempotency key is dispatched at most once."""
        key = f"idem-{self.engagement_id}-{key_suffix}"
        proposal_id = _uid("PROP")
        with engagement_scope(self.engagement_id) as conn:
            existing = conn.execute(
                text("SELECT proposal_id FROM action_proposals "
                     "WHERE request_idempotency_key = :k"),
                {"k": key},
            ).scalar_one_or_none()
            if existing is None:
                conn.execute(
                    text("""
                        INSERT INTO action_proposals (proposal_id, engagement_id,
                            agent_id, request_idempotency_key, action, target,
                            "authorization", discovery)
                        VALUES (:p, :e, 'fake-worker', :k, :a, '{}'::jsonb,
                                '{}'::jsonb, '{}'::jsonb)
                    """),
                    {"p": proposal_id, "e": self.engagement_id, "k": key, "a": ACTION},
                )
                existing = proposal_id

            claimed = claim_for_dispatch(conn, existing)

        event("duplicate_dispatch: first claim" if claimed
              else "duplicate_dispatch: repeat claim correctly refused")
        self.dispatch_claims[key] = self.dispatch_claims.get(key, 0) + int(claimed)
        assert self.dispatch_claims[key] <= 1, (
            f"idempotency key {key} was dispatched "
            f"{self.dispatch_claims[key]} times (I7)"
        )

    # -----------------------------------------------------------------
    # Invariants — checked after every rule
    # -----------------------------------------------------------------

    @invariant()
    def i9_revocation_is_terminal(self):
        """Anything already revoked stays revoked, by every route."""
        if not self.must_be_revoked:
            return
        with engagement_scope(self.engagement_id) as conn:
            for capability_id in self.must_be_revoked:
                capability = get_capability(conn, capability_id)
                assert capability is not None
                assert capability.revoked is True, (
                    f"{capability_id} came back to life "
                    f"(killed={self.killed} paused={self.paused})"
                )

    @invariant()
    def i3_no_lease_outlives_its_budget(self):
        """Capability Confinement, under arbitrary interleaving."""
        if not self.issued:
            return
        with engagement_scope(self.engagement_id) as conn:
            rows = conn.execute(
                text("SELECT capability_id, issued_at, lease_expires_at, budget "
                     "FROM capabilities")
            ).mappings().all()
        for row in rows:
            budget = int(row["budget"].get("max_duration_seconds", BUDGET_SECONDS))
            granted = (row["lease_expires_at"] - row["issued_at"]).total_seconds()
            assert granted <= budget + 1, (
                f"{row['capability_id']} holds a {granted}s lease against a "
                f"{budget}s budget (I3)"
            )

    @invariant()
    def i1_live_capabilities_stay_in_scope(self):
        """Scope Safety: a capability still usable must still be authorized.

        Checked by re-resolving through the Authorization Resolver rather than
        by consulting the test's own record of what was registered — the
        question is what the system would decide now, not what the test
        remembers. The invariant deliberately uses the full resolver even
        though the broker uses a narrow liveness check: if the cheap check ever
        stops implying the real one, that is exactly the drift worth catching.

        The scope object is read from the capability's own row, so a capability
        that recorded the wrong one, or none, cannot pass by being re-resolved
        against whichever scope object happens to still be active.
        """
        with engagement_scope(self.engagement_id) as conn:
            rows = conn.execute(
                text("SELECT capability_id, constraints, scope_object_id "
                     "FROM capabilities "
                     "WHERE revoked IS FALSE AND lease_expires_at > now()")
            ).mappings().all()
            for row in rows:
                host = row["constraints"].get("host")
                if not host:
                    continue
                assert row["scope_object_id"] is not None, (
                    f"{row['capability_id']} is live but records no scope "
                    f"object, so nothing can re-check its authorization (I8)"
                )
                target = normalize_target(
                    {"logical_identity": {"type": "ip", "value": host}}
                )
                resolution = resolve_authorization(
                    conn, target=target, action=ACTION,
                    authorization={"source": "engagement_scope",
                                   "scope_object_id": row["scope_object_id"]},
                )
                assert resolution.authorized, (
                    f"{row['capability_id']} is live against {host} but the "
                    f"Authorization Resolver now says {resolution.reasons} (I1)"
                )

    @invariant()
    def i2_policy_only_tightens(self):
        """Policy Monotonicity across the whole run, not just at each change."""
        if self.policy_shape is None:
            return
        with engagement_scope(self.engagement_id) as conn:
            current = load_effective_policy(conn, self.engagement_id)
        assert current.data_deny >= self.policy_shape.data_deny, (
            "the effective data_deny shrank (I2)"
        )
        assert current.scope_deny >= self.policy_shape.scope_deny, (
            "the effective scope_deny shrank (I2)"
        )
        assert current.rate_limit <= self.policy_shape.rate_limit, (
            "the effective rate limit was raised (I2)"
        )
        for action, decision in self.policy_shape.actions.items():
            if decision == "DENY":
                assert current.actions.get(action) == "DENY", (
                    f"{action} was reopened after being denied (I2)"
                )

    def _why_dead(self, capability_id: str) -> set[str]:
        reasons = set()
        if self.killed:
            reasons.add(KILL_SWITCH)
        if self.paused:
            reasons.add(ENGAGEMENT_NOT_ACTIVE)
        if self.credential_revoked:
            reasons.add(CREDENTIAL_REVOKED)
        if self.tighten_counter:
            reasons.add(POLICY_CHANGED)
        state = self.issued.get(capability_id)
        if state and not self.scope_active[state["scope"]]:
            reasons.add(SCOPE_OBJECT_DEACTIVATED)
        if capability_id in self.must_be_revoked:
            reasons.add(ALREADY_REVOKED)
        return reasons

    def teardown(self) -> None:
        """Each example leaves its engagement behind; ids are unique."""


CapabilityLifecycle.TestCase.settings = settings(
    # §11 asks for at least 100 sequences. 300 is not padding: the states worth
    # reaching here need several specific rules to fire in order — issue on one
    # scope object, issue on the other, retire the first — and at 100 examples
    # the cascade branch was exercised three times. Sequence length is left to
    # Hypothesis, which shortens it again when shrinking a failure.
    max_examples=300,
    stateful_step_count=30,
    deadline=None,
    # Each step is a real database round trip, so examples are slow by nature
    # rather than by accident.
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

TestCapabilityLifecycle = CapabilityLifecycle.TestCase
