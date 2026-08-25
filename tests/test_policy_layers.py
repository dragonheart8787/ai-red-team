"""Publishing policy layers, and the merged policy that results (§4.5, I2).

The gap this closes: ``policy_layers`` had no writer. Every Emergency Overlay in
the test suite was a raw INSERT, so §4.5's central mechanism — the one I2 is
about — had never been exercised as an operation. Third instance of the same
pattern, after D8's kill switch and D9's credential cascade.

The tests are in two groups, and the second is the one that matters. Asserting
that a row landed in the table proves the INSERT works. Asserting that the
merged policy tightened proves the overlay does something, which before this
commit it could not have: nothing loaded the stored layers, so the enforced
policy and the stored Policy Pack were unrelated artifacts.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from control_plane.audit.query import audited_event_types, events_for_subject
from control_plane.policy.layers import (
    EMERGENCY_OVERLAY,
    EmergencyOverlayError,
    PolicyLayerError,
    deactivate_policy_layer,
    list_effective_policy_layers,
    load_effective_policy,
    publish_policy_layer,
)
from control_plane.policy.merge import ALLOW, DENY, UNIVERSE
from control_plane.state.db import engagement_scope


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _token(kind: str) -> str:
    """A data_class / action name no other test will mention.

    Global layers are visible to every engagement and outlive the test that
    published them, so an assertion like ``data_deny == {"PII"}`` is really an
    assertion about every test that ran first. Per-test tokens make each
    assertion about this test's own layers.
    """
    return f"{kind}-{uuid.uuid4().hex[:8]}"


def _version() -> int:
    """A version nobody else in the suite will pick.

    ``policy_layers_identity`` is unique over
    ``(layer, version, engagement_id, customer_id)``, and a *global* layer has a
    NULL engagement_id — so two tests publishing "emergency_overlay version 1"
    globally collide, across the whole run and across runs, since nothing
    truncates the table.
    """
    return int(uuid.uuid4().int % 1_000_000_000)


# Layers published by these tests are engagement-scoped unless a test is
# specifically about global reach. Global layers are shared mutable state: they
# are visible to every engagement by design, which is exactly what makes them
# unusable as a per-test fixture once anything actually loads and merges them.


# ---------------------------------------------------------------------------
# The operation
# ---------------------------------------------------------------------------

def test_publishing_a_layer_is_audited_with_its_document(engagement_id):
    """§4.4: an overlay pushed during an incident is read back literally.

    The whole document is recorded, not a summary of it. "Which keys did it
    set" is not what an investigator asks about an emergency overlay.
    """
    with engagement_scope(engagement_id) as conn:
        layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY, version=_version(),
            document={"data_deny": ["PII"], "actions": {"network.scan": "DENY"}},
            actor="incident-commander", scoped_to_engagement=True,
        )

    with engagement_scope(engagement_id) as conn:
        assert "policy_layer.published" in audited_event_types(conn)
        event = events_for_subject(conn, subject_id=str(layer_id))[0]

    assert event.actor == "incident-commander"
    assert event.payload["layer"] == EMERGENCY_OVERLAY
    assert event.payload["scope"] == "engagement"
    assert event.payload["policy_version"] == layer_id
    assert event.payload["document"] == {
        "data_deny": ["PII"], "actions": {"network.scan": "DENY"},
    }


def test_a_global_layer_is_visible_from_every_engagement(engagement_id):
    """Baseline and emergency layers carry a NULL engagement_id by design.

    Cleans up after itself. A global layer is shared mutable state for the whole
    suite, so a test that leaves one behind is a test that quietly changes the
    policy every later test loads.
    """
    token = _token("GLOBAL_PII")
    other = f"ENG-OTHER-{uuid.uuid4().hex[:8]}"
    with engagement_scope(engagement_id) as conn:
        layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY,
            version=_version(), document={"data_deny": [token]},
            actor="incident-commander",
        )
    try:
        with engagement_scope(other) as conn:
            conn.execute(
                text("INSERT INTO engagements (engagement_id, customer_id, "
                     "policy_snapshot_version) VALUES (:e, 'CUST', 1)"),
                {"e": other},
            )
            assert token in load_effective_policy(conn, other).data_deny
    finally:
        with engagement_scope(engagement_id) as conn:
            deactivate_policy_layer(
                conn, engagement_id=engagement_id, layer_id=layer_id,
                actor="test-cleanup",
            )


def test_an_engagement_scoped_layer_stays_in_its_engagement(engagement_id):
    """I4 at the policy layer: scoped_to_engagement means what it says."""
    other = f"ENG-OTHER-{uuid.uuid4().hex[:8]}"
    with engagement_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=_version(),
            document={"data_deny": ["local_only"]}, actor="engagement-manager",
            scoped_to_engagement=True,
        )
        assert "local_only" in load_effective_policy(conn, engagement_id).data_deny

    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST', 1)"),
            {"e": other},
        )
        assert "local_only" not in load_effective_policy(conn, other).data_deny


def test_an_unknown_layer_name_is_refused(engagement_id):
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(PolicyLayerError, match="unknown policy layer"):
            publish_policy_layer(
                conn, engagement_id=engagement_id, layer="whatever", version=_version(),
                document={}, actor="someone",
            )


def test_publishing_requires_an_actor(engagement_id):
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(PolicyLayerError, match="actor"):
            publish_policy_layer(
                conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY,
                version=_version(), document={}, actor="",
            )


# ---------------------------------------------------------------------------
# Tighten-only (§4.5), at both layers of enforcement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("document,match", [
    ({"scope_allow": ["10.0.0.0/8"]}, "scope_allow"),
    ({"actions": {"network.scan": ALLOW}}, "ALLOW"),
])
def test_an_overlay_that_would_relax_anything_is_refused(
    engagement_id, document, match
):
    """The API refuses before the database has to."""
    version = _version()
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(EmergencyOverlayError, match=match):
            publish_policy_layer(
                conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY,
                version=version, document=document, actor="incident-commander",
            )
        # Nothing was written. Counted by this version rather than by layer
        # name: global layers outlive the test that published them, so "no
        # emergency overlay exists" is not a thing any single test can assert.
        assert conn.execute(
            text("SELECT count(*) FROM policy_layers WHERE version = :v"),
            {"v": version},
        ).scalar_one() == 0


@pytest.mark.parametrize("document", [
    {"scope_allow": ["10.0.0.0/8"]},
    {"actions": {"network.scan": ALLOW}},
])
def test_bypassing_the_api_still_hits_the_database_constraint(
    engagement_id, document
):
    """The guarantee does not depend on going through publish_policy_layer.

    Asserted explicitly because a validation that lives only in the API is a
    validation that a future second writer will not have. §4.5's tighten-only
    rule is a property of the table, and this is what says so.
    """
    import json

    with engagement_scope(engagement_id) as conn:
        with pytest.raises(IntegrityError, match="emergency_overlay_can_only_tighten"):
            conn.execute(
                text("INSERT INTO policy_layers (layer, version, document) "
                     "VALUES (:l, 99, CAST(:d AS jsonb))"),
                {"l": EMERGENCY_OVERLAY, "d": json.dumps(document)},
            )


def test_a_non_emergency_layer_may_allow(engagement_id):
    """The restriction is the overlay's, not every layer's.

    Without this, a tighten-only check applied to all four layers would pass
    every test above while making the baseline unable to permit anything.
    """
    action = _token("probe.action")
    with engagement_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="baseline_global",
            version=_version(),
            document={"scope_allow": ["10.0.0.0/8"], "actions": {action: ALLOW}},
            actor="platform-owner", scoped_to_engagement=True,
        )
        policy = load_effective_policy(conn, engagement_id)

    assert policy.action_decision(action) == ALLOW
    assert policy.scope_allow == frozenset({"10.0.0.0/8"})


# ---------------------------------------------------------------------------
# End to end: publishing changes what merge_policy produces
# ---------------------------------------------------------------------------

def test_an_engagement_with_no_layers_of_its_own_is_not_denied_everything(
    engagement_id
):
    """Neutral elements, reached from the loading side (§4.5).

    The bug this guards is the one ``intersect_allow`` exists for: folding an
    unpublished layer in as an empty allow list would deny everything the
    moment a layer stayed silent.

    Asserted on an engagement that has published nothing of its own rather than
    on an empty table, because the table is never empty. Global layers have a
    NULL engagement_id, are visible to every engagement by design, and outlive
    the test that published them — so no single test can assert what the whole
    table contains. The exact neutral-element algebra is pinned where it
    belongs, on the pure function, in test_merge.py.
    """
    with engagement_scope(engagement_id) as conn:
        policy = load_effective_policy(conn, engagement_id)

    # Not the empty set: unset means unconstrained, not "deny everything".
    assert policy.scope_allow is UNIVERSE or isinstance(
        policy.scope_allow, frozenset
    )
    assert "nothing-published-this-key" not in policy.data_deny
    # Fail-closed all the same: an action nobody mentioned is denied (I10).
    assert policy.action_decision(f"never.mentioned.{uuid.uuid4().hex[:6]}") == DENY


def test_publishing_an_overlay_tightens_the_merged_policy(engagement_id):
    """The test the whole commit exists for (I2).

    A baseline that permits the scan, then an overlay that denies it. The
    assertion is on the merged policy, not on the row: before this commit
    nothing loaded the stored layers, so an overlay could be published
    perfectly and change no decision anywhere.
    """
    action, data = _token("probe.action"), _token("PII")
    with engagement_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="baseline_global",
            version=_version(),
            document={"scope_allow": ["10.0.0.0/8", "192.168.0.0/16"],
                      "actions": {action: ALLOW}, "rate_limit": 100},
            actor="platform-owner", scoped_to_engagement=True,
        )
        before = load_effective_policy(conn, engagement_id)
        assert before.action_decision(action) == ALLOW
        assert data not in before.data_deny

        publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY,
            version=_version(),
            document={"data_deny": [data], "scope_deny": ["192.168.0.0/16"],
                      "actions": {action: DENY}, "rate_limit": 5},
            actor="incident-commander", scoped_to_engagement=True,
        )
        after = load_effective_policy(conn, engagement_id)

    # Every dimension moved in the tightening direction, and none the other way.
    assert after.action_decision(action) == DENY
    assert data in after.data_deny
    assert "192.168.0.0/16" in after.scope_deny
    assert after.rate_limit == 5
    assert after.scope_allow == before.scope_allow  # overlay may not widen it

    assert after.data_deny >= before.data_deny
    assert after.scope_deny >= before.scope_deny
    assert after.rate_limit <= before.rate_limit


def test_publishing_moves_the_policy_version_capabilities_are_checked_against(
    engagement_id
):
    """The link to I9: a new layer is what makes outstanding capabilities stale."""
    from control_plane.capability.broker import current_policy_version

    with engagement_scope(engagement_id) as conn:
        before = current_policy_version(conn, engagement_id)
        layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY, version=_version(),
            document={"data_deny": ["PII"]}, actor="incident-commander",
            scoped_to_engagement=True,
        )
        after = current_policy_version(conn, engagement_id)

    assert after == layer_id
    assert after > before


def test_rows_of_one_layer_combine_rather_than_the_latest_masking_the_rest(
    engagement_id
):
    """Republishing accumulates. Superseding would be a way to escape a tighten.

    The alternative — latest row wins per layer name — looked natural and is
    unsafe. Emergency overlays are global; an engagement-scoped overlay of the
    same layer name would then shadow the global one, so publishing an empty
    overlay under a global tightening would lift it. §4.5 says the overlay can
    only tighten, and that has to hold against the loader too.

    So retiring a layer is deactivation, not republication.
    """
    pii, phi = _token("PII"), _token("PHI")
    with engagement_scope(engagement_id) as conn:
        first = publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY,
            version=_version(), document={"data_deny": [pii]},
            actor="incident-commander", scoped_to_engagement=True,
        )
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY,
            version=_version(), document={"data_deny": [phi]},
            actor="incident-commander", scoped_to_engagement=True,
        )
        both = load_effective_policy(conn, engagement_id)

        # Neither publication was lost.
        assert {pii, phi} <= both.data_deny

        # An empty later overlay cannot lift an earlier one.
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY,
            version=_version(), document={}, actor="attacker",
            scoped_to_engagement=True,
        )
        assert {pii, phi} <= load_effective_policy(
            conn, engagement_id
        ).data_deny

        # Deactivation is how a layer is actually retired.
        deactivate_policy_layer(
            conn, engagement_id=engagement_id, layer_id=first, actor="operator",
        )
        after = load_effective_policy(conn, engagement_id)

    assert pii not in after.data_deny
    assert phi in after.data_deny


def test_deactivating_a_layer_widens_and_revokes_nothing(engagement_id):
    """What deactivation actually does, which is not what the docs claimed.

    Found writing this test. ``current_policy_version``'s docstring had said
    since D5 that deactivating a layer does not move the version, on the
    reasoning that a widening cannot make an outstanding capability more
    permissive. The reasoning holds; the claim did not. The version is
    ``max(id)`` over *active* rows, so retiring the highest layer lowers it, and
    every outstanding capability is revoked for POLICY_CHANGED on its next
    heartbeat.

    Over-revoking on a widening is fail-closed, so the behaviour stands and the
    docstring was corrected instead. This asserts the real thing on both counts:
    the merged policy widens, and the version moves.
    """
    from control_plane.capability.broker import (
        Budget,
        current_policy_version,
        get_capability,
        issue_capability,
    )

    capability_id, token = _uid("CAP"), _token("PII")
    with engagement_scope(engagement_id) as conn:
        layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY, version=_version(),
            document={"data_deny": [token]}, actor="incident-commander",
            scoped_to_engagement=True,
        )
        issue_capability(
            conn, engagement_id=engagement_id, capability_id=capability_id,
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            budget=Budget(), ttl_seconds=60,
        )
        version_with_layer = current_policy_version(conn, engagement_id)

        assert deactivate_policy_layer(
            conn, engagement_id=engagement_id, layer_id=layer_id, actor="operator",
        ) is True

        assert token not in load_effective_policy(conn, engagement_id).data_deny

        # The version moves down, because the maximum is over active rows.
        assert current_policy_version(conn, engagement_id) < version_with_layer

        # Deactivation itself revokes nothing -- no cascade runs here. The
        # capability is still live until something asks it to renew, which is
        # when the moved version will refuse it.
        assert get_capability(conn, capability_id).revoked is False
        assert "policy_layer.deactivated" in audited_event_types(conn)


def test_deactivating_an_absent_layer_reports_rather_than_raises(engagement_id):
    with engagement_scope(engagement_id) as conn:
        assert deactivate_policy_layer(
            conn, engagement_id=engagement_id, layer_id=999999, actor="operator",
        ) is False


# ---------------------------------------------------------------------------
# list_effective_policy_layers — D14, DEFERRED 11.1
# ---------------------------------------------------------------------------

class _WatchingConnection:
    """A Connection proxy that keeps every result ``execute`` handed back.

    Written this way on purpose. The binding constraint is that the listing
    returns *exactly* the rows the merge consumed, and a test comparing the
    listing to its own hand-written SELECT would only be asserting that two
    copies of one query agree. This watches what ``load_effective_policy``
    actually fetches, so rewriting its selection — a different predicate, a
    LIMIT, dropping the ORDER BY, forgetting the global rows — changes what the
    spy sees and turns the test red.
    """

    def __init__(self, inner):
        self._inner = inner
        self.fetched: list[list[dict]] = []

    def execute(self, statement, *args, **kwargs):
        result = self._inner.execute(statement, *args, **kwargs)
        rows = result.mappings().all()
        self.fetched.append([dict(row) for row in rows])
        return _ReplayedResult(rows)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _ReplayedResult:
    """Hands the already-consumed rows back to the real caller."""

    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows

    def scalar_one(self):
        return next(iter(self._rows[0].values()))

    def scalar_one_or_none(self):
        if not self._rows:
            return None
        return next(iter(self._rows[0].values()))

    def one(self):
        return self._rows[0]

    def one_or_none(self):
        return self._rows[0] if self._rows else None


@pytest.fixture
def layered_engagement(engagement_id):
    """One global layer and one engagement-scoped layer, both active, plus a
    retired one and another engagement's, neither of which may be listed."""
    action = _token("action")
    other_engagement = _uid("ENG-OTHER")

    with engagement_scope(engagement_id) as conn:
        global_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer="baseline_global",
            version=_version(), document={"actions": {action: ALLOW}},
            actor="platform-owner",
        )
        scoped_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement",
            version=_version(), document={"data_deny": [_token("class")]},
            actor="engagement-manager", scoped_to_engagement=True,
        )
        retired_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer="customer",
            version=_version(), document={"data_deny": [_token("class")]},
            actor="engagement-manager", scoped_to_engagement=True,
        )
        deactivate_policy_layer(
            conn, engagement_id=engagement_id, layer_id=retired_id,
            actor="engagement-manager",
        )

    with engagement_scope(other_engagement) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other_engagement},
        )
        foreign_id = publish_policy_layer(
            conn, engagement_id=other_engagement, layer="engagement",
            version=_version(), document={"data_deny": [_token("class")]},
            actor="engagement-manager", scoped_to_engagement=True,
        )

    yield {
        "engagement_id": engagement_id, "action": action,
        "global_id": global_id, "scoped_id": scoped_id,
        "retired_id": retired_id, "foreign_id": foreign_id,
    }

    # Retire the global layer this fixture published. A global row applies to
    # every engagement in the database and nothing expires it, which is the
    # accumulation DEFERRED 11.1 exists because of -- and a test that leaves one
    # behind is the mechanism that produced the nineteen. The engagement-scoped
    # rows are harmless and are left alone.
    with engagement_scope(engagement_id) as conn:
        deactivate_policy_layer(
            conn, engagement_id=engagement_id, layer_id=global_id,
            actor="test-teardown",
        )


def test_the_listing_returns_exactly_the_rows_the_merge_consumed(layered_engagement):
    """The binding constraint from DEFERRED 11.1, pinned against the real merge.

    Not "similar", not "a superset" — the same ids. A listing that shows a
    different set from the one being enforced is worse than no listing, because
    it will be believed. Asserted by watching the rows ``load_effective_policy``
    actually fetched rather than by re-deriving them here, so a change to its
    selection that this function did not follow is caught.
    """
    eid = layered_engagement["engagement_id"]

    with engagement_scope(eid) as conn:
        listed = list_effective_policy_layers(conn, eid)
        watcher = _WatchingConnection(conn)
        load_effective_policy(watcher, eid)

    consumed = [row for batch in watcher.fetched for row in batch]
    assert consumed, "load_effective_policy fetched nothing to compare against"
    assert {row["id"] for row in consumed} == {layer.id for layer in listed}
    # And in the same order, so "which layer wins" reads the same both ways.
    assert [row["id"] for row in consumed] == [layer.id for layer in listed]


def test_the_listing_excludes_retired_and_foreign_layers(layered_engagement):
    """The control for the equality above.

    Without it, a listing that returned every row in the table would satisfy
    "exactly the rows the merge consumed" only if the merge were equally broken
    — and both being wrong together is precisely the failure mode the shared
    predicate exists to prevent, so it is worth checking the set is right and
    not merely agreed upon.
    """
    eid = layered_engagement["engagement_id"]
    with engagement_scope(eid) as conn:
        listed = list_effective_policy_layers(conn, eid)

    ids = {layer.id for layer in listed}
    assert layered_engagement["global_id"] in ids
    assert layered_engagement["scoped_id"] in ids
    assert layered_engagement["retired_id"] not in ids, "a retired layer was listed"
    assert layered_engagement["foreign_id"] not in ids, (
        "another engagement's layer was listed"
    )


def test_a_global_layer_is_labelled_global_not_inferred(layered_engagement):
    """DEFERRED 11.1's third constraint.

    The whole D11-6 failure was a global layer read as though it were the
    engagement's own, and "you can tell because the other column is empty" is
    the inference that failed. So it is a field.
    """
    eid = layered_engagement["engagement_id"]
    with engagement_scope(eid) as conn:
        listed = {layer.id: layer for layer in list_effective_policy_layers(conn, eid)}

    global_layer = listed[layered_engagement["global_id"]]
    scoped_layer = listed[layered_engagement["scoped_id"]]

    assert global_layer.scope == "global"
    assert global_layer.is_global is True
    assert global_layer.engagement_id is None

    assert scoped_layer.scope == "engagement"
    assert scoped_layer.is_global is False
    assert scoped_layer.engagement_id == eid


def test_an_invisible_attribution_says_so_rather_than_being_blank(layered_engagement):
    """DEFERRED 11.1's fourth constraint, and the line against papering over 11.2.

    A layer published from *this* engagement has a visible audit row, so the
    publisher is named. A layer whose audit row belongs to another engagement is
    invisible under RLS — and the listing must say that, because a blank field
    reads as "nobody published it", which is false and is exactly the confusion
    11.2 is about.
    """
    eid = layered_engagement["engagement_id"]
    foreign = _uid("ENG-FOREIGN")

    with engagement_scope(foreign) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-FOREIGN', 1)"),
            {"e": foreign},
        )
        invisible_id = publish_policy_layer(
            conn, engagement_id=foreign, layer="baseline_global",
            version=_version(), document={"actions": {_token("action"): ALLOW}},
            actor="someone-elses-operator",
        )

    with engagement_scope(eid) as conn:
        listed = {layer.id: layer for layer in list_effective_policy_layers(conn, eid)}
        # Same reason as the fixture's teardown: retire it before asserting, so
        # a failing assertion cannot leave a global layer behind.
        deactivate_policy_layer(
            conn, engagement_id=eid, layer_id=invisible_id, actor="test-teardown",
        )

    # An engagement-scoped layer published from this engagement has its audit
    # row here, so the publisher is named.
    published_here = listed[layered_engagement["scoped_id"]]
    assert published_here.published_by == "engagement-manager"
    assert published_here.published_at is not None
    assert published_here.attribution_note is None

    # A global layer's attribution is no longer visible from the engagement — the
    # D11-7 fix stopped the global publish audit from being mis-scoped into the
    # publisher's engagement, so even a global layer published from *this*
    # engagement now records globally. Its publisher is read from the global
    # trail (scripts/global_audit.py), not from here; the listing says so rather
    # than leaving a blank that reads as "nobody published it".
    for global_id in (layered_engagement["global_id"], invisible_id):
        glob = listed[global_id]
        assert glob.is_global is True
        assert glob.published_by is None
        assert glob.attribution_note, (
            "an invisible attribution was left blank, which reads as 'no publisher'"
        )
        assert "not visible" in glob.attribution_note
        assert "11.2" in glob.attribution_note


def test_the_listing_carries_the_document_that_decides_the_action(layered_engagement):
    """The question the command exists to answer: *which* layer said DENY."""
    eid = layered_engagement["engagement_id"]
    action = layered_engagement["action"]

    with engagement_scope(eid) as conn:
        deny_id = publish_policy_layer(
            conn, engagement_id=eid, layer=EMERGENCY_OVERLAY, version=_version(),
            document={"actions": {action: DENY}}, actor="incident-commander",
            scoped_to_engagement=True,
        )
        listed = list_effective_policy_layers(conn, eid)
        policy = load_effective_policy(conn, eid)

    assert policy.action_decision(action) == DENY
    culprits = [
        layer for layer in listed
        if (layer.document.get("actions") or {}).get(action) == DENY
    ]
    assert [layer.id for layer in culprits] == [deny_id]


def test_the_listing_writes_nothing(layered_engagement):
    """Read-only, asserted rather than assumed.

    ``policy_layers`` and ``audit_log`` are both append-friendly for this role,
    so "it only reads" needs checking rather than trusting: a listing that
    logged its own invocation would grow the audit trail every time somebody
    asked a question.
    """
    eid = layered_engagement["engagement_id"]
    with engagement_scope(eid) as conn:
        before = conn.execute(
            text("SELECT count(*) FROM policy_layers")).scalar_one()
        audit_before = conn.execute(
            text("SELECT count(*) FROM audit_log")).scalar_one()

        list_effective_policy_layers(conn, eid)

        assert conn.execute(
            text("SELECT count(*) FROM policy_layers")).scalar_one() == before
        assert conn.execute(
            text("SELECT count(*) FROM audit_log")).scalar_one() == audit_before


def test_an_engagement_with_no_layers_lists_nothing_and_denies_everything():
    """The empty case reads the same both ways (§4.5, I10)."""
    eid = _uid("ENG-EMPTY")
    with engagement_scope(eid) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-EMPTY', 1)"),
            {"e": eid},
        )
        # Retire everything global so this engagement genuinely sees nothing.
        globals_ = [
            r[0] for r in conn.execute(
                text("SELECT id FROM policy_layers WHERE active "
                     "AND engagement_id IS NULL")).all()
        ]
        for layer_id in globals_:
            deactivate_policy_layer(
                conn, engagement_id=eid, layer_id=layer_id, actor="test-cleanup")

        listed = list_effective_policy_layers(conn, eid)
        policy = load_effective_policy(conn, eid)

        assert listed == ()
        assert policy.action_decision("network.scan") == DENY

        # Put them back: global layers belong to the whole database and this
        # test does not own them.
        for layer_id in globals_:
            conn.execute(
                text("UPDATE policy_layers SET active = TRUE WHERE id = :i"),
                {"i": layer_id})
