"""A policy layer published for one customer applies only to that customer (ACCEPTANCE 5.35).

``_APPLICABLE`` selected on ``engagement_id`` alone and never read ``customer_id``, so a
``customer`` layer published with ``customer_id = CUST-ALPHA`` was in force for every engagement
in the database. Executed at D54, before this fix: an ``actions: {a: ALLOW}`` layer for
``CUST-ALPHA`` turned ``DENY`` into ``ALLOW`` for an engagement of ``CUST-BETA``. Denies leaking
across customers is fail-safe; allows leaking is a customer's grant widening someone else's
authority.

The rule now: **a layer that names a customer applies only to engagements of that customer,
whatever the layer's name; a layer that names none applies as before.** The same predicate feeds
the merge, the listing and ``current_policy_version`` -- the last of which used to carry a private
copy of it, so a fix in one place would have left capability revocation describing a different set
of layers. ``test_one_predicate_feeds_every_reader`` pins that.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.capability.broker import current_policy_version
from control_plane.policy.layers import (
    PolicyLayerError,
    deactivate_policy_layer,
    list_effective_policy_layers,
    load_effective_policy,
    publish_policy_layer,
)
from control_plane.policy.merge import ALLOW, DENY
from control_plane.state.db import engagement_scope
from tests.helpers import make_engagement

CONTROL_PLANE = Path(__file__).resolve().parents[1] / "control_plane"


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _version() -> int:
    return uuid.uuid4().int % 2_000_000_000


@pytest.fixture
def two_customers(db_available):
    """An engagement each for two customers. The customer ids are unique to the test, so a
    layer left behind can never apply to another test's engagement."""
    alpha, beta = _uid("CUST-ALPHA"), _uid("CUST-BETA")
    eng_a, eng_b = _uid("ENG-A"), _uid("ENG-B")
    make_engagement(eng_a, alpha)
    make_engagement(eng_b, beta)
    published: list[tuple[str, int]] = []
    yield {"alpha": alpha, "beta": beta, "eng_a": eng_a, "eng_b": eng_b,
           "published": published}
    for eng, layer_id in published:
        with engagement_scope(eng) as conn:
            deactivate_policy_layer(conn, engagement_id=eng, layer_id=layer_id,
                                    actor="test-teardown")


def _publish(ctx, *, from_engagement, layer="customer", document, customer_id,
             scoped_to_engagement=False):
    with engagement_scope(from_engagement) as conn:
        layer_id = publish_policy_layer(
            conn, engagement_id=from_engagement, layer=layer, version=_version(),
            document=document, actor="platform-owner", customer_id=customer_id,
            scoped_to_engagement=scoped_to_engagement,
        )
    ctx["published"].append((from_engagement, layer_id))
    return layer_id


def _decision(engagement_id, action):
    with engagement_scope(engagement_id) as conn:
        return load_effective_policy(conn, engagement_id).action_decision(action)


# ---------------------------------------------------------------------------
# The case that was executed, written the other way round
# ---------------------------------------------------------------------------

def test_one_customers_allow_layer_does_not_widen_another_customers_engagement(two_customers):
    """The D54 finding as a regression test: ALPHA's ALLOW, beta's DENY."""
    ctx = two_customers
    action = f"probe.{uuid.uuid4().hex[:8]}"
    assert _decision(ctx["eng_b"], action) == DENY, "the control: nothing allows it yet"

    _publish(ctx, from_engagement=ctx["eng_a"], document={"actions": {action: ALLOW}},
             customer_id=ctx["alpha"])

    assert _decision(ctx["eng_a"], action) == ALLOW, (
        "the layer must still apply to the customer it was published for")
    assert _decision(ctx["eng_b"], action) == DENY, (
        "a layer published for another customer widened this engagement (ACCEPTANCE 5.35)")


def test_publishing_from_the_other_customers_engagement_changes_nothing(two_customers):
    """Where a layer is published *from* is not what scopes it. D11-7 already made the
    publishing engagement irrelevant for global rows; the customer is the scope."""
    ctx = two_customers
    action = f"probe.{uuid.uuid4().hex[:8]}"
    _publish(ctx, from_engagement=ctx["eng_b"], document={"actions": {action: ALLOW}},
             customer_id=ctx["alpha"])
    assert _decision(ctx["eng_a"], action) == ALLOW
    assert _decision(ctx["eng_b"], action) == DENY


def test_one_customers_deny_layer_does_not_restrict_another(two_customers):
    """Isolation, not merely widening: the leak was symmetric, and a customer's own
    restriction is that customer's business."""
    ctx = two_customers
    token = _uid("class")
    _publish(ctx, from_engagement=ctx["eng_a"], document={"data_deny": [token]},
             customer_id=ctx["alpha"])
    with engagement_scope(ctx["eng_a"]) as conn:
        assert token in load_effective_policy(conn, ctx["eng_a"]).data_deny
    with engagement_scope(ctx["eng_b"]) as conn:
        assert token not in load_effective_policy(conn, ctx["eng_b"]).data_deny


@pytest.mark.parametrize("layer", ["baseline_global", "emergency_overlay", "engagement"])
def test_the_rule_is_about_the_customer_id_not_the_layer_name(two_customers, layer):
    """A baseline or overlay that names a customer is that customer's; only one that
    names none is everyone's."""
    ctx = two_customers
    token = _uid("class")
    _publish(ctx, from_engagement=ctx["eng_a"], layer=layer,
             document={"data_deny": [token]}, customer_id=ctx["alpha"],
             scoped_to_engagement=(layer == "engagement"))
    with engagement_scope(ctx["eng_a"]) as conn:
        assert token in load_effective_policy(conn, ctx["eng_a"]).data_deny
    with engagement_scope(ctx["eng_b"]) as conn:
        assert token not in load_effective_policy(conn, ctx["eng_b"]).data_deny


def test_an_engagement_layer_naming_a_different_customer_is_not_applied(two_customers):
    """Belt and braces: an engagement-scoped row still has to agree with the engagement's
    own customer, so a mis-published row cannot bind an engagement to a foreign policy."""
    ctx = two_customers
    token = _uid("class")
    _publish(ctx, from_engagement=ctx["eng_b"], layer="engagement",
             document={"data_deny": [token]}, customer_id=ctx["alpha"],
             scoped_to_engagement=True)
    with engagement_scope(ctx["eng_b"]) as conn:
        assert token not in load_effective_policy(conn, ctx["eng_b"]).data_deny


def test_a_layer_naming_no_customer_still_applies_to_everyone(two_customers):
    """The negative control: this fix must not scope layers that were never customer-scoped."""
    ctx = two_customers
    token = _uid("class")
    _publish(ctx, from_engagement=ctx["eng_a"], layer="baseline_global",
             document={"data_deny": [token]}, customer_id=None)
    for eng in (ctx["eng_a"], ctx["eng_b"]):
        with engagement_scope(eng) as conn:
            assert token in load_effective_policy(conn, eng).data_deny


# ---------------------------------------------------------------------------
# The listing and the version describe the same set as the merge
# ---------------------------------------------------------------------------

def test_the_listing_and_the_version_agree_with_the_merge(two_customers):
    ctx = two_customers
    layer_id = _publish(ctx, from_engagement=ctx["eng_a"],
                        document={"data_deny": [_uid("class")]}, customer_id=ctx["alpha"])

    with engagement_scope(ctx["eng_b"]) as conn:
        listed_b = {layer.id for layer in list_effective_policy_layers(conn, ctx["eng_b"])}
        version_b = current_policy_version(conn, ctx["eng_b"])
    with engagement_scope(ctx["eng_a"]) as conn:
        listed_a = {layer.id for layer in list_effective_policy_layers(conn, ctx["eng_a"])}
        version_a = current_policy_version(conn, ctx["eng_a"])

    assert layer_id not in listed_b and layer_id in listed_a
    assert version_a == max(listed_a)
    assert version_b == max(listed_b, default=0)
    assert version_b != layer_id, (
        "another customer's layer moved this engagement's policy version, which would "
        "revoke its capabilities at the next heartbeat for a policy that is not in force")


def test_a_layer_for_one_customer_does_not_revoke_another_customers_capabilities(two_customers):
    ctx = two_customers
    with engagement_scope(ctx["eng_b"]) as conn:
        before = current_policy_version(conn, ctx["eng_b"])
    _publish(ctx, from_engagement=ctx["eng_a"], document={"data_deny": [_uid("class")]},
             customer_id=ctx["alpha"])
    with engagement_scope(ctx["eng_b"]) as conn:
        assert current_policy_version(conn, ctx["eng_b"]) == before


def test_the_listing_labels_a_customers_layer_as_the_customers_not_global(two_customers):
    """D14's rule (11.1's third constraint): scope is stated, never inferred from a null
    column. A customer layer has a NULL engagement_id like a global one, and 'global' would
    be exactly the confusion the label exists to prevent."""
    ctx = two_customers
    layer_id = _publish(ctx, from_engagement=ctx["eng_a"],
                        document={"data_deny": [_uid("class")]}, customer_id=ctx["alpha"])
    with engagement_scope(ctx["eng_a"]) as conn:
        (row,) = [layer for layer in list_effective_policy_layers(conn, ctx["eng_a"])
                  if layer.id == layer_id]
    assert row.scope == "customer"
    assert row.is_global is False
    assert row.customer_id == ctx["alpha"]


def test_an_engagement_that_does_not_exist_sees_no_customer_scoped_layer(two_customers):
    """No engagement row means no customer to match: fail closed, not 'everyone's'."""
    ctx = two_customers
    layer_id = _publish(ctx, from_engagement=ctx["eng_a"],
                        document={"data_deny": [_uid("class")]}, customer_id=ctx["alpha"])
    ghost = _uid("ENG-GHOST")
    with engagement_scope(ghost) as conn:
        assert layer_id not in {layer.id for layer in list_effective_policy_layers(conn, ghost)}


def test_the_version_recorded_at_creation_counts_the_customers_own_layers(two_customers):
    """``create_engagement`` computes its version before the row exists, so it has to be told
    the customer; otherwise it would silently ignore every layer the customer's engagement
    will in fact be governed by."""
    from control_plane.orchestrator.engagement import create_engagement
    from control_plane.state.db import registry_admin_scope

    ctx = two_customers
    layer_id = _publish(ctx, from_engagement=ctx["eng_a"],
                        document={"data_deny": [_uid("class")]}, customer_id=ctx["alpha"])

    same, other = _uid("ENG-SAME"), _uid("ENG-OTHER")
    with registry_admin_scope(same) as conn:
        create_engagement(conn, engagement_id=same, customer_id=ctx["alpha"], actor="t")
    with registry_admin_scope(other) as conn:
        create_engagement(conn, engagement_id=other, customer_id=ctx["beta"], actor="t")

    def stored(eng):
        with engagement_scope(eng) as conn:
            return conn.execute(
                text("SELECT policy_snapshot_version FROM engagements "
                     "WHERE engagement_id = :e"), {"e": eng}).scalar_one()

    assert stored(same) >= layer_id, "the customer's own layer was not counted"
    assert stored(other) < layer_id, "another customer's layer was counted"


# ---------------------------------------------------------------------------
# Publishing: a customer layer cannot be published as everyone's by omission
# ---------------------------------------------------------------------------

def test_a_global_customer_layer_must_name_its_customer(two_customers):
    """Otherwise leaving ``customer_id`` out reproduces the bug through the front door:
    a layer named 'customer' that applies to every customer."""
    ctx = two_customers
    with engagement_scope(ctx["eng_a"]) as conn:
        with pytest.raises(PolicyLayerError, match="customer_id"):
            publish_policy_layer(
                conn, engagement_id=ctx["eng_a"], layer="customer", version=_version(),
                document={"data_deny": ["x"]}, actor="platform-owner")


def test_an_engagement_scoped_customer_layer_needs_no_customer_id(two_customers):
    """It is confined by its engagement already; refusing it would be over-defence (and it
    is how the D14 fixture publishes one)."""
    ctx = two_customers
    _publish(ctx, from_engagement=ctx["eng_a"], document={"data_deny": [_uid("class")]},
             customer_id=None, scoped_to_engagement=True)


# ---------------------------------------------------------------------------
# One predicate
# ---------------------------------------------------------------------------

def test_one_predicate_feeds_every_reader():
    """The D14 guarantee, extended to the reader D14 missed. ``current_policy_version`` kept
    a private copy of the applicability predicate; a fix to the shared one would have left the
    version -- and so which capabilities are revoked -- describing a different set of layers.

    Nothing outside ``control_plane/policy/layers.py`` reads ``policy_layers``, and inside it
    exactly one statement has the applicability shape (``WHERE active IS TRUE``). Writes are not
    reads and are not counted; ``deactivate_policy_layer``'s by-id lookup is a different shape."""
    outside, applicability = [], []
    for path in CONTROL_PLANE.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(CONTROL_PLANE.parent))
        for match in re.finditer(r"FROM\s+policy_layers", source, flags=re.IGNORECASE):
            line = source.count("\n", 0, match.start()) + 1
            if rel != "control_plane/policy/layers.py":
                outside.append(f"{rel}:{line}")
            elif re.match(r"\s+WHERE\s+active\s+IS\s+TRUE", source[match.end():match.end() + 60]):
                applicability.append(f"{rel}:{line}")
    assert not outside, f"policy_layers is read outside layers.py: {outside}"
    assert len(applicability) == 1, (
        "the applicability predicate must exist exactly once "
        f"(layers.py::_APPLICABLE); found: {applicability}")
