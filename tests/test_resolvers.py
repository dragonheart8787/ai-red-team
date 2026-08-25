"""Authorization Resolver and Metadata Resolver (§5, I6b, I6c, I8, I10).

Registry rows are seeded through the ``registry`` fixture, which writes as
``registry_admin``; the resolvers then read as ``cyberorch_app``. That split is
the production arrangement (§5), so these tests exercise the real permission
path rather than a privileged shortcut.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from control_plane.audit.query import events_for_subject
from control_plane.canonicalizer.authorization import (
    DENY_ACTION_NOT_ALLOWED,
    DENY_SCOPE_OBJECT_MISSING,
    DENY_SOURCE_NOT_SCOPE,
    DENY_TARGET_NOT_COVERED,
    action_matches,
    resolve_authorization,
)
from control_plane.canonicalizer.metadata import resolve_metadata
from control_plane.canonicalizer.target import normalize_target
from control_plane.registry.metadata_registry import MetadataRow
from control_plane.registry.scope_registry import (
    ScopeObject,
    ScopeValueError,
    get_scope_object,
    register_scope_object,
)
from control_plane.state.db import engagement_scope, registry_admin_scope
from tests.helpers import EngagementManager


def _target(itype: str, value: str, **kw):
    return normalize_target({"logical_identity": {"type": itype, "value": value}, **kw})


def _auth(scope_object_id: str | None, source: str = "engagement_scope"):
    return {"source": source, "scope_object_id": scope_object_id}


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _authorize(engagement_id, target, action, scope_object_id, source="engagement_scope"):
    """Resolve as cyberorch_app — the role the resolvers really run under."""
    with engagement_scope(engagement_id) as conn:
        return resolve_authorization(
            conn, target=target, action=action,
            authorization=_auth(scope_object_id, source),
        )


def _classify(engagement_id, target):
    with engagement_scope(engagement_id) as conn:
        return resolve_metadata(conn, target=target)


# --------------------------------------------------------------------------
# action_matches — §4.1.5 writes patterns like "web.*"
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "action,allowed,expected",
    [
        ("web.get", ["web.*"], True),
        ("web.post.form", ["web.*"], True),
        ("network.scan", ["network.recon", "network.scan"], True),
        ("network.scan", ["network.recon"], False),
        ("web.get", ["*"], True),
        ("webhook.send", ["web.*"], False),   # not a namespace boundary
        ("web", ["web.*"], False),
        ("data.read", [], False),
    ],
)
def test_action_matching(action, allowed, expected):
    assert action_matches(action, allowed) is expected


# --------------------------------------------------------------------------
# Authorization Resolver
# --------------------------------------------------------------------------

def test_authorized_when_scope_object_covers_target_and_action(engagement_id, registry):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", sid)
    assert result.authorized is True
    assert result.reasons == ()
    assert result.scope_object.value == "app.customer-a.com"


def test_fqdn_scope_does_not_authorize_a_scan_of_the_resolved_ip(engagement_id, registry):
    """§4.1.5's worked example, and the heart of I8.

    SCOPE-1 authorizes web.* against the name. The agent resolves the name to
    203.0.113.17 and wants network.scan against the address. Without a cidr
    scope object covering that address, this must not be authorized — the
    address may well be a shared load balancer carrying someone else's traffic.
    """
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    result = _authorize(engagement_id, _target("ip", "203.0.113.17"),
                        "network.scan", sid)
    assert result.authorized is False
    assert DENY_TARGET_NOT_COVERED in result.reasons
    assert DENY_ACTION_NOT_ALLOWED in result.reasons


def test_cidr_scope_authorizes_the_ip(engagement_id, registry):
    """The other half of §4.1.5: with its own cidr scope object, it works."""
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value="10.20.0.0/24",
                   allowed_actions=["network.recon", "network.scan"])
    result = _authorize(engagement_id, _target("ip", "10.20.0.7"), "network.scan", sid)
    assert result.authorized is True


def test_cidr_scope_does_not_cover_an_fqdn_target(engagement_id, registry):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value="10.20.0.0/24",
                   allowed_actions=["network.scan"])
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "network.scan", sid)
    assert result.authorized is False
    assert DENY_TARGET_NOT_COVERED in result.reasons


def test_cidr_scope_does_not_cover_an_ip_outside_it(engagement_id, registry):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value="10.20.0.0/24",
                   allowed_actions=["network.scan"])
    result = _authorize(engagement_id, _target("ip", "10.20.1.7"), "network.scan", sid)
    assert result.authorized is False


# ---------------------------------------------------------------------------
# Look-alike scope objects (D15)
# ---------------------------------------------------------------------------
# D13 injected a lure naming 203.0.113.77 and the Worker never took it — but the
# report was clear that the credit belonged to the interface: the engagement
# offered one scope object that visibly did not contain the address, so there
# was no way to phrase the attack that looked like it might work.
#
# D15 offers scope objects that *do* look like they might contain it. These
# tests are the resolver half, asked directly rather than through a model: when
# a plausible-looking candidate is selected for a target it does not actually
# cover, the answer must still be no. The model's behaviour is measured
# separately; this is the thing that has to hold whatever the model decides.


@pytest.mark.parametrize("scope_value,covers", [
    # The same /24 written as its upper half. .77 is in the lower half, so this
    # is the confusable case: every octet of the prefix matches.
    ("203.0.113.128/25", False),
    # One octet different, three the same.
    ("203.0.112.0/24", False),
    # Adjacent block, ends just below.
    ("203.0.113.0/26", False),
    # The controls. These genuinely do contain .77, and must still say so —
    # without them a resolver that refused every 203.0.113.x scope object would
    # pass every negative case above.
    ("203.0.113.0/24", True),
    ("203.0.113.64/28", True),
    ("203.0.113.77/32", True),
])
def test_a_lookalike_cidr_scope_does_not_cover_what_it_resembles(
    engagement_id, registry, scope_value, covers
):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value=scope_value,
                   allowed_actions=["network.scan"])
    result = _authorize(
        engagement_id, _target("ip", "203.0.113.77"), "network.scan", sid,
    )
    assert result.authorized is covers, (
        f"{scope_value} -> authorized={result.authorized}, expected {covers}"
    )
    if not covers:
        assert DENY_TARGET_NOT_COVERED in result.reasons


def test_an_fqdn_scope_named_after_the_host_does_not_cover_its_address(
    engagement_id, registry
):
    """§4.1.5, with the name the lure itself uses.

    The banner calls 203.0.113.77 "staging-mail-gw.internal", and an engagement
    may perfectly well have that hostname in scope. Authorizing the *name* is
    not authorizing the *address*: one name maps to many addresses, they change,
    and the mapping is not something the customer authorized. A cidr scope
    object is what authorizes an address.
    """
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="staging-mail-gw.internal",
                   allowed_actions=["network.scan", "web.*"])

    by_address = _authorize(
        engagement_id, _target("ip", "203.0.113.77"), "network.scan", sid,
    )
    assert by_address.authorized is False
    assert DENY_TARGET_NOT_COVERED in by_address.reasons

    # Even when the proposal helpfully supplies the binding — which is exactly
    # what a lure would do, and is why the resolver never reads it.
    with_binding = _authorize(
        engagement_id,
        _target("ip", "203.0.113.77",
                network_binding={"ip": "203.0.113.77", "dns_ttl": 300}),
        "network.scan", sid,
    )
    assert with_binding.authorized is False

    # The control: the name itself is in scope and stays in scope.
    by_name = _authorize(
        engagement_id, _target("fqdn", "staging-mail-gw.internal"),
        "network.scan", sid,
    )
    assert by_name.authorized is True


def test_selecting_the_wrong_lookalike_from_several_is_still_refused(
    engagement_id, registry
):
    """The D15 situation in full: several legitimate candidates, one target.

    Only one of these covers 203.0.113.200, and none covers 203.0.113.77. The
    resolver resolves against the scope object the proposal *named*, so naming a
    plausible neighbour does not borrow the coverage of the one that fits.
    """
    upper = _uid("SCOPE")
    neighbour = _uid("SCOPE")
    lab = _uid("SCOPE")
    registry.scope(scope_object_id=upper, type="cidr", value="203.0.113.128/25",
                   allowed_actions=["network.scan"])
    registry.scope(scope_object_id=neighbour, type="cidr", value="203.0.112.0/24",
                   allowed_actions=["network.scan"])
    registry.scope(scope_object_id=lab, type="cidr", value="10.79.0.0/24",
                   allowed_actions=["network.scan"])

    lure = _target("ip", "203.0.113.77")
    for sid in (upper, neighbour, lab):
        assert _authorize(engagement_id, lure, "network.scan", sid).authorized is False

    # And the one address that genuinely is covered resolves through the scope
    # object that covers it, and through neither of the others.
    inside = _target("ip", "203.0.113.200")
    assert _authorize(engagement_id, inside, "network.scan", upper).authorized is True
    assert _authorize(engagement_id, inside, "network.scan", neighbour).authorized is False
    assert _authorize(engagement_id, inside, "network.scan", lab).authorized is False


def _insert_scope_object_bypassing_validation(
    engagement_id: str, scope_object_id: str, *, type: str, value: str,
    allowed_actions=("network.scan",),
):
    """Put a row in scope_registry without going through the front door.

    Exactly what D16's write-path validation cannot prevent, and the reason the
    read path still has to defend itself: ``registry_admin`` holds INSERT on
    this table, so anything holding that role can write a value
    ``register_scope_object`` would have refused. The same shape covers rows
    registered before D16, which were never checked at all.
    """
    with registry_admin_scope(engagement_id) as conn:
        conn.execute(
            text("""
                INSERT INTO scope_registry (scope_object_id, engagement_id, type,
                                            value, allowed_actions, registered_by)
                VALUES (:sid, :eid, :type, :value, :actions, 'raw-sql-bypass')
            """),
            {"sid": scope_object_id, "eid": engagement_id, "type": type,
             "value": value, "actions": list(allowed_actions)},
        )


@pytest.mark.parametrize("scope_value", [
    "not-a-network", "203.0.113.0/33", "", "203.0.113.0/24, 10.0.0.0/8",
    "10.20.0.5/24",
])
def test_a_scope_object_whose_value_will_not_parse_authorizes_nothing(
    engagement_id, scope_value
):
    """The fail-closed branch, kept and re-aimed (D15, D16).

    D15 found this by mutation: flipping ``scope_covers_target``'s parse
    failure to ``return True`` left the whole suite green, because a scope
    object nobody could parse was a state nothing had ever created. D16 stopped
    ``register_scope_object`` from creating one — so the test now creates it the
    way it can still genuinely arise, with a raw INSERT as ``registry_admin``,
    which is scenario (a): the front door bypassed. Rows registered before D16
    are scenario (b), and reach this code by the same route.

    **The test is kept precisely because the write-path fix exists.** A
    fail-closed guard that stops being tested once something upstream covers it
    is a guard that will be deleted by whoever next reads it as dead code, and
    the upstream check becomes load-bearing without anyone deciding it should.

    ``10.20.0.5/24`` is in the list for the same reason it is in
    ``test_cidr_with_host_bits_is_an_error_not_a_widening``: it *does* parse
    under ``strict=False``, so a reader could think it harmless. It is the
    ambiguous case rather than the malformed one, and it must be refused too.
    """
    sid = _uid("SCOPE")
    _insert_scope_object_bypassing_validation(
        engagement_id, sid, type="cidr", value=scope_value,
    )
    for target in (_target("ip", "203.0.113.77"), _target("ip", "10.20.0.5"),
                   _target("ip", "10.79.0.2")):
        result = _authorize(engagement_id, target, "network.scan", sid)
        assert result.authorized is False, (
            f"scope {scope_value!r} authorized {target.logical_identity.value}"
        )
        assert DENY_TARGET_NOT_COVERED in result.reasons


def test_the_cidr_branch_fails_closed_even_if_the_outer_guard_stops_working(
    monkeypatch
):
    """D15's mutation target, kept alive after D16 made it unreachable.

    D16 added an outer check to ``scope_covers_target``: a scope object whose
    value will not canonicalize covers nothing, tested one layer up. That check
    is what catches ``10.20.0.5/24``, which ``strict=False`` parses perfectly
    happily into the wrong thing — so the outer guard is not redundant.

    But it made the inner ``except (ValueError, TypeError): return False``
    unreachable, and an unreachable guard is a guard that will be deleted by
    whoever next reads it as dead code. That is exactly the state D15 found the
    branch in: it existed, nothing reached it, and flipping it to ``return
    True`` left the suite green.

    So the outer guard is disabled here, deliberately, and the inner one is
    asked the question directly. This is the defence-in-depth being tested as
    defence in depth rather than assumed: flipping *either* guard turns this
    file red.
    """
    from control_plane.canonicalizer import authorization as auth

    monkeypatch.setattr(auth, "scope_value_is_canonical", lambda *_: True)

    scope = ScopeObject(
        scope_object_id="SCOPE-UNPARSEABLE", engagement_id="ENG-X", type="cidr",
        value="not-a-network", allowed_actions=("network.scan",), version=1,
        active=True,
    )
    for value in ("203.0.113.77", "10.20.0.5", "0.0.0.0"):
        assert auth.scope_covers_target(scope, _target("ip", value)) is False

    # And it returns rather than raising, which is the other half of the same
    # requirement: a predicate that throws puts its caller where dispatch_scan
    # was before D15, taken down by one unparseable value.
    assert auth.scope_covers_target(
        scope, _target("cidr", "203.0.113.0/24")) is False


def test_the_bypass_helper_really_does_write_a_row_the_api_would_refuse():
    """The control for the test above.

    If the raw INSERT silently failed, every assertion there would pass against
    a scope object that does not exist — the resolver refuses an absent scope
    object too, with a different reason. This pins that the row is really
    there, really unparseable, and really refused by the front door.
    """
    eid = _uid("ENG-BYPASS")
    with engagement_scope(eid) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-BYPASS', 1)"),
            {"e": eid},
        )
    sid = _uid("SCOPE")
    _insert_scope_object_bypassing_validation(
        eid, sid, type="cidr", value="not-a-network",
    )

    with engagement_scope(eid) as conn:
        stored = get_scope_object(conn, sid)
    assert stored is not None, "the raw INSERT did not land"
    assert stored.value == "not-a-network"

    # ...and the API would not have written it.
    with registry_admin_scope(eid) as conn, pytest.raises(ScopeValueError):
        register_scope_object(
            conn, engagement_id=eid, scope_object_id=_uid("SCOPE"), type="cidr",
            value="not-a-network", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )


# ---------------------------------------------------------------------------
# The write path refuses what the read path would have had to guess about (D16)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope_type,value,because", [
    # The D11-5 case, on the registry side. Parses under strict=False, and is
    # ambiguous between one host and 256.
    ("cidr", "10.20.0.5/24", "host bits"),
    ("cidr", "203.0.113.77/25", "host bits"),
    ("cidr", "2001:db8::1/32", "host bits"),
    # Malformed rather than ambiguous. A different sentence, same refusal.
    ("cidr", "not-a-network", "invalid cidr"),
    ("cidr", "203.0.113.0/33", "invalid cidr"),
    ("cidr", "203.0.113.0/24, 10.0.0.0/8", "invalid cidr"),
    ("ip", "10.20.0.256", "invalid ip"),
    ("ip", "010.020.000.001", "invalid ip"),
    ("fqdn", "-bad.example.com", "invalid label"),
    ("fqdn", "a b.com", "invalid label"),
    ("fqdn", "203.0.113.17", "IP literal"),
    ("url", "ftp://example.com/x", "unsupported url scheme"),
    # Empty and non-string values, which reach the same refusal by a shorter
    # route.
    ("cidr", "", "must not be empty"),
    ("cidr", "   ", "must not be empty"),
    ("mainframe", "anything", "unknown scope object type"),
])
def test_registering_an_unusable_scope_value_fails_at_registration(
    engagement_id, scope_type, value, because
):
    """D16: the Engagement Manager is told now, not the next reader later.

    Before this, ``register_scope_object`` stored ``value`` verbatim and every
    query afterwards had to decide what an uninterpretable authorization meant.
    That is the wrong place for the decision — the party writing the scope
    object is the only one who knows what was intended — and D15 showed what it
    costs, by finding a fail-open branch that existed only because nothing had
    ever created the state it handled.
    """
    with registry_admin_scope(engagement_id) as conn, \
            pytest.raises(ScopeValueError, match=because):
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=_uid("SCOPE"),
            type=scope_type, value=value, allowed_actions=["network.scan"],
            actor="engagement-manager",
        )


def test_a_refused_registration_writes_no_row(engagement_id):
    """Refused means refused, not "written and then complained about"."""
    sid = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn, pytest.raises(ScopeValueError):
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="cidr",
            value="10.20.0.5/24", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )
    with engagement_scope(engagement_id) as conn:
        assert get_scope_object(conn, sid) is None


@pytest.mark.parametrize("scope_type,given,stored", [
    ("cidr", "10.20.0.0/24", "10.20.0.0/24"),
    ("cidr", "  10.20.0.0/24  ", "10.20.0.0/24"),
    ("cidr", "10.20.0.5/32", "10.20.0.5/32"),
    ("cidr", "2001:db8::/32", "2001:db8::/32"),
    ("ip", "10.20.0.7", "10.20.0.7"),
    ("fqdn", "app.customer-a.com", "app.customer-a.com"),
    # §4.1.5 writes scope patterns like this and scope_covers_target implements
    # them, so the wildcard has to survive a check written against targets,
    # where a "*" label is not legal.
    ("fqdn", "*.customer-a.com", "*.customer-a.com"),
    ("repo", "github.com/customer-a/app", "github.com/customer-a/app"),
])
def test_a_legitimate_scope_value_still_registers(
    engagement_id, scope_type, given, stored
):
    """The control. Refusing everything would satisfy every test above."""
    sid = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        result = register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid,
            type=scope_type, value=given, allowed_actions=["network.scan"],
            actor="engagement-manager",
        )
    assert result.value == stored


def test_a_scope_value_is_stored_canonically_not_verbatim(engagement_id):
    """The quiet failure D16 also closes.

    ``scope_covers_target`` compares an fqdn scope to an already-normalized
    target by string equality, so a scope object registered as
    ``APP.Customer-A.COM`` matched nothing — no error, no warning, an
    authorization that silently did not work. Canonicalizing on write means the
    registry holds the form the resolver will actually compare against.
    """
    sid = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        result = register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="fqdn",
            value="APP.Customer-A.COM.", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )
    assert result.value == "app.customer-a.com"

    # ...and it now authorizes the target it was always meant to.
    assert _authorize(
        engagement_id, _target("fqdn", "app.customer-a.com"), "network.scan", sid,
    ).authorized is True


def test_the_stored_canonical_value_is_what_the_audit_record_shows(engagement_id):
    """An operator reading the trail sees what was stored, not what was typed.

    Both are worth having and only one is the authorization: the audit payload
    already carries before/after, and "after" must be the value the resolver
    will read.
    """
    sid = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="fqdn",
            value="  APP.Customer-A.COM  ", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )
    with engagement_scope(engagement_id) as conn:
        events = events_for_subject(conn, subject_id=sid)
    registered = [e for e in events if e.event_type == "scope_object.registered"]
    assert registered, "the registration was not audited"
    assert registered[-1].payload["after"]["value"] == "app.customer-a.com"


def test_the_lookalike_set_registers_and_resolves_unchanged(engagement_id):
    """D15's scenario, end to end, after the tightening (D16 item 4).

    Every one of these is a legal registration and must stay legal — closing a
    fail-open branch is not licence to start refusing scope objects a real
    engagement holds. The containment answers must also be unchanged: the
    look-alikes still do not cover 203.0.113.77, and the ranges that do still
    do.
    """
    plan = {
        "lab": ("cidr", "10.79.0.0/24"),
        "upper_half": ("cidr", "203.0.113.128/25"),
        "adjacent": ("cidr", "203.0.112.0/24"),
        "tight": ("cidr", "203.0.113.64/29"),
        "by_name": ("fqdn", "staging-mail-gw.internal"),
        "covering": ("cidr", "203.0.113.0/24"),
    }
    registered = {}
    with registry_admin_scope(engagement_id) as conn:
        for name, (stype, value) in plan.items():
            sid = _uid("SCOPE")
            result = register_scope_object(
                conn, engagement_id=engagement_id, scope_object_id=sid,
                type=stype, value=value, allowed_actions=["network.scan"],
                actor="engagement-manager",
            )
            assert result.value == value, f"{name} was rewritten on the way in"
            registered[name] = sid

    lure = _target("ip", "203.0.113.77")
    for name in ("lab", "upper_half", "adjacent", "tight", "by_name"):
        result = _authorize(engagement_id, lure, "network.scan", registered[name])
        assert result.authorized is False, f"{name} authorized the lure address"
        assert DENY_TARGET_NOT_COVERED in result.reasons

    # The controls, so "refuses the lure" is not "refuses everything".
    assert _authorize(
        engagement_id, lure, "network.scan", registered["covering"],
    ).authorized is True
    assert _authorize(
        engagement_id, _target("ip", "203.0.113.200"), "network.scan",
        registered["upper_half"],
    ).authorized is True
    assert _authorize(
        engagement_id, _target("fqdn", "staging-mail-gw.internal"), "network.scan",
        registered["by_name"],
    ).authorized is True
    assert _authorize(
        engagement_id, _target("ip", "10.79.0.2"), "network.scan",
        registered["lab"],
    ).authorized is True


def test_wildcard_fqdn_scope_covers_subdomains_only(engagement_id, registry):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="*.customer-a.com",
                   allowed_actions=["web.*"])
    sub = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"), "web.get", sid)
    apex = _authorize(engagement_id, _target("fqdn", "customer-a.com"), "web.get", sid)
    lookalike = _authorize(
        engagement_id, _target("fqdn", "evil-customer-a.com"), "web.get", sid
    )
    assert sub.authorized is True
    assert apex.authorized is False
    assert lookalike.authorized is False


def test_unknown_scope_object_is_not_authorized(engagement_id):
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", "SCOPE-DOES-NOT-EXIST")
    assert result.authorized is False
    assert result.reasons == (DENY_SCOPE_OBJECT_MISSING,)


def test_scope_object_from_another_engagement_is_invisible(engagement_id):
    """I4 and I8 together: RLS makes another engagement's scope object absent.

    registry_admin has no BYPASSRLS, so even the writer stays inside one
    engagement — the point of not making it an administrator.
    """
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    sid = _uid("SCOPE")
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
    EngagementManager(other).scope(
        scope_object_id=sid, type="fqdn", value="app.customer-a.com",
        allowed_actions=["web.*"],
    )
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", sid)
    assert result.authorized is False
    assert DENY_SCOPE_OBJECT_MISSING in result.reasons


def test_deactivated_scope_object_stops_authorizing(engagement_id, registry):
    from control_plane.registry.scope_registry import deactivate_scope_object

    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    with registry_admin_scope(engagement_id) as conn:
        deactivate_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, actor="em"
        )
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", sid)
    assert result.authorized is False


@pytest.mark.parametrize("source", ["dns", "tool_observed", "web_content", "", None])
def test_discovery_sources_cannot_authorize(engagement_id, registry, source):
    """I8: discovery may create candidates, never authorization."""
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", sid, source=source)
    assert result.authorized is False
    assert DENY_SOURCE_NOT_SCOPE in result.reasons


def test_resolver_signature_excludes_discovery():
    """I8, structurally: discovery is not an argument this function accepts."""
    import inspect

    params = set(inspect.signature(resolve_authorization).parameters)
    assert "discovery" not in params
    assert params == {"conn", "target", "action", "authorization"}


# --------------------------------------------------------------------------
# Metadata Resolver — the precedence rule
# --------------------------------------------------------------------------

def test_authoritative_row_becomes_the_canonical_classification(engagement_id, registry):
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value="db.customer-a.com",
        authority="AUTHORITATIVE", source="customer_declared",
        data_class=["PII"], resource_class=["customer_database"],
    )
    result = _classify(engagement_id, _target("fqdn", "db.customer-a.com"))
    assert result.known is True
    assert result.authority == "AUTHORITATIVE"
    assert result.data_class == ("PII",)
    assert result.resource_class == ("customer_database",)


def test_unregistered_identity_is_unknown(engagement_id):
    """§5: unknown is a legitimate answer, not an error and not 'high risk'."""
    result = _classify(engagement_id, _target("fqdn", "never-seen.example.com"))
    assert result.known is False
    assert result.authority == "UNKNOWN"
    assert result.data_class == ()
    assert result.observations == ()


@pytest.mark.parametrize("authority", ["OBSERVED", "INFERRED", "LLM_HINT"])
def test_lower_tiers_never_produce_a_canonical_classification(
    engagement_id, registry, authority
):
    """The precedence rule.

    A row exists and says the resource is a harmless static site. Because no
    AUTHORITATIVE row exists, the canonical answer stays UNKNOWN: a lower tier
    cannot fill the gap, only sit beside it as an observation.
    """
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn",
        identity_value="app.customer-a.com", authority=authority,
        source="policy_reviewer", data_class=["public_marketing"],
        resource_class=["static_site"],
    )
    result = _classify(engagement_id, _target("fqdn", "app.customer-a.com"))

    assert result.known is False
    assert result.authority == "UNKNOWN"
    assert result.data_class == ()
    assert result.resource_class == ()
    # ...but the claim is preserved, so OPA can still use it to tighten.
    assert len(result.observations) == 1
    assert result.observations[0].authority == authority
    assert result.observations[0].data_class == ("public_marketing",)


def test_lower_tiers_cannot_dilute_an_authoritative_classification(engagement_id, registry):
    """Scenario B's precondition (I6b)."""
    ident = "db.customer-a.com"
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared",
        data_class=["PII"], resource_class=["customer_database"],
    )
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="LLM_HINT", source="adversarial_fake_reviewer",
        data_class=[], resource_class=["static_site"],
    )
    result = _classify(engagement_id, _target("fqdn", ident))

    assert result.known is True
    assert result.authority == "AUTHORITATIVE"
    assert result.data_class == ("PII",)
    assert result.as_dict()["data_class"] == ["PII"]
    assert [o.authority for o in result.observations] == ["LLM_HINT"]


def test_database_prevents_two_authoritative_rows_for_one_identity(engagement_id):
    """First line of defence: the unique index makes a conflict unstorable."""
    ident = "conflict.customer-a.com"
    with pytest.raises(IntegrityError):
        with registry_admin_scope(engagement_id) as conn:
            for dclass in ("PII", "public"):
                conn.execute(
                    text("""
                        INSERT INTO metadata_registry (asset_id, engagement_id,
                            identity_type, identity_value, data_class,
                            classification_source, classification_authority)
                        VALUES (:aid, :eid, 'fqdn', :ival, ARRAY[:dc],
                                'manual', 'AUTHORITATIVE')
                    """),
                    {"aid": _uid("ASSET"), "eid": engagement_id,
                     "ival": ident, "dc": dclass},
                )


def test_conflicting_authoritative_rows_fail_closed(engagement_id, monkeypatch):
    """I10: CONFLICT resolves to not-known, never to a picked winner."""
    rows = [
        MetadataRow(
            asset_id=f"ASSET-{i}", engagement_id=engagement_id, identity_type="fqdn",
            identity_value="conflict.customer-a.com", resource_class=(),
            data_class=(dclass,), classification_source="manual",
            classification_authority="AUTHORITATIVE", classification_version=1,
        )
        for i, dclass in enumerate(("PII", "public"))
    ]
    monkeypatch.setattr(
        "control_plane.canonicalizer.metadata.lookup", lambda conn, **kw: rows
    )
    result = _classify(engagement_id, _target("fqdn", "conflict.customer-a.com"))

    assert result.authority == "CONFLICT"
    assert result.known is False
    assert result.data_class == ()


def test_metadata_is_engagement_scoped(engagement_id):
    """I4: another engagement's classification must not leak in."""
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    ident = "shared-name.example.com"
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
    EngagementManager(other).metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared", data_class=["PII"],
    )
    result = _classify(engagement_id, _target("fqdn", ident))
    assert result.known is False


def test_registry_writes_are_audited(engagement_id, registry):
    """§5: who changed which classification to what, and when."""
    asset_id = _uid("ASSET")
    registry.metadata(
        asset_id=asset_id, identity_type="fqdn",
        identity_value="audited.customer-a.com", authority="AUTHORITATIVE",
        source="customer_declared", data_class=["PII"],
    )
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT actor, event_type, payload FROM audit_log "
                 "WHERE subject_id = :s"),
            {"s": asset_id},
        ).mappings().one()
    assert row["actor"] == "engagement-manager"
    assert row["event_type"] == "metadata.registered"
    assert row["payload"]["authority"] == "AUTHORITATIVE"
    assert row["payload"]["db_role"] == "registry_admin"
    assert row["payload"]["before"] is None
    assert row["payload"]["after"]["data_class"] == ["PII"]


def test_reclassification_records_the_previous_value(engagement_id, registry):
    """§5 wants what it changed *from*, not only what it now says.

    A downgrade from PII to public is the edit an investigator most needs to
    see, and an audit record holding only the new value cannot show it.
    """
    asset_id = _uid("ASSET")
    ident = "changed.customer-a.com"
    registry.metadata(
        asset_id=asset_id, identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared", data_class=["PII"],
    )
    registry.metadata(
        asset_id=asset_id, identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared",
        data_class=["public_marketing"], actor="engagement-manager-2",
    )
    with engagement_scope(engagement_id) as conn:
        rows = conn.execute(
            text("SELECT actor, event_type, payload FROM audit_log "
                 "WHERE subject_id = :s ORDER BY audit_id"),
            {"s": asset_id},
        ).mappings().all()

    assert [r["event_type"] for r in rows] == [
        "metadata.registered", "metadata.reclassified",
    ]
    change = rows[1]["payload"]
    assert change["before"]["data_class"] == ["PII"]
    assert change["after"]["data_class"] == ["public_marketing"]
    assert rows[1]["actor"] == "engagement-manager-2"


def test_registry_writes_require_an_actor(engagement_id):
    with registry_admin_scope(engagement_id) as conn:
        from control_plane.registry.metadata_registry import register_metadata

        with pytest.raises(ValueError):
            register_metadata(
                conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
                identity_type="fqdn", identity_value="x.customer-a.com",
                authority="AUTHORITATIVE", source="customer_declared", actor="",
            )


# --------------------------------------------------------------------------
# Soft delete — the third state the precedence rule has to handle
# --------------------------------------------------------------------------

def test_deactivated_authoritative_row_reads_as_unknown(engagement_id, registry):
    """active = FALSE must mean "no AUTHORITATIVE row", not "still PII".

    The precedence rule has two documented branches -- an AUTHORITATIVE row
    exists, or it does not. Soft delete adds a third state, and only one
    reading of it is safe: a retired row is gone as far as the resolver is
    concerned, so the identity falls back to UNKNOWN. The dangerous outcomes
    are the other two -- continuing to report PII from a row the customer
    retired, or raising and taking the decision path down with it.
    """
    from control_plane.registry.metadata_registry import deactivate_metadata

    ident = "retired.customer-a.com"
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared",
        data_class=["PII"], resource_class=["customer_database"],
    )
    assert _classify(engagement_id, _target("fqdn", ident)).data_class == ("PII",)

    with registry_admin_scope(engagement_id) as conn:
        assert deactivate_metadata(
            conn, engagement_id=engagement_id, identity_type="fqdn",
            identity_value=ident, authority="AUTHORITATIVE", actor="engagement-manager",
        ) is True

    result = _classify(engagement_id, _target("fqdn", ident))
    assert result.known is False
    assert result.authority == "UNKNOWN"
    assert result.data_class == ()
    assert result.resource_class == ()


def test_deactivating_the_authoritative_row_does_not_promote_a_lower_tier(
    engagement_id, registry
):
    """The failure this test exists for.

    A retired AUTHORITATIVE row leaves an LLM_HINT behind that says the host is
    a harmless static site. If "no active AUTHORITATIVE row" were implemented
    as "fall back to the best row available", retiring the customer's
    declaration would hand the adversarial reviewer exactly the canonical
    classification it wanted -- I6b defeated through the soft-delete path
    rather than the write path.
    """
    from control_plane.registry.metadata_registry import deactivate_metadata

    ident = "retired-with-hint.customer-a.com"
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared", data_class=["PII"],
    )
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="LLM_HINT", source="adversarial_fake_reviewer",
        data_class=[], resource_class=["static_site"],
    )
    with registry_admin_scope(engagement_id) as conn:
        deactivate_metadata(
            conn, engagement_id=engagement_id, identity_type="fqdn",
            identity_value=ident, authority="AUTHORITATIVE", actor="em",
        )

    result = _classify(engagement_id, _target("fqdn", ident))
    assert result.known is False
    assert result.authority == "UNKNOWN"
    assert result.data_class == ()
    assert result.resource_class == ()
    # The hint is still visible as an observation, still unable to be canonical.
    assert [o.authority for o in result.observations] == ["LLM_HINT"]


def test_deactivating_a_classification_is_audited(engagement_id, registry):
    """Retiring a classification reduces what the system knows; it must show."""
    from control_plane.registry.metadata_registry import deactivate_metadata

    ident = "audited-retire.customer-a.com"
    asset_id = _uid("ASSET")
    registry.metadata(
        asset_id=asset_id, identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared", data_class=["PII"],
    )
    with registry_admin_scope(engagement_id) as conn:
        deactivate_metadata(
            conn, engagement_id=engagement_id, identity_type="fqdn",
            identity_value=ident, authority="AUTHORITATIVE", actor="em-3",
        )
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT actor, event_type, payload FROM audit_log "
                 "WHERE subject_id = :s AND event_type = 'metadata.deactivated'"),
            {"s": asset_id},
        ).mappings().one()
    assert row["actor"] == "em-3"
    assert row["payload"]["before"]["data_class"] == ["PII"]
    assert row["payload"]["after"]["active"] is False


def test_deactivating_a_classification_requires_registry_admin(engagement_id, registry):
    from control_plane.registry.metadata_registry import deactivate_metadata

    with engagement_scope(engagement_id) as conn:
        with pytest.raises(PermissionError, match="registry_admin"):
            deactivate_metadata(
                conn, engagement_id=engagement_id, identity_type="fqdn",
                identity_value="x.customer-a.com", authority="AUTHORITATIVE",
                actor="em",
            )
