"""Identity containment geometry — "is this identity inside that one?" (D25).

One question, asked by two subsystems that must never be confused with each
other, and answered here so it can only be answered one way.

* The **Authorization Resolver** (§5) asks it about a *scope object* and a
  *target*: does this registered scope cover the thing a proposal names? The
  answer feeds an authorization decision.
* The **Metadata Resolver** (§5, D25) asks it about two *registry identities*:
  is this classified identity an ancestor of the one being resolved? The answer
  feeds a classification observation.

Those are different decisions on different tables with different trust models,
and ADR_CLASSIFICATION_INHERITANCE.md §6 is explicit that they must stay apart.
What they share is not a decision at all — it is arithmetic about addresses and
names. ``10.79.0.42`` is inside ``10.79.0.0/24`` whoever is asking and whatever
they plan to do with the answer.

So this module holds the arithmetic and nothing else. There is no
``ScopeObject`` here, no ``CanonicalTarget``, no registry row, no notion of
authorization or classification — only ``(type, value)`` pairs of the six kinds
in ``IDENTITY_TYPES``. That is the whole point of extracting it: the two callers
share one implementation of the geometry without the classification path
acquiring a dependency on the authorization path. The alternative considered and
rejected in the ADR was having the Metadata Resolver import
``scope_covers_target`` and hand it fabricated scope objects, which would have
dressed metadata rows up as authorization inputs — the exact entanglement D25
was told to avoid.

The other alternative — copying the arithmetic into the metadata path — is what
D15's mutation testing punished. Two implementations of one fact drift, and the
one that drifts is the one nobody was looking at.

Two rules govern everything below:

**It never raises.** A predicate that answers "does this contain that" by
throwing puts its caller in the position ``dispatch_scan`` was in before D15,
where one unparseable value took down the loop that would have refused it.

**Unparseable means "contains nothing".** A value nobody can interpret must
denote *less* than one that parses, never more. D15 found this the wrong way
round in ``scope_covers_target``: flipping the cidr branch's parse failure to
``return True`` left the entire suite green, because a value nobody could parse
was a state nothing had ever created. The direction of that answer is
load-bearing on both sides of the boundary — a scope object that covers
everything authorizes everything, and an ancestor that contains everything would
apply its classification to the whole registry.
"""

from __future__ import annotations

import ipaddress

# Mirrors target.IDENTITY_TYPES / §4.1.5. Imported rather than redefined would
# be circular: target.py is about normalizing one identity, this is about
# comparing two, and the type list belongs to the schema both describe.
CONTAINMENT_TYPES = frozenset({"fqdn", "ip", "cidr", "url", "repo", "ad_domain"})


def fqdn_is_subdomain_of(domain: str, host: str) -> bool:
    """Is ``host`` a *proper* subdomain of ``domain``, at a label boundary?

    ``api.pii.example.com`` is under ``pii.example.com`` and under
    ``example.com``. ``customer-a.com`` is **not** under ``a.com``: the string
    does end with ``a.com``, but the boundary falls inside the ``customer-a``
    label rather than at a dot, and substring suffix matching is how a scope or
    a classification comes to reach a domain nobody registered.

    Proper: a domain is not a subdomain of itself. Callers that want reflexive
    containment test equality themselves, which keeps the two cases visible at
    the call site instead of hidden in this predicate.
    """
    if not domain or not host:
        return False
    return host.endswith("." + domain)


def address_contains(network_value: str, child_type: str, child_value: str) -> bool:
    """Address arithmetic: is ``child`` inside the network ``network_value``?

    Accepts an ``ip`` child (membership) or a ``cidr`` child (subnet), and
    refuses everything else — an fqdn is never inside a network here, however it
    resolves. Resolving a name to an address is the step §8.9/I8 forbids as an
    authorization input, and D25 forbids it as a classification input for the
    same reason: a name and an address are different identities even when they
    point at the same host.

    ``strict=False`` on both sides is deliberate and safe: values reaching this
    function have already been canonicalized on write (D16) or come from a
    proposal that ``normalize_cidr`` refused to widen (D11-5). Parsing
    permissively here would only matter for a value that got past both, and such
    a value is refused by the exception handler below rather than reinterpreted.
    """
    if child_type not in ("ip", "cidr"):
        return False
    try:
        network = ipaddress.ip_network(network_value, strict=False)
        if child_type == "ip":
            return ipaddress.ip_address(child_value) in network
        return ipaddress.ip_network(child_value, strict=False).subnet_of(network)
    except (ValueError, TypeError):
        # Fail closed. Reached whenever either value is malformed, and also when
        # the two are different address families — subnet_of raises TypeError
        # comparing an IPv6 network to an IPv4 one, which must read as "does not
        # contain" rather than propagating out of a predicate.
        return False


def identity_contains(
    parent_type: str, parent_value: str, child_type: str, child_value: str
) -> bool:
    """Does the set denoted by the parent identity contain the child identity?

    **Reflexive**: a set contains itself, so an identity contains an identical
    identity. That is what the Authorization Resolver needs — an exact scope
    object covers its target — and callers wanting *proper* containment (the
    Metadata Resolver, for which a row is not its own ancestor) exclude the
    equal case themselves. Making reflexivity explicit at the call site beats
    hiding a "but not itself" rule in here, where only one of the two callers
    would ever want it.

    Type asymmetries are carried straight from §4.1.5 and are the point of typed
    identities: an ``fqdn`` parent never contains an ``ip`` child, a ``cidr``
    parent never contains an ``fqdn`` child.

    One spelling carries real meaning. For ``fqdn``, a leading ``*.`` denotes
    *the subtree below a domain*, while a bare domain denotes *one host*:

        identity_contains("fqdn", "*.example.com", "fqdn", "a.example.com") -> True
        identity_contains("fqdn", "*.example.com", "fqdn", "example.com")   -> False
        identity_contains("fqdn", "example.com",   "fqdn", "a.example.com") -> False
        identity_contains("fqdn", "example.com",   "fqdn", "example.com")   -> True

    That is §4.1.5's distinction — "a target is one host; a scope is a set" —
    and it is why the two callers pass different spellings rather than this
    function taking a mode flag. The Authorization Resolver passes a scope
    object's stored value, where ``*.`` means what the Engagement Manager wrote.
    The Metadata Resolver, whose rows are bare domains classifying a named
    thing, asks about a subtree by passing ``"*." + domain`` explicitly. A mode
    flag would put the choice of semantics inside the shared primitive, where
    the next caller would have to guess which mode it wanted; a spelling puts it
    at the call site, in the caller's own words.
    """
    if parent_type not in CONTAINMENT_TYPES or child_type not in CONTAINMENT_TYPES:
        return False
    if not isinstance(parent_value, str) or not isinstance(child_value, str):
        return False

    if parent_type == "fqdn":
        if child_type != "fqdn":
            return False
        if parent_value.startswith("*."):
            return fqdn_is_subdomain_of(parent_value[2:], child_value)
        return child_value == parent_value

    if parent_type == "ip":
        return child_type == "ip" and child_value == parent_value

    if parent_type == "cidr":
        return address_contains(parent_value, child_type, child_value)

    # url, repo, ad_domain: opaque identifiers the system only ever compares for
    # equality (see canonicalize_scope_value). They have structure a human reads
    # as hierarchy — a URL path, a repo's org, an AD tree — but no canonical
    # containment arithmetic is defined for any of them, and inventing one here
    # would change what matches without anyone deciding it should.
    return child_type == parent_type and child_value == parent_value
