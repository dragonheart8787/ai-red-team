"""Which adapter serves which action, and what each one does to a target.

§3 names this file as the tool capability/budget schema per tool (§4.6). It
holds the one mapping from an ``action`` string to the adapter that implements
it, and it is the only place that mapping exists — dispatch routes through it,
and the policy path reads side effects out of it.

Why the side-effect profile lives here (D34)
---------------------------------------------
D31 declared ``writes_data`` / ``changes_state`` on the web.get adapter and
argued they were trustworthy because ``build_plan`` was structurally incapable
of emitting anything with side effects. D34 adds web.post, which ends that
argument: something in ``web.*`` can now change a target.

The authority had to move somewhere sturdier, and the requirement on wherever
it moved was that a compromised or mistaken caller must not be able to *steer*
it. The answer is the **action**:

* the action is decided before anything runs. It is what the Worker proposed,
  what the Authorization Resolver matched against a scope object, what OPA
  judged, and what the Capability Broker issued a capability for;
* by dispatch time it is a column on the issued capability row, read back out
  of the database. Dispatch takes no action parameter and no side-effect
  parameter — there is no argument on that path that could carry a different
  value;
* so this lookup answers "what does the thing that was approved actually do",
  not "what does the caller say it does".

That is the same shape as D20's fix for ``discovery_source``: the Worker used
to report its own provenance, and the repair was not a better-validated field
but a value the pipeline computes and the agent cannot supply. A test inspects
the signatures on this path and asserts the absence of such a parameter, in the
style of D13's "the function has no ``discovery`` argument to falsify".

**The floor only raises.** ``side_effect_floor`` takes the Worker's claim and
the action's profile and returns the more cautious of the two. A Worker that
declares ``writes_data=True`` for a web.get keeps its caution — lowering it
would be the system overriding an agent's caution with its own optimism, which
is the one direction I6c forbids.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from tool_gateway.adapters import browser, http_get, http_post, nmap

#: Action → adapter module.
#:
#: A capability whose action has no adapter is refused rather than defaulted to
#: one. Defaulting is how a ``web.get`` capability would have executed as an
#: nmap scan while every record said otherwise.
#:
#: A ``MappingProxyType`` rather than a dict: the table is read on the
#: authorization path since D34, so a runtime mutation would change what the
#: policy believes a pending action does. Immutable here means the only way to
#: change it is a code change that goes through review and CI.
ADAPTERS = MappingProxyType({
    "network.scan": nmap,
    "network.recon": nmap,
    http_get.ACTION: http_get,
    http_post.ACTION: http_post,
    browser.ACTION: browser,
})

#: A capability naming an action no adapter implements.
UNKNOWN_ACTION = "no_adapter_for_action"

#: A web.* action dispatched with no egress proxy to route it through (D34).
PROXY_REQUIRED = "egress_proxy_required"


@dataclass(frozen=True)
class SideEffects:
    """What running one action does to the target (§4.1)."""

    writes_data: bool
    changes_state: bool

    def raised_by(self, *, writes_data: bool, changes_state: bool) -> SideEffects:
        """This profile, no lower than the claim it is compared with."""
        return SideEffects(
            writes_data=self.writes_data or bool(writes_data),
            changes_state=self.changes_state or bool(changes_state),
        )


def adapter_for(action: str):
    """The adapter that serves this action, or ``None``."""
    return ADAPTERS.get(action)


def requires_proxy(action: str) -> bool:
    """Whether this action's adapter must be routed through the egress proxy."""
    adapter = adapter_for(action)
    return bool(adapter is not None and getattr(adapter, "REQUIRES_PROXY", False))


def side_effects_for(action: str) -> SideEffects | None:
    """What the tool behind ``action`` does, or ``None`` if nothing runs it.

    Read off the adapter's own constants rather than restated in a table here.
    A second list of "what web.post does" would be a second thing to keep equal
    to the first, which is the defect D30 closed and D33 refused to reintroduce.

    ``None`` for an action no adapter implements, and that is not a gap: an
    action with no adapter cannot execute at all — dispatch refuses it with
    ``UNKNOWN_ACTION`` before a container starts — so there is no tool
    behaviour to state a floor about. The Worker's own claim stands, and it
    governs nothing but whether §5 asks for a human.
    """
    adapter = adapter_for(action)
    if adapter is None:
        return None
    return SideEffects(
        writes_data=bool(adapter.WRITES_DATA),
        changes_state=bool(adapter.CHANGES_STATE),
    )


def side_effect_floor(
    *, action: str, writes_data: bool, changes_state: bool
) -> SideEffects:
    """The side effects OPA should judge, given what the Worker claimed.

    Deliberately takes the claim as two booleans rather than a proposal object:
    the caller passes what the agent said, and gets back what the system is
    willing to believe. Nothing in the signature can express "use these flags
    instead of the action's".
    """
    profile = side_effects_for(action)
    if profile is None:
        return SideEffects(
            writes_data=bool(writes_data), changes_state=bool(changes_state)
        )
    return profile.raised_by(writes_data=writes_data, changes_state=changes_state)
